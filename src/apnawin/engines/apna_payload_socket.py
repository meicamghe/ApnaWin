"""Socket establishment for APNA-family SSH payload injection.

This layer opens a TCP/TLS stream, writes the expanded payload, and optionally
validates the proxy's HTTP CONNECT response. It deliberately does not perform
SSH authentication or create a VPN interface; those remain separate stages.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from apnawin.engines.apna_payload import PayloadRotation, render_apna_payload, send_payload


class PayloadTransportError(ConnectionError):
    """The payload transport could not establish a usable SSH byte stream."""


class PayloadSocketMode(str, Enum):
    DIRECT = "direct"
    HTTP_PROXY = "http_proxy"
    TLS_DIRECT = "tls_direct"


@dataclass(frozen=True, slots=True)
class PayloadSocketConfig:
    mode: PayloadSocketMode
    connect_host: str
    connect_port: int
    target_host: str
    target_port: int
    payload: str = ""
    sni: str | None = None
    protocol: str = "HTTP/1.0"
    dropbear_no_response: bool = False
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    max_response_header_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        for name in ("connect_host", "target_host"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 253:
                raise ValueError(f"{name} must be a non-empty host name")
            if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
                raise ValueError(f"{name} contains whitespace or control characters")
        for name in ("connect_port", "target_port"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
                raise ValueError(f"{name} must be between 1 and 65535")
        for name in ("connect_timeout", "read_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be positive")
        if not 64 <= self.max_response_header_bytes <= 64 * 1024:
            raise ValueError("max_response_header_bytes is outside the safe range")
        if self.sni is not None and (
            not isinstance(self.sni, str)
            or not self.sni
            or len(self.sni) > 253
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in self.sni)
        ):
            raise ValueError("sni is invalid")


class _SocketWriter:
    def __init__(self, sock: socket.socket) -> None:
        self._socket = sock

    def write(self, data: bytes) -> None:
        self._socket.sendall(data)

    def flush(self) -> None:
        # sendall() has already handed all bytes to the socket implementation.
        return None


def _read_http_connect_response(sock: socket.socket, limit: int) -> int:
    """Read only through CRLFCRLF so SSH bytes following the header stay buffered."""
    response = bytearray()
    while not response.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise PayloadTransportError("Proxy closed before completing its HTTP response")
        response.extend(chunk)
        if len(response) > limit:
            raise PayloadTransportError("Proxy response headers exceed the configured limit")

    first_line = bytes(response).split(b"\r\n", 1)[0]
    try:
        status_line = first_line.decode("iso-8859-1")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[0] not in {"HTTP/1.0", "HTTP/1.1"}:
            raise ValueError
        status = int(parts[1])
    except (UnicodeError, ValueError) as exc:
        raise PayloadTransportError("Proxy returned an invalid HTTP status line") from exc
    if status != 200:
        raise PayloadTransportError(f"Proxy rejected the SSH payload (HTTP {status})")
    return status


class ApnaPayloadSocketConnector:
    """Create the TCP/TLS socket used as the lower transport for an SSH client."""

    def __init__(
        self,
        *,
        socket_factory: Callable[..., socket.socket] = socket.create_connection,
        tls_context: ssl.SSLContext | None = None,
        rotation: PayloadRotation | None = None,
    ) -> None:
        self._socket_factory = socket_factory
        self._tls_context = tls_context or ssl.create_default_context()
        self._rotation = rotation or PayloadRotation()

    def connect(self, config: PayloadSocketConfig) -> socket.socket:
        if not isinstance(config, PayloadSocketConfig):
            raise TypeError("config must be a PayloadSocketConfig")
        raw_socket: socket.socket | None = None
        active_socket: socket.socket | None = None
        try:
            raw_socket = self._socket_factory(
                (config.connect_host, config.connect_port),
                timeout=config.connect_timeout,
            )
            raw_socket.settimeout(config.read_timeout)
            active_socket = raw_socket

            if config.mode is PayloadSocketMode.TLS_DIRECT:
                active_socket = self._tls_context.wrap_socket(
                    raw_socket,
                    server_hostname=config.sni or config.target_host,
                )
                active_socket.settimeout(config.read_timeout)

            if config.mode is PayloadSocketMode.DIRECT:
                return active_socket

            chunks = render_apna_payload(
                config.payload,
                host=config.target_host,
                port=config.target_port,
                protocol=config.protocol,
                rotation=self._rotation,
            )
            send_payload(_SocketWriter(active_socket), chunks)

            if config.mode is PayloadSocketMode.HTTP_PROXY and not config.dropbear_no_response:
                _read_http_connect_response(active_socket, config.max_response_header_bytes)

            return active_socket
        except Exception as exc:
            if active_socket is not None:
                try:
                    active_socket.close()
                except OSError:
                    pass
            elif raw_socket is not None:
                try:
                    raw_socket.close()
                except OSError:
                    pass
            if isinstance(exc, (PayloadTransportError, ValueError, TypeError)):
                raise
            raise PayloadTransportError(
                f"Could not establish {config.mode.value} payload transport"
            ) from exc
