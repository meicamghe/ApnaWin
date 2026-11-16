"""SOCKS5 CONNECT transport for a UDPGW stream carried over SSH.

The SSH layer supplies a local SOCKS5 dynamic-forwarding endpoint. This module
uses that endpoint to open a TCP stream to the remote UDPGW server, then sends
and receives BadVPN-compatible PacketProto frames over the resulting channel.
"""
from __future__ import annotations

import ipaddress
import math
import socket
import struct
from collections import deque
from dataclasses import dataclass
from typing import Callable

from apnawin.engines.udpgw_protocol import (
    PacketProtoDecoder,
    UdpGwPacket,
    decode_udpgw_payload,
    encode_datagram,
    encode_keepalive,
)


class Socks5ProtocolError(ConnectionError):
    """SOCKS5 negotiation failed or returned a malformed response."""


class UdpGwTransportError(ConnectionError):
    """The SSH-carried UDPGW TCP stream is unavailable or malformed."""


@dataclass(frozen=True, slots=True)
class Socks5ConnectConfig:
    proxy_host: str
    proxy_port: int
    target_host: str
    target_port: int
    timeout: float = 10.0

    def __post_init__(self) -> None:
        for name in ("proxy_host", "target_host"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 253:
                raise ValueError(f"{name} must be a non-empty host")
            if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
                raise ValueError(f"{name} contains whitespace or control characters")
        for name in ("proxy_port", "target_port"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
                raise ValueError(f"{name} must be between 1 and 65535")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ValueError("timeout must be positive")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    if size < 0:
        raise ValueError("size cannot be negative")
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise Socks5ProtocolError("SOCKS5 proxy closed during negotiation")
        result.extend(chunk)
    return bytes(result)


def _encode_socks5_address(host: str) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            encoded = host.encode("idna")
        except UnicodeError as exc:
            raise Socks5ProtocolError("Invalid SOCKS5 destination hostname") from exc
        if not encoded or len(encoded) > 255:
            raise Socks5ProtocolError("SOCKS5 destination hostname is too long")
        return b"\x03" + bytes((len(encoded),)) + encoded
    if isinstance(address, ipaddress.IPv4Address):
        return b"\x01" + address.packed
    return b"\x04" + address.packed


def _consume_socks5_bound_address(sock: socket.socket, address_type: int) -> None:
    if address_type == 1:
        _recv_exact(sock, 4)
    elif address_type == 4:
        _recv_exact(sock, 16)
    elif address_type == 3:
        length = _recv_exact(sock, 1)[0]
        if length == 0:
            raise Socks5ProtocolError("SOCKS5 proxy returned an empty bound hostname")
        _recv_exact(sock, length)
    else:
        raise Socks5ProtocolError("SOCKS5 proxy returned an unknown address type")
    _recv_exact(sock, 2)


def open_socks5_connect(
    config: Socks5ConnectConfig,
    *,
    socket_factory: Callable[..., socket.socket] = socket.create_connection,
) -> socket.socket:
    """Open a TCP connection to config.target through a local SOCKS5 proxy."""
    if not isinstance(config, Socks5ConnectConfig):
        raise TypeError("config must be a Socks5ConnectConfig")
    sock: socket.socket | None = None
    try:
        sock = socket_factory(
            (config.proxy_host, config.proxy_port),
            timeout=config.timeout,
        )
        sock.settimeout(config.timeout)
        sock.sendall(b"\x05\x01\x00")  # SOCKS5, one method, no authentication
        greeting = _recv_exact(sock, 2)
        if greeting[0] != 5 or greeting[1] != 0:
            raise Socks5ProtocolError(
                f"SOCKS5 proxy selected unsupported authentication method {greeting[1]}"
            )

        request = (
            b"\x05\x01\x00"
            + _encode_socks5_address(config.target_host)
            + struct.pack("!H", config.target_port)
        )
        sock.sendall(request)
        response = _recv_exact(sock, 4)
        version, reply, reserved, address_type = response
        if version != 5 or reserved != 0:
            raise Socks5ProtocolError("SOCKS5 proxy returned an invalid CONNECT response")
        if reply != 0:
            raise Socks5ProtocolError(f"SOCKS5 CONNECT failed with reply code {reply}")
        _consume_socks5_bound_address(sock, address_type)
        return sock
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        raise


class UdpGwStreamClient:
    """Synchronous UDPGW stream over an SSH-provided SOCKS5 endpoint."""

    def __init__(
        self,
        config: Socks5ConnectConfig,
        *,
        socket_factory: Callable[..., socket.socket] = socket.create_connection,
    ) -> None:
        self._config = config
        self._socket_factory = socket_factory
        self._socket: socket.socket | None = None
        self._decoder = PacketProtoDecoder()
        self._pending: deque[UdpGwPacket] = deque()

    @property
    def connected(self) -> bool:
        return self._socket is not None and self._socket.fileno() >= 0

    @property
    def pending_packets(self) -> int:
        return len(self._pending)

    def fileno(self) -> int:
        return self._require_socket().fileno()

    @property
    def socket(self) -> socket.socket:
        return self._require_socket()

    def connect(self) -> UdpGwStreamClient:
        if self.connected:
            return self
        self._socket = None
        self._decoder = PacketProtoDecoder()
        self._pending.clear()
        try:
            self._socket = open_socks5_connect(
                self._config,
                socket_factory=self._socket_factory,
            )
        except (OSError, Socks5ProtocolError) as exc:
            raise UdpGwTransportError("Could not open UDPGW stream through SSH SOCKS5") from exc
        return self

    def send_datagram(
        self,
        *,
        connection_id: int,
        address: str,
        port: int,
        data: bytes,
        is_dns: bool = False,
        rebind: bool = False,
    ) -> None:
        sock = self._require_socket()
        try:
            sock.sendall(
                encode_datagram(
                    connection_id=connection_id,
                    address=address,
                    port=port,
                    data=data,
                    is_dns=is_dns,
                    rebind=rebind,
                )
            )
        except OSError as exc:
            raise UdpGwTransportError("Could not send UDPGW datagram") from exc

    def send_keepalive(self) -> None:
        sock = self._require_socket()
        try:
            sock.sendall(encode_keepalive())
        except OSError as exc:
            raise UdpGwTransportError("Could not send UDPGW keepalive") from exc

    def receive_packet(self, *, timeout: float | None = None) -> UdpGwPacket:
        sock = self._require_socket()
        if timeout is not None:
            if (
                isinstance(timeout, bool)
                or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout)
                or timeout <= 0
            ):
                raise ValueError("timeout must be positive and finite")
            sock.settimeout(timeout)
        while not self._pending:
            try:
                chunk = sock.recv(64 * 1024)
            except OSError as exc:
                raise UdpGwTransportError("Could not receive UDPGW stream data") from exc
            if not chunk:
                raise UdpGwTransportError("UDPGW stream closed by remote server")
            try:
                self._pending.extend(
                    decode_udpgw_payload(frame) for frame in self._decoder.feed(chunk)
                )
            except ValueError as exc:
                raise UdpGwTransportError("Remote server sent malformed UDPGW data") from exc
        return self._pending.popleft()

    def close(self) -> None:
        sock, self._socket = self._socket, None
        self._pending.clear()
        self._decoder = PacketProtoDecoder()
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def _require_socket(self) -> socket.socket:
        if self._socket is None or self._socket.fileno() < 0:
            raise UdpGwTransportError("UDPGW stream is not connected")
        return self._socket

    def __enter__(self) -> UdpGwStreamClient:
        return self.connect()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
