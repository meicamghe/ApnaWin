"""Socket establishment for APNA-family SSH payload injection.

This layer opens a TCP/TLS stream, writes the expanded payload, and optionally
validates the proxy's HTTP CONNECT response. It deliberately does not perform
SSH authentication or create a VPN interface; those remain separate stages.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import math
import socket
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from apnawin.engines.apna_payload import PayloadRotation, render_apna_payload, send_payload
from apnawin.engines.websocket_stream import WebSocketStreamSocket


class PayloadTransportError(ConnectionError):
    """The lower transport failed; stage identifies DNS, TCP, TLS or HTTP."""

    def __init__(self, message: str, *, stage: str = "http_proxy") -> None:
        super().__init__(message)
        if stage not in {"dns", "tcp", "tls", "http_proxy", "websocket", "transport"}:
            raise ValueError("invalid payload transport failure stage")
        self.stage = stage


def _redacted_request_summary(config: "PayloadSocketConfig", chunks: tuple) -> str:
    """Summarize HTTP routing metadata without logging payloads or query secrets."""
    request = b"".join(chunk.data for chunk in chunks).decode("iso-8859-1", errors="replace")
    lines = request.split("\r\n")
    parts = lines[0].split() if lines else []
    if len(parts) != 3:
        return (
            f"mode={config.mode.value}; endpoint={config.connect_host}:{config.connect_port}; "
            f"target={config.target_host}:{config.target_port}"
        )

    method, target, version = parts
    path = target.split("?", 1)[0].split("#", 1)[0]
    # Opaque/long path segments may be provider tokens; retain route shape only.
    safe_segments = []
    for segment in path.split("/"):
        if len(segment) > 24 or (
            len(segment) >= 16
            and any(char.isdigit() for char in segment)
            and any(char.isalpha() for char in segment)
        ):
            safe_segments.append("<redacted>")
        else:
            safe_segments.append(segment[:64])
    safe_path = "/".join(safe_segments)[:192] or "/"

    host_header = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == "host":
            host_header = " ".join(value.strip().split())[:253]
            break

    fields = [
        f"mode={config.mode.value}",
        f"request={method[:16]} {safe_path} {version[:16]}",
        f"Host={host_header or '[absent]'}",
        f"endpoint={config.connect_host}:{config.connect_port}",
        f"target={config.target_host}:{config.target_port}",
    ]
    if config.mode in {PayloadSocketMode.TLS_DIRECT, PayloadSocketMode.TLS_HTTP_PROXY}:
        default_sni = (
            config.connect_host
            if config.mode is PayloadSocketMode.TLS_HTTP_PROXY
            else config.target_host
        )
        fields.append(f"SNI={config.sni or default_sni}")
    return "; ".join(fields)


class PayloadSocketMode(str, Enum):
    DIRECT = "direct"
    HTTP_PROXY = "http_proxy"
    TLS_DIRECT = "tls_direct"
    TLS_HTTP_PROXY = "tls_http_proxy"


@dataclass(frozen=True, slots=True)
class PayloadSocketConfig:
    mode: PayloadSocketMode
    connect_host: str
    connect_port: int
    target_host: str
    target_port: int
    payload: str = ""
    sni: str | None = None
    ca_bundle_file: str | None = None
    allow_insecure_tls: bool = False
    cf_host: str | None = None
    brand: str | None = None
    user_agent: str | None = None
    protocol: str = "HTTP/1.0"
    dropbear_no_response: bool = False
    validate_http_response: bool = True
    expected_http_statuses: tuple[int, ...] = (200,)
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    max_response_header_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.mode, PayloadSocketMode):
            raise ValueError("mode must be a PayloadSocketMode")
        if not isinstance(self.expected_http_statuses, tuple) or not self.expected_http_statuses:
            raise ValueError("expected_http_statuses must be a non-empty tuple")
        if any(
            isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
            for status in self.expected_http_statuses
        ):
            raise ValueError("expected_http_statuses contains an invalid HTTP status")
        if len(set(self.expected_http_statuses)) != len(self.expected_http_statuses):
            raise ValueError("expected_http_statuses must not contain duplicates")
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
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be finite and positive")
        if not 64 <= self.max_response_header_bytes <= 64 * 1024:
            raise ValueError("max_response_header_bytes is outside the safe range")
        if self.cf_host is not None and (
            not isinstance(self.cf_host, str)
            or not self.cf_host
            or len(self.cf_host) > 253
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in self.cf_host)
        ):
            raise ValueError("cf_host is invalid")
        if self.brand is not None and (
            not isinstance(self.brand, str)
            or len(self.brand) > 128
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in self.brand)
        ):
            raise ValueError("brand is invalid")
        if self.user_agent is not None and (
            not isinstance(self.user_agent, str)
            or len(self.user_agent) > 1024
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in self.user_agent)
        ):
            raise ValueError("user_agent is invalid")
        if self.mode in {PayloadSocketMode.DIRECT, PayloadSocketMode.TLS_DIRECT} and self.payload:
            raise ValueError("direct transport modes must not contain an HTTP payload")
        if self.mode in {PayloadSocketMode.HTTP_PROXY, PayloadSocketMode.TLS_HTTP_PROXY} and not self.payload:
            raise ValueError("HTTP proxy transport modes require a non-empty payload")
        if self.sni is not None and (
            not isinstance(self.sni, str)
            or not self.sni
            or len(self.sni) > 253
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in self.sni)
        ):
            raise ValueError("sni is invalid")
        if not isinstance(self.allow_insecure_tls, bool):
            raise TypeError("allow_insecure_tls must be a boolean")
        if self.ca_bundle_file is not None and (
            not isinstance(self.ca_bundle_file, str)
            or not self.ca_bundle_file
            or len(self.ca_bundle_file) > 4096
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in self.ca_bundle_file)
        ):
            raise ValueError("ca_bundle_file must be a valid trusted CA bundle path")


class _SocketWriter:
    def __init__(self, sock: socket.socket) -> None:
        self._socket = sock

    def write(self, data: bytes) -> None:
        self._socket.sendall(data)

    def flush(self) -> None:
        # sendall() has already handed all bytes to the socket implementation.
        return None


def _read_http_connect_response(
    sock: socket.socket,
    limit: int,
    expected_statuses: tuple[int, ...],
    request_context: str = "",
) -> tuple[int, dict[str, tuple[str, ...]]]:
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
    header_lines = bytes(response).decode("iso-8859-1").split("\r\n")[1:]
    parsed_headers: dict[str, list[str]] = {}
    for line in header_lines:
        if not line:
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key:
            parsed_headers.setdefault(key, []).append(" ".join(value.strip().split()))
    response_headers = {key: tuple(values) for key, values in parsed_headers.items()}
    if status not in expected_statuses:
        expected = ", ".join(str(value) for value in expected_statuses)
        # Keep diagnostics useful without exposing cookies, authentication
        # challenges, arbitrary provider data, or response bodies.
        headers = {
            key: values[0][:160]
            for key, values in response_headers.items()
            if values and key in {"server", "via", "x-cache", "cf-ray", "content-type", "retry-after"}
        }
        context = f" Request details: {request_context}." if request_context else ""
        metadata = (
            " Response headers: "
            + ", ".join(f"{key}={value}" for key, value in sorted(headers.items()))
            + "."
            if headers else ""
        )
        if 300 <= status < 400:
            location = next(
                (
                    values[0][:512]
                    for key, values in response_headers.items()
                    if key == "location" and values
                ),
                "",
            )
            destination = f" Location: {location}." if location else ""
            raise PayloadTransportError(
                f"Proxy returned HTTP {status} redirect.{destination}{metadata} "
                "Redirects are not followed for SSH payloads because changing the "
                "request target can alter the provider's SSH tunnel route. "
                f"Expected one of: {expected}. Check the selected payload, host, port and path."
                f"{context}"
            )
        if status == 101:
            diagnosis = (
                "The endpoint switched protocols (HTTP 101), but this profile is not "
                "configured to accept a WebSocket Upgrade response. The selected payload "
                "may be missing its explicit 'Upgrade: websocket' header, may be the wrong "
                "payload for this endpoint, or this installed app build may predate the "
                "WebSocket status-mapping fix. Do not accept 101 for a non-WebSocket payload "
                "or pass raw WebSocket frames directly to SSH."
            )
        elif status == 400:
            diagnosis = (
                "The proxy rejected the HTTP request as malformed. Check payload syntax, "
                "HTTP method/version, Host header, path, target host/port and CRLF placement."
            )
        elif status == 401 or status == 407:
            diagnosis = (
                "The proxy requires authentication or rejected proxy credentials; "
                "verify the provider's required authentication mode."
            )
        elif status == 403:
            cloudfront_edge = (
                headers.get("server", "").lower() == "cloudfront"
                or "cloudfront" in headers.get("via", "").lower()
                or "error from cloudfront" in headers.get("x-cache", "").lower()
            )
            cloudflare_edge = (
                headers.get("server", "").lower() == "cloudflare"
                or bool(headers.get("cf-ray"))
            )
            if cloudfront_edge:
                diagnosis = (
                    "CloudFront returned an edge-level HTTP denial. The request reached "
                    "CloudFront, but no SSH stream was established. Verify this profile's "
                    "catalog payload method/path, Host header, viewer port, SNI and the "
                    "provider's CloudFront behavior/origin policy; do not substitute another "
                    "profile's values."
                )
            elif cloudflare_edge:
                diagnosis = (
                    "Cloudflare returned an HTTP 403 at its edge or proxy layer. The request "
                    "reached Cloudflare, but no SSH stream was established. The cf-ray value "
                    "identifies the edge request for the provider. Verify this profile's "
                    "payload method/path, Host header, endpoint port, SNI and whether the "
                    "provider's Cloudflare rules/origin policy allow this tunnel; do not "
                    "disable TLS checks or blindly change Host/SNI."
                )
            else:
                diagnosis = (
                    "The proxy understood the request but denied it. Check provider policy, "
                    "payload/server pairing, Host/SNI and whether this endpoint permits tunneling."
                )
        elif status == 404:
            diagnosis = "The requested proxy path was not found; verify the payload path and Host."
        elif status == 409:
            diagnosis = (
                "The proxy reported a conflict for this request. Verify the provider's required "
                "payload method/path, Host, SNI, endpoint port and session policy; do not retry "
                "with altered routing values unless the provider documents them."
            )
        elif status == 408 or status == 504:
            diagnosis = "The proxy timed out while handling the request; check endpoint reachability and load."
        elif status == 429:
            diagnosis = "The proxy rate-limited the request; respect Retry-After and avoid rapid retries."
        elif 500 <= status <= 599:
            diagnosis = "The proxy or upstream service failed; retry later and verify provider status."
        else:
            diagnosis = "The proxy returned an unexpected HTTP response; verify the selected payload and endpoint."
        raise PayloadTransportError(
            f"Proxy returned HTTP {status}; {diagnosis}{metadata}{context} Expected one of: {expected}"
        )
    return status, response_headers


def _websocket_request_headers(request_bytes: bytes) -> dict[str, tuple[str, ...]]:
    text = request_bytes.decode("iso-8859-1")
    header_block = text.split("\r\n\r\n", 1)[0]
    lines = header_block.split("\r\n")
    request_line = lines[0].split() if lines else []
    if len(request_line) != 3 or request_line[0] != "GET" or request_line[2] != "HTTP/1.1":
        raise PayloadTransportError("HTTP 101 requires a GET HTTP/1.1 WebSocket Upgrade request")
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            raise PayloadTransportError("WebSocket Upgrade request contains a malformed header")
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if not key:
            raise PayloadTransportError("WebSocket Upgrade request contains an empty header name")
        headers.setdefault(key, []).append(value.strip())
    return {key: tuple(values) for key, values in headers.items()}


def _single_header(headers: dict[str, tuple[str, ...]], name: str, side: str) -> str:
    values = headers.get(name, ())
    if len(values) != 1:
        raise PayloadTransportError(
            f"HTTP 101 WebSocket handshake requires exactly one {side} {name} header"
        )
    return values[0].strip()


def _has_header_token(value: str, token: str) -> bool:
    return token in {part.strip().lower() for part in value.split(",")}


def _validate_websocket_upgrade(
    request_bytes: bytes,
    response_headers: dict[str, tuple[str, ...]],
) -> None:
    request_headers = _websocket_request_headers(request_bytes)
    request_upgrade = _single_header(request_headers, "upgrade", "request")
    request_connection = _single_header(request_headers, "connection", "request")
    request_key = _single_header(request_headers, "sec-websocket-key", "request")
    request_version = _single_header(request_headers, "sec-websocket-version", "request")
    if not _has_header_token(request_upgrade, "websocket") or not _has_header_token(request_connection, "upgrade"):
        raise PayloadTransportError(
            "HTTP 101 request is missing Upgrade: websocket or Connection: Upgrade"
        )
    if request_version != "13":
        raise PayloadTransportError("HTTP 101 WebSocket request must use Sec-WebSocket-Version: 13")
    try:
        decoded_key = base64.b64decode(request_key, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise PayloadTransportError("HTTP 101 request has an invalid Sec-WebSocket-Key") from exc
    if len(decoded_key) != 16:
        raise PayloadTransportError("HTTP 101 Sec-WebSocket-Key must decode to exactly 16 bytes")

    response_upgrade = _single_header(response_headers, "upgrade", "response")
    response_connection = _single_header(response_headers, "connection", "response")
    response_accept = _single_header(response_headers, "sec-websocket-accept", "response")
    if not _has_header_token(response_upgrade, "websocket") or not _has_header_token(response_connection, "upgrade"):
        raise PayloadTransportError("HTTP 101 response is not a valid WebSocket protocol upgrade")
    expected_accept = base64.b64encode(
        hashlib.sha1(
            (request_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"),
            usedforsecurity=False,
        ).digest()
    ).decode("ascii")
    if not hmac.compare_digest(response_accept, expected_accept):
        raise PayloadTransportError("HTTP 101 Sec-WebSocket-Accept does not match the request key")


def _tls_certificate_diagnosis(exc: ssl.SSLCertVerificationError) -> str:
    """Explain certificate verification failures without weakening TLS checks."""
    reason = str(exc).lower()
    verify_code = getattr(exc, "verify_code", None)
    verify_message = str(getattr(exc, "verify_message", "") or "").lower()
    detail = f"{reason} {verify_message}"
    if "hostname" in detail or "ip address mismatch" in detail or verify_code == 62:
        return "TLS certificate hostname/SNI mismatch"
    if "self-signed" in detail or "unknown ca" in detail or verify_code in {18, 19, 20, 21}:
        return (
            "TLS certificate is self-signed or its issuer is not trusted; "
            "use only a CA certificate obtained from a trusted provider source"
        )
    if "expired" in detail or "not yet valid" in detail or verify_code in {9, 10}:
        return "TLS certificate is expired or not yet valid"
    if "unable to get local issuer" in detail or "unable to verify the first certificate" in detail:
        return "TLS certificate chain is incomplete or its issuer is not trusted"
    return "TLS certificate verification failed"


def _sni_warning(sni: str, endpoint_host: str) -> str:
    """Flag a likely catalog SNI mismatch; never rewrite provider configuration."""
    try:
        ipaddress.ip_address(sni)
    except ValueError:
        return ""
    try:
        ipaddress.ip_address(endpoint_host)
    except ValueError:
        return (
            "; WARNING: SNI is an IP literal while the endpoint is a DNS hostname; "
            "verify the catalog SNI value with the provider"
        )
    return ""


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

    def connect(self, config: PayloadSocketConfig) -> socket.socket | WebSocketStreamSocket:
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

            if config.mode in {PayloadSocketMode.TLS_DIRECT, PayloadSocketMode.TLS_HTTP_PROXY}:
                default_sni = (
                    config.connect_host
                    if config.mode is PayloadSocketMode.TLS_HTTP_PROXY
                    else config.target_host
                )
                tls_context = self._tls_context
                if config.allow_insecure_tls:
                    # Explicit per-profile compatibility mode for endpoints using
                    # self-signed/untrusted certificates. SNI is still sent; only
                    # certificate-chain and hostname verification are disabled.
                    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    tls_context.check_hostname = False
                    tls_context.verify_mode = ssl.CERT_NONE
                elif config.ca_bundle_file is not None:
                    # Add a provider-supplied CA to the normal system trust store.
                    # Certificate verification remains enabled.
                    tls_context = ssl.create_default_context()
                    try:
                        tls_context.load_verify_locations(cafile=config.ca_bundle_file)
                    except (OSError, ssl.SSLError) as exc:
                        raise PayloadTransportError(
                            "Configured provider CA bundle could not be loaded; verify that "
                            "the file exists, is readable, and was obtained from a trusted provider source",
                            stage="tls",
                        ) from exc
                active_socket = tls_context.wrap_socket(
                    raw_socket,
                    server_hostname=config.sni or default_sni,
                )
                active_socket.settimeout(config.read_timeout)

            if config.mode in {PayloadSocketMode.DIRECT, PayloadSocketMode.TLS_DIRECT}:
                return active_socket

            chunks = render_apna_payload(
                config.payload,
                host=config.target_host,
                port=config.target_port,
                protocol=config.protocol,
                cf_host=config.cf_host or config.connect_host,
                brand=config.brand,
                user_agent=config.user_agent,
                rotation=self._rotation,
            )
            send_payload(_SocketWriter(active_socket), chunks)

            if (
                config.validate_http_response
                and not config.dropbear_no_response
                and config.mode in {PayloadSocketMode.HTTP_PROXY, PayloadSocketMode.TLS_HTTP_PROXY}
            ):
                request_context = _redacted_request_summary(config, chunks)
                status, response_headers = _read_http_connect_response(
                    active_socket,
                    config.max_response_header_bytes,
                    config.expected_http_statuses,
                    request_context,
                )
                if status == 101:
                    request_bytes = b"".join(chunk.data for chunk in chunks)
                    _validate_websocket_upgrade(request_bytes, response_headers)
                    active_socket = WebSocketStreamSocket(active_socket)

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
            # SSLCertVerificationError inherits ValueError as well as SSLError.
            # Classify TLS verification failures before the generic ValueError
            # passthrough so certificate/SNI diagnostics are not lost.
            if isinstance(exc, PayloadTransportError):
                raise
            endpoint = f"{config.connect_host}:{config.connect_port}"
            sni = config.sni or (
                config.connect_host
                if config.mode is PayloadSocketMode.TLS_HTTP_PROXY
                else config.target_host
            )
            failure_stage = "transport"
            if isinstance(exc, socket.gaierror):
                failure_stage = "dns"
                diagnosis = (
                    "DNS resolution failed before TCP connection; check the system resolver "
                    "and whether this endpoint hostname is currently resolvable"
                )
            elif isinstance(exc, ssl.SSLCertVerificationError):
                failure_stage = "tls"
                diagnosis = _tls_certificate_diagnosis(exc)
            elif isinstance(exc, ssl.SSLError):
                failure_stage = "tls"
                tls_reason = str(exc).lower()
                if "hostname mismatch" in tls_reason or "hostname" in tls_reason:
                    diagnosis = "TLS certificate hostname/SNI mismatch"
                elif "certificate_verify_failed" in tls_reason or "certificate verify failed" in tls_reason:
                    diagnosis = "TLS certificate verification failed"
                else:
                    diagnosis = "TLS handshake failed"
            elif isinstance(exc, (ConnectionRefusedError, TimeoutError, socket.timeout)):
                failure_stage = "tcp"
                diagnosis = "TCP connection failed (refused or timed out)"
            elif isinstance(exc, OSError):
                failure_stage = "tcp"
                diagnosis = "TCP socket or network connection failed"
            elif isinstance(exc, (ValueError, TypeError)):
                raise
            else:
                diagnosis = "payload transport failed"
            sni_detail = (
                f"; SNI {sni}{_sni_warning(sni, config.connect_host)}"
                if config.mode in {PayloadSocketMode.TLS_DIRECT, PayloadSocketMode.TLS_HTTP_PROXY}
                else ""
            )
            raise PayloadTransportError(
                f"{diagnosis}: {config.mode.value} endpoint={endpoint}{sni_detail}; "
                f"{type(exc).__name__}: {exc}",
                stage=failure_stage,
            ) from exc
