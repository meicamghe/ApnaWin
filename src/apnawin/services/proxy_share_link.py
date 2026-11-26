"""Strict parser for standard Xray share links.

This module parses VLESS, VMess, Trojan and Shadowsocks links into Xray
outbound objects. It does not fetch subscriptions, resolve DNS, validate
credentials, or establish a connection. Unsupported URI extensions fail closed.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from unicodedata import category
from urllib.parse import parse_qsl, unquote, urlsplit

from apnawin.domain.profile import _validate_endpoint_host

MAX_LINK_BYTES = 16 * 1024
MAX_CREDENTIAL_BYTES = 1024
MAX_LABEL_LENGTH = 128

_SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
_QUERY_KEYS = {
    "type", "security", "sni", "fp", "alpn", "host", "path",
    "serviceName", "mode", "pbk", "sid", "spx", "flow",
    "encryption",
}


@dataclass(frozen=True, slots=True)
class ParsedProxyLink:
    """A parsed proxy definition. Credential-bearing fields are hidden in repr."""

    name: str
    protocol: str
    server: str
    port: int
    settings: dict[str, object] = field(repr=False)
    stream_settings: dict[str, object] = field(default_factory=dict, repr=False)

    def to_outbound(self, tag: str = "proxy") -> dict[str, object]:
        if not isinstance(tag, str) or not tag or len(tag) > 64:
            raise ValueError("Outbound tag must contain 1 to 64 characters")
        outbound: dict[str, object] = {
            "tag": tag,
            "protocol": self.protocol,
            "settings": dict(self.settings),
        }
        if self.stream_settings:
            outbound["streamSettings"] = json.loads(json.dumps(self.stream_settings))
        return outbound


def _validate_percent_encoding(value: str) -> None:
    """Reject incomplete or non-hex percent escapes before urllib can forgive them."""
    for match in re.finditer("%", value):
        token = value[match.start() + 1:match.start() + 3]
        if len(token) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            raise ValueError("Share link contains malformed percent encoding")


def _strict_unquote(value: str, field_name: str) -> str:
    _validate_percent_encoding(value)
    try:
        return unquote(value, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{field_name} contains invalid UTF-8 percent encoding") from exc


def _bounded(value: str, field_name: str, limit: int = MAX_CREDENTIAL_BYTES) -> str:
    if not value or len(value.encode("utf-8")) > limit:
        raise ValueError(f"{field_name} must contain 1 to {limit} UTF-8 bytes")
    if any(category(ch) == "Cc" for ch in value):
        raise ValueError(f"{field_name} contains control characters")
    return value


def _port(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("Server port must be an integer from 1 to 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Server port must be an integer from 1 to 65535") from exc
    if str(value).strip() != str(port) or not 1 <= port <= 65535:
        raise ValueError("Server port must be an integer from 1 to 65535")
    return port


def _name(fragment: str, fallback: str) -> str:
    value = _strict_unquote(fragment, "Profile name").strip() or fallback
    value = "".join(ch for ch in value if category(ch) != "Cc")
    return (value[:MAX_LABEL_LENGTH] or fallback)


def _decode_b64(value: str, field_name: str) -> bytes:
    raw = value.strip()
    if not raw or len(raw) > MAX_LINK_BYTES:
        raise ValueError(f"{field_name} is empty or too large")
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.b64decode(raw.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} is not valid URL-safe Base64") from exc


def _query(query: str) -> dict[str, str]:
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=32, errors="strict")
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate share-link parameter: {key}")
        if key not in _QUERY_KEYS:
            raise ValueError(f"Unsupported share-link parameter: {key}")
        result[key] = value
    return result


def _stream(params: dict[str, str], protocol: str) -> dict[str, object]:
    transport = params.get("type", "tcp").lower()
    transport_names = {
        "tcp": "raw",
        "raw": "raw",
        "ws": "websocket",
        "grpc": "grpc",
    }
    if transport not in transport_names:
        raise ValueError(f"Unsupported Xray transport: {transport}")
    network = transport_names[transport]
    if transport != "ws" and any(key in params for key in ("host", "path")):
        raise ValueError("WebSocket host/path parameters require type=ws")
    if transport != "grpc" and any(key in params for key in ("serviceName", "mode")):
        raise ValueError("gRPC parameters require type=grpc")
    security = params.get("security", "tls" if protocol == "trojan" else "none").lower()
    if security not in {"none", "tls", "reality"}:
        raise ValueError(f"Unsupported transport security: {security}")
    if security == "none" and any(key in params for key in ("sni", "fp", "alpn", "pbk", "sid", "spx")):
        raise ValueError("TLS/REALITY parameters require transport security")
    if security == "tls" and any(key in params for key in ("pbk", "sid", "spx")):
        raise ValueError("REALITY parameters cannot be used with TLS")
    if protocol == "trojan" and security == "none":
        raise ValueError("Trojan links require TLS or REALITY transport security")
    if security == "reality" and network not in {"raw", "grpc"}:
        raise ValueError("REALITY is supported here only with TCP or gRPC")

    stream: dict[str, object] = {"method": network, "security": security}
    if security == "tls":
        tls: dict[str, object] = {}
        if params.get("sni"):
            tls["serverName"] = _bounded(params["sni"], "SNI", 253)
        if params.get("fp"):
            tls["fingerprint"] = _bounded(params["fp"], "TLS fingerprint", 64)
        if params.get("alpn"):
            protocols = [_bounded(x.strip(), "ALPN", 32) for x in params["alpn"].split(",") if x.strip()]
            if not protocols:
                raise ValueError("ALPN must contain at least one protocol")
            tls["alpn"] = protocols
        stream["tlsSettings"] = tls
    elif security == "reality":
        if "alpn" in params:
            raise ValueError("ALPN is not supported as a REALITY link parameter")
        reality: dict[str, object] = {}
        if params.get("sni"):
            reality["serverName"] = _bounded(params["sni"], "REALITY server name", 253)
        if params.get("fp"):
            reality["fingerprint"] = _bounded(params["fp"], "REALITY fingerprint", 64)
        if params.get("pbk"):
            reality["publicKey"] = _bounded(params["pbk"], "REALITY public key", 256)
        if params.get("sid"):
            reality["shortId"] = _bounded(params["sid"], "REALITY short ID", 64)
        if params.get("spx"):
            reality["spiderX"] = _bounded(params["spx"], "REALITY spider path", 1024)
        if not reality.get("serverName") or not reality.get("fingerprint") or not reality.get("publicKey"):
            raise ValueError("REALITY links require sni, fp and pbk parameters")
        stream["realitySettings"] = reality

    if network == "websocket":
        ws: dict[str, object] = {}
        if params.get("path"):
            ws["path"] = _bounded(params["path"], "WebSocket path", 2048)
        if params.get("host"):
            ws["headers"] = {"Host": _bounded(params["host"], "WebSocket host", 253)}
        stream["wsSettings"] = ws
    elif network == "grpc":
        grpc: dict[str, object] = {}
        if params.get("serviceName"):
            grpc["serviceName"] = _bounded(params["serviceName"], "gRPC service name", 256)
        if params.get("mode"):
            mode = params["mode"].lower()
            if mode not in {"multi", "gun"}:
                raise ValueError("gRPC mode must be multi or gun")
            grpc["multiMode"] = mode == "multi"
        stream["grpcSettings"] = grpc
    return stream


def _parse_vless(parts) -> ParsedProxyLink:
    if not parts.username or parts.password is not None:
        raise ValueError("VLESS link must contain a user ID and no password field")
    params = _query(parts.query)
    user_id = _bounded(_strict_unquote(parts.username, "VLESS user ID"), "VLESS user ID", 128)
    server = _bounded(parts.hostname or "", "Server host", 253)
    _validate_endpoint_host(server)
    port = _port(parts.port)
    encryption = params.get("encryption", "none")
    if not encryption:
        raise ValueError("VLESS encryption cannot be empty")
    settings: dict[str, object] = {
        "address": server,
        "port": port,
        "id": user_id,
        "encryption": _bounded(encryption, "VLESS encryption", 256),
        "level": 0,
    }
    if params.get("flow"):
        settings["flow"] = _bounded(params["flow"], "VLESS flow", 64)
    return ParsedProxyLink(_name(parts.fragment, server), "vless", server, port, settings, _stream(params, "vless"))


def _parse_trojan(parts) -> ParsedProxyLink:
    if not parts.username or parts.password is not None:
        raise ValueError("Trojan link must contain a password in its user-info")
    params = _query(parts.query)
    if "flow" in params or "encryption" in params:
        raise ValueError("VLESS-only parameters cannot be used in a Trojan link")
    password = _bounded(_strict_unquote(parts.username, "Trojan password"), "Trojan password")
    server = _bounded(parts.hostname or "", "Server host", 253)
    _validate_endpoint_host(server)
    port = _port(parts.port)
    settings = {"address": server, "port": port, "password": password}
    return ParsedProxyLink(_name(parts.fragment, server), "trojan", server, port, settings, _stream(params, "trojan"))


def _parse_shadowsocks(link: str, parts) -> ParsedProxyLink:
    if parts.query:
        raise ValueError("Shadowsocks plugin and query extensions are not supported")
    if parts.username is not None:
        if not parts.hostname or parts.port is None:
            userinfo = _decode_b64(parts.netloc, "Shadowsocks user-info").decode("utf-8")
            if "@" not in userinfo:
                raise ValueError("Legacy Shadowsocks link must encode method:password@host:port")
            credentials, endpoint = userinfo.rsplit("@", 1)
            if ":" not in credentials:
                raise ValueError("Shadowsocks credentials must be method:password")
            method, password = credentials.split(":", 1)
            endpoint_parts = urlsplit("ss://" + endpoint)
            server = endpoint_parts.hostname or ""
            port = _port(endpoint_parts.port)
        else:
            userinfo = _strict_unquote(parts.username, "Shadowsocks credentials")
            if parts.password is not None:
                userinfo += ":" + _strict_unquote(parts.password, "Shadowsocks credentials")
            if ":" not in userinfo:
                userinfo = _decode_b64(userinfo, "Shadowsocks credentials").decode("utf-8")
            if ":" not in userinfo:
                raise ValueError("Shadowsocks credentials must be method:password")
            method, password = userinfo.split(":", 1)
            server = parts.hostname
            port = _port(parts.port)
    else:
        encoded_payload = (parts.netloc + parts.path).lstrip("/")
        payload = _decode_b64(encoded_payload, "Legacy Shadowsocks link").decode("utf-8")
        if "@" not in payload:
            raise ValueError("Legacy Shadowsocks link must encode method:password@host:port")
        credentials, endpoint = payload.rsplit("@", 1)
        if ":" not in credentials:
            raise ValueError("Shadowsocks credentials must be method:password")
        method, password = credentials.split(":", 1)
        endpoint_parts = urlsplit("ss://" + endpoint)
        server = endpoint_parts.hostname or ""
        port = _port(endpoint_parts.port)

    method = _bounded(method, "Shadowsocks method", 64).lower()
    password = _bounded(password, "Shadowsocks password")
    if method not in _SS_METHODS:
        raise ValueError(f"Unsupported Shadowsocks cipher: {method}")
    server = _bounded(server, "Server host", 253)
    _validate_endpoint_host(server)
    settings = {"address": server, "port": port, "method": method, "password": password}
    return ParsedProxyLink(_name(parts.fragment, server), "shadowsocks", server, port, settings)


def _parse_vmess(link: str) -> ParsedProxyLink:
    payload = link[len("vmess://"):]
    encoded, separator, fragment = payload.partition("#")
    document = _decode_b64(encoded, "VMess payload")
    try:
        config = json.loads(document.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("VMess payload must be Base64-encoded UTF-8 JSON") from exc
    if not isinstance(config, dict):
        raise ValueError("VMess payload must be a JSON object")
    allowed_fields = {"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp"}
    if set(config) - allowed_fields:
        raise ValueError("VMess payload contains unsupported fields")
    if not isinstance(config.get("add"), str) or not isinstance(config.get("id"), str):
        raise ValueError("VMess server address and user ID must be strings")
    host = _bounded(config["add"], "Server host", 253)
    _validate_endpoint_host(host)
    port = _port(config.get("port"))
    user_id = _bounded(config["id"], "VMess user ID", 128)
    security = str(config.get("scy", "auto")).lower()
    if security not in {"auto", "aes-128-gcm", "chacha20-poly1305"}:
        raise ValueError(f"Unsupported VMess security: {security}")
    alter_id = config.get("aid", "0")
    if str(alter_id) not in {"", "0"}:
        raise ValueError("Legacy VMess alterId must be zero for current Xray-core")
    network = str(config.get("net", "tcp")).lower()
    transport = {"tcp": "tcp", "raw": "tcp", "ws": "ws", "grpc": "grpc"}.get(network)
    if transport is None:
        raise ValueError(f"Unsupported VMess transport: {network}")
    header_type = str(config.get("type", "none")).lower()
    if header_type not in {"", "none"}:
        raise ValueError(f"Unsupported VMess header type: {header_type}")
    tls_value = str(config.get("tls", "")).lower()
    if tls_value not in {"", "none", "tls"}:
        raise ValueError(f"Unsupported VMess security mode: {tls_value}")
    params: dict[str, str] = {"type": transport, "security": "tls" if tls_value == "tls" else "none"}
    for source, target in (("sni", "sni"), ("host", "host"), ("path", "path"), ("fp", "fp"), ("alpn", "alpn")):
        value = config.get(source, "")
        if value:
            params[target] = str(value)
    settings = {"address": host, "port": port, "id": user_id, "security": security, "level": 0}
    display_name = config.get("ps", "")
    if not isinstance(display_name, str):
        raise ValueError("VMess profile name must be a string")
    return ParsedProxyLink(_name(fragment if separator else display_name, host), "vmess", host, port, settings, _stream(params, "vmess"))


def parse_proxy_link(link: str) -> ParsedProxyLink:
    """Parse one standard share link into a credential-bearing Xray outbound.

    Supported schemes: vless://, vmess://, trojan:// and ss://.
    Unknown schemes, duplicate/unknown parameters and unsupported transports
    are rejected rather than silently discarded.
    """
    if not isinstance(link, str):
        raise TypeError("Share link must be a string")
    if not link or len(link.encode("utf-8")) > MAX_LINK_BYTES:
        raise ValueError("Share link is empty or exceeds the 16 KiB limit")
    if any(category(ch) == "Cc" for ch in link):
        raise ValueError("Share link contains control characters")
    _validate_percent_encoding(link)
    scheme = link.split(":", 1)[0].lower() if ":" in link else ""
    if scheme == "vmess":
        return _parse_vmess(link)
    if scheme == "ss":
        parts = urlsplit(link)
        return _parse_shadowsocks(link, parts)
    parts = urlsplit(link)
    if parts.scheme.lower() == "vless":
        return _parse_vless(parts)
    if parts.scheme.lower() == "trojan":
        return _parse_trojan(parts)
    raise ValueError("Unsupported share-link scheme; expected VLESS, VMess, Trojan or Shadowsocks")


def parse_proxy_links(document: str | bytes) -> tuple[ParsedProxyLink, ...]:
    """Parse a plain-text, newline-separated list atomically.

    Blank lines and full-line comments beginning with # are ignored. The
    function does not decode provider-specific subscription wrappers or fetch
    URLs; every remaining line must be a supported individual share link.
    """
    if isinstance(document, bytes):
        if len(document) > 1024 * 1024:
            raise ValueError("Share-link list exceeds the 1 MiB limit")
        try:
            text = document.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Share-link list must be valid UTF-8") from exc
    elif isinstance(document, str):
        try:
            encoded = document.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("Share-link list must be valid UTF-8") from exc
        if len(encoded) > 1024 * 1024:
            raise ValueError("Share-link list exceeds the 1 MiB limit")
        text = document
    else:
        raise TypeError("Share-link list must be str or bytes")

    parsed: list[ParsedProxyLink] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if len(parsed) >= 500:
            raise ValueError("Share-link list exceeds the 500-profile limit")
        try:
            parsed.append(parse_proxy_link(line))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid share link on line {line_number}: {exc}") from exc
    if not parsed:
        raise ValueError("Share-link list contains no supported profiles")
    return tuple(parsed)
