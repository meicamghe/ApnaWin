"""Import secure Xray share links into encrypted Windows TUN profiles.

The bundled Xray runtime supplies the protocol implementations. This module
normalizes supported VLESS, VMess, Trojan and Shadowsocks share links into a
strict full-tunnel config; credentials are returned only inside config_bytes
for immediate DPAPI storage and are never included in profile metadata/errors.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.xray_process import inspect_tun_inbound


_DEFAULT_DNS = ("1.1.1.1", "2606:4700:4700::1111")
_SUPPORTED_SCHEMES = frozenset({"vless", "vmess", "trojan", "ss"})
_SUPPORTED_NETWORKS = frozenset({"tcp", "ws", "grpc", "httpupgrade", "xhttp"})
_SUPPORTED_SECURITY = frozenset({"none", "tls", "reality"})
_NAME_RE = re.compile(r"[^\w .()\[\]-]+", re.UNICODE)


class XrayShareLinkError(ValueError):
    """A share link is malformed or requests an unsupported Xray feature."""


@dataclass(frozen=True, slots=True)
class ImportedXrayProfile:
    """Non-secret profile metadata plus the config to encrypt immediately."""

    profile: ConnectionProfile
    config_bytes: bytes
    protocol: str


def _decode_base64(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 65536:
        raise XrayShareLinkError(f"{field} is empty or exceeds the size limit")
    encoded = value.strip()
    encoded += "=" * (-len(encoded) % 4)
    try:
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise XrayShareLinkError(f"{field} is not valid Base64") from exc


def _query(parsed) -> dict[str, str]:
    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=128,
        )
    except ValueError as exc:
        raise XrayShareLinkError(
            "Share link query is malformed or contains too many parameters"
        ) from exc
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result:
            raise XrayShareLinkError(f"Share link contains duplicate query parameter: {key}")
        result[key] = value
    return result


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate VMess JSON fields instead of silently choosing the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise XrayShareLinkError("VMess payload contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    """Reject non-standard NaN/Infinity tokens in VMess JSON."""
    raise XrayShareLinkError("VMess payload contains a non-finite JSON value")


def _url_endpoint(parsed) -> tuple[str, int]:
    try:
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise XrayShareLinkError("Share link contains an invalid server endpoint") from exc
    return _host_port(host, port)


def _host_port(host: str | None, port: int | None) -> tuple[str, int]:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise XrayShareLinkError("Share link must contain a valid server hostname")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise XrayShareLinkError("Share link must contain a valid server port")
    try:
        ConnectionProfile("Xray endpoint", Transport.XRAY, host, port)
    except (TypeError, ValueError) as exc:
        raise XrayShareLinkError("Share link contains an invalid server endpoint") from exc
    return host, port


def _name(fragment: str, protocol: str, host: str, port: int) -> str:
    candidate = unquote(fragment).strip() if fragment else ""
    candidate = _NAME_RE.sub("", candidate).strip(" .-_")
    if not candidate:
        candidate = f"{protocol.upper()} · {host}:{port}"
    return candidate[:128]


def _transport_path(value: str, transport: str) -> str:
    """Bound transport paths and reject control characters before config generation."""
    path = value or "/"
    if len(path) > 2048 or any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise XrayShareLinkError(f"{transport} path is invalid")
    return path


def _safe_option_text(value: str, field: str, *, max_length: int, allow_empty: bool = True) -> str:
    """Bound free-form Xray options and reject control characters before config generation."""
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value) > max_length
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise XrayShareLinkError(f"{field} is invalid")
    return value


def _stream_settings(
    network: str,
    security: str,
    host: str,
    query: dict[str, str],
    *,
    allow_reality: bool = True,
) -> dict:
    network = (network or "tcp").lower()
    security = (security or "none").lower()
    if network not in _SUPPORTED_NETWORKS:
        raise XrayShareLinkError(f"Unsupported Xray network transport: {network}")
    if security not in _SUPPORTED_SECURITY or (security == "reality" and not allow_reality):
        raise XrayShareLinkError(f"Unsupported Xray stream security: {security}")
    if security == "reality" and network not in {"tcp", "grpc", "xhttp"}:
        raise XrayShareLinkError(
            "REALITY security is supported only with TCP, gRPC or XHTTP by this importer"
        )

    settings: dict = {"network": network, "security": security}
    if network == "ws":
        path = _transport_path(query.get("path", "/"), "WebSocket")
        headers = {}
        ws_host = query.get("host", "")
        if ws_host:
            _host_port(ws_host, 443)
            headers["Host"] = ws_host
        settings["wsSettings"] = {"path": path, "headers": headers}
    elif network == "grpc":
        service_name = query.get("serviceName", query.get("path", ""))
        if len(service_name) > 512 or any(ord(ch) < 32 or ord(ch) == 127 for ch in service_name):
            raise XrayShareLinkError("gRPC service name is invalid")
        authority = _safe_option_text(
            query.get("authority", query.get("host", "")),
            "gRPC authority",
            max_length=512,
        )
        grpc = {"serviceName": service_name, "multiMode": query.get("mode", "") == "multi"}
        if authority:
            grpc["authority"] = authority
        settings["grpcSettings"] = grpc
    elif network == "httpupgrade":
        path = _transport_path(query.get("path", "/"), "HTTPUpgrade")
        upgrade_host = query.get("host", "")
        upgrade = {"path": path}
        if upgrade_host:
            _host_port(upgrade_host, 443)
            upgrade["host"] = upgrade_host
        settings["httpupgradeSettings"] = upgrade
    elif network == "xhttp":
        path = _transport_path(query.get("path", "/"), "XHTTP")
        xhttp_host = query.get("host", "")
        mode = query.get("mode", "auto") or "auto"
        if mode not in {"auto", "packet-up", "stream-up", "stream-one"}:
            raise XrayShareLinkError("Unsupported XHTTP mode")
        xhttp = {"path": path, "mode": mode}
        if xhttp_host:
            _host_port(xhttp_host, 443)
            xhttp["host"] = xhttp_host
        settings["xhttpSettings"] = xhttp

    if security == "tls":
        if query.get("allowInsecure", "").lower() in {"1", "true", "yes"}:
            raise XrayShareLinkError("Insecure TLS certificate verification is not supported")
        server_name = _safe_option_text(
            query.get("sni", query.get("servername", host)),
            "TLS server name",
            max_length=253,
            allow_empty=False,
        )
        tls: dict = {"serverName": server_name, "allowInsecure": False}
        alpn = query.get("alpn")
        if alpn:
            values = [
                _safe_option_text(
                    item.strip(),
                    "TLS ALPN value",
                    max_length=32,
                    allow_empty=False,
                )
                for item in alpn.split(",")
                if item.strip()
            ]
            if not values or len(values) > 8:
                raise XrayShareLinkError("TLS ALPN list is invalid")
            tls["alpn"] = values
        fingerprint = query.get("fp")
        if fingerprint:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", fingerprint):
                raise XrayShareLinkError("TLS fingerprint identifier is invalid")
            tls["fingerprint"] = fingerprint
        settings["tlsSettings"] = tls
    elif security == "reality":
        server_name = _safe_option_text(
            query.get("sni", query.get("servername", "")),
            "Reality server name",
            max_length=253,
            allow_empty=False,
        )
        public_key = query.get("pbk", query.get("publicKey", ""))
        short_id = query.get("sid", query.get("shortId", ""))
        fingerprint = query.get("fp", "")
        if not server_name or not public_key or not fingerprint:
            raise XrayShareLinkError("Reality links require SNI, public key and fingerprint")
        if len(public_key) > 256 or len(short_id) > 64:
            raise XrayShareLinkError("Reality public key or short ID exceeds the size limit")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", public_key):
            raise XrayShareLinkError("Reality public key must be a Base64URL-encoded 32-byte key")
        try:
            decoded_public_key = _decode_base64(public_key, "Reality public key")
        except XrayShareLinkError as exc:
            raise XrayShareLinkError("Reality public key must be a Base64URL-encoded 32-byte key") from exc
        if len(decoded_public_key) != 32:
            raise XrayShareLinkError("Reality public key must decode to exactly 32 bytes")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
            raise XrayShareLinkError("Reality short ID must be empty or up to 8 bytes of hexadecimal")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", fingerprint):
            raise XrayShareLinkError("Reality fingerprint identifier is invalid")
        settings["realitySettings"] = {
            "serverName": server_name,
            "publicKey": public_key,
            "shortId": short_id,
            "fingerprint": fingerprint,
            "spiderX": _safe_option_text(query.get("spx", ""), "Reality spiderX", max_length=2048),
        }
    return settings


def _parse_vless(parsed) -> tuple[str, int, dict, dict]:
    host, port = _url_endpoint(parsed)
    if parsed.password is not None:
        raise XrayShareLinkError("VLESS link must not contain a password field")
    user_id = unquote(parsed.username or "")
    try:
        normalized_id = str(uuid.UUID(user_id))
    except (ValueError, AttributeError) as exc:
        raise XrayShareLinkError("VLESS link must contain a valid UUID user ID") from exc
    query = _query(parsed)
    encryption = query.get("encryption", "none")
    if encryption != "none":
        raise XrayShareLinkError("Only VLESS encryption=none is supported by this importer")
    user: dict = {"id": normalized_id, "encryption": "none"}
    flow = query.get("flow", "")
    network = query.get("type", query.get("network", "tcp")).lower()
    security = query.get("security", "none").lower()
    if flow:
        if flow not in {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}:
            raise XrayShareLinkError("Unsupported VLESS flow")
        if network != "tcp" or security not in {"tls", "reality"}:
            raise XrayShareLinkError(
                "VLESS Vision flow requires TCP with TLS or REALITY security"
            )
        user["flow"] = flow
    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": _stream_settings(network, security, host, query),
    }
    return host, port, outbound, query


def _parse_vmess(parsed) -> tuple[str, int, dict, dict]:
    encoded = parsed.netloc or parsed.path
    if "@" in encoded:
        raise XrayShareLinkError("VMess link must use the standard Base64 JSON form")
    document_bytes = _decode_base64(encoded, "VMess payload")
    try:
        document = json.loads(
            document_bytes.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise XrayShareLinkError("VMess payload must contain a UTF-8 JSON object") from exc
    if not isinstance(document, dict):
        raise XrayShareLinkError("VMess payload must contain a JSON object")
    host = document.get("add")
    raw_port = document.get("port")
    if isinstance(raw_port, bool) or not isinstance(raw_port, (str, int)):
        raise XrayShareLinkError("VMess payload contains an invalid port")
    if isinstance(raw_port, str) and not re.fullmatch(r"[0-9]{1,5}", raw_port):
        raise XrayShareLinkError("VMess payload contains an invalid port")
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise XrayShareLinkError("VMess payload contains an invalid port") from exc
    host, port = _host_port(host, port)
    try:
        user_id = str(uuid.UUID(str(document.get("id", ""))))
    except ValueError as exc:
        raise XrayShareLinkError("VMess payload must contain a valid UUID user ID") from exc
    raw_alter_id = document.get("aid", 0)
    if isinstance(raw_alter_id, bool) or not isinstance(raw_alter_id, (str, int)):
        raise XrayShareLinkError("VMess alterId must be an integer")
    if isinstance(raw_alter_id, str) and not re.fullmatch(r"[0-9]{1,5}", raw_alter_id):
        raise XrayShareLinkError("VMess alterId must be an integer")
    try:
        alter_id = int(raw_alter_id)
    except (TypeError, ValueError) as exc:
        raise XrayShareLinkError("VMess alterId must be an integer") from exc
    if alter_id != 0:
        raise XrayShareLinkError(
            "Xray VMess is AEAD-only; non-zero alterId is not supported"
        )
    cipher = str(document.get("scy") or "auto")
    if cipher not in {"auto", "aes-128-gcm", "chacha20-poly1305"}:
        raise XrayShareLinkError("Unsupported VMess cipher")
    raw_tls = document.get("tls", "")
    if not isinstance(raw_tls, str):
        raise XrayShareLinkError("VMess TLS mode must be text")
    tls_mode = raw_tls.strip().lower()
    if tls_mode not in {"", "none", "false", "0", "tls", "true", "1"}:
        raise XrayShareLinkError("Unsupported VMess TLS mode")
    query = {
        "type": str(document.get("net") or "tcp"),
        "security": "tls" if tls_mode in {"tls", "true", "1"} else "none",
        "host": str(document.get("host") or ""),
        "path": str(document.get("path") or "/"),
        "sni": str(document.get("sni") or document.get("host") or host),
        "fp": str(document.get("fp") or ""),
        "mode": str(document.get("mode") or "auto"),
        "profile_name": str(document.get("ps") or ""),
    }
    if query["type"] == "grpc":
        query["serviceName"] = query["path"].lstrip("/")
    user = {"id": user_id, "security": cipher}
    outbound = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": _stream_settings(query["type"], query["security"], host, query),
    }
    return host, port, outbound, query


def _parse_trojan(parsed) -> tuple[str, int, dict, dict]:
    host, port = _url_endpoint(parsed)
    password = unquote(parsed.username or "")
    if (
        not password
        or len(password) > 1024
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in password)
    ):
        raise XrayShareLinkError("Trojan link must contain a valid password")
    query = _query(parsed)
    network = query.get("type", query.get("network", "tcp"))
    security = query.get("security", "tls").lower()
    if security == "none":
        raise XrayShareLinkError("Trojan share links must use TLS or Reality security")
    outbound = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": _stream_settings(network, security, host, query),
    }
    return host, port, outbound, query


def _parse_shadowsocks(parsed) -> tuple[str, int, dict, dict]:
    raw = parsed.netloc
    if "@" not in raw:
        decoded = _decode_base64(raw.split("#", 1)[0], "Shadowsocks user info").decode("utf-8")
        if "@" not in decoded:
            raise XrayShareLinkError("Shadowsocks link must include method:password@host:port")
        user_info, endpoint = decoded.rsplit("@", 1)
        host_port = urlsplit("//" + endpoint)
        host, port = _url_endpoint(host_port)
    else:
        user_info, _separator, endpoint = raw.rpartition("@")
        host_port = urlsplit("//" + endpoint)
        host, port = _url_endpoint(host_port)
        if ":" not in user_info and "%3a" not in user_info.lower():
            user_info = _decode_base64(user_info, "Shadowsocks credentials").decode("utf-8")
        else:
            # SIP002 permits percent-encoded user-info; decode the method/password
            # separator and password bytes before splitting the credentials.
            user_info = unquote(user_info)
    if ":" not in user_info:
        raise XrayShareLinkError("Shadowsocks credentials must contain method and password")
    method, password = user_info.split(":", 1)
    if method not in {
        "aes-128-gcm", "aes-256-gcm",
        "chacha20-poly1305", "chacha20-ietf-poly1305",
        "xchacha20-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    }:
        raise XrayShareLinkError("Unsupported Shadowsocks cipher method")
    if not password or len(password) > 1024:
        raise XrayShareLinkError("Shadowsocks password is empty or too long")
    query = _query(parsed)
    if "plugin" in query:
        raise XrayShareLinkError("Shadowsocks SIP003 plugins are not yet supported")
    outbound = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
    }
    return host, port, outbound, query


def build_xray_tun_config(outbound: dict, *, adapter_name: str = "ApnaWin") -> bytes:
    """Wrap one validated remote Xray outbound in ApnaWin's strict dual-stack TUN."""
    if not isinstance(outbound, dict) or outbound.get("protocol") not in {
        "vless", "vmess", "trojan", "shadowsocks"
    }:
        raise XrayShareLinkError("Unsupported Xray outbound protocol")
    if (
        not isinstance(adapter_name, str)
        or not re.fullmatch(r"[A-Za-z0-9 _.-]{1,128}", adapter_name)
    ):
        raise XrayShareLinkError("Windows TUN adapter name is invalid")
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "apnawin-system-tun",
            "protocol": "tun",
            "port": 0,
            "settings": {
                "name": adapter_name,
                "desc": "ApnaWin multi-protocol Xray TUN",
                "mtu": 1500,
                "gateway": ["10.255.0.1/30", "fd42:6170:6e61:7769::1/64"],
                "dns": list(_DEFAULT_DNS),
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto",
                "autoSystemWfpBlockLeak": ["allexceptlan", "dns"],
            },
        }],
        "outbounds": [outbound],
    }
    try:
        inspect_tun_inbound(config)
    except (TypeError, ValueError) as exc:
        raise XrayShareLinkError("Generated Xray TUN policy failed validation") from exc
    return (json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def import_xray_share_link(uri: str) -> ImportedXrayProfile:
    """Parse a VLESS/VMess/Trojan/Shadowsocks link without persisting plaintext secrets."""
    if not isinstance(uri, str) or not uri.strip() or len(uri) > 131072:
        raise XrayShareLinkError("Share link is empty or exceeds the size limit")
    text = uri.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise XrayShareLinkError("Share link contains control characters")
    scheme = text.split(":", 1)[0].lower()
    if scheme not in _SUPPORTED_SCHEMES:
        raise XrayShareLinkError("Supported share-link schemes: vless, vmess, trojan and ss")
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise XrayShareLinkError("Share link URL is malformed") from exc
    if scheme == "vmess":
        host, port, outbound, query = _parse_vmess(parsed)
        fragment = parsed.fragment or query.get("profile_name", "")
    else:
        if parsed.scheme.lower() != scheme:
            raise XrayShareLinkError("Share-link scheme is invalid")
        if scheme == "vless":
            host, port, outbound, query = _parse_vless(parsed)
        elif scheme == "trojan":
            host, port, outbound, query = _parse_trojan(parsed)
        else:
            host, port, outbound, query = _parse_shadowsocks(parsed)
        fragment = parsed.fragment
    protocol = outbound["protocol"]
    profile_name = _name(fragment, protocol, host, port)
    profile = ConnectionProfile(profile_name, Transport.XRAY, host, port)
    return ImportedXrayProfile(
        profile=profile,
        config_bytes=build_xray_tun_config(outbound),
        protocol=protocol,
    )
