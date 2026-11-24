"""Import secure Xray share links and WireGuard configs into encrypted Windows TUN profiles.

The bundled Xray runtime supplies the protocol implementations. This module
normalizes VLESS, VMess, Trojan, Shadowsocks and Hysteria 2 links, plus standard
WireGuard configs, into a strict full-tunnel config; credentials are returned only inside config_bytes
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
_SUPPORTED_SCHEMES = frozenset({"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "socks", "socks5", "http", "https"})
_SUPPORTED_NETWORKS = frozenset({"tcp", "ws", "grpc", "httpupgrade", "xhttp", "mkcp"})
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



def _xhttp_range(value: object, field: str, *, minimum: int = 0, maximum: int = 10000000) -> object:
    """Validate Xray integer or inclusive low-high range fields."""
    if isinstance(value, bool):
        raise XrayShareLinkError(f"XHTTP {field} is invalid")
    if isinstance(value, int):
        if not minimum <= value <= maximum:
            raise XrayShareLinkError(f"XHTTP {field} is outside the supported range")
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,8}(?:-[0-9]{1,8})?", value):
        parts = [int(part) for part in value.split("-", 1)]
        if not minimum <= parts[0] <= maximum or (len(parts) == 2 and not parts[0] <= parts[1] <= maximum):
            raise XrayShareLinkError(f"XHTTP {field} is outside the supported range")
        return value
    raise XrayShareLinkError(f"XHTTP {field} must be an integer or numeric range")


def _xhttp_headers(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 32:
        raise XrayShareLinkError("XHTTP headers must be a bounded object")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]{1,128}", key):
            raise XrayShareLinkError("XHTTP header name is invalid")
        if not isinstance(item, str) or len(item) > 4096 or any(ord(ch) < 32 and ch != "\t" or ord(ch) == 127 for ch in item):
            raise XrayShareLinkError("XHTTP header value is invalid")
        result[key] = item
    return result


def _parse_xhttp_extra(raw: str) -> dict:
    if not isinstance(raw, str) or not raw or len(raw) > 32768:
        raise XrayShareLinkError("XHTTP extra is empty or exceeds the size limit")
    try:
        extra = json.loads(raw, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, XrayShareLinkError) as exc:
        raise XrayShareLinkError("XHTTP extra must be valid unambiguous JSON") from exc
    if not isinstance(extra, dict):
        raise XrayShareLinkError("XHTTP extra must be a JSON object")
    allowed = {
        "headers", "xPaddingBytes", "noGRPCHeader", "noSSEHeader",
        "scMaxEachPostBytes", "scMinPostsIntervalMs", "scMaxBufferedPosts",
        "scStreamUpServerSecs", "xmux", "downloadSettings",
    }
    if set(extra) - allowed:
        raise XrayShareLinkError("XHTTP extra contains unsupported fields")
    result = {}
    if "headers" in extra:
        result["headers"] = _xhttp_headers(extra["headers"])
    if "xPaddingBytes" in extra:
        result["xPaddingBytes"] = _xhttp_range(extra["xPaddingBytes"], "xPaddingBytes", maximum=1000000)
    for key in ("noGRPCHeader", "noSSEHeader"):
        if key in extra:
            if not isinstance(extra[key], bool):
                raise XrayShareLinkError(f"XHTTP {key} must be boolean")
            result[key] = extra[key]
    for key, minimum, maximum in (
        ("scMaxEachPostBytes", 1, 100000000),
        ("scMinPostsIntervalMs", 0, 600000),
        ("scMaxBufferedPosts", 0, 100000),
        ("scStreamUpServerSecs", 0, 86400),
    ):
        if key in extra:
            result[key] = _xhttp_range(extra[key], key, minimum=minimum, maximum=maximum)
    if "xmux" in extra:
        xmux = extra["xmux"]
        if not isinstance(xmux, dict) or set(xmux) - {
            "maxConcurrency", "maxConnections", "cMaxReuseTimes",
            "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod",
        }:
            raise XrayShareLinkError("XHTTP xmux contains unsupported fields")
        safe_mux = {}
        for key in ("maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs"):
            if key in xmux:
                safe_mux[key] = _xhttp_range(xmux[key], f"xmux.{key}", maximum=1000000)
        if "hKeepAlivePeriod" in xmux:
            value = xmux["hKeepAlivePeriod"]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 86400:
                raise XrayShareLinkError("XHTTP xmux.hKeepAlivePeriod is invalid")
            safe_mux["hKeepAlivePeriod"] = value
        result["xmux"] = safe_mux
    if "downloadSettings" in extra:
        download = extra["downloadSettings"]
        if not isinstance(download, dict) or set(download) - {
            "address", "port", "network", "security", "tlsSettings", "xhttpSettings",
        }:
            raise XrayShareLinkError("XHTTP downloadSettings contains unsupported fields")
        address, port = _host_port(download.get("address"), download.get("port"))
        if download.get("network") != "xhttp" or download.get("security") != "tls":
            raise XrayShareLinkError("XHTTP downloadSettings currently requires XHTTP over verified TLS")
        tls = download.get("tlsSettings", {})
        if not isinstance(tls, dict) or set(tls) - {"serverName", "alpn", "allowInsecure", "fingerprint"}:
            raise XrayShareLinkError("XHTTP download TLS settings contain unsupported fields")
        if tls.get("allowInsecure", False) is not False:
            raise XrayShareLinkError("Insecure XHTTP download TLS is not supported")
        server_name = _safe_option_text(tls.get("serverName", address), "XHTTP download TLS server name", max_length=253, allow_empty=False)
        _host_port(server_name, 443)
        alpn = tls.get("alpn", ["h2"])
        if not isinstance(alpn, list) or not 1 <= len(alpn) <= 3 or any(item not in {"h2", "h3", "http/1.1"} for item in alpn):
            raise XrayShareLinkError("XHTTP download TLS ALPN is invalid")
        tls_config = {"serverName": server_name, "alpn": alpn, "allowInsecure": False}
        if "fingerprint" in tls:
            fp = tls["fingerprint"]
            if not isinstance(fp, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", fp):
                raise XrayShareLinkError("XHTTP download TLS fingerprint is invalid")
            tls_config["fingerprint"] = fp
        xhttp = download.get("xhttpSettings")
        if not isinstance(xhttp, dict) or set(xhttp) - {"host", "path", "mode"}:
            raise XrayShareLinkError("XHTTP download xhttpSettings are invalid")
        path = _transport_path(xhttp.get("path", "/"), "XHTTP download")
        mode = xhttp.get("mode", "auto")
        if mode not in {"auto", "packet-up", "stream-up", "stream-one", "stream-down"}:
            raise XrayShareLinkError("XHTTP download mode is unsupported")
        normalized_xhttp = {"path": path, "mode": mode}
        if xhttp.get("host"):
            _host_port(xhttp["host"], 443)
            normalized_xhttp["host"] = xhttp["host"]
        result["downloadSettings"] = {
            "address": address, "port": port, "network": "xhttp", "security": "tls",
            "tlsSettings": tls_config, "xhttpSettings": normalized_xhttp,
        }
    return result


def _stream_settings(
    network: str,
    security: str,
    host: str,
    query: dict[str, str],
    *,
    allow_reality: bool = True,
) -> dict:
    network = (network or "tcp").lower()
    if network == "kcp":
        network = "mkcp"
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
        if "extra" in query:
            xhttp["extra"] = _parse_xhttp_extra(query["extra"])
        settings["xhttpSettings"] = xhttp


    elif network == "mkcp":
        kcp = {"mtu": 1350, "tti": 50, "uplinkCapacity": 5, "downlinkCapacity": 20}
        numeric = {
            "mtu": (576, 1460),
            "tti": (10, 100),
            "uplinkCapacity": (0, 10000),
            "downlinkCapacity": (0, 10000),
        }
        for key, bounds in numeric.items():
            if key in query:
                value = query[key]
                if not re.fullmatch(r"[0-9]{1,5}", value) or not bounds[0] <= int(value) <= bounds[1]:
                    raise XrayShareLinkError("mKCP numeric setting is outside the supported range")
                kcp[key] = int(value)
        settings["kcpSettings"] = kcp
        header = query.get("headerType", "").lower()
        if header == "none":
            header = ""
        if header not in {"", "dns", "dtls", "srtp", "utp", "wechat", "wireguard"}:
            raise XrayShareLinkError("mKCP headerType is unsupported")
        seed = _safe_option_text(query.get("seed", ""), "mKCP seed", max_length=1024)
        if header and seed and header != "dns":
            raise XrayShareLinkError("mKCP seed is only meaningful for the DNS header")
        if header or seed or "headerType" in query:
            if header == "dns" and seed:
                _host_port(seed, 443)
            settings["finalmask"] = {
                "udp": [{"type": "mkcp-legacy", "settings": {"header": header, "value": seed}}]
            }

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
            raw_values = alpn.split(",")
            if not 1 <= len(raw_values) <= 8 or any(not item.strip() for item in raw_values):
                raise XrayShareLinkError("TLS ALPN list is invalid")
            values = [
                _safe_option_text(
                    item.strip(),
                    "TLS ALPN value",
                    max_length=32,
                    allow_empty=False,
                )
                for item in raw_values
            ]
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
    if parsed.path not in {"", "/"}:
        raise XrayShareLinkError("VLESS share link contains an unsupported URL path")
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



def import_masque_config(text: str, *, profile_name: str = "MASQUE") -> ImportedXrayProfile:
    """Import one documented Xray MASQUE outbound into the strict ApnaWin TUN."""
    if not isinstance(text, str) or not text.strip() or len(text) > 262144:
        raise XrayShareLinkError("MASQUE JSON is empty or exceeds the size limit")
    try:
        document = json.loads(text, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, XrayShareLinkError) as exc:
        raise XrayShareLinkError("MASQUE configuration must be valid unambiguous JSON") from exc
    if not isinstance(document, dict):
        raise XrayShareLinkError("MASQUE configuration must be a JSON object")
    if "outbounds" in document:
        outbounds = document.get("outbounds")
        if not isinstance(outbounds, list) or len(outbounds) != 1:
            raise XrayShareLinkError("MASQUE import accepts exactly one outbound")
        outbound = outbounds[0]
    else:
        outbound = document
    if not isinstance(outbound, dict) or outbound.get("protocol") != "masque":
        raise XrayShareLinkError("JSON must contain one Xray MASQUE outbound")
    if set(outbound) - {"protocol", "settings", "streamSettings", "tag", "mux"}:
        raise XrayShareLinkError("MASQUE outbound contains unsupported top-level fields")
    if "mux" in outbound and (
        not isinstance(outbound["mux"], dict) or outbound["mux"].get("enabled", False) is not False
    ):
        raise XrayShareLinkError("MASQUE outbound does not support Mux")
    settings, stream = outbound.get("settings"), outbound.get("streamSettings")
    if not isinstance(settings, dict) or not isinstance(stream, dict):
        raise XrayShareLinkError("MASQUE outbound requires settings and streamSettings")
    if set(settings) - {"address", "port", "remoteDNS"}:
        raise XrayShareLinkError("MASQUE settings contain unsupported fields")
    host, port = _host_port(settings.get("address"), settings.get("port"))
    dns = settings.get("remoteDNS", [])
    if not isinstance(dns, list) or len(dns) > 16:
        raise XrayShareLinkError("MASQUE remoteDNS must contain at most 16 IP addresses")
    try:
        import ipaddress
        dns = [str(ipaddress.ip_address(item)) for item in dns]
    except (TypeError, ValueError) as exc:
        raise XrayShareLinkError("MASQUE remoteDNS entries must be IP addresses") from exc
    if set(stream) - {"network", "method", "security", "tlsSettings", "masqueSettings"}:
        raise XrayShareLinkError("MASQUE streamSettings contain unsupported fields")
    if stream.get("network", stream.get("method")) != "masque" or stream.get("network") not in {None, "masque"} or stream.get("method") not in {None, "masque"}:
        raise XrayShareLinkError("MASQUE outbound requires a consistent masque transport")
    if stream.get("security") != "tls":
        raise XrayShareLinkError("MASQUE requires TLS; REALITY and plaintext are unsupported")
    tls, masque = stream.get("tlsSettings"), stream.get("masqueSettings")
    if not isinstance(tls, dict) or not isinstance(masque, dict):
        raise XrayShareLinkError("MASQUE requires tlsSettings and masqueSettings")
    if set(tls) - {"serverName", "alpn", "allowInsecure", "fingerprint"}:
        raise XrayShareLinkError("MASQUE TLS settings contain unsupported fields")
    if tls.get("allowInsecure", False) is not False:
        raise XrayShareLinkError("Insecure MASQUE TLS is not supported")
    server_name = _safe_option_text(tls.get("serverName", host), "MASQUE TLS server name", max_length=253, allow_empty=False)
    _host_port(server_name, 443)
    alpn = tls.get("alpn", ["h3"])
    if not isinstance(alpn, list) or not 1 <= len(alpn) <= 2 or any(item not in {"h2", "h3"} for item in alpn):
        raise XrayShareLinkError("MASQUE TLS ALPN must contain h2 and/or h3")
    tls_settings = {"serverName": server_name, "alpn": alpn, "allowInsecure": False}
    if "fingerprint" in tls:
        fp = tls["fingerprint"]
        if not isinstance(fp, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", fp):
            raise XrayShareLinkError("MASQUE TLS fingerprint is invalid")
        tls_settings["fingerprint"] = fp
    if set(masque) - {"host", "path", "user", "pass", "headers"}:
        raise XrayShareLinkError("MASQUE settings contain unsupported fields")
    authority = _safe_option_text(masque.get("host", server_name), "MASQUE HTTP authority", max_length=253, allow_empty=False)
    _host_port(authority, 443)
    path = _safe_option_text(masque.get("path", "/.well-known/masque/ip/{target}/{ipproto}/"), "MASQUE CONNECT-IP path", max_length=2048, allow_empty=False)
    residue = re.sub(r"\{(?:target|ipproto|\?target,ipproto)\}", "", path)
    if not path.startswith("/") or "{" in residue or "}" in residue:
        raise XrayShareLinkError("MASQUE path contains unsupported template variables")
    user, password = masque.get("user", ""), masque.get("pass", "")
    if not isinstance(user, str) or not isinstance(password, str) or bool(user) != bool(password) or ":" in user:
        raise XrayShareLinkError("MASQUE requires both username and password; username cannot contain colon")
    if any(ord(ch) < 32 or ord(ch) == 127 for value in (user, password) for ch in value):
        raise XrayShareLinkError("MASQUE credentials contain control characters")
    headers = masque.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > 64:
        raise XrayShareLinkError("MASQUE headers must be a bounded JSON object")
    safe_headers = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]{1,128}", key):
            raise XrayShareLinkError("MASQUE header name is invalid")
        if not isinstance(value, str) or len(value) > 8192 or any(ord(ch) < 32 and ch != "\t" or ord(ch) == 127 for ch in value):
            raise XrayShareLinkError("MASQUE header value is invalid")
        safe_headers[key] = value
    outbound_config = {
        "tag": "proxy", "protocol": "masque",
        "settings": {"address": host, "port": port, **({"remoteDNS": dns} if dns else {})},
        "streamSettings": {
            "network": "masque", "security": "tls", "tlsSettings": tls_settings,
            "masqueSettings": {
                "host": authority, "path": path,
                **({"user": user, "pass": password} if user else {}),
                **({"headers": safe_headers} if safe_headers else {}),
            },
        },
    }
    profile = ConnectionProfile(_name(profile_name, "masque", host, port), Transport.XRAY, host, port)
    return ImportedXrayProfile(profile, build_xray_tun_config(outbound_config), "masque")



def _parse_simple_proxy(parsed, protocol: str) -> tuple[str, int, dict, dict]:
    """Import HTTP(S) or SOCKS5 proxy URI; these outbounds are TCP-only."""
    if parsed.path not in {"", "/"}:
        raise XrayShareLinkError("Proxy URI contains an unsupported path")
    host, port = _url_endpoint(parsed)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if bool(username) != bool(password):
        raise XrayShareLinkError("Proxy authentication requires both username and password")
    for value in (username, password):
        if len(value) > 1024 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise XrayShareLinkError("Proxy credentials are invalid")
    query = _query(parsed)
    is_tls_http = parsed.scheme.lower() == "https"
    if protocol == "socks" and query:
        raise XrayShareLinkError("SOCKS proxy URI query parameters are not supported")
    if protocol == "http" and query.keys() - ({"sni"} if is_tls_http else set()):
        raise XrayShareLinkError("HTTP proxy URI contains unsupported query parameters")
    server = {"address": host, "port": port}
    if username:
        server["users"] = [{"user": username, "pass": password}]
    outbound = {"tag": "proxy", "protocol": protocol, "settings": {"servers": [server]}}
    if is_tls_http:
        server_name = _safe_option_text(query.get("sni", host), "HTTPS proxy TLS server name", max_length=253, allow_empty=False)
        _host_port(server_name, 443)
        outbound["streamSettings"] = {
            "network": "tcp", "security": "tls",
            "tlsSettings": {"serverName": server_name, "allowInsecure": False},
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
    if parsed.path not in {"", "/"}:
        raise XrayShareLinkError("Trojan share link contains an unsupported URL path")
    host, port = _url_endpoint(parsed)
    if parsed.password is not None:
        raise XrayShareLinkError(
            "Trojan password must be a single URL user-info value; encode literal colons as %3A"
        )
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


def _decode_shadowsocks_userinfo(encoded: str, field: str) -> str:
    try:
        return _decode_base64(encoded, field).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise XrayShareLinkError(f"{field} must decode to UTF-8 text") from exc


def _parse_shadowsocks(parsed) -> tuple[str, int, dict, dict]:
    raw = parsed.netloc
    if "@" not in raw:
        decoded = _decode_shadowsocks_userinfo(raw.split("#", 1)[0], "Shadowsocks user info")
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
            user_info = _decode_shadowsocks_userinfo(user_info, "Shadowsocks credentials")
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
    if (
        not password
        or len(password) > 1024
        or any(ord(character) < 32 or ord(character) == 127 for character in password)
    ):
        raise XrayShareLinkError("Shadowsocks password is empty, too long, or contains control characters")
    query = _query(parsed)
    if "plugin" in query:
        raise XrayShareLinkError("Shadowsocks SIP003 plugins are not yet supported")
    outbound = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
    }
    return host, port, outbound, query



def _parse_hysteria2(parsed) -> tuple[str, int, dict, dict]:
    """Translate the interoperable Hysteria 2 URI subset supported by Xray."""
    if parsed.path not in {"", "/"}:
        raise XrayShareLinkError("Hysteria 2 share link contains an unsupported URL path")
    try:
        host, port = _host_port(parsed.hostname, parsed.port or 443)
    except ValueError as exc:
        raise XrayShareLinkError("Hysteria 2 server endpoint is invalid") from exc
    if not parsed.username:
        raise XrayShareLinkError("Hysteria 2 link must contain authentication credentials")
    auth = unquote(parsed.username)
    if parsed.password is not None:
        auth += ":" + unquote(parsed.password)
    if not auth or len(auth) > 1024 or any(ord(ch) < 32 or ord(ch) == 127 for ch in auth):
        raise XrayShareLinkError("Hysteria 2 link must contain valid authentication credentials")
    query = _query(parsed)
    if query.get("insecure", "0").lower() not in {"0", "false", "no"}:
        raise XrayShareLinkError("Insecure Hysteria 2 TLS is not supported")
    unsupported = {"obfs", "obfs-password", "pinSHA256", "ech"} & query.keys()
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise XrayShareLinkError(f"Xray Hysteria 2 importer does not support: {names}")
    unknown = query.keys() - {"insecure", "sni"}
    if unknown:
        raise XrayShareLinkError("Hysteria 2 link contains unsupported query parameters")
    server_name = _safe_option_text(
        query.get("sni", host), "Hysteria 2 TLS server name",
        max_length=253, allow_empty=False,
    )
    _host_port(server_name, 443)
    outbound = {
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": {"version": 2, "address": host, "port": port},
        "streamSettings": {
            "method": "hysteria",
            "security": "tls",
            "tlsSettings": {"serverName": server_name, "allowInsecure": False},
            "hysteriaSettings": {"version": 2, "auth": auth},
        },
    }
    return host, port, outbound, query


def _wireguard_key(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise XrayShareLinkError(f"WireGuard {field} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise XrayShareLinkError(f"WireGuard {field} must be Base64") from exc
    if len(decoded) != 32:
        raise XrayShareLinkError(f"WireGuard {field} must decode to 32 bytes")
    return base64.b64encode(decoded).decode("ascii")


def import_wireguard_config(
    text: str, *, profile_name: str = "WireGuard"
) -> ImportedXrayProfile:
    """Import a standard single/multi-peer WireGuard INI config into Xray TUN."""
    if not isinstance(text, str) or not text.strip() or len(text) > 262144:
        raise XrayShareLinkError("WireGuard configuration is empty or exceeds the size limit")
    if any(ord(ch) < 32 and ch not in "\r\n\t" or ord(ch) == 127 for ch in text):
        raise XrayShareLinkError("WireGuard configuration contains control characters")
    sections: list[tuple[str, dict[str, str]]] = []
    current: dict[str, str] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().casefold()
            if section not in {"interface", "peer"}:
                raise XrayShareLinkError("WireGuard config contains an unsupported section")
            current = {}
            sections.append((section, current))
            continue
        if current is None or "=" not in line:
            raise XrayShareLinkError("WireGuard config contains a malformed setting")
        key, value = (part.strip() for part in line.split("=", 1))
        key = key.casefold()
        if key in current:
            raise XrayShareLinkError(f"WireGuard config contains duplicate {key} setting")
        current[key] = value
    interfaces = [item for name, item in sections if name == "interface"]
    peers = [item for name, item in sections if name == "peer"]
    if len(interfaces) != 1 or not peers:
        raise XrayShareLinkError("WireGuard config requires one Interface and at least one Peer")
    if len(peers) > 64:
        raise XrayShareLinkError("WireGuard config exceeds the 64-peer limit")
    interface = interfaces[0]
    allowed_interface = {"privatekey", "address", "dns", "mtu"}
    if set(interface) - allowed_interface:
        raise XrayShareLinkError("WireGuard Interface contains unsupported settings")
    private_key = _wireguard_key(interface.get("privatekey", ""), "private key")
    addresses = [item.strip() for item in interface.get("address", "").split(",") if item.strip()]
    if not addresses or len(addresses) > 8:
        raise XrayShareLinkError("WireGuard Interface requires one to eight IP addresses")
    try:
        import ipaddress
        normalized_addresses = [str(ipaddress.ip_interface(item).ip) for item in addresses]
    except ValueError as exc:
        raise XrayShareLinkError("WireGuard Interface Address contains an invalid IP prefix") from exc
    if len(set(normalized_addresses)) != len(normalized_addresses):
        raise XrayShareLinkError("WireGuard Interface Address entries must be unique")
    dns_raw = interface.get("dns", "")
    dns_servers = [item.strip() for item in dns_raw.split(",") if item.strip()]
    if len(dns_servers) > 16:
        raise XrayShareLinkError("WireGuard DNS list exceeds the size limit")
    try:
        dns_addresses = [ipaddress.ip_address(item) for item in dns_servers]
    except ValueError as exc:
        raise XrayShareLinkError("WireGuard DNS entries must be IP addresses") from exc
    if any(address.is_unspecified or address.is_multicast or address.is_link_local for address in dns_addresses):
        raise XrayShareLinkError("WireGuard DNS servers must be usable unicast addresses")
    normalized_dns = [str(address) for address in dns_addresses]
    if len(set(normalized_dns)) != len(normalized_dns):
        raise XrayShareLinkError("WireGuard DNS server addresses must be unique")
    mtu = 1420
    if "mtu" in interface:
        if not re.fullmatch(r"[0-9]{3,4}", interface["mtu"]):
            raise XrayShareLinkError("WireGuard MTU must be an integer")
        mtu = int(interface["mtu"])
        if not 576 <= mtu <= 9000:
            raise XrayShareLinkError("WireGuard MTU is outside the supported range")
    peer_records = []
    first_endpoint: tuple[str, int] | None = None
    for peer in peers:
        if set(peer) - {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}:
            raise XrayShareLinkError("WireGuard Peer contains unsupported settings")
        public_key = _wireguard_key(peer.get("publickey", ""), "peer public key")
        endpoint_value = peer.get("endpoint", "")
        try:
            endpoint = urlsplit("//" + endpoint_value)
            if endpoint.username is not None or endpoint.password is not None or endpoint.path or endpoint.query or endpoint.fragment:
                raise ValueError("WireGuard endpoint must be host:port only")
            endpoint_host, endpoint_port = _url_endpoint(endpoint)
        except (ValueError, XrayShareLinkError) as exc:
            raise XrayShareLinkError("WireGuard Peer Endpoint is invalid") from exc
        if first_endpoint is None:
            first_endpoint = (endpoint_host, endpoint_port)
        allowed_raw = [item.strip() for item in peer.get("allowedips", "").split(",") if item.strip()]
        if not allowed_raw or len(allowed_raw) > 64:
            raise XrayShareLinkError("WireGuard Peer requires one to 64 AllowedIPs prefixes")
        try:
            allowed_ips = [str(ipaddress.ip_network(item, strict=False)) for item in allowed_raw]
        except ValueError as exc:
            raise XrayShareLinkError("WireGuard AllowedIPs contains an invalid IP prefix") from exc
        if len(set(allowed_ips)) != len(allowed_ips):
            raise XrayShareLinkError("WireGuard AllowedIPs prefixes must be unique within each peer")
        record = {
            "endpoint": f"[{endpoint_host}]:{endpoint_port}" if ":" in endpoint_host else f"{endpoint_host}:{endpoint_port}",
            "publicKey": public_key,
            "allowedIPs": allowed_ips,
        }
        if "presharedkey" in peer:
            record["preSharedKey"] = _wireguard_key(peer["presharedkey"], "preshared key")
        if "persistentkeepalive" in peer:
            keepalive = peer["persistentkeepalive"]
            if not re.fullmatch(r"[0-9]{1,5}", keepalive) or int(keepalive) > 65535:
                raise XrayShareLinkError("WireGuard PersistentKeepalive is invalid")
            record["keepAlive"] = int(keepalive)
        peer_records.append(record)
    assert first_endpoint is not None
    allowed_networks = [
        ipaddress.ip_network(prefix)
        for peer_record in peer_records
        for prefix in peer_record["allowedIPs"]
    ]
    if not any(network.version == 4 and network.prefixlen == 0 for network in allowed_networks):
        raise XrayShareLinkError("WireGuard full-tunnel config requires an IPv4 default AllowedIPs route")
    if not any(network.version == 6 and network.prefixlen == 0 for network in allowed_networks):
        raise XrayShareLinkError("WireGuard full-tunnel config requires an IPv6 default AllowedIPs route")
    settings = {
        "secretKey": private_key,
        "address": normalized_addresses,
        "peers": peer_records,
        "mtu": mtu,
        "noKernelTun": False,
    }
    if normalized_dns:
        settings["remoteDNS"] = normalized_dns
    outbound = {"tag": "proxy", "protocol": "wireguard", "settings": settings}
    profile = ConnectionProfile(
        _name(profile_name, "wireguard", first_endpoint[0], first_endpoint[1]),
        Transport.XRAY, first_endpoint[0], first_endpoint[1],
    )
    return ImportedXrayProfile(
        profile=profile,
        config_bytes=build_xray_tun_config(outbound),
        protocol="wireguard",
    )


def build_xray_tun_config(outbound: dict, *, adapter_name: str = "ApnaWin") -> bytes:
    """Wrap one validated remote Xray outbound in ApnaWin's strict dual-stack TUN."""
    if not isinstance(outbound, dict) or outbound.get("protocol") not in {
        "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "masque", "socks", "http"
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
    """Parse a supported Xray share link without persisting plaintext secrets."""
    if not isinstance(uri, str) or not uri.strip() or len(uri) > 131072:
        raise XrayShareLinkError("Share link is empty or exceeds the size limit")
    text = uri.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise XrayShareLinkError("Share link contains control characters")
    scheme = text.split(":", 1)[0].lower()
    if scheme not in _SUPPORTED_SCHEMES:
        raise XrayShareLinkError("Supported share-link schemes: vless, vmess, trojan, ss, hysteria2, socks and http")
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise XrayShareLinkError("Share link URL is malformed") from exc
    if scheme == "vmess":
        host, port, outbound, query = _parse_vmess(parsed)
        fragment = parsed.fragment or query.get("profile_name", "")
    elif scheme in {"hysteria2", "hy2"}:
        host, port, outbound, query = _parse_hysteria2(parsed)
        fragment = parsed.fragment
    elif scheme in {"socks", "socks5"}:
        host, port, outbound, query = _parse_simple_proxy(parsed, "socks")
        fragment = parsed.fragment
    elif scheme in {"http", "https"}:
        host, port, outbound, query = _parse_simple_proxy(parsed, "http")
        fragment = parsed.fragment
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
