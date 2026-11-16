"""Strict mapper for the APNA Lite catalog's SSH/WebSocket server families.

Only the SSH-compatible categories are accepted here. UDP-only, XRay,
Shadowsocks and Trojan catalog entries require separate engines and are
rejected rather than silently treated as SSH.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode
from apnawin.engines.apna_ssh_session import ApnaSshConfig
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig
from apnawin.services.apna_lite_catalog import (
    ApnaLiteCredentials,
    ApnaLiteCatalogError,
    decode_apna_lite_catalog_credentials,
)


_SSH_CATEGORIES = frozenset({"ocsws", "ocscf", "ocsnormal", "ocshttp"})
_SUPPORTED_METHODS = frozenset({"direct", "http", "ssl"})
_DEFAULT_DNS = "1.1.1.1"


class ApnaLiteProfileError(ValueError):
    """The selected APNA catalog server/payload pair cannot be mapped safely."""


@dataclass(frozen=True, slots=True)
class ApnaLiteProfile:
    profile: ConnectionProfile
    session_config: ApnaTunnelSessionConfig
    category: str
    method: str
    server_name: str
    payload_name: str


def _host_pool(value: object, field: str) -> list[str]:
    if not isinstance(value, str) or not value:
        raise ApnaLiteProfileError(f"{field} is missing")
    if value == "Pulled":
        return ["Pulled"]
    hosts = [item.strip() for item in value.split(";") if item.strip()]
    if not hosts or any(
        len(host) > 253
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in host)
        or any(char in host for char in "/\\@?#[]")
        for host in hosts
    ):
        raise ApnaLiteProfileError(f"{field} contains an invalid host pool")
    return list(dict.fromkeys(hosts))


def _select(pool: list[str], selector: Callable[[list[str]], str], field: str) -> str:
    selected = selector(pool)
    if selected not in pool:
        raise ApnaLiteProfileError(f"{field} selector returned a value outside the pool")
    return selected


def _port(value: object, fallback: object, field: str) -> int:
    selected = fallback if value in ("Pulled", None, "") else value
    try:
        port = int(selected)
    except (TypeError, ValueError) as exc:
        raise ApnaLiteProfileError(f"{field} is not a numeric port") from exc
    if not 1 <= port <= 65535:
        raise ApnaLiteProfileError(f"{field} is outside the TCP/UDP port range")
    return port


def _catalog_bool(value: object, field: str) -> bool:
    if value is True or value == "true":
        return True
    if value is False or value == "false":
        return False
    raise ApnaLiteProfileError(f"{field} must be true or false")



def list_apna_lite_ssh_servers(catalog: dict) -> list[dict]:
    """Return only free-catalog server records supported by the SSH mapper."""
    if not isinstance(catalog, dict):
        raise TypeError("catalog must be a dictionary")
    records = catalog.get("Free_servers")
    if not isinstance(records, list):
        raise ApnaLiteProfileError("APNA catalog has no free server list")
    return [
        record for record in records
        if isinstance(record, dict) and record.get("category") in _SSH_CATEGORIES
    ]


def list_apna_lite_ssh_payloads(catalog: dict, category: str) -> list[dict]:
    """Return SSH-compatible payloads for one exact catalog category."""
    if not isinstance(catalog, dict):
        raise TypeError("catalog must be a dictionary")
    if category not in _SSH_CATEGORIES:
        return []
    records = catalog.get("Payloads")
    if not isinstance(records, list):
        raise ApnaLiteProfileError("APNA catalog has no payload list")
    return [
        record for record in records
        if isinstance(record, dict)
        and record.get("category") == category
        and record.get("method") in _SUPPORTED_METHODS
    ]


def build_apna_lite_ssh_profile(
    catalog: dict,
    server_record: dict,
    payload_record: dict,
    *,
    credentials: ApnaLiteCredentials | None = None,
    host_selector: Callable[[list[str]], str] = secrets.choice,
    host_key_sha256: str | None = None,
    known_hosts_files: tuple[str, ...] = (),
    transparent_dns: bool = False,
    dns_resolver: str = _DEFAULT_DNS,
    brand: str | None = None,
    user_agent: str | None = None,
) -> ApnaLiteProfile:
    """Map one SSH-family catalog pair to encrypted-profile-ready settings.

    The Android DEX confirms SSH host/port, HTTP payload, proxy host/port, SNI,
    tunnel type and UDPGW settings. The catalog's Pulled sentinel means use
    the corresponding selected server endpoint. Host pools are selected once
    and stored in the resulting profile to keep each connection deterministic.
    """
    if not isinstance(catalog, dict) or not isinstance(server_record, dict) or not isinstance(payload_record, dict):
        raise TypeError("catalog, server_record and payload_record must be dictionaries")
    if not callable(host_selector):
        raise TypeError("host_selector must be callable")

    category = server_record.get("category")
    if category not in _SSH_CATEGORIES or payload_record.get("category") != category:
        raise ApnaLiteProfileError("Selected server/payload pair is not an SSH-compatible category")
    method = payload_record.get("method")
    if method not in _SUPPORTED_METHODS:
        raise ApnaLiteProfileError(f"Unsupported APNA tunnel method: {method!r}")

    try:
        account = credentials or decode_apna_lite_catalog_credentials(catalog)
    except (ApnaLiteCatalogError, TypeError) as exc:
        raise ApnaLiteProfileError("APNA catalog credentials could not be decoded") from exc
    if not account.username or not account.password:
        raise ApnaLiteProfileError("APNA catalog account credentials are empty")

    server_host = _select(
        _host_pool(server_record.get("server_host"), "server_host"),
        host_selector,
        "server_host",
    )
    server_port = _port(server_record.get("server_port"), None, "server_port")
    ssl_port = _port(server_record.get("ssl_port"), server_port, "ssl_port")
    udp_port_value = server_record.get("server_udp_port")
    udpgw_port = None if udp_port_value in (None, "") else _port(
        udp_port_value, None, "server_udp_port"
    )
    udp_host = server_host if udpgw_port is not None else None

    payload_host_pool = _host_pool(payload_record.get("host"), "payload.host")
    selected_payload_host = (
        server_host
        if payload_host_pool == ["Pulled"]
        else _select(payload_host_pool, host_selector, "payload.host")
    )
    sslws = _catalog_bool(payload_record.get("sslws"), "payload.sslws")
    payload_port_raw = payload_record.get("port")
    fallback_port = ssl_port if sslws or method == "ssl" else server_port
    connect_port = _port(payload_port_raw, fallback_port, "payload.port")
    payload_text = payload_record.get("payload", "")
    if not isinstance(payload_text, str) or len(payload_text) > 64 * 1024:
        raise ApnaLiteProfileError("payload text is invalid or too large")

    sausage_pool = (
        _host_pool(payload_record["sausage"], "payload.sausage")
        if payload_record.get("sausage")
        else []
    )
    sni = (
        _select(sausage_pool, host_selector, "payload.sausage")
        if sausage_pool
        else (selected_payload_host if method == "http" and sslws else server_host)
    )

    if method == "direct":
        if payload_text or payload_host_pool != ["Pulled"] or payload_port_raw != "Pulled":
            raise ApnaLiteProfileError("direct SSH catalog entries must use the selected server endpoint without an HTTP payload")
        mode = PayloadSocketMode.DIRECT
        connect_host = server_host
        connect_port = server_port
        expected_statuses = (200,)
    elif method == "ssl":
        if payload_text:
            raise ApnaLiteProfileError("SSL-direct catalog entries must not contain an HTTP payload")
        mode = PayloadSocketMode.TLS_DIRECT
        connect_host = selected_payload_host
        connect_port = _port(payload_port_raw, ssl_port, "payload.port")
        expected_statuses = (200,)
    else:
        if not payload_text:
            raise ApnaLiteProfileError("HTTP catalog entries require a payload template")
        mode = PayloadSocketMode.TLS_HTTP_PROXY if sslws else PayloadSocketMode.HTTP_PROXY
        connect_host = selected_payload_host
        if "[brand]" in payload_text and brand is None:
            raise ApnaLiteProfileError("This payload requires an explicit [brand] substitution")
        expected_statuses = (
            (101,)
            if "upgrade: websocket" in payload_text.lower()
            else (200,)
        )

    server_name = server_record.get("server_name")
    payload_name = payload_record.get("friendly_name")
    if not isinstance(server_name, str) or not server_name.strip():
        server_name = "APNA server"
    if not isinstance(payload_name, str) or not payload_name.strip():
        payload_name = "APNA payload"
    profile_name = f"{server_name.strip()} - {payload_name.strip()}"[:128]
    profile = ConnectionProfile(
        profile_name or "APNA SSH",
        Transport.APNA_SSH,
        server_host,
        server_port,
    )
    ssh = ApnaSshConfig(
        ssh_host=server_host,
        ssh_port=server_port,
        username=account.username,
        password=account.password,
        known_hosts_files=known_hosts_files,
        host_key_sha256=host_key_sha256,
    )
    payload = PayloadSocketConfig(
        mode=mode,
        connect_host=connect_host,
        connect_port=connect_port,
        target_host=server_host,
        target_port=server_port,
        payload=payload_text,
        sni=sni if mode in {PayloadSocketMode.TLS_DIRECT, PayloadSocketMode.TLS_HTTP_PROXY} else None,
        cf_host=connect_host,
        brand=brand,
        user_agent=user_agent,
        expected_http_statuses=expected_statuses,
    )
    session_config = ApnaTunnelSessionConfig(
        ssh=ssh,
        payload=payload,
        udpgw_host=udp_host,
        udpgw_port=udpgw_port,
        transparent_dns=transparent_dns,
        dns_resolver=dns_resolver,
    )
    return ApnaLiteProfile(
        profile=profile,
        session_config=session_config,
        category=category,
        method=method,
        server_name=server_name,
        payload_name=payload_name,
    )
