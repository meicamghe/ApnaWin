from __future__ import annotations

import base64
import struct

import pytest

from apnawin.engines.apna_payload_socket import PayloadSocketMode
from apnawin.services.apna_lite_catalog import DELTA, MASK, _CATALOG_KEY, _mx, _words
from apnawin.services.apna_lite_profile_mapper import (
    ApnaLiteProfileError,
    build_apna_lite_ssh_profile,
    list_apna_lite_ssh_payloads,
    list_apna_lite_ssh_servers,
)


def _encrypt_xxtea(plaintext: bytes) -> bytes:
    """Test-only XXTEA encoder for synthetic catalog credentials."""
    values = _words(plaintext) + [len(plaintext)]
    key = _words(_CATALOG_KEY.ljust(16, b"\0"))
    last = len(values) - 1
    rounds = 6 + 52 // len(values)
    total = 0
    z = values[last]
    while rounds:
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for index in range(last):
            y = values[index + 1]
            values[index] = (values[index] + _mx(total, y, z, index, e, key)) & MASK
            z = values[index]
        y = values[0]
        values[last] = (values[last] + _mx(total, y, z, last, e, key)) & MASK
        z = values[last]
        rounds -= 1
    return struct.pack("<" + "I" * len(values), *values)


def _catalog():
    return {
        "Username": base64.b64encode(_encrypt_xxtea(b"synthetic-user")).decode(),
        "Password": base64.b64encode(_encrypt_xxtea(b"synthetic-password")).decode(),
    }


def _server(category="ocsws"):
    return {
        "server_name": "MASTER SSH",
        "server_host": "ssh-a.example.test;ssh-b.example.test",
        "server_port": "1194",
        "server_udp_port": "53",
        "ssl_port": "443",
        "category": category,
    }


def _payload(method="http", sslws="false", host="front-a.example.test;front-b.example.test", port="80", template=None):
    if template is None:
        template = (
            "GET / HTTP/1.1[crlf]Host: [cf][crlf]"
            "X-Online-Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
        )
    return {
        "friendly_name": "TEST WEBSOCKET",
        "category": "ocsws",
        "method": method,
        "sslws": sslws,
        "host": host,
        "port": port,
        "payload": template,
        "sausage": "",
    }


def _first(items):
    return items[0]


def test_maps_plain_http_websocket_to_ssh_and_udpgw():
    mapped = build_apna_lite_ssh_profile(
        _catalog(), _server(), _payload(), host_selector=_first
    )
    assert mapped.profile.transport.value == "apna_ssh"
    assert mapped.profile.endpoint_host == "ssh-a.example.test"
    assert mapped.profile.endpoint_port == 1194
    assert mapped.session_config.ssh.username == "synthetic-user"
    assert mapped.session_config.payload.mode is PayloadSocketMode.HTTP_PROXY
    assert mapped.session_config.payload.connect_host == "front-a.example.test"
    assert mapped.session_config.payload.connect_port == 80
    assert mapped.session_config.payload.target_host == "ssh-a.example.test"
    assert mapped.session_config.payload.target_port == 1194
    assert mapped.session_config.payload.cf_host == "front-a.example.test"
    assert mapped.session_config.payload.expected_http_statuses == (200, 101)
    assert mapped.session_config.udpgw_host == "ssh-a.example.test"
    assert mapped.session_config.udpgw_port == 53


def test_maps_tls_websocket_payload_to_tls_http_proxy():
    mapped = build_apna_lite_ssh_profile(
        _catalog(),
        _server(),
        _payload(sslws="true", port="443"),
        host_selector=_first,
    )
    assert mapped.session_config.payload.mode is PayloadSocketMode.TLS_HTTP_PROXY
    assert mapped.session_config.payload.connect_port == 443
    assert mapped.session_config.payload.sni == "front-a.example.test"


def test_maps_ssl_direct_payload_to_server_ssl_port_and_sni():
    payload = _payload(
        method="ssl",
        sslws="false",
        host="Pulled",
        port="Pulled",
        template="",
    )
    payload["sausage"] = "amtun.example.test"
    mapped = build_apna_lite_ssh_profile(
        _catalog(), _server(), payload, host_selector=_first
    )
    assert mapped.session_config.payload.mode is PayloadSocketMode.TLS_DIRECT
    assert mapped.session_config.payload.connect_host == "ssh-a.example.test"
    assert mapped.session_config.payload.connect_port == 443
    assert mapped.session_config.payload.sni == "amtun.example.test"


def test_maps_direct_ssh_without_payload():
    payload = _payload(method="direct", host="Pulled", port="Pulled", template="")
    mapped = build_apna_lite_ssh_profile(
        _catalog(), _server(), payload, host_selector=_first
    )
    assert mapped.session_config.payload.mode is PayloadSocketMode.DIRECT
    assert mapped.session_config.payload.connect_host == "ssh-a.example.test"
    assert mapped.session_config.payload.connect_port == 1194


def test_rejects_non_ssh_categories_and_methods():
    with pytest.raises(ApnaLiteProfileError, match="SSH-compatible"):
        build_apna_lite_ssh_profile(
            _catalog(), _server("ocsudp"), _payload(), host_selector=_first
        )
    udp = _payload(method="udp")
    with pytest.raises(ApnaLiteProfileError, match="Unsupported"):
        build_apna_lite_ssh_profile(_catalog(), _server(), udp, host_selector=_first)


def test_rejects_category_mismatch_and_unresolved_brand_token():
    payload = _payload(template="GET /[brand] HTTP/1.1[crlf][crlf]")
    with pytest.raises(ApnaLiteProfileError, match="brand"):
        build_apna_lite_ssh_profile(
            _catalog(), _server(), payload, host_selector=_first
        )
    with pytest.raises(ApnaLiteProfileError, match="category"):
        build_apna_lite_ssh_profile(
            _catalog(), _server(), _payload().copy() | {"category": "ocscf"},
            host_selector=_first,
        )


def test_rejects_invalid_host_selector_result():
    with pytest.raises(ApnaLiteProfileError, match="outside the pool"):
        build_apna_lite_ssh_profile(
            _catalog(), _server(), _payload(), host_selector=lambda pool: "evil.example.test"
        )


def test_allows_explicit_host_key_pin_and_dns_override():
    mapped = build_apna_lite_ssh_profile(
        _catalog(),
        _server(),
        _payload(),
        host_selector=_first,
        host_key_sha256="SHA256:" + "A" * 43,
        transparent_dns=True,
        dns_resolver="9.9.9.9",
        brand="ApnaWin",
    )
    assert mapped.session_config.ssh.host_key_sha256 == "SHA256:" + "A" * 43
    assert mapped.session_config.transparent_dns is True
    assert mapped.session_config.dns_resolver == "9.9.9.9"



def test_catalog_choice_helpers_filter_out_non_ssh_protocols():
    catalog = {
        "Free_servers": [
            _server(),
            _server("ocsudp"),
        ],
        "Payloads": [
            _payload(),
            _payload(method="udp"),
            _payload().copy() | {"category": "ocsudp"},
        ],
    }
    servers = list_apna_lite_ssh_servers(catalog)
    payloads = list_apna_lite_ssh_payloads(catalog, "ocsws")
    assert len(servers) == 1
    assert len(payloads) == 1
    assert payloads[0]["method"] == "http"
    assert list_apna_lite_ssh_payloads(catalog, "ocsudp") == []



def test_websocket_payload_accepts_both_http_connect_and_upgrade_success():
    mapped = build_apna_lite_ssh_profile(
        _catalog(), _server(), _payload(), host_selector=_first
    )
    assert mapped.session_config.payload.expected_http_statuses == (200, 101)


def test_non_websocket_http_payload_requires_connect_success_only():
    payload = _payload(template="CONNECT [host_port] [protocol][crlf][crlf]")
    mapped = build_apna_lite_ssh_profile(
        _catalog(), _server(), payload, host_selector=_first
    )
    assert mapped.session_config.payload.expected_http_statuses == (200,)


def test_lists_ssh_servers_from_every_catalog_tier_without_mutating_records():
    free = _server()
    premium = _server().copy() | {"server_name": "PREMIUM SSH"}
    vip = _server().copy() | {"server_name": "VIP SSH"}
    private = _server().copy() | {"server_name": "PRIVATE SSH"}
    catalog = {
        "Free_servers": [free, _server("ocsudp")],
        "Premium_servers": [premium],
        "Vip_servers": [vip],
        "Private_servers": [private],
    }

    servers = list_apna_lite_ssh_servers(catalog)

    assert [item["server_name"] for item in servers] == [
        "MASTER SSH", "PREMIUM SSH", "VIP SSH", "PRIVATE SSH"
    ]
    assert [item["_catalog_section"] for item in servers] == [
        "Free_servers", "Premium_servers", "Vip_servers", "Private_servers"
    ]
    assert "_catalog_section" not in free
    assert len(servers) == 4

def test_ssh_server_without_udp_gateway_remains_importable_for_tcp():
    server = _server()
    server.pop("server_udp_port")
    mapped = build_apna_lite_ssh_profile(_catalog(), server, _payload(), host_selector=_first)
    assert mapped.session_config.udpgw_host is None
    assert mapped.session_config.udpgw_port is None
    assert mapped.session_config.transparent_dns is False




def test_maps_only_an_explicit_provider_ca_bundle_path():
    mapped = build_apna_lite_ssh_profile(
        _catalog(),
        _server(),
        _payload(sslws="true", port="443"),
        host_selector=_first,
        ca_bundle_file="trusted-provider-ca.pem",
    )
    assert mapped.session_config.payload.ca_bundle_file == "trusted-provider-ca.pem"
