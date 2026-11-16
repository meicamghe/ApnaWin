from __future__ import annotations

import base64

import pytest

from apnawin.engines.apna_payload_socket import PayloadSocketMode
from apnawin.services.apna_lite_catalog import _encrypt_xxtea
from apnawin.services.apna_lite_profile_mapper import (
    ApnaLiteProfileError,
    build_apna_lite_ssh_profile,
)


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
    assert mapped.session_config.payload.expected_http_statuses == (101,)
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
