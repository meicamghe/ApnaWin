"""Synthetic tests for the APNA Lite catalog decoder.

Fixtures intentionally contain no real provider credentials or server endpoints.
"""
from __future__ import annotations

import base64
import json
import struct

import pytest

from apnawin.services.apna_lite_catalog import (
    DELTA,
    MASK,
    ApnaLiteCatalogError,
    _CATALOG_KEY,
    _mx,
    _words,
    decode_apna_lite_catalog,
    summarize_apna_lite_catalog,
)


def _encrypt_xxtea(plaintext: bytes) -> bytes:
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


def _server() -> dict[str, str]:
    return {
        "server_name": "Synthetic test server",
        "server_host": "vpn.invalid",
        "server_port": "",
        "server_udp_port": "",
        "ssl_port": "",
        "category": "ocsws",
        "username": "",
        "password": "",
        "custom_cert": "",
    }


def _payload() -> dict[str, str]:
    return {
        "friendly_name": "Synthetic test payload",
        "category": "ocsws",
        "host": "example.invalid",
        "port": "80",
        "method": "http",
        "payload": "GET / HTTP/1.1[crlf][crlf]",
        "query": "",
        "sslws": "false",
        "sausage": "",
        "dothost": "",
        "message": "",
    }


def _encrypted(document: dict[str, object]) -> bytes:
    plaintext = json.dumps(document, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(_encrypt_xxtea(plaintext))


def _document() -> dict[str, object]:
    return {
        "Version": "test-1",
        "Free_servers": [_server()],
        "Premium_servers": [],
        "Vip_servers": [],
        "Private_servers": [],
        "Payloads": [_payload()],
        "Username": "synthetic-user",
        "Password": "synthetic-password",
    }


def test_decode_synthetic_catalog_and_safe_summary() -> None:
    encoded = _encrypted(_document())
    encoded = b" \n".join(encoded[index : index + 24] for index in range(0, len(encoded), 24))

    decoded = decode_apna_lite_catalog(encoded)

    assert decoded["Version"] == "test-1"
    assert decoded["Free_servers"][0]["server_name"] == "Synthetic test server"
    assert decoded["Payloads"][0]["friendly_name"] == "Synthetic test payload"
    summary = summarize_apna_lite_catalog(decoded)
    assert summary == {
        "version": "test-1",
        "free_servers": 1,
        "premium_servers": 0,
        "vip_servers": 0,
        "private_servers": 0,
        "payloads": 1,
    }
    assert "Username" not in summary
    assert "Password" not in summary


def test_rejects_invalid_base64() -> None:
    with pytest.raises(ApnaLiteCatalogError, match="Base64"):
        decode_apna_lite_catalog(b"not base64!")


def test_rejects_duplicate_json_keys() -> None:
    plaintext = (
        b'{"Version":"one","Version":"two","Free_servers":[],"Payloads":[]}'
    )
    encoded = base64.b64encode(_encrypt_xxtea(plaintext))
    with pytest.raises(ApnaLiteCatalogError, match="Duplicate JSON key"):
        decode_apna_lite_catalog(encoded)


def test_rejects_wrong_root_schema() -> None:
    encoded = _encrypted({"Version": "test-1", "Free_servers": []})
    with pytest.raises(ApnaLiteCatalogError, match="Payloads"):
        decode_apna_lite_catalog(encoded)


def test_rejects_missing_server_fields() -> None:
    document = _document()
    document["Free_servers"] = [{"server_name": "incomplete"}]
    with pytest.raises(ApnaLiteCatalogError, match="missing required fields"):
        decode_apna_lite_catalog(_encrypted(document))


def test_rejects_oversized_input() -> None:
    with pytest.raises(ApnaLiteCatalogError, match="size"):
        decode_apna_lite_catalog(b"A" * (8 * 1024 * 1024 + 1))


def test_rejects_non_bytes_input() -> None:
    with pytest.raises(TypeError, match="bytes"):
        decode_apna_lite_catalog("not bytes")  # type: ignore[arg-type]
