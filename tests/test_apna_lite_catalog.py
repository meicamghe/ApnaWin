"""Synthetic tests for the APNA Lite catalog decoder.

Fixtures intentionally contain no real provider credentials or server endpoints.
"""
from __future__ import annotations

import base64
import json
import struct
import zipfile
from io import BytesIO

import pytest

from apnawin.services.apna_lite_catalog import (
    DELTA,
    MASK,
    ApnaLiteCatalogError,
    _CATALOG_KEY,
    decode_apna_lite_apk_catalog,
    decode_apna_lite_catalog_credential,
    decode_apna_lite_catalog_credentials,
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



def test_decode_accepts_valid_unpadded_base64_catalog() -> None:
    encoded = _encrypted(_document()).rstrip(b"=")
    decoded = decode_apna_lite_catalog(encoded)
    assert decoded["Version"] == "test-1"


def test_decode_reports_invalid_xxtea_length_after_base64_padding() -> None:
    # Valid Base64, but decoded bytes cannot be an XXTEA block envelope.
    with pytest.raises(ApnaLiteCatalogError, match="XXTEA data"):
        decode_apna_lite_catalog(base64.b64encode(b"1234567890").rstrip(b"="))

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



def test_decode_apk_embedded_catalog_asset() -> None:
    apk = BytesIO()
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/janur.json", _encrypted(_document()))
        archive.writestr("classes.dex", b"synthetic dex")
    decoded = decode_apna_lite_apk_catalog(apk.getvalue())
    assert decoded["Version"] == "test-1"
    assert len(decoded["Free_servers"]) == 1


def test_apk_import_rejects_missing_or_duplicate_catalog_asset() -> None:
    missing = BytesIO()
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("classes.dex", b"synthetic")
    with pytest.raises(ApnaLiteCatalogError, match="exactly one"):
        decode_apna_lite_apk_catalog(missing.getvalue())

    duplicate = BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("assets/janur.json", _encrypted(_document()))
        archive.writestr("assets/janur.json", _encrypted(_document()))
    with pytest.raises(ApnaLiteCatalogError, match="exactly one"):
        decode_apna_lite_apk_catalog(duplicate.getvalue())


def test_decode_catalog_credentials_redacts_repr() -> None:
    document = _document()
    document["Username"] = base64.b64encode(_encrypt_xxtea(b"synthetic-user")).decode()
    document["Password"] = base64.b64encode(_encrypt_xxtea(b"synthetic-password")).decode()
    credentials = decode_apna_lite_catalog_credentials(document)
    assert credentials.username == "synthetic-user"
    assert credentials.password == "synthetic-password"
    assert "synthetic-user" not in repr(credentials)
    assert "synthetic-password" not in repr(credentials)


def test_decode_catalog_credential_rejects_invalid_encoding() -> None:
    with pytest.raises(ApnaLiteCatalogError, match="encoding"):
        decode_apna_lite_catalog_credential("not-base64!")
