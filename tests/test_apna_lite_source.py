"""Tests for the discovery-only APNA Lite catalog HTTP source."""
from __future__ import annotations

import base64
import json
import struct

import pytest

from apnawin.services.apna_lite_catalog import DELTA, MASK, _CATALOG_KEY, _mx, _words
from apnawin.services.apna_lite_source import (
    APNA_LITE_CATALOG_URL,
    ApnaLiteCatalogSource,
)


class _Response:
    def __init__(self, body: bytes, *, status: int = 200, headers=None) -> None:
        self.body = body
        self.status = status
        self.headers = headers or {"Content-Length": str(len(body))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class _Opener:
    def __init__(self, body: bytes, *, status: int = 200, headers=None) -> None:
        self.body = body
        self.status = status
        self.headers = headers
        self.request = None
        self.timeout = None

    def open(self, request, timeout: float):
        self.request = request
        self.timeout = timeout
        return _Response(self.body, status=self.status, headers=self.headers)


def _encrypted_catalog() -> bytes:
    document = {
        "Version": "synthetic",
        "Free_servers": [],
        "Payloads": [],
        "Username": "not-a-real-account",
        "Password": "not-a-real-password",
    }
    plaintext = json.dumps(document, separators=(",", ":")).encode()
    values = _words(plaintext) + [len(plaintext)]
    key = _words(_CATALOG_KEY.ljust(16, bytes([0])))
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
    return base64.b64encode(struct.pack("<" + "I" * len(values), *values))


def test_source_uses_reported_request_headers_and_finite_timeout() -> None:
    opener = _Opener(_encrypted_catalog())
    source = ApnaLiteCatalogSource(timeout_seconds=3.5, opener=opener)

    result = source.fetch_document()

    assert result["Version"] == "synthetic"
    assert opener.request.full_url == APNA_LITE_CATALOG_URL
    assert opener.request.get_header("User-agent") == "Dalvik/2.1.0"
    assert opener.request.get_header("Accept-encoding") == "identity"
    assert opener.timeout == 3.5


def test_safe_summary_does_not_expose_credentials_or_payloads() -> None:
    source = ApnaLiteCatalogSource(opener=_Opener(_encrypted_catalog()))

    summary = source.fetch_summary()

    assert summary == {
        "version": "synthetic",
        "free_servers": 0,
        "premium_servers": 0,
        "vip_servers": 0,
        "private_servers": 0,
        "payloads": 0,
    }
    assert "Username" not in summary
    assert "Password" not in summary


def test_rejects_empty_or_oversized_response() -> None:
    source = ApnaLiteCatalogSource(opener=_Opener(b""))
    with pytest.raises(ValueError, match="size"):
        source.fetch_document()


def test_rejects_oversized_response() -> None:
    from apnawin.services.apna_lite_catalog import MAX_INPUT_BYTES

    source = ApnaLiteCatalogSource(opener=_Opener(b"A" * (MAX_INPUT_BYTES + 1)))
    with pytest.raises(ValueError, match="size"):
        source.fetch_document()


def test_rejects_partial_http_response() -> None:
    source = ApnaLiteCatalogSource(
        opener=_Opener(_encrypted_catalog(), status=206)
    )
    with pytest.raises(ValueError, match="status"):
        source.fetch_document()


def test_rejects_compressed_response_despite_identity_request() -> None:
    source = ApnaLiteCatalogSource(
        opener=_Opener(
            _encrypted_catalog(),
            headers={
                "Content-Length": str(len(_encrypted_catalog())),
                "Content-Encoding": "gzip",
            },
        )
    )
    with pytest.raises(ValueError, match="encoding"):
        source.fetch_document()


def test_rejects_truncated_content_length() -> None:
    body = _encrypted_catalog()
    source = ApnaLiteCatalogSource(
        opener=_Opener(
            body[:-1],
            headers={"Content-Length": str(len(body))},
        )
    )
    with pytest.raises(ValueError, match="truncated"):
        source.fetch_document()


@pytest.mark.parametrize("timeout", [0, float("inf"), float("nan"), True])
def test_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        ApnaLiteCatalogSource(timeout_seconds=timeout)
