"""Tests for the discovery-only APNA Lite catalog HTTP source."""
from __future__ import annotations

import base64
import json
import struct
from urllib.error import URLError

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
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        chunk = self.body[self.offset : self.offset + limit]
        self.offset += len(chunk)
        return chunk


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


class _SequenceOpener:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout: float):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


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


def test_source_reports_download_progress_with_total_bytes() -> None:
    body = _encrypted_catalog()
    updates: list[tuple[int, int | None]] = []
    source = ApnaLiteCatalogSource(
        opener=_Opener(body),
        progress_callback=lambda received, total: updates.append((received, total)),
    )

    source.fetch_document()

    assert updates[0] == (0, len(body))
    assert updates[-1] == (len(body), len(body))
    assert all(received <= total for received, total in updates if total is not None)


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
    with pytest.raises(ValueError, match="empty|size"):
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
    with pytest.raises(ValueError, match="full download restart was incomplete"):
        source.fetch_document()


@pytest.mark.parametrize("timeout", [0, float("inf"), float("nan"), True])
def test_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        ApnaLiteCatalogSource(timeout_seconds=timeout)


def test_source_resumes_a_truncated_catalog_with_bounded_http_ranges() -> None:
    body = _encrypted_catalog()
    first_end = 17
    second_end = 31
    opener = _SequenceOpener(
        [
            _Response(body[:first_end], headers={"Content-Length": str(len(body))}),
            _Response(
                body[first_end:second_end],
                status=206,
                headers={
                    "Content-Length": str(second_end - first_end),
                    "Content-Range": f"bytes {first_end}-{second_end - 1}/{len(body)}",
                },
            ),
            _Response(
                body[second_end:],
                status=206,
                headers={
                    "Content-Length": str(len(body) - second_end),
                    "Content-Range": f"bytes {second_end}-{len(body) - 1}/{len(body)}",
                },
            ),
        ]
    )
    source = ApnaLiteCatalogSource(opener=opener, sleep=lambda _seconds: None)

    document = source.fetch_document()

    assert document["Version"] == "synthetic"
    assert len(opener.requests) == 3
    assert opener.requests[1][0].get_header("Range") == f"bytes={first_end}-{len(body) - 1}"
    assert opener.requests[2][0].get_header("Range") == f"bytes={second_end}-{len(body) - 1}"


def test_source_retries_transient_network_errors_before_decoding() -> None:
    body = _encrypted_catalog()
    opener = _SequenceOpener(
        [
            URLError("temporary network failure"),
            _Response(body),
        ]
    )
    source = ApnaLiteCatalogSource(opener=opener, sleep=lambda _seconds: None)

    assert source.fetch_document()["Version"] == "synthetic"
    assert len(opener.requests) == 2


def test_source_rejects_mismatched_content_range() -> None:
    body = _encrypted_catalog()
    opener = _SequenceOpener(
        [
            _Response(body[:10], headers={"Content-Length": str(len(body))}),
            _Response(
                body[10:],
                status=206,
                headers={
                    "Content-Length": str(len(body) - 10),
                    "Content-Range": f"bytes 0-{len(body) - 11}/{len(body)}",
                },
            ),
        ]
    )
    source = ApnaLiteCatalogSource(opener=opener, sleep=lambda _seconds: None)

    with pytest.raises(ValueError, match="Content-Range"):
        source.fetch_document()



class _InterruptingResponse(_Response):
    def __init__(self, body: bytes, *, interrupt_after: int, headers=None) -> None:
        super().__init__(body, headers=headers)
        self.interrupt_after = interrupt_after
        self.interrupted = False

    def read(self, limit: int) -> bytes:
        if not self.interrupted and self.offset >= self.interrupt_after:
            self.interrupted = True
            raise OSError("connection reset during response body")
        allowed = limit
        if not self.interrupted:
            allowed = min(limit, self.interrupt_after - self.offset)
        return super().read(allowed)


def test_source_resumes_after_socket_reset_without_losing_received_bytes() -> None:
    body = _encrypted_catalog()
    received = 19
    opener = _SequenceOpener(
        [
            _InterruptingResponse(
                body,
                interrupt_after=received,
                headers={"Content-Length": str(len(body))},
            ),
            _Response(
                body[received:],
                status=206,
                headers={
                    "Content-Length": str(len(body) - received),
                    "Content-Range": f"bytes {received}-{len(body) - 1}/{len(body)}",
                },
            ),
        ]
    )
    source = ApnaLiteCatalogSource(opener=opener, sleep=lambda _seconds: None)

    document = source.fetch_document()

    assert document["Version"] == "synthetic"
    assert len(opener.requests) == 2
    assert opener.requests[1][0].get_header("Range") == f"bytes={received}-{len(body) - 1}"



def test_https_redirect_handler_allows_https_and_rejects_downgrade():
    from urllib.request import Request
    from apnawin.services.apna_lite_source import _SafeHttpsRedirects

    handler = _SafeHttpsRedirects()
    request = Request("https://paperonboard.com/updater/catalog")
    redirected = handler.redirect_request(
        request, None, 301, "Moved Permanently", {}, "https://cdn.example.test/catalog"
    )
    assert redirected.full_url == "https://cdn.example.test/catalog"

    with pytest.raises(ValueError, match="HTTPS destination required"):
        handler.redirect_request(
            request, None, 301, "Moved Permanently", {}, "http://cdn.example.test/catalog"
        )

    with pytest.raises(ValueError, match="HTTPS destination required"):
        handler.redirect_request(
            request, None, 301, "Moved Permanently", {}, "https://user:pass@cdn.example.test/catalog"
        )


def test_source_restarts_full_download_when_server_ignores_range() -> None:
    body = _encrypted_catalog()
    first = _Response(body[:19], headers={"Content-Length": str(len(body))})
    range_ignored = _Response(body, status=200)
    restarted_full = _Response(body)
    opener = _SequenceOpener([first, range_ignored, restarted_full])
    source = ApnaLiteCatalogSource(opener=opener, sleep=lambda _seconds: None)

    assert source.fetch_document()["Version"] == "synthetic"
    assert len(opener.requests) == 3
    assert opener.requests[1][0].get_header("Range") == f"bytes=19-{len(body) - 1}"
    assert opener.requests[2][0].get_header("Range") is None



def test_source_restarts_clean_download_when_range_resume_network_retries_fail() -> None:
    body = _encrypted_catalog()
    received = 19
    opener = _SequenceOpener(
        [
            _Response(body[:received], headers={"Content-Length": str(len(body))}),
            URLError("range request connection reset"),
            URLError("range request connection reset"),
            URLError("range request connection reset"),
            _Response(body),
        ]
    )
    source = ApnaLiteCatalogSource(opener=opener, sleep=lambda _seconds: None)

    document = source.fetch_document()

    assert document["Version"] == "synthetic"
    assert len(opener.requests) == 5
    assert opener.requests[1][0].get_header("Range") == f"bytes={received}-{len(body) - 1}"
    assert opener.requests[4][0].get_header("Range") is None
