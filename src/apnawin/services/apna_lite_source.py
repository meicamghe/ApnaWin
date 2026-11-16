"""Discovery-only HTTPS source for APNA TUNNEL LITE catalogs.

This module deliberately stops at decoding and safe metadata extraction. It
does not convert APNA records into connection profiles or select a tunnel
engine: those semantics must be recovered from the Android runtime first.
"""
from __future__ import annotations

from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from apnawin.services.apna_lite_catalog import (
    MAX_INPUT_BYTES,
    decode_apna_lite_catalog,
    summarize_apna_lite_catalog,
)

APNA_LITE_CATALOG_URL = (
    "https://paperonboard.com/updater/6aa1acd5d8b2b25e6884eae4483e57"
)


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ApnaLiteCatalogSource:
    """Fetch, decode and summarize the APNA Lite catalog without persisting it.

    The URL and headers are based on third-party APK research and remain
    subject to live verification. TLS certificate validation is left enabled.
    """

    def __init__(self, *, timeout_seconds: float = 10.0, opener=None) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive number")
        self.timeout_seconds = float(timeout_seconds)
        self._opener = opener or build_opener(_RejectRedirects())

    def fetch_document(self) -> dict:
        """Fetch and decode one bounded catalog; caller must treat it as secret-bearing."""
        request = Request(
            APNA_LITE_CATALOG_URL,
            headers={
                "User-Agent": "Dalvik/2.1.0",
                "Accept-Encoding": "identity",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(MAX_INPUT_BYTES + 1)
        except HTTPError:
            # Never expose response bodies or server-supplied error text.
            raise

        if not raw or len(raw) > MAX_INPUT_BYTES:
            raise ValueError("APNA Lite catalog response size is invalid")
        return decode_apna_lite_catalog(raw)

    def fetch_summary(self) -> dict[str, int | str]:
        """Return only version and record counts; never expose credentials or payloads."""
        return summarize_apna_lite_catalog(self.fetch_document())
