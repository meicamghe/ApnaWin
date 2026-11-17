"""Resilient HTTPS source for the APNA TUNNEL LITE live catalog.

The request reproduces the app's Dalvik User-Agent and identity encoding. If
the server truncates a response that declared Content-Length, bounded HTTP
Range requests resume only the missing bytes. TLS verification stays enabled;
redirects, compression, oversized bodies and inconsistent ranges are rejected.
"""
from __future__ import annotations

from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
import math
import re
import time
from typing import Callable
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from apnawin.services.apna_lite_catalog import (
    MAX_INPUT_BYTES,
    decode_apna_lite_catalog,
    summarize_apna_lite_catalog,
)

APNA_LITE_CATALOG_URL = (
    "https://paperonboard.com/updater/6aa1acd5d8b2b25e6884eae4483e57"
)
_USER_AGENT = "Dalvik/2.1.0"
_RANGE_CHUNK_BYTES = 64 * 1024
_CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+)", re.IGNORECASE)


class _SafeHttpsRedirects(HTTPRedirectHandler):
    """Follow bounded HTTPS redirects without permitting TLS downgrade or userinfo."""

    max_redirections = 5
    max_repeats = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source = urlsplit(req.full_url)
        target = urlsplit(newurl)
        if (
            source.scheme.lower() != "https"
            or target.scheme.lower() != "https"
            or not target.hostname
            or target.username is not None
            or target.password is not None
            or target.port not in (None, 443)
            or target.fragment
        ):
            raise ValueError("APNA catalog redirect rejected: HTTPS destination required")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ApnaLiteCatalogSource:
    """Fetch, decode and summarize the live catalog without persisting it."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        retry_attempts: int = 3,
        opener=None,
        sleep: Callable[[float], object] = time.sleep,
        progress_callback: Callable[[int, int | None], object] | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")
        if (
            isinstance(retry_attempts, bool)
            or not isinstance(retry_attempts, int)
            or not 1 <= retry_attempts <= 5
        ):
            raise ValueError("retry_attempts must be between 1 and 5")
        if not callable(sleep):
            raise TypeError("sleep must be callable")
        if progress_callback is not None and not callable(progress_callback):
            raise TypeError("progress_callback must be callable")
        self.timeout_seconds = float(timeout_seconds)
        self.retry_attempts = retry_attempts
        self._opener = opener or build_opener(_SafeHttpsRedirects())
        self._sleep = sleep
        self._progress_callback = progress_callback

    def _report_progress(self, received: int, total: int | None) -> None:
        if self._progress_callback is not None:
            self._progress_callback(received, total)

    @staticmethod
    def _headers() -> dict[str, str]:
        return {
            "User-Agent": _USER_AGENT,
            "Accept-Encoding": "identity",
        }

    @staticmethod
    def _content_length(headers) -> int | None:
        declared = headers.get("Content-Length")
        if declared is None:
            return None
        try:
            length = int(declared)
        except (TypeError, ValueError) as exc:
            raise ValueError("APNA Lite catalog content length is invalid") from exc
        if length < 0 or length > MAX_INPUT_BYTES:
            raise ValueError("APNA Lite catalog response size is invalid")
        return length

    @staticmethod
    def _validate_encoding(headers) -> None:
        encoding = headers.get("Content-Encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            raise ValueError("APNA Lite catalog content encoding is unsupported")

    def _read_initial_response(self) -> tuple[bytes, int | None]:
        request = Request(
            APNA_LITE_CATALOG_URL,
            headers=self._headers(),
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise ValueError("APNA Lite catalog HTTP status is invalid")
                self._validate_encoding(response.headers)
                declared = self._content_length(response.headers)
                raw_buffer = bytearray()
                interrupted = False
                self._report_progress(0, declared)
                while len(raw_buffer) <= MAX_INPUT_BYTES:
                    try:
                        chunk = response.read(
                            min(_RANGE_CHUNK_BYTES, MAX_INPUT_BYTES + 1 - len(raw_buffer))
                        )
                    except IncompleteRead as exc:
                        raw_buffer.extend(exc.partial)
                        self._report_progress(len(raw_buffer), declared)
                        interrupted = True
                        break
                    except (URLError, OSError):
                        # Keep bytes already received. If Content-Length is known,
                        # fetch_bytes() can continue from this exact offset with
                        # validated Range requests instead of restarting the GET.
                        if declared is None:
                            raise
                        interrupted = True
                        break
                    if not chunk:
                        break
                    raw_buffer.extend(chunk)
                    self._report_progress(len(raw_buffer), declared)
                    if declared is not None and len(raw_buffer) >= declared:
                        break
                raw = bytes(raw_buffer)
        except HTTPError as exc:
            raise ValueError(
                f"APNA Lite catalog HTTP request failed (status {exc.code})"
            ) from None
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("APNA Lite catalog response size is invalid")
        if declared is not None and len(raw) > declared:
            raise ValueError("APNA Lite catalog response exceeds Content-Length")
        return raw, declared

    def _resume_ranges(self, partial: bytes, total: int) -> bytes:
        if not 0 <= len(partial) < total <= MAX_INPUT_BYTES:
            raise ValueError("APNA Lite catalog range resume bounds are invalid")
        result = bytearray(partial)
        while len(result) < total:
            start = len(result)
            requested_end = min(start + _RANGE_CHUNK_BYTES - 1, total - 1)
            last_error: Exception | None = None
            for attempt in range(self.retry_attempts):
                headers = self._headers()
                headers["Range"] = f"bytes={start}-{requested_end}"
                request = Request(APNA_LITE_CATALOG_URL, headers=headers, method="GET")
                try:
                    with self._opener.open(request, timeout=self.timeout_seconds) as response:
                        if response.status != 206:
                            raise ValueError("APNA Lite catalog range response status is invalid")
                        self._validate_encoding(response.headers)
                        content_range = response.headers.get("Content-Range", "")
                        match = _CONTENT_RANGE.fullmatch(content_range.strip())
                        if match is None:
                            raise ValueError("APNA Lite catalog Content-Range is invalid")
                        range_start, range_end, range_total = map(int, match.groups())
                        if (
                            range_start != start
                            or range_total != total
                            or range_end < range_start
                            or range_end > requested_end
                        ):
                            raise ValueError("APNA Lite catalog Content-Range does not match request")
                        expected = range_end - range_start + 1
                        declared = self._content_length(response.headers)
                        if declared is not None and declared != expected:
                            raise ValueError("APNA Lite catalog range Content-Length is invalid")
                        try:
                            chunk = response.read(expected + 1)
                        except IncompleteRead as exc:
                            chunk = exc.partial
                    if not chunk or len(chunk) > expected:
                        raise ValueError("APNA Lite catalog range body size is invalid")
                    result.extend(chunk)
                    self._report_progress(len(result), total)
                    last_error = None
                    break
                except (HTTPError, URLError, OSError, IncompleteRead) as exc:
                    last_error = exc
                    if attempt + 1 < self.retry_attempts:
                        self._sleep(0.5 * (attempt + 1))
                if last_error is None:
                    continue
            if last_error is not None:
                raise ValueError("APNA Lite catalog range resume failed") from None
            if len(result) > total:
                raise ValueError("APNA Lite catalog range assembly exceeded declared size")
        if len(result) != total:
            raise ValueError("APNA Lite catalog range assembly is incomplete")
        return bytes(result)

    def fetch_bytes(self) -> bytes:
        """Fetch the encrypted catalog with bounded retries and range resumption."""
        last_error: Exception | None = None
        for attempt in range(self.retry_attempts):
            try:
                raw, declared = self._read_initial_response()
                if declared is not None and len(raw) != declared:
                    if len(raw) < declared:
                        return self._resume_ranges(raw, declared)
                    raise ValueError("APNA Lite catalog response length is inconsistent")
                if not raw:
                    raise ValueError("APNA Lite catalog response is empty")
                self._report_progress(len(raw), len(raw))
                return raw
            except (HTTPError, URLError, OSError, IncompleteRead) as exc:
                last_error = exc
                if attempt + 1 < self.retry_attempts:
                    self._sleep(0.5 * (attempt + 1))
            except ValueError as exc:
                # A declared truncation is resumed in the same attempt. Other
                # protocol/schema errors are not hidden by blind retries.
                last_error = exc
                if "HTTP request failed (status 5" in str(exc) and attempt + 1 < self.retry_attempts:
                    self._sleep(0.5 * (attempt + 1))
                else:
                    raise
        raise ValueError("APNA Lite catalog download failed after bounded retries") from None

    def fetch_document(self) -> dict:
        """Fetch and decode one catalog; caller must treat it as secret-bearing."""
        return decode_apna_lite_catalog(self.fetch_bytes())

    def fetch_summary(self) -> dict[str, int | str]:
        """Return only version and record counts; never expose credentials or payloads."""
        return summarize_apna_lite_catalog(self.fetch_document())
