"""Bounded HTTPS transport for normalized remote catalog documents.

This adapter accepts an explicitly configured URL. It does not discover or
assume any APNA endpoint, authentication scheme, or upstream response format.
"""

from __future__ import annotations

import math
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from apnawin.domain.remote_catalog import MAX_REMOTE_CATALOG_BYTES


class _NoRedirectHandler(HTTPRedirectHandler):
    """Reject redirects until a provider has an explicit redirect policy."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpsCatalogProvider:
    """Fetch a bounded catalog document over certificate-validated HTTPS."""

    def __init__(self, url: str, *, timeout_seconds: float = 10.0) -> None:
        if not isinstance(url, str) or not url or len(url) > 2048:
            raise ValueError("url must be a non-empty string of at most 2048 characters")
        if any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in url):
            raise ValueError("url must not contain whitespace, controls, or backslashes")
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("url is malformed") from exc
        if (
            parsed.scheme.lower() != "https"
            or not hostname
            or not hostname.isascii()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("url must be an HTTPS URL without credentials or a fragment")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("url port must be between 1 and 65535")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")

        self.url = url
        self.timeout_seconds = float(timeout_seconds)
        self._opener = build_opener(_NoRedirectHandler())

    def fetch_catalog(self) -> bytes:
        """Return at most the configured catalog limit, rejecting redirects and oversize data."""
        request = Request(
            self.url,
            headers={
                "Accept": "application/json",
                "User-Agent": "ApnaWin/0.1",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                document = response.read(MAX_REMOTE_CATALOG_BYTES + 1)
        except HTTPError:
            # Do not expose response bodies or server-provided error text.
            raise

        if len(document) > MAX_REMOTE_CATALOG_BYTES:
            raise ValueError("Remote catalog exceeds the document-size limit")
        return document
