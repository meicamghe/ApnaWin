from urllib.error import HTTPError

import pytest

from apnawin.domain.remote_catalog import MAX_REMOTE_CATALOG_BYTES
from apnawin.services.https_provider import HttpsCatalogProvider, _NoRedirectHandler


class FakeResponse:
    def __init__(self, body):
        self.body = body
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        self.read_sizes.append(size)
        return self.body[:size]


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, *, timeout):
        self.request = request
        self.timeout = timeout
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_provider_fetches_over_configured_https_url_with_bounded_read(monkeypatch):
    response = FakeResponse(b'{"catalog":true}')
    opener = FakeOpener(response)
    monkeypatch.setattr(
        "apnawin.services.https_provider.build_opener",
        lambda handler: opener,
    )
    provider = HttpsCatalogProvider("https://catalog.example.test/v1/catalog", timeout_seconds=4)

    assert provider.fetch_catalog() == b'{"catalog":true}'
    assert opener.request.full_url == "https://catalog.example.test/v1/catalog"
    assert opener.request.get_method() == "GET"
    assert opener.request.get_header("Accept") == "application/json"
    assert opener.timeout == 4
    assert response.read_sizes == [MAX_REMOTE_CATALOG_BYTES + 1]


def test_provider_rejects_oversized_response(monkeypatch):
    opener = FakeOpener(FakeResponse(b"x" * (MAX_REMOTE_CATALOG_BYTES + 1)))
    monkeypatch.setattr(
        "apnawin.services.https_provider.build_opener",
        lambda handler: opener,
    )
    provider = HttpsCatalogProvider("https://catalog.example.test/catalog")
    with pytest.raises(ValueError, match="size limit"):
        provider.fetch_catalog()


@pytest.mark.parametrize(
    "url",
    [
        "http://catalog.example.test/catalog",
        "file:///etc/passwd",
        "https:///missing-host",
        "https://user:password@catalog.example.test/catalog",
        "https://catalog.example.test/catalog#fragment",
        "https://catalog.example.test\\@evil.example/catalog",
        "https://café.example/catalog",
        "https://catalog.example.test:99999/catalog",
    ],
)
def test_provider_rejects_unsafe_or_malformed_urls(url):
    with pytest.raises(ValueError):
        HttpsCatalogProvider(url)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True, "5"])
def test_provider_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError, match="timeout_seconds"):
        HttpsCatalogProvider("https://catalog.example.test/catalog", timeout_seconds=timeout)


def test_redirect_handler_does_not_follow_redirects():
    handler = _NoRedirectHandler()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://other.example/") is None


def test_provider_does_not_return_http_error_body(monkeypatch):
    error = HTTPError(
        "https://catalog.example.test/catalog",
        503,
        "sensitive server detail",
        {},
        None,
    )
    opener = FakeOpener(error)
    monkeypatch.setattr(
        "apnawin.services.https_provider.build_opener",
        lambda handler: opener,
    )
    provider = HttpsCatalogProvider("https://catalog.example.test/catalog")
    with pytest.raises(HTTPError):
        provider.fetch_catalog()
