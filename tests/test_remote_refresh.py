import json
import threading
import time

import pytest

from apnawin.services.remote_refresh import (
    RefreshStatus,
    RemoteCatalogRefreshCoordinator,
)
from apnawin.storage.remote_catalog_store import RemoteCatalogStore


def document(revision="r1"):
    return json.dumps(
        {
            "format_version": 1,
            "revision": revision,
            "generated_at": "2026-11-14T06:00:00Z",
            "expires_at": "2026-11-14T07:00:00Z",
            "servers": [
                {"id": "eu-1", "name": "Europe", "region": "EU", "available": True}
            ],
        }
    )


class FakeProvider:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else document()
        self.error = error
        self.calls = 0

    def fetch_catalog(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.response


def test_refresh_fetches_validates_and_persists_catalog(tmp_path):
    provider = FakeProvider(document("fresh-r2"))
    coordinator = RemoteCatalogRefreshCoordinator(
        provider, RemoteCatalogStore(tmp_path / "catalog.json")
    )
    result = coordinator.refresh()
    assert result.status is RefreshStatus.UPDATED
    assert result.catalog.revision == "fresh-r2"
    assert provider.calls == 1


def test_failed_refresh_returns_last_known_good_catalog(tmp_path):
    store = RemoteCatalogStore(tmp_path / "catalog.json")
    store.save(document("last-good"))
    provider = FakeProvider(error=TimeoutError("sensitive detail must not escape"))
    coordinator = RemoteCatalogRefreshCoordinator(provider, store)
    result = coordinator.refresh()
    assert result.status is RefreshStatus.FAILED
    assert result.catalog.revision == "last-good"
    assert result.error_type == "TimeoutError"
    assert "sensitive" not in repr(result)


def test_failed_refresh_uses_exponential_backoff_and_force_bypasses_it(tmp_path):
    now = [100.0]
    provider = FakeProvider(error=OSError("offline"))
    coordinator = RemoteCatalogRefreshCoordinator(
        provider,
        RemoteCatalogStore(tmp_path / "catalog.json"),
        base_backoff_seconds=5,
        max_backoff_seconds=12,
        monotonic=lambda: now[0],
    )
    first = coordinator.refresh()
    assert first.status is RefreshStatus.FAILED
    assert coordinator.consecutive_failures == 1
    now[0] += 2
    skipped = coordinator.refresh()
    assert skipped.status is RefreshStatus.BACKOFF
    assert skipped.retry_after_seconds == pytest.approx(3)
    assert provider.calls == 1
    forced = coordinator.refresh(force=True)
    assert forced.status is RefreshStatus.FAILED
    assert provider.calls == 2
    assert coordinator.consecutive_failures == 2


def test_backoff_is_capped_and_success_resets_failure_count(tmp_path):
    now = [0.0]
    provider = FakeProvider(error=OSError("offline"))
    coordinator = RemoteCatalogRefreshCoordinator(
        provider,
        RemoteCatalogStore(tmp_path / "catalog.json"),
        base_backoff_seconds=4,
        max_backoff_seconds=6,
        monotonic=lambda: now[0],
    )
    coordinator.refresh()
    now[0] = 4
    coordinator.refresh(force=True)
    assert coordinator.consecutive_failures == 2
    now[0] = 8
    coordinator.refresh(force=True)
    assert coordinator.consecutive_failures == 3
    provider.error = None
    provider.response = document("recovered")
    recovered = coordinator.refresh(force=True)
    assert recovered.status is RefreshStatus.UPDATED
    assert coordinator.consecutive_failures == 0


def test_invalid_remote_document_cannot_replace_cache(tmp_path):
    store = RemoteCatalogStore(tmp_path / "catalog.json")
    store.save(document("last-good"))
    provider = FakeProvider('{"format_version":1,"bad":true}')
    coordinator = RemoteCatalogRefreshCoordinator(provider, store)
    result = coordinator.refresh()
    assert result.status is RefreshStatus.FAILED
    assert result.catalog.revision == "last-good"
    assert store.load().revision == "last-good"


def test_concurrent_refresh_calls_share_one_provider_request(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    class BlockingProvider(FakeProvider):
        def fetch_catalog(self):
            self.calls += 1
            entered.set()
            assert release.wait(timeout=3)
            return document("single-flight")

    provider = BlockingProvider()
    coordinator = RemoteCatalogRefreshCoordinator(
        provider, RemoteCatalogStore(tmp_path / "catalog.json")
    )
    results = []
    first = threading.Thread(target=lambda: results.append(coordinator.refresh()))
    second = threading.Thread(target=lambda: results.append(coordinator.refresh()))
    first.start()
    assert entered.wait(timeout=3)
    second.start()
    time.sleep(0.05)
    release.set()
    first.join(timeout=3)
    second.join(timeout=3)
    assert not first.is_alive()
    assert not second.is_alive()
    assert provider.calls == 1
    assert len(results) == 2
    assert results[0] == results[1]
    assert results[0].status is RefreshStatus.UPDATED


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_backoff_seconds": 0},
        {"base_backoff_seconds": float("inf")},
        {"base_backoff_seconds": True},
        {"max_backoff_seconds": 0},
        {"base_backoff_seconds": 10, "max_backoff_seconds": 5},
    ],
)
def test_invalid_backoff_configuration_is_rejected(tmp_path, kwargs):
    with pytest.raises(ValueError):
        RemoteCatalogRefreshCoordinator(
            FakeProvider(),
            RemoteCatalogStore(tmp_path / "catalog.json"),
            **kwargs,
        )


def test_force_must_be_boolean(tmp_path):
    coordinator = RemoteCatalogRefreshCoordinator(
        FakeProvider(), RemoteCatalogStore(tmp_path / "catalog.json")
    )
    with pytest.raises(TypeError, match="boolean"):
        coordinator.refresh(force=1)
