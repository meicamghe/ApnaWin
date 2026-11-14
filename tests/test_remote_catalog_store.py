import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from apnawin.domain.remote_catalog import MAX_REMOTE_CATALOG_BYTES
from apnawin.storage.remote_catalog_store import RemoteCatalogStore


def catalog_document(revision="catalog-42", expires_at="2026-11-14T07:00:00Z"):
    return json.dumps(
        {
            "format_version": 1,
            "revision": revision,
            "generated_at": "2026-11-14T06:00:00Z",
            "expires_at": expires_at,
            "servers": [
                {"id": "eu-1", "name": "Europe", "region": "EU", "available": True}
            ],
        }
    )


def test_store_saves_and_reloads_valid_catalog(tmp_path):
    store = RemoteCatalogStore(tmp_path / "cache" / "catalog.json")
    saved = store.save(catalog_document())
    loaded = store.load()

    assert loaded == saved
    assert loaded.revision == "catalog-42"
    assert store.path.read_text(encoding="utf-8") == catalog_document()


def test_store_returns_none_only_when_cache_is_missing(tmp_path):
    assert RemoteCatalogStore(tmp_path / "missing.json").load() is None


def test_store_rejects_invalid_update_without_replacing_last_good(tmp_path):
    store = RemoteCatalogStore(tmp_path / "catalog.json")
    store.save(catalog_document())
    previous = store.path.read_bytes()

    with pytest.raises(ValueError, match="schema"):
        store.save('{"format_version":1,"unexpected":true}')

    assert store.path.read_bytes() == previous
    assert store.load().revision == "catalog-42"


def test_store_rejects_oversized_document_without_touching_cache(tmp_path):
    store = RemoteCatalogStore(tmp_path / "catalog.json")
    store.save(catalog_document())
    previous = store.path.read_bytes()

    with pytest.raises(ValueError, match="size limit"):
        store.save(b" " * (MAX_REMOTE_CATALOG_BYTES + 1))

    assert store.path.read_bytes() == previous


def test_store_rejects_invalid_utf8_without_touching_cache(tmp_path):
    store = RemoteCatalogStore(tmp_path / "catalog.json")
    store.save(catalog_document())
    previous = store.path.read_bytes()

    with pytest.raises(ValueError, match="UTF-8"):
        store.save(b"\xff")

    assert store.path.read_bytes() == previous


def test_store_rejects_corrupt_or_oversized_existing_cache(tmp_path):
    path = tmp_path / "catalog.json"
    store = RemoteCatalogStore(path)
    path.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="UTF-8"):
        store.load()

    path.write_bytes(b" " * (MAX_REMOTE_CATALOG_BYTES + 1))
    with pytest.raises(ValueError, match="size limit"):
        store.load()


def test_store_keeps_stale_catalog_but_does_not_mark_it_fresh(tmp_path):
    store = RemoteCatalogStore(tmp_path / "catalog.json")
    store.save(catalog_document())
    loaded = store.load()

    assert loaded.revision == "catalog-42"
    assert not loaded.is_fresh(datetime(2026, 11, 14, 8, 0, tzinfo=timezone.utc))


def test_store_atomic_replace_failure_preserves_previous_cache(tmp_path, monkeypatch):
    store = RemoteCatalogStore(tmp_path / "catalog.json")
    store.save(catalog_document())
    previous = store.path.read_bytes()
    original_replace = Path.replace

    def fail_cache_replace(self, target):
        if self.name.startswith(".catalog.json.") and str(target) == str(store.path):
            raise OSError("simulated replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_cache_replace)
    with pytest.raises(OSError, match="simulated"):
        store.save(catalog_document(revision="catalog-43"))

    assert store.path.read_bytes() == previous
    assert store.load().revision == "catalog-42"
    assert list(tmp_path.glob(".catalog.json.*.tmp")) == []
