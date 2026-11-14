import json
from datetime import datetime, timezone

import pytest

from apnawin.domain.remote_catalog import (
    MAX_REMOTE_CATALOG_BYTES,
    RemoteServer,
    parse_remote_catalog,
)


def catalog_payload():
    return {
        "format_version": 1,
        "revision": "catalog-42",
        "generated_at": "2026-11-14T06:00:00Z",
        "expires_at": "2026-11-14T07:00:00+00:00",
        "servers": [
            {"id": "eu-1", "name": "Europe", "region": "EU", "available": True},
            {"id": "us-1", "name": "America", "region": "US", "available": False},
        ],
    }


def test_remote_catalog_parses_normalized_metadata():
    catalog = parse_remote_catalog(json.dumps(catalog_payload()))
    assert catalog.revision == "catalog-42"
    assert catalog.servers == (
        RemoteServer("eu-1", "Europe", "EU", True),
        RemoteServer("us-1", "America", "US", False),
    )


def test_remote_catalog_freshness_uses_timezone_aware_window():
    catalog = parse_remote_catalog(json.dumps(catalog_payload()))
    assert catalog.is_fresh(datetime(2026, 11, 14, 6, 30, tzinfo=timezone.utc))
    assert not catalog.is_fresh(datetime(2026, 11, 14, 7, 0, tzinfo=timezone.utc))
    assert not catalog.is_fresh(datetime(2026, 11, 14, 5, 59, tzinfo=timezone.utc))


def test_remote_catalog_rejects_naive_now():
    catalog = parse_remote_catalog(json.dumps(catalog_payload()))
    with pytest.raises(ValueError, match="timezone-aware"):
        catalog.is_fresh(datetime(2026, 11, 14, 6, 30))


@pytest.mark.parametrize("version", [True, 1.0, "1", 2])
def test_remote_catalog_rejects_invalid_version(version):
    payload = catalog_payload()
    payload["format_version"] = version
    with pytest.raises(ValueError, match="version"):
        parse_remote_catalog(json.dumps(payload))


def test_remote_catalog_rejects_unknown_fields():
    payload = catalog_payload()
    payload["credentials"] = {"token": "must-not-be-accepted"}
    with pytest.raises(ValueError, match="schema"):
        parse_remote_catalog(json.dumps(payload))


def test_remote_catalog_rejects_duplicate_json_keys():
    raw = (
        '{"format_version":1,"revision":"a","revision":"b",'
        '"generated_at":"2026-11-14T06:00:00Z",'
        '"expires_at":"2026-11-14T07:00:00Z","servers":[]}'
    )
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        parse_remote_catalog(raw)


def test_remote_catalog_rejects_nested_duplicate_keys():
    raw = (
        '{"format_version":1,"revision":"a",'
        '"generated_at":"2026-11-14T06:00:00Z",'
        '"expires_at":"2026-11-14T07:00:00Z",'
        '"servers":[{"id":"x","id":"y","name":"n","region":"r","available":true}]}'
    )
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        parse_remote_catalog(raw)


def test_remote_catalog_rejects_nonstandard_json_constants():
    raw = (
        '{"format_version":1,"revision":"a",'
        '"generated_at":"2026-11-14T06:00:00Z",'
        '"expires_at":"2026-11-14T07:00:00Z","servers":[],"extra":NaN}'
    )
    with pytest.raises(ValueError, match="Invalid JSON constant"):
        parse_remote_catalog(raw)


def test_remote_catalog_rejects_duplicate_server_ids_case_insensitively():
    payload = catalog_payload()
    payload["servers"][1]["id"] = "EU-1"
    with pytest.raises(ValueError, match="Duplicate server id"):
        parse_remote_catalog(json.dumps(payload))


@pytest.mark.parametrize("available", [1, 0, "true", None])
def test_remote_catalog_requires_boolean_availability(available):
    payload = catalog_payload()
    payload["servers"][0]["available"] = available
    with pytest.raises(ValueError, match="boolean"):
        parse_remote_catalog(json.dumps(payload))


def test_remote_catalog_rejects_timezone_free_timestamps():
    payload = catalog_payload()
    payload["generated_at"] = "2026-11-14T06:00:00"
    with pytest.raises(ValueError, match="timezone"):
        parse_remote_catalog(json.dumps(payload))


def test_remote_catalog_rejects_non_increasing_expiry():
    payload = catalog_payload()
    payload["expires_at"] = payload["generated_at"]
    with pytest.raises(ValueError, match="later"):
        parse_remote_catalog(json.dumps(payload))


def test_remote_catalog_rejects_control_characters_in_display_fields():
    payload = catalog_payload()
    payload["servers"][0]["name"] = "Europe\nInjected"
    with pytest.raises(ValueError, match="control characters"):
        parse_remote_catalog(json.dumps(payload))


def test_remote_catalog_rejects_oversized_bytes_before_parsing():
    with pytest.raises(ValueError, match="size limit"):
        parse_remote_catalog(b" " * (MAX_REMOTE_CATALOG_BYTES + 1))


def test_remote_catalog_rejects_invalid_utf8():
    with pytest.raises(ValueError, match="UTF-8"):
        parse_remote_catalog(b"\\xff")


def test_remote_catalog_rejects_non_string_input():
    with pytest.raises(TypeError, match="str or bytes"):
        parse_remote_catalog(123)
