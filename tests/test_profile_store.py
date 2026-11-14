import json

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.storage.profile_store import load_profiles, save_profiles


def sample_profiles():
    return [
        ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443),
        ConnectionProfile("Lab", Transport.OPENVPN, "192.0.2.10", 1194),
    ]


def test_profile_store_round_trip(tmp_path):
    path = tmp_path / "profiles" / "connections.json"
    expected = sample_profiles()

    save_profiles(path, expected)

    assert load_profiles(path) == expected


def test_profile_store_supports_empty_list(tmp_path):
    path = tmp_path / "profiles.json"
    save_profiles(path, [])
    assert load_profiles(path) == []


def test_profile_store_rejects_unknown_version(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"format_version": 99, "profiles": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="version"):
        load_profiles(path)


@pytest.mark.parametrize("version", [True, 1.0, "1", None])
def test_profile_store_rejects_non_integer_version(tmp_path, version):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"format_version": version, "profiles": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="version"):
        load_profiles(path)


def test_profile_store_rejects_malformed_record(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "profiles": [{"name": "broken", "transport": "unknown"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="schema"):
        load_profiles(path)


def test_profile_store_rejects_boolean_port(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "profiles": [
                    {
                        "name": "bad",
                        "transport": "socks",
                        "endpoint_host": "localhost",
                        "endpoint_port": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="integer"):
        load_profiles(path)


def test_profile_store_does_not_overwrite_on_invalid_input(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text("keep this", encoding="utf-8")

    with pytest.raises(TypeError):
        save_profiles(path, ["not a profile"])

    assert path.read_text(encoding="utf-8") == "keep this"


def test_profile_store_rejects_wrong_field_types(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "profiles": [
                    {
                        "name": 123,
                        "transport": "socks",
                        "endpoint_host": "localhost",
                        "endpoint_port": 1080,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="name must be a string"):
        load_profiles(path)


def test_profile_store_preserves_previous_file_when_atomic_replace_fails(tmp_path, monkeypatch):
    from pathlib import Path

    path = tmp_path / "profiles.json"
    path.write_text("previous contents", encoding="utf-8")

    def fail_replace(_self, _target):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        save_profiles(path, sample_profiles())

    assert path.read_text(encoding="utf-8") == "previous contents"
    assert list(tmp_path.glob(".profiles.json.*.tmp")) == []


def test_profile_store_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        '{"format_version":1,"format_version":1,"profiles":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate JSON key"):
        load_profiles(path)


def test_profile_store_rejects_nonstandard_json_constants(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        '{"format_version":1,"profiles":[],"unexpected":NaN}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid JSON constant"):
        load_profiles(path)


def test_profile_store_rejects_duplicate_profile_names_case_insensitively(tmp_path):
    path = tmp_path / "profiles.json"
    payload = {
        "format_version": 1,
        "profiles": [
            {"name": "Office", "transport": "socks", "endpoint_host": "localhost", "endpoint_port": 1080},
            {"name": "office", "transport": "socks", "endpoint_host": "127.0.0.1", "endpoint_port": 1081},
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate profile name"):
        load_profiles(path)


def test_profile_store_rejects_unknown_top_level_fields(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps({"format_version": 1, "profiles": [], "credentials": {"token": "x"}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid schema"):
        load_profiles(path)
