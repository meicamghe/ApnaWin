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

