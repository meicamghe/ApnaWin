from __future__ import annotations

import base64
import json

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.services.udpq_sidecar import UdpqClientConfig
from apnawin.storage.udpq_config_store import UdpqConfigStore


def _profile(name="udpq-test", host="vpn.example.test", port=443):
    return ConnectionProfile(name, Transport.UDPQ, host, port)


def _config(**overrides):
    values = {
        "server_host": "vpn.example.test",
        "server_port": 443,
        "auth_str": "secret-must-not-leak",
        "alpn": "hysteria",
        "server_name": "vpn.example.test",
        "up_mbps": 10,
        "down_mbps": 20,
        "socks_host": "127.0.0.1",
        "socks_port": 10808,
    }
    values.update(overrides)
    return UdpqClientConfig(**values)


def _store(path):
    return UdpqConfigStore(path, protect=lambda value: b"encrypted:" + value,
                           unprotect=lambda value: value.removeprefix(b"encrypted:"))


def test_udpq_store_encrypts_roundtrips_and_renames(tmp_path):
    path = tmp_path / "udpq-profiles.json"
    store = _store(path)
    config = _config()

    store.save(_profile(), config)

    raw = path.read_text(encoding="utf-8")
    assert "secret-must-not-leak" not in raw
    assert store.has_config("UDPQ-TEST")
    assert store.load("udpq-test") == config

    store.rename("udpq-test", "renamed")
    assert not store.has_config("udpq-test")
    assert store.load("renamed") == config

    store.remove_many(["renamed"])
    assert not store.has_config("renamed")


def test_udpq_store_rejects_profile_transport_and_endpoint_mismatch(tmp_path):
    store = _store(tmp_path / "udpq.json")
    with pytest.raises(ValueError, match="UDPQ connection profile"):
        store.save(
            ConnectionProfile("xray", Transport.XRAY, "vpn.example.test", 443),
            _config(),
        )
    with pytest.raises(ValueError, match="endpoint"):
        store.save(_profile(host="other.example.test"), _config())


def test_udpq_store_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "udpq.json"
    path.write_text('{"format_version":1,"format_version":1,"configs":{}}', encoding="utf-8")
    store = _store(path)
    with pytest.raises(ValueError, match="invalid JSON"):
        store.has_config("udpq-test")


def test_udpq_store_rejects_corrupt_base64_and_decrypted_schema(tmp_path):
    path = tmp_path / "udpq.json"
    path.write_text(json.dumps({
        "format_version": 1,
        "configs": {"udpq-test": "%%%"},
    }), encoding="utf-8")
    store = _store(path)
    with pytest.raises(ValueError, match="could not be decrypted"):
        store.load("udpq-test")

    path.write_text(json.dumps({
        "format_version": 1,
        "configs": {"udpq-test": base64.b64encode(b"encrypted:{}").decode("ascii")},
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        store.load("udpq-test")


def test_udpq_store_rejects_non_standard_constants(tmp_path):
    path = tmp_path / "udpq.json"
    path.write_text('{"format_version":NaN,"configs":{}}', encoding="utf-8")
    store = _store(path)
    with pytest.raises(ValueError, match="invalid JSON"):
        store.has_config("udpq-test")


def test_udpq_store_roundtrips_multi_port_hopping_config(tmp_path):
    store = _store(tmp_path / "udpq.json")
    config = _config(server_port_spec="443,8443-8445")
    store.save(_profile(), config)
    assert store.load("udpq-test") == config
