from __future__ import annotations

import base64
import json

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode
from apnawin.engines.apna_ssh_session import ApnaSshConfig
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig
from apnawin.storage.apna_profile_store import ApnaProfileStore, ApnaProfileStoreError


def _profile():
    return ConnectionProfile("APNA work", Transport.APNA_SSH, "ssh.example.test", 443)


def _config():
    return ApnaTunnelSessionConfig(
        ssh=ApnaSshConfig(
            "ssh.example.test", 443, "demo-user", password="do-not-log",
            host_key_sha256="SHA256:" + "A" * 43,
        ),
        payload=PayloadSocketConfig(
            mode=PayloadSocketMode.HTTP_PROXY,
            connect_host="proxy.example.test",
            connect_port=8080,
            target_host="ssh.example.test",
            target_port=443,
            payload="CONNECT [host_port] [protocol][crlf][crlf]",
            sni="proxy.example.test",
            ca_bundle_file="trusted-provider-ca.pem",
            cf_host="front.example.test",
            brand="ApnaWin",
            user_agent="ApnaWin-Test/1.0",
        ),
        udpgw_host="udpgw.example.test",
        udpgw_port=7300,
        transparent_dns=True,
        dns_resolver="1.1.1.1",
    )


def _store(tmp_path):
    return ApnaProfileStore(
        tmp_path / "apna-profiles.json",
        protect=lambda raw: b"encrypted:" + raw,
        unprotect=lambda raw: raw.removeprefix(b"encrypted:"),
    )


def test_round_trip_encrypted_profile_and_config_loader(tmp_path):
    store = _store(tmp_path)
    store.save(_profile(), _config())
    raw_store = (tmp_path / "apna-profiles.json").read_text(encoding="utf-8")
    assert "do-not-log" not in raw_store
    loaded = store.load(_profile())
    assert loaded.ssh.password == "do-not-log"
    assert loaded.ssh.host_key_sha256 == _config().ssh.host_key_sha256
    assert loaded.payload.payload == _config().payload.payload
    assert loaded.payload.ca_bundle_file == "trusted-provider-ca.pem"
    assert loaded.payload.allow_insecure_tls is False
    assert loaded.payload.cf_host == "front.example.test"
    assert loaded.payload.brand == "ApnaWin"
    assert loaded.payload.user_agent == "ApnaWin-Test/1.0"
    assert loaded.udpgw_host == "udpgw.example.test"
    assert loaded.transparent_dns is True


def test_store_rejects_non_apna_profile_and_endpoint_mismatch(tmp_path):
    store = _store(tmp_path)
    wrong = ConnectionProfile("wrong", Transport.XRAY, "ssh.example.test", 443)
    with pytest.raises(TypeError, match="APNA_SSH"):
        store.save(wrong, _config())
    mismatched = ConnectionProfile("wrong endpoint", Transport.APNA_SSH, "other.example.test", 443)
    with pytest.raises(ValueError, match="match"):
        store.save(mismatched, _config())


def test_store_rejects_invalid_or_tampered_ciphertext(tmp_path):
    store = _store(tmp_path)
    store.save(_profile(), _config())
    path = tmp_path / "apna-profiles.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["profiles"]["apna work"] = "not base64!"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ApnaProfileStoreError, match="decrypt"):
        store.load(_profile())


def test_store_remove_is_idempotent(tmp_path):
    store = _store(tmp_path)
    store.save(_profile(), _config())
    store.remove("APNA work")
    store.remove("APNA work")
    assert not (tmp_path / "apna-profiles.json").read_text(encoding="utf-8").find("apna work") >= 0


def test_store_rejects_symlink(tmp_path):
    store = _store(tmp_path)
    target = tmp_path / "target.json"
    target.write_text('{"format_version":1,"profiles":{}}', encoding="utf-8")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    linked_store = ApnaProfileStore(
        link,
        protect=lambda raw: raw,
        unprotect=lambda raw: raw,
    )
    with pytest.raises(ApnaProfileStoreError, match="symbolic link"):
        linked_store.load(_profile())



def test_store_has_config_tracks_encrypted_profile_presence(tmp_path):
    store = _store(tmp_path)
    assert not store.has_config("APNA work")
    store.save(_profile(), _config())
    assert store.has_config("apna WORK")
    store.remove("APNA work")
    assert not store.has_config("APNA work")



def test_store_renames_profile_without_exposing_secret(tmp_path):
    store = _store(tmp_path)
    store.save(_profile(), _config())
    renamed = ConnectionProfile(
        "APNA work renamed", Transport.APNA_SSH, "ssh.example.test", 443
    )
    store.rename(_profile(), renamed)
    assert not store.has_config("APNA work")
    assert store.has_config("APNA work renamed")
    assert store.load(renamed).ssh.password == "do-not-log"


def test_store_rename_rejects_changed_endpoint(tmp_path):
    store = _store(tmp_path)
    store.save(_profile(), _config())
    changed = ConnectionProfile(
        "APNA work renamed", Transport.APNA_SSH, "other.example.test", 443
    )
    with pytest.raises(ValueError, match="match"):
        store.rename(_profile(), changed)
    assert store.has_config("APNA work")
    assert not store.has_config("APNA work renamed")


def test_save_many_writes_batch_once_and_round_trips(tmp_path, monkeypatch):
    store = _store(tmp_path)
    writes = []
    original_write = store._write

    def counted_write(records):
        writes.append(len(records))
        return original_write(records)

    monkeypatch.setattr(store, "_write", counted_write)
    second = ConnectionProfile("APNA second", Transport.APNA_SSH, "ssh.example.test", 443)
    store.save_many([(_profile(), _config()), (second, _config())])

    assert writes == [2]
    assert store.has_config("APNA work")
    assert store.has_config("APNA second")
    assert store.load(second).ssh.password == "do-not-log"


def test_save_many_rejects_duplicate_names_before_writing(tmp_path, monkeypatch):
    store = _store(tmp_path)
    writes = []
    monkeypatch.setattr(store, "_write", lambda _records: writes.append(True))
    with pytest.raises(ValueError, match="duplicate"):
        store.save_many([(_profile(), _config()), (_profile(), _config())])
    assert writes == []


def test_remove_many_writes_once(tmp_path, monkeypatch):
    store = _store(tmp_path)
    second = ConnectionProfile("APNA second", Transport.APNA_SSH, "ssh.example.test", 443)
    store.save_many([(_profile(), _config()), (second, _config())])
    writes = []
    original_write = store._write

    def counted_write(records):
        writes.append(len(records))
        return original_write(records)

    monkeypatch.setattr(store, "_write", counted_write)
    store.remove_many(["APNA work", "APNA second"])
    assert writes == [0]
    assert not store.has_config("APNA work")
    assert not store.has_config("APNA second")


def test_store_accepts_catalog_batch_larger_than_legacy_four_mib_limit(tmp_path):
    store = ApnaProfileStore(
        tmp_path / "apna-profiles.json",
        protect=lambda _raw: b"x" * (3 * 1024 * 1024),
        unprotect=lambda raw: raw,
    )
    store.save(_profile(), _config())
    path = tmp_path / "apna-profiles.json"
    assert path.stat().st_size > 4 * 1024 * 1024
    assert store.has_config("APNA work")




def test_store_loads_legacy_profile_without_optional_ca_bundle(tmp_path):
    store = _store(tmp_path)
    store.save(_profile(), _config())
    path = tmp_path / "apna-profiles.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    ciphertext = base64.b64decode(document["profiles"]["apna work"])
    plaintext = json.loads(ciphertext.removeprefix(b"encrypted:").decode("utf-8"))
    plaintext["payload"].pop("ca_bundle_file", None)
    legacy_ciphertext = b"encrypted:" + json.dumps(
        plaintext, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    document["profiles"]["apna work"] = base64.b64encode(legacy_ciphertext).decode("ascii")
    path.write_text(json.dumps(document), encoding="utf-8")

    loaded = store.load(_profile())
    assert loaded.payload.ca_bundle_file is None


def test_store_round_trips_explicit_insecure_tls_compatibility_flag(tmp_path):
    from dataclasses import replace

    store = _store(tmp_path)
    config = _config()
    payload = replace(config.payload, allow_insecure_tls=True)
    store.save(_profile(), replace(config, payload=payload))
    loaded = store.load(_profile())
    assert loaded.payload.allow_insecure_tls is True
