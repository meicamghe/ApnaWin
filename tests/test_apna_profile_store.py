from __future__ import annotations

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
