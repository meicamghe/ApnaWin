import base64
import hashlib
import json

import pytest

from apnawin.storage.xray_config_store import XrayConfigStore


def valid_config_bytes():
    config = {
        "inbounds": [{
            "protocol": "tun",
            "port": 0,
            "settings": {
                "name": "ApnaWin",
                "gateway": ["10.255.0.1/30", "fd42:6170:6e61:7769::1/64"],
                "dns": ["1.1.1.1"],
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto",
                "autoSystemWfpBlockLeak": ["allexceptlan", "dns"],
            },
        }],
        "outbounds": [{"protocol": "vless", "settings": {"id": "private-secret"}}],
    }
    return json.dumps(config).encode("utf-8")


def fake_crypto():
    def protect(data):
        return b"test-encrypted:" + hashlib.sha256(data).digest() + data[::-1]

    def unprotect(data):
        if not data.startswith(b"test-encrypted:"):
            raise ValueError("ciphertext integrity failure")
        payload = data[len(b"test-encrypted:"):]
        digest, reversed_plaintext = payload[:32], payload[32:]
        plaintext = reversed_plaintext[::-1]
        if hashlib.sha256(plaintext).digest() != digest:
            raise ValueError("ciphertext integrity failure")
        return plaintext

    return protect, unprotect


def test_store_round_trips_encrypted_config_without_plaintext_on_disk(tmp_path):
    protect, unprotect = fake_crypto()
    path = tmp_path / "xray-configs.json"
    store = XrayConfigStore(path, protect=protect, unprotect=unprotect)
    secret = b"private-secret"
    config = valid_config_bytes()
    store.save("Office", config)
    assert store.has_config("office")
    assert store.load("OFFICE") == config
    assert secret not in path.read_bytes()
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert base64.b64decode(stored["configs"]["office"]).startswith(b"test-encrypted:")


def test_store_renames_and_removes_profile_config(tmp_path):
    protect, unprotect = fake_crypto()
    store = XrayConfigStore(tmp_path / "xray-configs.json", protect=protect, unprotect=unprotect)
    config = valid_config_bytes()
    store.save("Office", config)
    store.rename("office", "Branch")
    assert not store.has_config("Office")
    assert store.load("branch") == config
    store.remove("BRANCH")
    assert not store.has_config("branch")


def test_store_rejects_duplicate_profile_config_name(tmp_path):
    protect, unprotect = fake_crypto()
    store = XrayConfigStore(tmp_path / "xray-configs.json", protect=protect, unprotect=unprotect)
    store.save("Office", valid_config_bytes())
    store.save("Other", valid_config_bytes())
    with pytest.raises(ValueError, match="already stored"):
        store.rename("Office", "Other")


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"not-json",
        b'{"inbounds":[],"outbounds":[]}',
        b'{"inbounds":[],"inbounds":[],"outbounds":[]}',
        b'{"inbounds":[],"outbounds":[],"number":NaN}',
        b'{"inbounds":[],"outbounds":[]}',
    ],
)
def test_store_rejects_invalid_or_unsafe_config(value, tmp_path):
    protect, unprotect = fake_crypto()
    store = XrayConfigStore(tmp_path / "xray-configs.json", protect=protect, unprotect=unprotect)
    with pytest.raises(ValueError):
        store.save("Office", value)


def test_store_rejects_corrupt_ciphertext(tmp_path):
    protect, unprotect = fake_crypto()
    store = XrayConfigStore(tmp_path / "xray-configs.json", protect=protect, unprotect=unprotect)
    store.save("Office", valid_config_bytes())
    document = json.loads(store.path.read_text(encoding="utf-8"))
    document["configs"]["office"] = "not base64!"
    store.path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="base64"):
        store.load("Office")


def test_store_rejects_tampered_dpapi_ciphertext(tmp_path):
    protect, unprotect = fake_crypto()
    store = XrayConfigStore(tmp_path / "xray-configs.json", protect=protect, unprotect=unprotect)
    store.save("Office", valid_config_bytes())
    document = json.loads(store.path.read_text(encoding="utf-8"))
    import base64
    raw = base64.b64decode(document["configs"]["office"])
    document["configs"]["office"] = base64.b64encode(raw + b"x").decode("ascii")
    store.path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity failure"):
        store.load("Office")


def test_store_rejects_symlink_destination(tmp_path):
    protect, unprotect = fake_crypto()
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    store = XrayConfigStore(link, protect=protect, unprotect=unprotect)
    with pytest.raises(OSError, match="symbolic link"):
        store.save("Office", valid_config_bytes())


def test_profile_key_rejects_controls_and_empty_names(tmp_path):
    protect, unprotect = fake_crypto()
    store = XrayConfigStore(tmp_path / "xray-configs.json", protect=protect, unprotect=unprotect)
    with pytest.raises(ValueError):
        store.save(" ", valid_config_bytes())
    with pytest.raises(ValueError):
        store.save("bad\nname", valid_config_bytes())


def test_store_rejects_non_integer_format_version(tmp_path):
    protect, unprotect = fake_crypto()
    path = tmp_path / "xray-configs.json"
    path.write_text('{"format_version": 1.0, "configs": {}}', encoding="utf-8")
    store = XrayConfigStore(path, protect=protect, unprotect=unprotect)
    with pytest.raises(ValueError, match="invalid schema"):
        store.has_config("Office")
