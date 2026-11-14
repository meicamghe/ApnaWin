import json
import stat
import zipfile

import pytest

from apnawin.services import apk_inventory
from apnawin.services.apk_inventory import inspect_apk


def test_inventory_reports_only_safe_static_metadata(tmp_path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"not decoded")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("classes2.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libengine.so", b"native")
        archive.writestr("lib/armeabi-v7a/libengine.so", b"native")
        archive.writestr("META-INF/CERT.RSA", b"signature")
        archive.writestr("assets/private-token.txt", b"must never be read")

    result = inspect_apk(apk)

    assert result["format"] == "apnawin-apk-inventory-v1"
    assert result["manifest_present"] is True
    assert result["dex_file_count"] == 2
    assert result["native_abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert result["signature_file_count"] == 1
    assert result["content_extracted"] is False
    assert result["executed"] is False
    assert "private-token" not in json.dumps(result)
    assert len(result["sha256"]) == 64


def test_inventory_rejects_missing_path(tmp_path):
    with pytest.raises(ValueError, match="existing regular file"):
        inspect_apk(tmp_path / "missing.apk")


def test_inventory_rejects_non_zip_file(tmp_path):
    apk = tmp_path / "broken.apk"
    apk.write_bytes(b"not an apk")
    with pytest.raises(ValueError, match="readable ZIP archive"):
        inspect_apk(apk)


def test_inventory_rejects_duplicate_zip_entry_names(tmp_path):
    apk = tmp_path / "duplicate.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"one")
        archive.writestr("classes.dex", b"two")
    with pytest.raises(ValueError, match="duplicate ZIP entry"):
        inspect_apk(apk)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/drive"])
def test_inventory_rejects_unsafe_member_paths(tmp_path, name):
    apk = tmp_path / "unsafe.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(name, b"data")
    with pytest.raises(ValueError, match="unsafe ZIP entry path"):
        inspect_apk(apk)


def test_inventory_rejects_backslash_member_path():
    info = zipfile.ZipInfo("safe")
    info.filename = "assets" + chr(92) + "escape"
    with pytest.raises(ValueError, match="unsafe ZIP entry path"):
        apk_inventory._validate_entry(info)


def test_inventory_rejects_symbolic_link_entries(tmp_path):
    apk = tmp_path / "symlink.apk"
    info = zipfile.ZipInfo("assets/link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(info, b"target")
    with pytest.raises(ValueError, match="symbolic-link"):
        inspect_apk(apk)


def test_inventory_enforces_aggregate_uncompressed_size(tmp_path, monkeypatch):
    apk = tmp_path / "large.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("one.bin", b"1234")
        archive.writestr("two.bin", b"5678")
    monkeypatch.setattr(apk_inventory, "_MAX_TOTAL_UNCOMPRESSED_BYTES", 7)
    with pytest.raises(ValueError, match="aggregate size"):
        inspect_apk(apk)


def test_inventory_enforces_per_entry_uncompressed_size(tmp_path, monkeypatch):
    apk = tmp_path / "entry-large.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("large.bin", b"12345678")
    monkeypatch.setattr(apk_inventory, "_MAX_ENTRY_UNCOMPRESSED_BYTES", 7)
    with pytest.raises(ValueError, match="oversized ZIP entry"):
        inspect_apk(apk)


def test_inventory_rejects_encrypted_entry_metadata():
    info = zipfile.ZipInfo("encrypted.bin")
    info.flag_bits |= 0x1
    with pytest.raises(ValueError, match="encrypted ZIP entry"):
        apk_inventory._validate_entry(info)
