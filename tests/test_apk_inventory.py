import json
import zipfile

import pytest

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
