import hashlib
import json

import pytest

from apnawin.services.vpn_runtime import (
    VpnRuntimeIntegrityError,
    verify_vpn_runtime,
)


def _write_runtime(root):
    root.mkdir()
    xray = root / "xray.exe"
    wintun = root / "wintun.dll"
    xray.write_bytes(b"verified xray binary")
    wintun.write_bytes(b"verified wintun binary")
    manifest = {
        "schema_version": 1,
        "xray": {
            "version": "26.11.9",
            "archive_sha256": "a" * 64,
            "executable_sha256": hashlib.sha256(xray.read_bytes()).hexdigest(),
        },
        "wintun": {
            "version": "0.14.1",
            "archive_sha256": "b" * 64,
            "dll_sha256": hashlib.sha256(wintun.read_bytes()).hexdigest(),
            "signer": "CN=WireGuard LLC",
        },
    }
    (root / "runtime-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_runtime_verification_accepts_utf8_bom_manifest(tmp_path):
    root = tmp_path / "engine"
    manifest = _write_runtime(root)
    (root / "runtime-manifest.json").write_bytes(
        b"\\xef\\xbb\\xbf" + json.dumps(manifest).encode("utf-8")
    )
    assert verify_vpn_runtime(root) == manifest


def test_runtime_verification_accepts_matching_manifest_and_binaries(tmp_path):
    root = tmp_path / "engine"
    expected = _write_runtime(root)
    assert verify_vpn_runtime(root) == expected


def test_runtime_verification_rejects_modified_xray_or_wintun(tmp_path):
    root = tmp_path / "engine"
    _write_runtime(root)
    (root / "wintun.dll").write_bytes(b"modified")
    with pytest.raises(VpnRuntimeIntegrityError, match="hash mismatch"):
        verify_vpn_runtime(root)


@pytest.mark.parametrize(
    "manifest",
    [
        {},
        {"schema_version": True, "xray": {}, "wintun": {}},
        {
            "schema_version": 1,
            "xray": {"version": "1", "archive_sha256": "bad", "executable_sha256": "0" * 64},
            "wintun": {"version": "1", "archive_sha256": "0" * 64, "dll_sha256": "0" * 64, "signer": "CN=Other"},
        },
    ],
)
def test_runtime_verification_rejects_invalid_manifest_schema(tmp_path, manifest):
    root = tmp_path / "engine"
    root.mkdir()
    (root / "xray.exe").write_bytes(b"x")
    (root / "wintun.dll").write_bytes(b"w")
    (root / "runtime-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(VpnRuntimeIntegrityError):
        verify_vpn_runtime(root)


def test_runtime_verification_rejects_missing_or_symlinked_manifest(tmp_path):
    root = tmp_path / "engine"
    root.mkdir()
    with pytest.raises(VpnRuntimeIntegrityError, match="manifest"):
        verify_vpn_runtime(root)
    target = tmp_path / "manifest.json"
    target.write_text("{}", encoding="utf-8")
    try:
        (root / "runtime-manifest.json").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(VpnRuntimeIntegrityError, match="manifest"):
        verify_vpn_runtime(root)


def test_runtime_verification_rejects_binary_symlink(tmp_path):
    root = tmp_path / "engine"
    root.mkdir()
    target = tmp_path / "xray.exe"
    target.write_bytes(b"binary")
    try:
        (root / "xray.exe").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    (root / "wintun.dll").write_bytes(b"wintun")
    manifest = {
        "schema_version": 1,
        "xray": {"version": "1", "archive_sha256": "a" * 64, "executable_sha256": hashlib.sha256(b"binary").hexdigest()},
        "wintun": {"version": "1", "archive_sha256": "b" * 64, "dll_sha256": hashlib.sha256(b"wintun").hexdigest(), "signer": "WireGuard"},
    }
    (root / "runtime-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(VpnRuntimeIntegrityError, match="unsafe"):
        verify_vpn_runtime(root)
