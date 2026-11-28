import hashlib
import json

import pytest

from tools.analyze_native_fingerprints import analyze_native_fingerprints


def _fixture(root, payload=b"\\x7fELF" + b" quic quic runtime.main secret-token"):
    apk = "base.apk"
    abi = "arm64-v8a"
    library = "libengine.so"
    target = root / apk / abi
    target.mkdir(parents=True)
    (target / library).write_bytes(payload)
    manifest = {
        "format": "apnawin-native-extraction-v1",
        "libraries": [{
            "apk": apk,
            "abi": abi,
            "library": library,
            "relative_path": f"{apk}/{abi}/{library}",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return target / library


def test_reports_only_allowlisted_protocol_and_runtime_markers(tmp_path):
    _fixture(tmp_path)
    report = analyze_native_fingerprints(tmp_path)

    assert report["library_count"] == 1
    row = report["libraries"][0]
    assert row["elf_magic"] is True
    assert row["marker_groups"]["protocol_family"]["quic"] == 2
    assert row["marker_groups"]["go_runtime"]["go_runtime_main"] == 1
    assert "secret-token" not in json.dumps(report)
    assert report["arbitrary_strings_included"] is False
    assert report["native_code_executed"] is False


def test_rejects_hash_mismatch_before_fingerprinting(tmp_path):
    target = _fixture(tmp_path)
    target.write_bytes(target.read_bytes() + b"tampered")

    with pytest.raises(ValueError, match="failed manifest verification"):
        analyze_native_fingerprints(tmp_path)


def test_rejects_symlinked_library_parent(tmp_path):
    target = tmp_path / "real" / "arm64-v8a"
    target.mkdir(parents=True)
    payload = b"\\x7fELF quic"
    lib = target / "libengine.so"
    lib.write_bytes(payload)
    (tmp_path / "base.apk").symlink_to(tmp_path / "real", target_is_directory=True)
    manifest = {
        "format": "apnawin-native-extraction-v1",
        "libraries": [{
            "apk": "base.apk",
            "abi": "arm64-v8a",
            "library": "libengine.so",
            "relative_path": "base.apk/arm64-v8a/libengine.so",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="missing or unsafe"):
        analyze_native_fingerprints(tmp_path)


def test_rejects_unsafe_manifest_relative_path(tmp_path):
    _fixture(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["libraries"][0]["relative_path"] = "../libengine.so"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe row"):
        analyze_native_fingerprints(tmp_path)
