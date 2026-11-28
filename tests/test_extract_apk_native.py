import hashlib
import json
import zipfile

import pytest

from tools import extract_apk_native


def _write_apk(path, members):
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)


def test_extracts_and_verifies_native_members_across_splits(tmp_path):
    base = tmp_path / "base.apk"
    split = tmp_path / "split_config.arm64_v8a.apk"
    one = b"native-one"
    two = b"native-two"
    _write_apk(base, [("lib/arm64-v8a/libone.so", one)])
    _write_apk(split, [("lib/arm64-v8a/libtwo.so", two)])
    output = tmp_path / "out"

    result = extract_apk_native.extract_native_libraries([base, split], output)

    assert result["extracted_library_count"] == 2
    assert result["total_bytes_written"] == len(one) + len(two)
    assert result["native_code_executed"] is False
    assert (output / "base.apk/arm64-v8a/libone.so").read_bytes() == one
    assert (output / "split_config.arm64_v8a.apk/arm64-v8a/libtwo.so").read_bytes() == two
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["extracted_library_count"] == 2
    assert {row["sha256"] for row in manifest["libraries"]} == {
        hashlib.sha256(one).hexdigest(),
        hashlib.sha256(two).hexdigest(),
    }
    assert all(row["executed"] is False for row in manifest["libraries"])


def test_rejects_nonempty_output_directory(tmp_path):
    apk = tmp_path / "base.apk"
    _write_apk(apk, [("lib/arm64-v8a/libone.so", b"one")])
    output = tmp_path / "out"
    output.mkdir()
    (output / "keep.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        extract_apk_native.extract_native_libraries([apk], output)

    assert (output / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_rejects_duplicate_apk_basenames(tmp_path):
    first_dir = tmp_path / "one"
    second_dir = tmp_path / "two"
    first_dir.mkdir()
    second_dir.mkdir()
    first = first_dir / "base.apk"
    second = second_dir / "base.apk"
    _write_apk(first, [("lib/arm64-v8a/libone.so", b"one")])
    _write_apk(second, [("lib/arm64-v8a/libtwo.so", b"two")])

    with pytest.raises(ValueError, match="unique basenames"):
        extract_apk_native.extract_native_libraries(
            [first, second], tmp_path / "out"
        )


def test_rechecks_aggregate_extraction_limit(tmp_path, monkeypatch):
    apk = tmp_path / "base.apk"
    _write_apk(apk, [
        ("lib/arm64-v8a/libone.so", b"1234"),
        ("lib/arm64-v8a/libtwo.so", b"5678"),
    ])
    monkeypatch.setattr(extract_apk_native, "_MAX_TOTAL_NATIVE_BYTES", 7)

    with pytest.raises(ValueError, match="aggregate extraction limit"):
        extract_apk_native.extract_native_libraries([apk], tmp_path / "out")
