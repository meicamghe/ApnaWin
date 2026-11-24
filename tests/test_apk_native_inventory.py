from __future__ import annotations

import io
import json
import zipfile

from tools.apk_native_inventory import inspect_path, inventory_zip


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_inventory_reports_target_hash_and_abi(tmp_path):
    sample = b"\\x7fELF" + b"sample-native-bytes"
    apk = tmp_path / "split_config.arm64_v8a.apk"
    apk.write_bytes(_zip_bytes({
        "lib/arm64-v8a/libudpqtwo.so": sample,
        "lib/arm64-v8a/libunrelated.so": b"not-an-elf",
        "assets/readme.txt": b"ignore",
    }))

    results = inspect_path(apk, None)
    target = next(item for item in results if item.get("target_match"))

    assert target["abi"] == "arm64-v8a"
    assert target["library_name"] == "libudpqtwo.so"
    assert target["sha256"] == __import__("hashlib").sha256(sample).hexdigest()
    assert target["elf_magic"] is True
    assert target["native_code_executed"] if "native_code_executed" in target else True


def test_inventory_finds_native_library_inside_nested_xapk(tmp_path):
    sample = b"\\x7fELF" + b"udp-thunder-sample"
    nested_apk = _zip_bytes({"lib/arm64-v8a/libudpqtwo.so": sample})
    xapk = tmp_path / "udp-thunder-1.1.xapk"
    xapk.write_bytes(_zip_bytes({
        "manifest.json": json.dumps({"package_name": "com.udpthunder.vpn"}).encode(),
        "config.arm64_v8a.apk": nested_apk,
    }))

    results = inspect_path(xapk, None)
    target = next(item for item in results if item.get("target_match"))

    assert target["nested_apk"] == "config.arm64_v8a.apk"
    assert target["abi"] == "arm64-v8a"
    assert target["sha256"] == __import__("hashlib").sha256(sample).hexdigest()


def test_inventory_extracts_only_to_explicit_directory(tmp_path):
    sample = b"\\x7fELF" + b"native"
    apk = tmp_path / "split.apk"
    apk.write_bytes(_zip_bytes({"lib/arm64-v8a/libudpqtwo.so": sample}))
    output = tmp_path / "extracted"

    results = inspect_path(apk, output)
    target = next(item for item in results if item.get("target_match"))

    extracted = output / target["extracted_to"].split("/")[-1]
    assert extracted.read_bytes() == sample
    assert extracted.parent == output


def test_inventory_ignores_non_library_archive_members():
    results = inventory_zip(_zip_bytes({
        "assets/libudpqtwo.so": b"not-in-a-lib-abi-directory",
        "lib/arm64-v8a/not-a-library.txt": b"ignore",
    }), "fixture.apk", None)

    assert results == []
