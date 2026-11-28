import hashlib
import struct
import zipfile

import pytest

from tools import inventory_apk_native


def _elf64_pie_candidate():
    interpreter = b"/system/bin/linker64\0"
    data = bytearray(120 + len(interpreter))
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        3, 183, 1,
        0x1000, 64, 0, 0,
        64, 56, 1, 64, 0, 0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        3, 4, 120, 0, 0,
        len(interpreter), len(interpreter), 1,
    )
    data[120:] = interpreter
    return bytes(data)


def test_inventory_hashes_and_classifies_native_members_across_splits(tmp_path):
    base = tmp_path / "base.apk"
    split = tmp_path / "split_config.arm64_v8a.apk"
    pie = _elf64_pie_candidate()
    with zipfile.ZipFile(base, "w") as archive:
        archive.writestr("lib/arm64-v8a/libengine.so", pie)
        archive.writestr("assets/not-native.bin", b"ignored")
    with zipfile.ZipFile(split, "w") as archive:
        archive.writestr("lib/x86/libbroken.so", b"not an ELF")

    report = inventory_apk_native.inventory_native_libraries([split, base])

    assert report["format"] == "apnawin-native-elf-inventory-v1"
    assert report["apk_count"] == 2
    assert report["native_library_count"] == 2
    assert report["executed"] is False
    engine = next(row for row in report["libraries"] if row["library"] == "libengine.so")
    assert engine["sha256"] == hashlib.sha256(pie).hexdigest()
    assert engine["elf"]["execution_model"] == "pie_executable_candidate"
    assert engine["elf"]["interpreter_present"] is True
    broken = next(row for row in report["libraries"] if row["library"] == "libbroken.so")
    assert broken["elf"] is None
    assert broken["elf_error"] == "native library is not an ELF file"
    assert broken["executed"] is False


def test_inventory_rejects_duplicate_archive_names(tmp_path):
    apk = tmp_path / "duplicate.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libone.so", b"one")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("lib/arm64-v8a/libone.so", b"two")
    with pytest.raises(ValueError, match="duplicate ZIP entry"):
        inventory_apk_native.inventory_native_libraries([apk])


def test_inventory_enforces_aggregate_native_size(tmp_path, monkeypatch):
    apk = tmp_path / "two-libs.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libone.so", b"1234")
        archive.writestr("lib/arm64-v8a/libtwo.so", b"5678")
    monkeypatch.setattr(inventory_apk_native, "_MAX_TOTAL_NATIVE_BYTES", 7)
    with pytest.raises(ValueError, match="aggregate analysis limit"):
        inventory_apk_native.inventory_native_libraries([apk])


def test_inventory_requires_at_least_one_apk():
    with pytest.raises(ValueError, match="input count"):
        inventory_apk_native.inventory_native_libraries([])
