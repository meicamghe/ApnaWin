import struct
import zipfile
import pytest
from apnawin.services.apk_elf import inspect_elf_bytes, inspect_apk_native_libraries


def _elf64_with_jni_exports():
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    dynstr = b"\x00JNI_OnLoad\x00Java_org_example_Tunnel_start\x00ordinary\x00"
    names = {
        "jni_onload": dynstr.index(b"JNI_OnLoad"),
        "jni_method": dynstr.index(b"Java_org_example_Tunnel_start"),
        "ordinary": dynstr.index(b"ordinary"),
    }
    symbols = [bytes(24)]
    for key in ("jni_onload", "jni_method", "ordinary"):
        symbols.append(struct.pack("<IBBHQQ", names[key], 0x12, 0, 1, 0, 0))
    dynsym = b"".join(symbols)
    shstr = b"\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
    dynstr_offset = 64
    dynsym_offset = dynstr_offset + len(dynstr)
    shstr_offset = dynsym_offset + len(dynsym)
    section_offset = (shstr_offset + len(shstr) + 7) & ~7
    sections = [
        bytes(64),
        struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, dynstr_offset, len(dynstr), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 9, 11, 0, 0, dynsym_offset, len(dynsym), 1, 1, 8, 24),
        struct.pack("<IIQQQQIIQQ", 17, 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0),
    ]
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 3, 183, 1, 0, 0, section_offset, 0, 64, 0, 0, 64, 4, 3,
    )
    return header + dynstr + dynsym + shstr + bytes(section_offset - shstr_offset - len(shstr)) + b"".join(sections)


def test_inspect_elf_bytes_counts_only_exported_jni_symbol_names():
    result = inspect_elf_bytes(_elf64_with_jni_exports())
    assert result == {
        "elf_valid": True, "elf_class": 64, "endianness": "little",
        "machine": 183, "machine_name": "aarch64", "file_type": 3,
        "dynamic_symbol_table_present": True, "dynamic_symbol_count": 4,
        "jni_exported_symbol_count": 1, "jni_onload_exported": True,
        "inspection_status": "complete",
    }
    assert "Java_org_example_Tunnel_start" not in str(result)
    assert "JNI_OnLoad" not in str(result)


def test_inspect_elf_bytes_reports_no_dynamic_symbol_table():
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", ident, 3, 183, 1, 0, 0, 64, 0, 64, 0, 0, 64, 1, 0,
    )
    result = inspect_elf_bytes(header + bytes(64))
    assert result["elf_valid"] is True
    assert result["dynamic_symbol_table_present"] is False
    assert result["jni_exported_symbol_count"] is None
    assert result["inspection_status"] == "no_dynamic_symbol_table"


@pytest.mark.parametrize("payload", [b"", b"not-elf", b"\x7fELF"])
def test_inspect_elf_bytes_rejects_non_elf_or_truncated_input(payload):
    with pytest.raises(ValueError):
        inspect_elf_bytes(payload)


def test_inspect_elf_bytes_rejects_out_of_bounds_section_table():
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", ident, 3, 183, 1, 0, 0, 4096, 0, 64, 0, 0, 64, 1, 0,
    )
    with pytest.raises(ValueError, match="out of bounds"):
        inspect_elf_bytes(header)



def test_inspect_apk_native_libraries_reads_only_bounded_metadata(tmp_path):
    apk = tmp_path / "native.apk"
    payload = _elf64_with_jni_exports()
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libengine.so", payload)
    result = inspect_apk_native_libraries(
        apk,
        [{"abi": "arm64-v8a", "library_name": "libengine.so", "file_size_bytes": len(payload)}],
    )
    assert result["libraries_inspected"] == 1
    assert result["jni_exported_library_count"] == 1
    assert result["jni_onload_library_count"] == 1
    assert result["bytes_read_in_memory"] == len(payload)
    assert result["archive_members_written"] is False
    assert result["native_code_executed"] is False
    assert result["raw_symbol_names_included"] is False


def test_inspect_apk_native_libraries_marks_non_elf_as_unreadable(tmp_path):
    apk = tmp_path / "not-elf.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libfake.so", b"not an ELF")
    result = inspect_apk_native_libraries(
        apk,
        [{"abi": "arm64-v8a", "library_name": "libfake.so", "file_size_bytes": 10}],
    )
    assert result["libraries"][0]["inspection_status"] == "invalid_or_unreadable"
    assert result["libraries_inspected"] == 0
    assert result["skipped_library_count"] == 1
    assert result["jni_exported_library_count"] == 0
