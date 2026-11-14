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


def test_inspect_elf_bytes_ignores_non_function_jni_named_symbols():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynsym_offset = struct.unpack_from("<Q", data, section_offset + 2 * 64 + 24)[0]
    # The fixture's second and third symbols are JNI_OnLoad and Java_... .
    data[dynsym_offset + 24 + 4] = 0x11
    data[dynsym_offset + 48 + 4] = 0x11
    result = inspect_elf_bytes(bytes(data))
    assert result["dynamic_symbol_count"] == 4
    assert result["jni_exported_symbol_count"] == 0
    assert result["jni_onload_exported"] is False


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


def test_inspect_elf_bytes_supports_extended_section_count():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    # e_shnum = 0 means the real count is stored in section-zero sh_size.
    struct.pack_into("<H", data, 60 + 4, 0)
    struct.pack_into("<Q", data, section_offset + 32, 4)
    result = inspect_elf_bytes(bytes(data))
    assert result["dynamic_symbol_table_present"] is True
    assert result["dynamic_symbol_count"] == 4
    assert result["jni_exported_symbol_count"] == 1
    assert result["jni_onload_exported"] is True


def test_inspect_elf_bytes_rejects_invalid_extended_section_count():
    ident = b"\\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    section = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 4097, 0, 0, 0, 0)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 3, 183, 1, 0, 0, 64, 0, 64, 0, 0, 64, 0, 0,
    )
    with pytest.raises(ValueError, match="extended section count"):
        inspect_elf_bytes(header + section)


@pytest.mark.parametrize("payload", [b"", b"not-elf", b"\\x7fELF"])
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


def test_inspect_elf_bytes_rejects_oversized_dynamic_symbol_table():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynsym_header = section_offset + 2 * 64
    struct.pack_into("<Q", data, dynsym_header + 32, 16 * 1024 * 1024 + 24)
    with pytest.raises(ValueError, match="exceeds the analysis limit"):
        inspect_elf_bytes(bytes(data))


def test_inspect_elf_bytes_rejects_non_string_dynamic_symbol_link():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynsym_header = section_offset + 2 * 64
    struct.pack_into("<I", data, dynsym_header + 40, 2)
    with pytest.raises(ValueError, match="invalid section type"):
        inspect_elf_bytes(bytes(data))



@pytest.mark.parametrize(
    ("abi", "elf_class", "machine"),
    [("armeabi-v7a", 32, 40), ("arm64-v8a", 64, 183),
     ("x86", 32, 3), ("x86_64", 64, 62)],
)
def test_android_abi_mapping_checks_class_machine_and_endianness(abi, elf_class, machine):
    from apnawin.services.apk_elf import _abi_compatibility

    parsed = {"elf_valid": True, "elf_class": elf_class, "machine": machine, "endianness": "little"}
    assert _abi_compatibility(abi, parsed) == {
        "abi_compatible": True, "abi_compatibility_status": "compatible"
    }


def test_android_abi_mapping_rejects_wrong_identity_and_big_endian():
    from apnawin.services.apk_elf import _abi_compatibility

    assert _abi_compatibility("arm64-v8a", {
        "elf_valid": True, "elf_class": 32, "machine": 40, "endianness": "little"
    })["abi_compatibility_status"] == "mismatch"
    assert _abi_compatibility("arm64-v8a", {
        "elf_valid": True, "elf_class": 64, "machine": 183, "endianness": "big"
    })["abi_compatibility_status"] == "mismatch"


def test_android_abi_mapping_keeps_unknown_and_invalid_unclassified():
    from apnawin.services.apk_elf import _abi_compatibility

    assert _abi_compatibility("vendor-abi", {
        "elf_valid": True, "elf_class": 64, "machine": 183, "endianness": "little"
    }) == {"abi_compatible": None, "abi_compatibility_status": "unknown_abi"}
    assert _abi_compatibility("arm64-v8a", {"elf_valid": False}) == {
        "abi_compatible": None, "abi_compatibility_status": "not_checked"
    }


def test_native_library_report_includes_abi_compatibility_counts(tmp_path):
    apk = tmp_path / "abi.apk"
    payload = _elf64_with_jni_exports()
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libgood.so", payload)
        archive.writestr("lib/x86_64/libwrong.so", payload)
        archive.writestr("lib/vendor-abi/libunknown.so", payload)
        archive.writestr("lib/arm64-v8a/libbroken.so", b"not ELF")
    result = inspect_apk_native_libraries(apk, [
        {"abi": "arm64-v8a", "library_name": "libgood.so", "file_size_bytes": len(payload)},
        {"abi": "x86_64", "library_name": "libwrong.so", "file_size_bytes": len(payload)},
        {"abi": "vendor-abi", "library_name": "libunknown.so", "file_size_bytes": len(payload)},
        {"abi": "arm64-v8a", "library_name": "libbroken.so", "file_size_bytes": 7},
    ])
    assert result["abi_compatibility_counts"] == {
        "compatible": 1, "mismatch": 1, "unknown_abi": 1, "not_checked": 1
    }
    assert result["abi_mismatch_count"] == 1


def _elf32_minimal(machine):
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    return struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 3, machine, 1, 0, 0, 0, 0, 52, 0, 0, 40, 0, 0,
    )


@pytest.mark.parametrize(("abi", "machine"), [("armeabi-v7a", 40), ("x86", 3)])
def test_inspect_real_elf32_identity_matches_32_bit_android_abi(abi, machine):
    from apnawin.services.apk_elf import _abi_compatibility

    parsed = inspect_elf_bytes(_elf32_minimal(machine))
    assert parsed["elf_class"] == 32
    assert parsed["machine"] == machine
    assert _abi_compatibility(abi, parsed) == {
        "abi_compatible": True, "abi_compatibility_status": "compatible"
    }
