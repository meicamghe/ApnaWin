from __future__ import annotations

import struct

import pytest

from tools.recover_go_pclntab import recover_go_pclntab


def _synthetic_go_elf(*, magic: int = 0x12345678) -> bytes:
    data = bytearray(0x1100)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        b"\x7fELF" + bytes([2, 1, 1]) + bytes(9),
        3, 183, 1, 0x2000, 64, 0, 0, 64, 56, 1, 0, 0, 0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x100, 0x1000, 0, 0x1000, 0x1000, 0x1000)
    pclntab_offset = 0x200
    header = bytearray(72)
    struct.pack_into("<I", header, 0, magic)
    header[4:8] = bytes([0, 0, 1, 8])
    struct.pack_into("<8Q", header, 8, 2, 1, 0x1800, 0x60, 0x80, 0x90, 0xA0, 0xC0)
    data[pclntab_offset:pclntab_offset + len(header)] = header
    data[pclntab_offset + 0x60:pclntab_offset + 0x60 + 24] = b"main.main\0runtime.goexit\0"
    struct.pack_into("<IIIII", data, pclntab_offset + 0xC0, 0, 0xE0, 0x10, 0xF0, 0x20)
    struct.pack_into("<Ii", data, pclntab_offset + 0xC0 + 0xE0, 0, 0)
    struct.pack_into("<Ii", data, pclntab_offset + 0xC0 + 0xF0, 0x10, 10)
    return bytes(data)


def test_recovers_go118_function_table_and_names_from_stomped_header():
    report = recover_go_pclntab(_synthetic_go_elf(), 0x1100, allow_stomped_magic=True)
    assert report["magic_stomped"] is True
    assert report["nfunc"] == 2
    assert report["functab_va"] == "0x11c0"
    assert [row["name"] for row in report["functions"]] == [
        "main.main",
        "runtime.goexit",
    ]
    assert report["terminal_entry_offset"] == 0x20
    assert report["binary_executed"] is False


def test_rejects_stomped_magic_without_explicit_opt_in():
    with pytest.raises(ValueError, match="stomped-magic"):
        recover_go_pclntab(_synthetic_go_elf(), 0x1100)


def test_rejects_invalid_pclntab_header_byte_fields():
    data = bytearray(_synthetic_go_elf())
    data[0x204] = 1
    with pytest.raises(ValueError, match="byte fields"):
        recover_go_pclntab(bytes(data), 0x1100, allow_stomped_magic=True)


def test_rejects_functab_outside_file_backed_load_segment():
    data = bytearray(_synthetic_go_elf())
    struct.pack_into("<Q", data, 0x240, 0x1000)
    with pytest.raises(ValueError, match="PT_LOAD|file-backed"):
        recover_go_pclntab(bytes(data), 0x1100, allow_stomped_magic=True)


def test_rejects_non_monotonic_function_entries():
    data = bytearray(_synthetic_go_elf())
    struct.pack_into("<I", data, 0x2C0, 0x10)
    struct.pack_into("<I", data, 0x2C8, 0)
    with pytest.raises(ValueError, match="strictly increasing"):
        recover_go_pclntab(bytes(data), 0x1100, allow_stomped_magic=True)



def test_rejects_function_name_offset_outside_funcnametab():
    data = bytearray(_synthetic_go_elf())
    # First _func.nameOff is signed and must remain inside [funcnameOff, cuOff).
    struct.pack_into("<i", data, 0x3A4, 0x80)
    with pytest.raises(ValueError, match="funcnametab"):
        recover_go_pclntab(bytes(data), 0x1100, allow_stomped_magic=True)


def test_rejects_function_entry_outside_executable_segment():
    data = bytearray(_synthetic_go_elf())
    # Second function entry is relative to textStart and must map to PF_X memory.
    struct.pack_into("<I", data, 0x2C8, 0x900)
    with pytest.raises(ValueError, match="executable"):
        recover_go_pclntab(bytes(data), 0x1100, allow_stomped_magic=True)


def test_rejects_ambiguous_overlapping_load_mapping():
    data = bytearray(_synthetic_go_elf())
    # Add a second overlapping PT_LOAD header; the table must not be read from
    # an arbitrary first matching segment.
    struct.pack_into("<IIQQQQQQ", data, 64 + 56, 1, 5, 0x100, 0x1000, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<H", data, 64 + 40, 56)
    struct.pack_into("<H", data, 64 + 44, 2)
    with pytest.raises(ValueError, match="unique file-backed"):
        recover_go_pclntab(bytes(data), 0x1100, allow_stomped_magic=True)
