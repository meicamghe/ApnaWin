from __future__ import annotations

import struct

import pytest

from tools.recover_go_pclntab import recover_go_pclntab


def _fixture(*, magic: int = 0x12345678) -> bytes:
    data = bytearray(0x1800)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", data, 0,
        b"\x7fELF" + bytes([2, 1, 1]) + bytes(9),
        3, 183, 1, 0x1000, 64, 0, 0, 64, 56, 2, 0, 0, 0,
    )
    # Read-only metadata at VA 0x1000; executable text at VA 0x3000.
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 0x200, 0x1000, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<IIQQQQQQ", data, 120, 1, 5, 0x1200, 0x3000, 0, 0x400, 0x400, 0x1000)
    p = 0x200
    h = bytearray(72)
    struct.pack_into("<I", h, 0, magic)
    h[4:8] = bytes([0, 0, 1, 8])
    struct.pack_into("<8Q", h, 8, 2, 1, 0x3000, 0x60, 0x80, 0x90, 0xA0, 0xC0)
    data[p:p + 72] = h
    data[p + 0x60:p + 0x60 + 32] = b"main.main\0runtime.goexit\0\0\0"
    # functab at 0x10c0; func records at 0x10e0 and 0x10f0.
    struct.pack_into("<IIIII", data, p + 0xC0, 0, 0xE0, 0x10, 0xF0, 0x20)
    struct.pack_into("<Ii", data, p + 0xE0, 0, 0)
    struct.pack_into("<Ii", data, p + 0xF0, 0x10, 10)
    # executable bytes cover [0x3000, 0x3400).
    return bytes(data)


def test_recovers_names_and_checks_executable_entries():
    report = recover_go_pclntab(_fixture(), 0x1000, allow_stomped_magic=True)
    assert report["format"].endswith("v2")
    assert report["nfunc"] == 2
    assert [f["name"] for f in report["functions"]] == ["main.main", "runtime.goexit"]
    assert report["binary_executed"] is False


def test_stomped_magic_requires_opt_in():
    with pytest.raises(ValueError, match="stomped-magic"):
        recover_go_pclntab(_fixture(), 0x1000)


def test_name_offset_cannot_escape_funcnametab():
    data = bytearray(_fixture())
    struct.pack_into("<i", data, 0x2E4, 0x100)  # first _func.nameOff
    with pytest.raises(ValueError, match="funcnametab"):
        recover_go_pclntab(bytes(data), 0x1000, allow_stomped_magic=True)


def test_function_entry_must_be_executable():
    data = bytearray(_fixture())
    struct.pack_into("<Q", data, 0x218, 0x1000)  # textStart points at metadata
    with pytest.raises(ValueError, match="executable"):
        recover_go_pclntab(bytes(data), 0x1000, allow_stomped_magic=True)


def test_rejects_ambiguous_overlapping_va_mappings():
    data = bytearray(_fixture())
    # Make the second PT_LOAD overlap the metadata VA interval.
    struct.pack_into("<Q", data, 120 + 16, 0x1000)
    with pytest.raises(ValueError, match="ambiguous"):
        recover_go_pclntab(bytes(data), 0x1000, allow_stomped_magic=True)
