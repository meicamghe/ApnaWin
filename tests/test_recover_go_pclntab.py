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
    names = b"main.main\0runtime.goexit\0\0\0"
    data[p + 0x60:p + 0x60 + len(names)] = names
    # functab at 0x10c0; func offsets are relative to pclnOffset (0xC0).
    # The two _func records follow the 20-byte functab.
    struct.pack_into("<IIIII", data, p + 0xC0, 0, 0x14, 0x10, 0x24, 0x20)
    struct.pack_into("<Ii", data, p + 0xD4, 0, 0)
    struct.pack_into("<Ii", data, p + 0xE4, 0x10, 10)
    # executable bytes cover [0x3000, 0x3400).
    return bytes(data)


def test_recovers_names_and_checks_executable_entries():
    report = recover_go_pclntab(_fixture(), 0x1000, allow_stomped_magic=True)
    assert report["format"].endswith("v3")
    assert report["nfunc"] == 2
    assert [f["name"] for f in report["functions"]] == ["main.main", "runtime.goexit"]
    assert report["binary_executed"] is False



def _fixture_with_zero_text_start(*, include_symbol: bool = True) -> bytes:
    data = bytearray(_fixture(magic=0xFFFFFFF1))
    # The ELF .text section may begin with a native entry stub. Anchor Go text
    # from a defined function symbol whose size matches its pclntab PC range.
    struct.pack_into("<Q", data, 0x218, 0)
    if not include_symbol:
        return bytes(data)
    struct.pack_into("<Q", data, 40, 0x1600)  # e_shoff
    struct.pack_into("<HHH", data, 58, 64, 5, 2)  # e_shentsize, e_shnum, e_shstrndx
    struct.pack_into(
        "<IIQQQQIIQQ", data, 0x1600 + 64,
        1, 1, 0x6, 0x3000, 0x1200, 0x400, 0, 0, 16, 0,
    )
    shstr = b"\\0.text\\0.shstrtab\\0.dynsym\\0.dynstr\\0"
    data[0x1740:0x1740 + len(shstr)] = shstr
    struct.pack_into(
        "<IIQQQQIIQQ", data, 0x1600 + 128,
        7, 3, 0, 0, 0x1740, len(shstr), 0, 0, 1, 0,
    )
    struct.pack_into(
        "<IIQQQQIIQQ", data, 0x1600 + 192,
        17, 11, 2, 0, 0x1768, 48, 4, 1, 8, 24,
    )
    struct.pack_into(
        "<IIQQQQIIQQ", data, 0x1600 + 256,
        25, 3, 0, 0, 0x1798, 10, 0, 0, 1, 0,
    )
    # One null symbol followed by global FUNC main.main at VA 0x3010, size 16.
    struct.pack_into("<IBBHQQ", data, 0x1780, 1, 0x12, 0, 1, 0x3010, 16)
    data[0x1798:0x17A2] = b"\\0main.main\\0"
    return bytes(data)


def test_zero_text_start_uses_matching_elf_function_symbol_anchor():
    report = recover_go_pclntab(_fixture_with_zero_text_start(), 0x1000)
    assert report["text_start"] == "0x0"
    assert report["resolved_text_start"] == "0x3010"
    assert report["text_start_resolution"] == "elf-function-symbol-anchor"
    assert [f["name"] for f in report["functions"]] == ["main.main", "runtime.goexit"]


def test_zero_text_start_without_symbol_anchor_fails_closed():
    with pytest.raises(ValueError, match="unique matching function-symbol anchor"):
        recover_go_pclntab(_fixture_with_zero_text_start(include_symbol=False), 0x1000)


def test_stomped_magic_requires_opt_in():
    with pytest.raises(ValueError, match="stomped-magic"):
        recover_go_pclntab(_fixture(), 0x1000)


def test_name_offset_cannot_escape_funcnametab():
    data = bytearray(_fixture())
    struct.pack_into("<i", data, 0x2D8, 0x100)  # first _func.nameOff
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


def test_rejects_function_name_crossing_partial_segment_overlap():
    data = bytearray(_fixture())
    # A second PT_LOAD overlaps only the tail of the function-name table.
    struct.pack_into("<Q", data, 120 + 16, 0x1068)
    struct.pack_into("<Q", data, 120 + 32, 0x10)
    struct.pack_into("<Q", data, 120 + 40, 0x10)
    with pytest.raises(ValueError, match="ambiguous"):
        recover_go_pclntab(bytes(data), 0x1000, allow_stomped_magic=True)
