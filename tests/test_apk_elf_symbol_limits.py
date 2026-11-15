"""Resource-limit regression tests for static ELF symbol tables."""
import struct

import pytest

from apnawin.services.apk_elf import inspect_elf_bytes


@pytest.mark.parametrize("elf_class", [32, 64])
def test_inspect_elf_rejects_excessive_static_symbol_count(elf_class):
    if elf_class == 64:
        ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
        header_fmt = "<16sHHIQQQIHHHHHH"
        section_fmt = "<IIQQQQIIQQ"
        word_fmt = "<Q"
        header_size, section_size, symbol_size, alignment = 64, 64, 24, 8
        shoff_field, shnum_field = 40, 60
        header = struct.pack(
            header_fmt, ident, 3, 183, 1, 0, 0, 0, 0,
            header_size, 0, 0, section_size, 4, 0,
        )
    else:
        ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
        header_fmt = "<16sHHIIIIIHHHHHH"
        section_fmt = "<IIIIIIIIII"
        word_fmt = "<I"
        header_size, section_size, symbol_size, alignment = 52, 40, 16, 4
        shoff_field, shnum_field = 32, 48
        header = struct.pack(
            header_fmt, ident, 3, 40, 1, 0, 0, 0, 0,
            header_size, 0, 0, section_size, 4, 0,
        )

    base_sections = [
        bytes(section_size),
        struct.pack(section_fmt, 0, 3, 0, 0, header_size, 1, 0, 0, 1, 0),
        struct.pack(section_fmt, 0, 11, 0, 0, header_size + 1, symbol_size * 1, 1, 1, alignment, symbol_size),
        struct.pack(section_fmt, 0, 3, 0, 0, header_size + 1 + symbol_size, 1, 0, 0, 1, 0),
    ]
    # Replace the dynamic table with a minimal, valid-sized one-symbol table.
    # The dynamic table is not needed for this test; retain the section shape
    # but point it at the one-byte string table and keep its entry count zero.
    payload = bytearray(header)
    payload.extend(b"\x00")
    payload.extend(bytes(section_size * 4))
    original_shoff = len(payload) - section_size * 4
    struct.pack_into(word_fmt, payload, shoff_field, original_shoff)
    payload.extend(b"\x00")
    static_strings_offset = len(payload)
    payload.extend(b"\x00")
    padding = (-len(payload)) % alignment
    payload.extend(bytes(padding))
    static_symbols_offset = len(payload)
    symbol_count = 262145
    payload.extend(bytes(symbol_count * symbol_size))
    new_shoff = (len(payload) + alignment - 1) // alignment * alignment
    payload.extend(bytes(new_shoff - len(payload)))
    sections = [
        bytes(section_size),
        struct.pack(section_fmt, 0, 3, 0, 0, header_size, 1, 0, 0, 1, 0),
        struct.pack(section_fmt, 0, 11, 0, 0, header_size + 1, symbol_size, 1, 1, alignment, symbol_size),
        struct.pack(section_fmt, 0, 3, 0, 0, header_size + 1 + symbol_size, 1, 0, 0, 1, 0),
        struct.pack(section_fmt, 0, 3, 0, 0, static_strings_offset, 1, 0, 0, 1, 0),
        struct.pack(section_fmt, 0, 2, 0, 0, static_symbols_offset, symbol_count * symbol_size, 4, 1, alignment, symbol_size),
    ]
    payload.extend(b"".join(sections))
    struct.pack_into(word_fmt, payload, shoff_field, new_shoff)
    struct.pack_into("<H", payload, shnum_field, len(sections))
    with pytest.raises(ValueError, match="ELF static symbol count exceeds the analysis limit"):
        inspect_elf_bytes(bytes(payload))
