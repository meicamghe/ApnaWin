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



def _elf32_with_jni_exports():
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    dynstr = b"\x00JNI_OnLoad\x00Java_org_example_Tunnel_start\x00ordinary\x00"
    names = {
        "jni_onload": dynstr.index(b"JNI_OnLoad"),
        "jni_method": dynstr.index(b"Java_org_example_Tunnel_start"),
        "ordinary": dynstr.index(b"ordinary"),
    }
    symbols = [bytes(16)]
    for key in ("jni_onload", "jni_method", "ordinary"):
        symbols.append(struct.pack("<IIIBBH", names[key], 0, 0, 0x12, 0, 1))
    dynsym = b"".join(symbols)
    shstr = b"\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
    dynstr_offset = 52
    dynsym_offset = dynstr_offset + len(dynstr)
    shstr_offset = dynsym_offset + len(dynsym)
    section_offset = (shstr_offset + len(shstr) + 3) & ~3
    sections = [
        bytes(40),
        struct.pack("<IIIIIIIIII", 1, 3, 0, 0, dynstr_offset, len(dynstr), 0, 0, 1, 0),
        struct.pack("<IIIIIIIIII", 9, 11, 0, 0, dynsym_offset, len(dynsym), 1, 1, 4, 16),
        struct.pack("<IIIIIIIIII", 17, 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0),
    ]
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 3, 40, 1, 0, 0, section_offset, 0, 52, 0, 0, 40, 4, 3,
    )
    return header + dynstr + dynsym + shstr + bytes(section_offset - shstr_offset - len(shstr)) + b"".join(sections)


def _elf_with_symtab_shndx(
    payload, elf_class, *, link=2, info=0, entry_size=4,
    table_size=None, word_values=None, xindex_symbol=False,
):
    data = bytearray(payload)
    section_offset_field = 40 if elf_class == 64 else 32
    section_count_field = 60 if elf_class == 64 else 48
    section_size = 64 if elf_class == 64 else 40
    section_fmt = "<IIQQQQIIQQ" if elf_class == 64 else "<IIIIIIIIII"
    word_format = "<Q" if elf_class == 64 else "<I"
    section_offset = struct.unpack_from(word_format, data, section_offset_field)[0]
    symbol_header_offset = section_offset + 2 * section_size
    symbol_offset_field = 24 if elf_class == 64 else 16
    symbol_entry_size = 24 if elf_class == 64 else 16
    symbol_data_offset = struct.unpack_from(word_format, data, symbol_header_offset + symbol_offset_field)[0]
    symbol_count = 4
    if xindex_symbol:
        struct.pack_into("<H", data, symbol_data_offset + symbol_entry_size + (6 if elf_class == 64 else 14), 0xFFFF)
    actual_size = symbol_count * 4 if table_size is None else table_size
    values = [0] * symbol_count if word_values is None else list(word_values)
    actual_offset = len(data) + section_size
    payload_bytes = b"".join(struct.pack("<I", value) for value in values)
    if len(payload_bytes) < actual_size:
        payload_bytes += bytes(actual_size - len(payload_bytes))
    else:
        payload_bytes = payload_bytes[:actual_size]
    header = struct.pack(
        section_fmt, 0, 18, 0, 0, actual_offset, actual_size,
        link, info, 4, entry_size,
    )
    struct.pack_into("<H", data, section_count_field, 5)
    data.extend(header)
    data.extend(payload_bytes)
    return bytes(data)


def _elf_with_dynamic_section(
    payload, elf_class, *, link=1, info=0, entry_size=None, dynamic_size=None,
    data_offset=None, dynamic_tag=0,
):
    data = bytearray(payload)
    section_count_field = 60 if elf_class == 64 else 48
    section_size = 64 if elf_class == 64 else 40
    section_fmt = "<IIQQQQIIQQ" if elf_class == 64 else "<IIIIIIIIII"
    record_size = 16 if elf_class == 64 else 8
    tag_format = "<q" if elf_class == 64 else "<i"
    record = struct.pack(tag_format, dynamic_tag) + bytes(record_size - struct.calcsize(tag_format))
    actual_size = record_size if dynamic_size is None else dynamic_size
    actual_offset = len(data) + section_size if data_offset is None else data_offset
    header = struct.pack(
        section_fmt, 0, 6, 0, 0, actual_offset, actual_size,
        link, info, record_size, record_size if entry_size is None else entry_size,
    )
    struct.pack_into("<H", data, section_count_field, 5)
    data.extend(header)
    if data_offset is None:
        data.extend(record[:actual_size].ljust(actual_size, b"\x00"))
    return bytes(data)


def _elf_with_hash_section(
    payload, elf_class, *, link=2, info=0, entry_size=4,
    bucket_count=1, chain_count=4, words=None, data_offset=None,
):
    data = bytearray(payload)
    section_count_field = 60 if elf_class == 64 else 48
    section_size = 64 if elf_class == 64 else 40
    section_fmt = "<IIQQQQIIQQ" if elf_class == 64 else "<IIIIIIIIII"
    actual_words = [1, 0, 2, 3, 0] if words is None else list(words)
    hash_payload = struct.pack("<II", bucket_count, chain_count)
    hash_payload += b"".join(struct.pack("<I", value) for value in actual_words)
    actual_offset = len(data) + section_size if data_offset is None else data_offset
    header = struct.pack(
        section_fmt, 0, 5, 0, 0, actual_offset, len(hash_payload),
        link, info, 4, entry_size,
    )
    struct.pack_into("<H", data, section_count_field, 5)
    data.extend(header)
    if data_offset is None:
        data.extend(hash_payload)
    return bytes(data)



def _elf_with_gnu_hash_section(
    payload, elf_class, *, link=2, info=0, alignment=None, entry_size=None,
    bucket_count=1, symbol_offset=1, bloom_count=1, bloom_shift=5,
    buckets=None, chains=None, data_offset=None,
):
    data = bytearray(payload)
    section_count_field = 60 if elf_class == 64 else 48
    section_size = 64 if elf_class == 64 else 40
    section_fmt = "<IIQQQQIIQQ" if elf_class == 64 else "<IIIIIIIIII"
    bloom_word_size = 8 if elf_class == 64 else 4
    actual_alignment = bloom_word_size if alignment is None else alignment
    actual_entry_size = (0 if elf_class == 64 else 4) if entry_size is None else entry_size
    actual_buckets = [1] if buckets is None else list(buckets)
    actual_chains = [2, 4, 5] if chains is None else list(chains)
    hash_payload = struct.pack(
        "<IIII", bucket_count, symbol_offset, bloom_count, bloom_shift
    )
    hash_payload += bytes(bloom_word_size * bloom_count)
    hash_payload += b"".join(struct.pack("<I", value) for value in actual_buckets)
    hash_payload += b"".join(struct.pack("<I", value) for value in actual_chains)
    actual_offset = len(data) + section_size if data_offset is None else data_offset
    header = struct.pack(
        section_fmt, 0, 0x6FFFFFF6, 0, 0, actual_offset, len(hash_payload),
        link, info, actual_alignment, actual_entry_size,
    )
    struct.pack_into("<H", data, section_count_field, 5)
    data.extend(header)
    if data_offset is None:
        data.extend(hash_payload)
    return bytes(data)


def _elf_with_relr_section(payload, elf_class, *, file_type=3, entry_size=None, relr_size=None, relr_offset=None):
    data = bytearray(payload)
    section_offset_field = 40 if elf_class == 64 else 32
    section_count_field = 60 if elf_class == 64 else 48
    section_size = 64 if elf_class == 64 else 40
    section_fmt = "<IIQQQQIIQQ" if elf_class == 64 else "<IIIIIIIIII"
    word_size = 8 if elf_class == 64 else 4
    section_offset = struct.unpack_from(
        "<Q" if elf_class == 64 else "<I", data, section_offset_field
    )[0]
    struct.pack_into("<H", data, 16, file_type)
    actual_entry_size = word_size if entry_size is None else entry_size
    actual_relr_size = word_size if relr_size is None else relr_size
    actual_relr_offset = len(data) + section_size if relr_offset is None else relr_offset
    relr_header = struct.pack(
        section_fmt, 0, 19, 0, 0, actual_relr_offset, actual_relr_size,
        0, 0, word_size, actual_entry_size,
    )
    struct.pack_into("<H", data, section_count_field, 5)
    data.extend(relr_header)
    if relr_offset is None:
        data.extend(bytes(actual_relr_size))
    return bytes(data)


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_accepts_valid_relr_section(payload, elf_class):
    result = inspect_elf_bytes(_elf_with_relr_section(payload, elf_class))
    assert result["inspection_status"] == "complete"


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_relr_in_relocatable_file(payload, elf_class):
    with pytest.raises(ValueError, match="only valid in ET_EXEC or ET_DYN"):
        inspect_elf_bytes(_elf_with_relr_section(payload, elf_class, file_type=1))


@pytest.mark.parametrize(
    ("payload", "elf_class", "entry_size", "relr_size"),
    [
        (_elf64_with_jni_exports(), 64, 4, 8),
        (_elf32_with_jni_exports(), 32, 8, 4),
        (_elf64_with_jni_exports(), 64, 8, 7),
        (_elf32_with_jni_exports(), 32, 4, 3),
    ],
)
def test_inspect_elf_rejects_invalid_relr_entry_metadata(
    payload, elf_class, entry_size, relr_size
):
    with pytest.raises(ValueError, match="SHT_RELR entry metadata is invalid"):
        inspect_elf_bytes(
            _elf_with_relr_section(
                payload, elf_class, entry_size=entry_size, relr_size=relr_size
            )
        )


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_out_of_bounds_relr_data(payload, elf_class):
    with pytest.raises(ValueError, match="SHT_RELR data is out of bounds"):
        inspect_elf_bytes(
            _elf_with_relr_section(
                payload, elf_class, relr_offset=0x7FFFFFFF
            )
        )


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_accepts_valid_symtab_shndx(payload, elf_class):
    result = inspect_elf_bytes(_elf_with_symtab_shndx(payload, elf_class))
    assert result["inspection_status"] == "complete"


@pytest.mark.parametrize(
    ("payload", "elf_class", "kwargs", "message"),
    [
        (_elf64_with_jni_exports(), 64, {"link": 3}, "invalid symbol-table reference"),
        (_elf32_with_jni_exports(), 32, {"link": 3}, "invalid symbol-table reference"),
        (_elf64_with_jni_exports(), 64, {"info": 1}, "sh_info must be zero"),
        (_elf32_with_jni_exports(), 32, {"info": 1}, "sh_info must be zero"),
        (_elf64_with_jni_exports(), 64, {"entry_size": 8}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"entry_size": 8}, "entry metadata is invalid"),
        (_elf64_with_jni_exports(), 64, {"table_size": 12}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"table_size": 12}, "entry metadata is invalid"),
    ],
)
def test_inspect_elf_rejects_invalid_symtab_shndx_metadata(
    payload, elf_class, kwargs, message
):
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(_elf_with_symtab_shndx(payload, elf_class, **kwargs))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_nonzero_unused_symtab_shndx_entry(payload, elf_class):
    with pytest.raises(ValueError, match="unused extended symbol index"):
        inspect_elf_bytes(
            _elf_with_symtab_shndx(
                payload, elf_class, word_values=[0, 1, 0, 0]
            )
        )


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_xindex_symbol_without_symtab_shndx(payload, elf_class):
    data = bytearray(payload)
    section_offset = struct.unpack_from(
        "<Q" if elf_class == 64 else "<I", data, 40 if elf_class == 64 else 32
    )[0]
    symbol_offset = struct.unpack_from(
        "<Q" if elf_class == 64 else "<I",
        data,
        section_offset + 2 * (64 if elf_class == 64 else 40) + (24 if elf_class == 64 else 16),
    )[0]
    struct.pack_into(
        "<H", data,
        symbol_offset + (24 if elf_class == 64 else 16) + (6 if elf_class == 64 else 14),
        0xFFFF,
    )
    with pytest.raises(ValueError, match="without an extended-index section"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_unrepresentable_extended_symbol_index(payload, elf_class):
    with pytest.raises(ValueError, match="exceeds the analysis limit"):
        inspect_elf_bytes(
            _elf_with_symtab_shndx(
                payload, elf_class, xindex_symbol=True,
                word_values=[0, 0xFF00, 0, 0],
            )
        )


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_accepts_valid_dynamic_section(payload, elf_class):
    assert inspect_elf_bytes(_elf_with_dynamic_section(payload, elf_class))["inspection_status"] == "complete"


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_dynamic_section_without_final_dt_null(payload, elf_class):
    with pytest.raises(ValueError, match="missing its DT_NULL terminator"):
        inspect_elf_bytes(
            _elf_with_dynamic_section(payload, elf_class, dynamic_tag=1)
        )


@pytest.mark.parametrize(
    ("payload", "elf_class", "kwargs", "message"),
    [
        (_elf64_with_jni_exports(), 64, {"link": 2}, "invalid string-table reference"),
        (_elf32_with_jni_exports(), 32, {"link": 2}, "invalid string-table reference"),
        (_elf64_with_jni_exports(), 64, {"info": 1}, "sh_info must be zero"),
        (_elf32_with_jni_exports(), 32, {"info": 1}, "sh_info must be zero"),
        (_elf64_with_jni_exports(), 64, {"entry_size": 8}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"entry_size": 4}, "entry metadata is invalid"),
        (_elf64_with_jni_exports(), 64, {"dynamic_size": 15}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"dynamic_size": 7}, "entry metadata is invalid"),
        (_elf64_with_jni_exports(), 64, {"data_offset": 0x7FFFFFFF}, "data is out of bounds"),
        (_elf32_with_jni_exports(), 32, {"data_offset": 0x7FFFFFFF}, "data is out of bounds"),
    ],
)
def test_inspect_elf_rejects_invalid_dynamic_section_metadata(
    payload, elf_class, kwargs, message
):
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(_elf_with_dynamic_section(payload, elf_class, **kwargs))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_accepts_valid_sysv_hash_section(payload, elf_class):
    assert inspect_elf_bytes(_elf_with_hash_section(payload, elf_class))["inspection_status"] == "complete"


@pytest.mark.parametrize(
    ("payload", "elf_class", "kwargs", "message"),
    [
        (_elf64_with_jni_exports(), 64, {"link": 3}, "invalid symbol-table reference"),
        (_elf32_with_jni_exports(), 32, {"link": 3}, "invalid symbol-table reference"),
        (_elf64_with_jni_exports(), 64, {"info": 1}, "sh_info must be zero"),
        (_elf32_with_jni_exports(), 32, {"info": 1}, "sh_info must be zero"),
        (_elf64_with_jni_exports(), 64, {"entry_size": 8}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"entry_size": 8}, "entry metadata is invalid"),
        (_elf64_with_jni_exports(), 64, {"bucket_count": 0}, "table dimensions are invalid"),
        (_elf32_with_jni_exports(), 32, {"chain_count": 3}, "table dimensions are invalid"),
        (_elf64_with_jni_exports(), 64, {"words": [4, 0, 2, 3, 0]}, "invalid symbol index"),
        (_elf32_with_jni_exports(), 32, {"words": [1, 0, 2, 4, 0]}, "invalid symbol index"),
        (_elf64_with_jni_exports(), 64, {"data_offset": 0x7FFFFFFF}, "data is out of bounds"),
        (_elf32_with_jni_exports(), 32, {"data_offset": 0x7FFFFFFF}, "data is out of bounds"),
    ],
)
def test_inspect_elf_rejects_invalid_sysv_hash_section_metadata(
    payload, elf_class, kwargs, message
):
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(_elf_with_hash_section(payload, elf_class, **kwargs))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_accepts_valid_gnu_hash_section(payload, elf_class):
    assert inspect_elf_bytes(
        _elf_with_gnu_hash_section(payload, elf_class)
    )["inspection_status"] == "complete"


def test_inspect_elf_accepts_gnu_hash_before_later_section(payload, elf_class):
    data = bytearray(_elf_with_gnu_hash_section(payload, elf_class))
    section_offset = struct.unpack_from(
        "<Q" if elf_class == 64 else "<I",
        data,
        40 if elf_class == 64 else 32,
    )[0]
    section_size = 64 if elf_class == 64 else 40
    # Put GNU_HASH before the section-name table so its alignment cannot be
    # accidentally taken from the final section-header iteration.
    gnu_header = bytes(data[section_offset + 4 * section_size:section_offset + 5 * section_size])
    names_header = bytes(data[section_offset + 3 * section_size:section_offset + 4 * section_size])
    data[section_offset + 3 * section_size:section_offset + 4 * section_size] = gnu_header
    data[section_offset + 4 * section_size:section_offset + 5 * section_size] = names_header
    struct.pack_into("<H", data, 62 if elf_class == 64 else 50, 4)
    assert inspect_elf_bytes(bytes(data))["inspection_status"] == "complete"


@pytest.mark.parametrize(
    ("payload", "elf_class", "kwargs", "message"),
    [
        (_elf64_with_jni_exports(), 64, {"link": 1}, "dynamic-symbol-table reference"),
        (_elf32_with_jni_exports(), 32, {"link": 1}, "dynamic-symbol-table reference"),
        (_elf64_with_jni_exports(), 64, {"info": 1}, "sh_info must be zero"),
        (_elf32_with_jni_exports(), 32, {"info": 1}, "sh_info must be zero"),
        (_elf64_with_jni_exports(), 64, {"entry_size": 4}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"entry_size": 0}, "entry metadata is invalid"),
        (_elf64_with_jni_exports(), 64, {"alignment": 4}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"alignment": 8}, "entry metadata is invalid"),
        (_elf32_with_jni_exports(), 32, {"bucket_count": 0}, "table dimensions are invalid"),
        (_elf64_with_jni_exports(), 64, {"bloom_count": 0}, "table dimensions are invalid"),
        (_elf32_with_jni_exports(), 32, {"bloom_count": 3}, "table dimensions are invalid"),
        (_elf64_with_jni_exports(), 64, {"symbol_offset": 5}, "table dimensions are invalid"),
        (_elf32_with_jni_exports(), 32, {"buckets": [4]}, "invalid bucket symbol index"),
        (_elf64_with_jni_exports(), 64, {"chains": [2, 4, 4]}, "unterminated chain"),
        (_elf32_with_jni_exports(), 32, {"data_offset": 0x7FFFFFFF}, "data is out of bounds"),
    ],
)
def test_inspect_elf_rejects_invalid_gnu_hash_section_metadata(
    payload, elf_class, kwargs, message
):
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(
            _elf_with_gnu_hash_section(payload, elf_class, **kwargs)
        )


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
    struct.pack_into("<H", data, 60, 0)
    struct.pack_into("<Q", data, section_offset + 32, 4)
    result = inspect_elf_bytes(bytes(data))
    assert result["dynamic_symbol_table_present"] is True
    assert result["dynamic_symbol_count"] == 4
    assert result["jni_exported_symbol_count"] == 1
    assert result["jni_onload_exported"] is True


def test_inspect_elf_bytes_rejects_invalid_extended_section_count():
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    section = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 4097, 0, 0, 0, 0)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 3, 183, 1, 0, 0, 64, 0, 64, 0, 0, 64, 0, 0,
    )
    with pytest.raises(ValueError, match="extended section count"):
        inspect_elf_bytes(header + section)


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




def test_inspect_elf_bytes_rejects_out_of_bounds_file_backed_section():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    header_offset = section_offset + 4 * 64
    data.extend(bytes(64))
    struct.pack_into("<H", data, 60, 5)
    struct.pack_into("<IIQQQQIIQQ", data, header_offset, 0, 1, 0, 0, 0xFFFFFFFF, 8, 0, 0, 1, 0)
    with pytest.raises(ValueError, match="section data is out of bounds"):
        inspect_elf_bytes(bytes(data))

def test_inspect_elf_bytes_allows_nobits_section_without_file_payload():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    header_offset = section_offset + 4 * 64
    data.extend(bytes(64))
    struct.pack_into("<H", data, 60, 5)
    struct.pack_into("<IIQQQQIIQQ", data, header_offset, 0, 8, 0, 0, len(data) + 4096, 8192, 0, 0, 1, 0)
    assert inspect_elf_bytes(bytes(data))["inspection_status"] == "complete"

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

def _elf32_with_jni_exports():
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    dynstr = b"\x00JNI_OnLoad\x00Java_org_example_Tunnel_start\x00ordinary\x00"
    names = {
        "jni_onload": dynstr.index(b"JNI_OnLoad"),
        "jni_method": dynstr.index(b"Java_org_example_Tunnel_start"),
        "ordinary": dynstr.index(b"ordinary"),
    }
    symbols = [bytes(16)]
    for key in ("jni_onload", "jni_method", "ordinary"):
        symbols.append(struct.pack("<IIIBBH", names[key], 0, 0, 0x12, 0, 1))
    dynsym = b"".join(symbols)
    shstr = b"\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
    dynstr_offset = 52
    dynsym_offset = dynstr_offset + len(dynstr)
    shstr_offset = dynsym_offset + len(dynsym)
    section_offset = (shstr_offset + len(shstr) + 3) & ~3
    sections = [
        bytes(40),
        struct.pack("<IIIIIIIIII", 1, 3, 0, 0, dynstr_offset, len(dynstr), 0, 0, 1, 0),
        struct.pack("<IIIIIIIIII", 9, 11, 0, 0, dynsym_offset, len(dynsym), 1, 1, 4, 16),
        struct.pack("<IIIIIIIIII", 17, 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0),
    ]
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident, 3, 3, 1, 0, 0, section_offset, 0, 52, 0, 0, 40, 4, 3,
    )
    return header + dynstr + dynsym + shstr + bytes(section_offset - shstr_offset - len(shstr)) + b"".join(sections)


def test_inspect_elf32_bytes_counts_exported_jni_function_symbols():
    result = inspect_elf_bytes(_elf32_with_jni_exports())
    assert result == {
        "elf_valid": True, "elf_class": 32, "endianness": "little",
        "machine": 3, "machine_name": "x86", "file_type": 3,
        "dynamic_symbol_table_present": True, "dynamic_symbol_count": 4,
        "jni_exported_symbol_count": 1, "jni_onload_exported": True,
        "inspection_status": "complete",
    }
    assert "Java_org_example_Tunnel_start" not in str(result)
    assert "JNI_OnLoad" not in str(result)



def test_inspect_elf_bytes_rejects_undersized_section_header_entry():
    data = bytearray(_elf64_with_jni_exports())
    struct.pack_into("<H", data, 58, 32)
    with pytest.raises(ValueError, match="section header size is invalid"):
        inspect_elf_bytes(bytes(data))


def test_inspect_elf_bytes_rejects_out_of_bounds_dynamic_string_table():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynstr_header = section_offset + 64
    struct.pack_into("<Q", data, dynstr_header + 32, len(data) + 1)
    with pytest.raises(ValueError, match="dynamic string table is out of bounds"):
        inspect_elf_bytes(bytes(data))


def test_inspect_elf32_bytes_rejects_truncated_header():
    data = _elf32_minimal(3)[:51]
    with pytest.raises(ValueError, match="ELF header is truncated"):
        inspect_elf_bytes(data)


@pytest.mark.parametrize(
    ("payload", "offset", "bad_value", "message"),
    [
        (_elf64_with_jni_exports(), 52, 63, "ELF header size is invalid"),
        (_elf32_minimal(3), 40, 51, "ELF header size is invalid"),
        (_elf64_with_jni_exports(), 20, 2, "ELF header version is unsupported"),
        (_elf32_minimal(3), 20, 0, "ELF header version is unsupported"),
    ],
)
def test_inspect_elf_bytes_rejects_invalid_header_size_or_version(
    payload, offset, bad_value, message
):
    data = bytearray(payload)
    struct.pack_into("<H" if offset in (52, 40) else "<I", data, offset, bad_value)
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(bytes(data))




def test_inspect_elf_bytes_rejects_misaligned_section_header_table():
    data = bytearray(_elf64_with_jni_exports())
    struct.pack_into("<Q", data, 40, 65)
    with pytest.raises(ValueError, match="section header table is misaligned"):
        inspect_elf_bytes(bytes(data))


def test_inspect_elf_bytes_rejects_non_power_of_two_section_alignment():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynstr_header = section_offset + 64
    struct.pack_into("<Q", data, dynstr_header + 48, 3)
    with pytest.raises(ValueError, match="section alignment is not a power of two"):
        inspect_elf_bytes(bytes(data))


def test_inspect_elf_bytes_accepts_zero_and_one_section_alignment():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynstr_header = section_offset + 64
    struct.pack_into("<Q", data, dynstr_header + 48, 0)
    result = inspect_elf_bytes(bytes(data))
    assert result["inspection_status"] == "complete"
    struct.pack_into("<Q", data, dynstr_header + 48, 1)
    assert inspect_elf_bytes(bytes(data))["inspection_status"] == "complete"

def test_inspect_elf_bytes_rejects_empty_dynamic_string_table():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynstr_header = section_offset + 64
    struct.pack_into("<Q", data, dynstr_header + 32, 0)
    with pytest.raises(ValueError, match="missing its leading NUL"):
        inspect_elf_bytes(bytes(data))


def test_inspect_elf_bytes_rejects_dynamic_string_table_without_initial_nul():
    data = bytearray(_elf64_with_jni_exports())
    data[64] = ord("X")
    with pytest.raises(ValueError, match="missing its leading NUL"):
        inspect_elf_bytes(bytes(data))

def test_inspect_elf_bytes_rejects_invalid_dynamic_symbol_local_boundary():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynsym_header = section_offset + 2 * 64
    struct.pack_into("<I", data, dynsym_header + 44, 5)
    with pytest.raises(ValueError, match="local-symbol boundary"):
        inspect_elf_bytes(bytes(data))


def test_inspect_elf_bytes_validates_names_even_for_null_local_symbols():
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynsym_header = section_offset + 2 * 64
    dynsym_offset = struct.unpack_from("<Q", data, dynsym_header + 24)[0]
    struct.pack_into("<I", data, dynsym_offset, 0xFFFFFFFF)
    with pytest.raises(ValueError, match="symbol name offset is invalid"):
        inspect_elf_bytes(bytes(data))



@pytest.mark.parametrize(
    ("field_offset", "value", "message"),
    [
        (40, 9, "symbol table metadata is invalid"),
        (40, 2, "symbol string table has an invalid section type"),
    ],
)
def test_inspect_elf_bytes_rejects_invalid_symbol_table_string_references(
    field_offset, value, message
):
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynsym_header = section_offset + 2 * 64
    struct.pack_into("<I", data, dynsym_header + field_offset, value)
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("field_offset", "format_code", "value", "message"),
    [
        (24, "<Q", 0xFFFFFFFF, "symbol table is out of bounds"),
        (32, "<Q", 95, "symbol table metadata is invalid"),
        (44, "<I", 99, "local-symbol boundary is invalid"),
    ],
)
def test_inspect_elf_bytes_rejects_malformed_symbol_table_metadata(
    field_offset, format_code, value, message
):
    data = bytearray(_elf64_with_jni_exports())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    dynsym_header = section_offset + 2 * 64
    struct.pack_into(format_code, data, dynsym_header + field_offset, value)
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(bytes(data))


def _elf_with_relocation_section(payload, elf_class):
    data = bytearray(payload)
    if elf_class == 64:
        section_offset = struct.unpack_from("<Q", data, 40)[0]
        header_offset = section_offset + 4 * 64
        data.extend(bytes(64))
        struct.pack_into("<H", data, 60, 5)
        struct.pack_into("<IIQQQQIIQQ", data, header_offset, 0, 4, 0, 0, 64, 24, 2, 1, 8, 24)
    else:
        section_offset = struct.unpack_from("<I", data, 32)[0]
        header_offset = section_offset + 4 * 40
        data.extend(bytes(40))
        struct.pack_into("<H", data, 48, 5)
        struct.pack_into("<IIIIIIIIII", data, header_offset, 0, 4, 0, 0, 52, 12, 2, 1, 4, 12)
    return data, header_offset

@pytest.mark.parametrize(
    ("elf_class", "payload"),
    [(64, _elf64_with_jni_exports()), (32, _elf32_with_jni_exports())],
)
def test_inspect_elf_bytes_accepts_valid_relocation_section(elf_class, payload):
    data, _ = _elf_with_relocation_section(payload, elf_class)
    assert inspect_elf_bytes(bytes(data))["inspection_status"] == "complete"


def test_inspect_elf_bytes_accepts_zero_target_for_dynamic_relocation_section():
    data, header_offset = _elf_with_relocation_section(_elf64_with_jni_exports(), 64)
    struct.pack_into("<I", data, header_offset + 44, 0)
    assert inspect_elf_bytes(bytes(data))["inspection_status"] == "complete"


def test_inspect_elf_bytes_rejects_zero_target_for_relocatable_object():
    data, header_offset = _elf_with_relocation_section(_elf64_with_jni_exports(), 64)
    struct.pack_into("<H", data, 16, 1)  # ET_REL
    struct.pack_into("<I", data, header_offset + 44, 0)
    with pytest.raises(ValueError, match="relocatable-file relocation target section is missing"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("link", 99, "invalid symbol-table reference"),
        ("info", 99, "invalid target-section reference"),
        ("entsize", 1, "entry metadata is invalid"),
        ("size", 23, "entry metadata is invalid"),
        ("offset", 0xFFFFFFFF, "data is out of bounds"),
    ],
)
@pytest.mark.parametrize(
    ("elf_class", "payload"),
    [(64, _elf64_with_jni_exports()), (32, _elf32_with_jni_exports())],
)
def test_inspect_elf_bytes_rejects_malformed_relocation_metadata(
    elf_class, payload, field, value, message
):
    data, header_offset = _elf_with_relocation_section(payload, elf_class)
    offsets = (
        {"link": (40, "<I"), "info": (44, "<I"), "entsize": (56, "<Q"),
         "size": (32, "<Q"), "offset": (24, "<Q")}
        if elf_class == 64 else
        {"link": (24, "<I"), "info": (28, "<I"), "entsize": (36, "<I"),
         "size": (20, "<I"), "offset": (16, "<I")}
    )
    field_offset, format_code = offsets[field]
    struct.pack_into(format_code, data, header_offset + field_offset, value)
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(bytes(data))



def _elf_with_group_section(payload, elf_class, group_words=(1, 6)):
    data = bytearray(payload)
    section_offset_field = 40 if elf_class == 64 else 32
    section_offset_fmt = "<Q" if elf_class == 64 else "<I"
    section_size = 64 if elf_class == 64 else 40
    section_fmt = "<IIQQQQIIQQ" if elf_class == 64 else "<IIIIIIIIII"
    count_offset = 60 if elf_class == 64 else 48
    section_offset = struct.unpack_from(section_offset_fmt, data, section_offset_field)[0]
    # ET_REL is required for SHT_GROUP and SHF_GROUP.
    struct.pack_into("<H", data, 16, 1)
    group_header_offset = section_offset + 5 * section_size
    member_header_offset = section_offset + 6 * section_size
    group_data = struct.pack("<" + "I" * len(group_words), *group_words)
    # The base fixture has sections 0..3. Add a null placeholder at 4,
    # then the group at 5 and its member at 6, keeping the section table
    # contiguous as required by e_shoff/e_shnum.
    group_payload_offset = len(data) + 3 * section_size
    member_payload_offset = group_payload_offset + len(group_data)
    group_header = struct.pack(
        section_fmt, 0, 17, 0, 0, group_payload_offset, len(group_data), 2, 1, 4, 4
    )
    member_header = struct.pack(
        section_fmt, 0, 1, 0x200, 0, member_payload_offset, 4, 0, 0, 4, 0
    )
    struct.pack_into("<H", data, count_offset, 7)
    data.extend(bytes(section_size))
    data.extend(group_header)
    data.extend(member_header)
    data.extend(group_data)
    data.extend(bytes(4))
    return bytes(data)


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_accepts_valid_group_section(payload, elf_class):
    result = inspect_elf_bytes(_elf_with_group_section(payload, elf_class))
    assert result["inspection_status"] == "complete"


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_group_member_without_shf_group(payload, elf_class):
    data = bytearray(_elf_with_group_section(payload, elf_class))
    section_offset = struct.unpack_from(
        "<Q" if elf_class == 64 else "<I", data, 40 if elf_class == 64 else 32
    )[0]
    section_size = 64 if elf_class == 64 else 40
    struct.pack_into(
        "<Q" if elf_class == 64 else "<I",
        data,
        section_offset + 6 * section_size + 8,
        0,
    )
    with pytest.raises(ValueError, match="member is missing SHF_GROUP"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("words", "message"),
    [
        ((1,), "entry metadata is invalid"),
        ((3, 1), "flags are invalid"),
        ((1, 0), "member index is invalid"),
        ((1, 99), "member index is invalid"),
        ((1, 5), "member index is invalid"),
        ((1, 4), "member index is invalid"),
        ((1, 1, 1), "member index is invalid"),
    ],
)
@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_invalid_group_members_and_flags(
    payload, elf_class, words, message
):
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(_elf_with_group_section(payload, elf_class, words))


@pytest.mark.parametrize(
    ("payload", "elf_class", "field_offset", "format_code", "value", "message"),
    [
        (_elf64_with_jni_exports(), 64, 40, "<I", 99, "invalid symbol-table reference"),
        (_elf64_with_jni_exports(), 64, 44, "<I", 99, "signature symbol index is invalid"),
        (_elf32_with_jni_exports(), 32, 24, "<I", 99, "invalid symbol-table reference"),
        (_elf32_with_jni_exports(), 32, 28, "<I", 99, "signature symbol index is invalid"),
    ],
)
def test_inspect_elf_rejects_invalid_group_symbol_references(
    payload, elf_class, field_offset, format_code, value, message
):
    data = bytearray(_elf_with_group_section(payload, elf_class))
    section_offset = struct.unpack_from("<Q" if elf_class == 64 else "<I", data, 40 if elf_class == 64 else 32)[0]
    struct.pack_into(format_code, data, section_offset + 5 * (64 if elf_class == 64 else 40) + field_offset, value)
    with pytest.raises(ValueError, match=message):
        inspect_elf_bytes(bytes(data))



def test_inspect_elf32_bytes_rejects_out_of_bounds_file_backed_section():
    data = bytearray(_elf32_with_jni_exports())
    section_offset = struct.unpack_from("<I", data, 32)[0]
    header_offset = section_offset + 4 * 40
    data.extend(bytes(40))
    struct.pack_into("<H", data, 48, 5)
    struct.pack_into("<IIIIIIIIII", data, header_offset, 0, 1, 0, 0, 0xFFFFFFFF, 8, 0, 0, 1, 0)
    with pytest.raises(ValueError, match="section data is out of bounds"):
        inspect_elf_bytes(bytes(data))

def test_inspect_elf32_bytes_allows_nobits_section_without_file_payload():
    data = bytearray(_elf32_with_jni_exports())
    section_offset = struct.unpack_from("<I", data, 32)[0]
    header_offset = section_offset + 4 * 40
    data.extend(bytes(40))
    struct.pack_into("<H", data, 48, 5)
    struct.pack_into("<IIIIIIIIII", data, header_offset, 0, 8, 0, 0, len(data) + 4096, 8192, 0, 0, 1, 0)
    assert inspect_elf_bytes(bytes(data))["inspection_status"] == "complete"

@pytest.mark.parametrize(
    ("payload", "index_offset", "bad_index"),
    [
        (_elf64_with_jni_exports(), 62, 4),
        (_elf32_with_jni_exports(), 50, 4),
    ],
)
def test_inspect_elf_rejects_out_of_range_section_name_table_index(
    payload, index_offset, bad_index
):
    data = bytearray(payload)
    struct.pack_into("<H", data, index_offset, bad_index)
    with pytest.raises(ValueError, match="section-name string-table index is out of bounds"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "index_offset", "bad_index"),
    [
        (_elf64_with_jni_exports(), 62, 2),
        (_elf32_with_jni_exports(), 50, 2),
    ],
)
def test_inspect_elf_rejects_non_string_section_name_table(
    payload, index_offset, bad_index
):
    data = bytearray(payload)
    struct.pack_into("<H", data, index_offset, bad_index)
    with pytest.raises(ValueError, match="section-name table has an invalid section type"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "section_offset_field", "entry_size", "name_field"),
    [
        (_elf64_with_jni_exports(), 40, 64, 0),
        (_elf32_with_jni_exports(), 32, 40, 0),
    ],
)
def test_inspect_elf_rejects_invalid_section_name_offset(
    payload, section_offset_field, entry_size, name_field
):
    data = bytearray(payload)
    section_offset = struct.unpack_from(
        "<Q" if entry_size == 64 else "<I", data, section_offset_field
    )[0]
    struct.pack_into("<I", data, section_offset + 3 * entry_size + name_field, 0xFFFFFFFF)
    with pytest.raises(ValueError, match="section name offset or termination"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "index_offset"),
    [(_elf64_with_jni_exports(), 62), (_elf32_with_jni_exports(), 50)],
)
def test_inspect_elf_rejects_extended_section_name_index_over_analysis_limit(
    payload, index_offset
):
    data = bytearray(payload)
    struct.pack_into("<H", data, index_offset, 0xFFFF)
    with pytest.raises(ValueError, match="extended section-name index exceeds the analysis limit"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "section_offset_field", "entry_size", "name_table_offset"),
    [
        (_elf64_with_jni_exports(), 40, 64, 62),
        (_elf32_with_jni_exports(), 32, 40, 50),
    ],
)
def test_inspect_elf_rejects_unterminated_section_name(
    payload, section_offset_field, entry_size, name_table_offset
):
    data = bytearray(payload)
    section_offset = struct.unpack_from(
        "<Q" if entry_size == 64 else "<I", data, section_offset_field
    )[0]
    name_section = section_offset + 3 * entry_size
    name_offset = struct.unpack_from(
        "<Q" if entry_size == 64 else "<I", data, name_section + (24 if entry_size == 64 else 16)
    )[0]
    name_size = struct.unpack_from(
        "<Q" if entry_size == 64 else "<I", data, name_section + (32 if entry_size == 64 else 20)
    )[0]
    data[name_offset + name_size - 1] = ord("X")
    with pytest.raises(ValueError, match="section name offset or termination"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_orphan_shf_group_section(payload, elf_class):
    data = bytearray(_elf_with_group_section(payload, elf_class))
    section_offset = struct.unpack_from(
        "<Q" if elf_class == 64 else "<I", data, 40 if elf_class == 64 else 32
    )[0]
    section_size = 64 if elf_class == 64 else 40
    # Mark section 1 as a group member without listing it in any group.
    struct.pack_into(
        "<Q" if elf_class == 64 else "<I",
        data,
        section_offset + section_size + 8,
        0x200,
    )
    with pytest.raises(ValueError, match="not referenced by a group"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_group_in_non_relocatable_file(payload, elf_class):
    data = bytearray(_elf_with_group_section(payload, elf_class))
    struct.pack_into("<H", data, 16, 3)  # ET_DYN
    with pytest.raises(ValueError, match="only valid in ET_REL"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_rejects_nonzero_group_header_flags(payload, elf_class):
    data = bytearray(_elf_with_group_section(payload, elf_class))
    section_offset = struct.unpack_from(
        "<Q" if elf_class == 64 else "<I", data, 40 if elf_class == 64 else 32
    )[0]
    group_offset = section_offset + 5 * (64 if elf_class == 64 else 40)
    struct.pack_into("<Q" if elf_class == 64 else "<I", data, group_offset + 8, 1)
    with pytest.raises(ValueError, match="header flags must be zero"):
        inspect_elf_bytes(bytes(data))


@pytest.mark.parametrize(
    ("payload", "elf_class"),
    [(_elf64_with_jni_exports(), 64), (_elf32_with_jni_exports(), 32)],
)
def test_inspect_elf_accepts_os_and_processor_group_flag_masks(payload, elf_class):
    result = inspect_elf_bytes(
        _elf_with_group_section(payload, elf_class, (0x1FF00001, 6))
    )
    assert result["inspection_status"] == "complete"
