"""Bounded, metadata-only ELF and JNI export inspection for APK libraries."""
from __future__ import annotations
import struct
import zipfile
from pathlib import Path
from typing import Any

_MAX_ELF_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_ELF_BYTES = 256 * 1024 * 1024
_MAX_ANALYZED_LIBRARIES = 256
_MAX_SECTION_HEADERS = 4096
_MAX_DYNAMIC_SYMBOL_TABLE_BYTES = 16 * 1024 * 1024
_MACHINE_NAMES = {3: "x86", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}

# Expected ELF class and e_machine for Android ABI directory labels.
_ANDROID_ABI_IDENTITY = {
    "armeabi-v7a": (32, 40),
    "arm64-v8a": (64, 183),
    "x86": (32, 3),
    "x86_64": (64, 62),
}


def _abi_compatibility(abi: str, elf: dict[str, Any]) -> dict[str, Any]:
    """Compare ELF header identity with a known Android ABI, not loadability."""
    expected = _ANDROID_ABI_IDENTITY.get(abi)
    if not elf.get("elf_valid"):
        return {"abi_compatible": None, "abi_compatibility_status": "not_checked"}
    if expected is None:
        return {"abi_compatible": None, "abi_compatibility_status": "unknown_abi"}
    expected_class, expected_machine = expected
    matches = (
        elf.get("elf_class") == expected_class
        and elf.get("machine") == expected_machine
        and elf.get("endianness") == "little"
    )
    return {
        "abi_compatible": matches,
        "abi_compatibility_status": "compatible" if matches else "mismatch",
    }


def inspect_elf_bytes(data: bytes) -> dict[str, Any]:
    """Read ELF identity and exported JNI symbol counts; never return symbol names."""
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("native library is not an ELF file")
    elf_class, encoding, ident_version = data[4], data[5], data[6]
    if elf_class not in (1, 2) or encoding not in (1, 2) or ident_version != 1:
        raise ValueError("ELF identification fields are unsupported")
    endian = "<" if encoding == 1 else ">"
    if elf_class == 2:
        header_fmt, section_fmt, symbol_fmt = endian + "16sHHIQQQIHHHHHH", endian + "IIQQQQIIQQ", endian + "IBBHQQ"
        expected_header, expected_section, expected_symbol = 64, 64, 24
    else:
        header_fmt, section_fmt, symbol_fmt = endian + "16sHHIIIIIHHHHHH", endian + "IIIIIIIIII", endian + "IIIBBH"
        expected_header, expected_section, expected_symbol = 52, 40, 16
    if len(data) < expected_header:
        raise ValueError("ELF header is truncated")
    header = struct.unpack_from(header_fmt, data, 0)
    elf_type, machine = header[1], header[2]
    if header[3] != 1:
        raise ValueError("ELF header version is unsupported")
    if header[8] != expected_header:
        raise ValueError("ELF header size is invalid")
    section_offset, section_entry_size, section_count = header[6], header[11], header[12]
    if section_count and section_count > _MAX_SECTION_HEADERS:
        raise ValueError("ELF has too many section headers")
    if section_offset:
        if section_entry_size < expected_section:
            raise ValueError("ELF section header size is invalid")
        if section_offset > len(data) or section_entry_size > len(data) - section_offset:
            raise ValueError("ELF section header table is out of bounds")
        # ELF extended numbering stores the real section count in sh_size
        # of section header zero when e_shnum is zero.
        first_section = struct.unpack_from(section_fmt, data, section_offset)
        if section_count == 0:
            section_count = first_section[5]
            if section_count == 0 or section_count > _MAX_SECTION_HEADERS:
                raise ValueError("ELF extended section count is invalid or exceeds the analysis limit")
        if section_count > _MAX_SECTION_HEADERS:
            raise ValueError("ELF has too many section headers")
        required_table_alignment = 8 if elf_class == 2 else 4
        if section_offset % required_table_alignment:
            raise ValueError("ELF section header table is misaligned")
        if section_count * section_entry_size > len(data) - section_offset:
            raise ValueError("ELF section header table is out of bounds")
        sections = [
            struct.unpack_from(section_fmt, data, section_offset + index * section_entry_size)
            for index in range(section_count)
        ]
        section_name_index = header[13]
        # SHN_XINDEX is reserved for indexes >= 0xFF00. This parser caps
        # section headers at 4096, so such an index cannot be represented.
        if section_name_index == 0xFFFF:
            raise ValueError("ELF extended section-name index exceeds the analysis limit")
        if section_name_index:
            if section_name_index >= len(sections):
                raise ValueError("ELF section-name string-table index is out of bounds")
            name_table = sections[section_name_index]
            if name_table[1] != 3:  # SHT_STRTAB
                raise ValueError("ELF section-name table has an invalid section type")
            name_offset, name_size = name_table[4], name_table[5]
            if name_offset > len(data) or name_size > len(data) - name_offset:
                raise ValueError("ELF section-name string table is out of bounds")
            names = data[name_offset:name_offset + name_size]
            if not names or names[0] != 0:
                raise ValueError("ELF section-name string table is missing its leading NUL")
            for section in sections:
                name_index = section[0]
                if name_index >= len(names) or names.find(b"\x00", name_index) < 0:
                    raise ValueError("ELF section name offset or termination is invalid")
        elif header[13] not in (0, 0xFFFF):
            raise ValueError("ELF section-name string-table index is invalid")
        for section in sections:
            alignment = section[8]
            if alignment > 1 and alignment & (alignment - 1):
                raise ValueError("ELF section alignment is not a power of two")
        # Relocation sections reference a symbol table and, for relocatable
        # objects, the section receiving the relocations. Validate metadata
        # without interpreting architecture-specific relocation records.
        relocation_entry_sizes = (
            {4: 24, 9: 16} if elf_class == 2 else {4: 12, 9: 8}
        )
        for section in sections:
            relocation_type = section[1]
            if relocation_type not in relocation_entry_sizes:
                continue
            relocation_offset, relocation_size = section[4], section[5]
            symbol_index, target_index, entry_size = section[6], section[7], section[9]
            if (
                symbol_index >= len(sections)
                or sections[symbol_index][1] not in (2, 11)
            ):
                raise ValueError("ELF relocation section has an invalid symbol-table reference")
            if target_index >= len(sections):
                raise ValueError("ELF relocation section has an invalid target-section reference")
            # In ET_REL files sh_info identifies the section being relocated;
            # section zero is not a valid relocation target. For ET_EXEC/ET_DYN,
            # zero is permitted for dynamic relocation sections.
            if elf_type == 1 and target_index == 0:
                raise ValueError("ELF relocatable-file relocation target section is missing")
            minimum_entry_size = relocation_entry_sizes[relocation_type]
            if entry_size < minimum_entry_size or relocation_size % entry_size:
                raise ValueError("ELF relocation section entry metadata is invalid")
            if (
                relocation_offset > len(data)
                or relocation_size > len(data) - relocation_offset
            ):
                raise ValueError("ELF relocation section data is out of bounds")
        # Validate section references and bounds for both static and dynamic
        # symbol tables before interpreting any dynamic symbols.
        for section in sections:
            if section[1] not in (2, 11):  # SHT_SYMTAB / SHT_DYNSYM
                continue
            symbol_offset, symbol_size = section[4], section[5]
            string_index, local_boundary, entry_size = section[6], section[7], section[9]
            if section[1] == 11 and symbol_size > _MAX_DYNAMIC_SYMBOL_TABLE_BYTES:
                raise ValueError("ELF dynamic symbol table exceeds the analysis limit")
            if (
                string_index >= len(sections)
                or entry_size < expected_symbol
                or symbol_size % entry_size
            ):
                raise ValueError("ELF symbol table metadata is invalid")
            if symbol_offset > len(data) or symbol_size > len(data) - symbol_offset:
                raise ValueError(
                    "ELF dynamic symbol table is out of bounds"
                    if section[1] == 11 else "ELF symbol table is out of bounds"
                )
            symbol_count = symbol_size // entry_size
            if local_boundary > symbol_count:
                raise ValueError("ELF symbol table local-symbol boundary is invalid")
            string_section = sections[string_index]
            if string_section[1] != 3:  # SHT_STRTAB
                raise ValueError("ELF symbol string table has an invalid section type")
            string_offset, string_size = string_section[4], string_section[5]
            if string_offset > len(data) or string_size > len(data) - string_offset:
                raise ValueError(
                    "ELF dynamic string table is out of bounds"
                    if section[1] == 11 else "ELF symbol string table is out of bounds"
                )
            if not string_size or data[string_offset] != 0:
                raise ValueError(
                    "ELF dynamic string table is missing its leading NUL"
                    if section[1] == 11 else "ELF symbol string table is missing its leading NUL"
                )
        # SHT_GROUP is valid only in relocatable objects. A section may
        # belong to at most one group, and its group header precedes it.
        grouped_members = set()
        for group_index, section in enumerate(sections):
            if section[1] != 17:  # SHT_GROUP
                continue
            if elf_type != 1:  # ET_REL
                raise ValueError("ELF section group is only valid in ET_REL files")
            if section[2] != 0:
                raise ValueError("ELF section group header flags must be zero")
            group_offset, group_size = section[4], section[5]
            symbol_table_index, signature_index, entry_size = section[6], section[7], section[9]
            if (
                symbol_table_index >= len(sections)
                or sections[symbol_table_index][1] not in (2, 11)
            ):
                raise ValueError("ELF section group has an invalid symbol-table reference")
            symbol_table = sections[symbol_table_index]
            symbol_entry_size = symbol_table[9]
            if symbol_entry_size < expected_symbol or symbol_table[5] % symbol_entry_size:
                raise ValueError("ELF section group references an invalid symbol table")
            symbol_count = symbol_table[5] // symbol_entry_size
            if signature_index == 0 or signature_index >= symbol_count:
                raise ValueError("ELF section group signature symbol index is invalid")
            if entry_size != 4 or group_size < 8 or group_size % 4:
                raise ValueError("ELF section group entry metadata is invalid")
            if group_offset > len(data) or group_size > len(data) - group_offset:
                raise ValueError("ELF section group data is out of bounds")
            group_words = struct.unpack_from(
                endian + "I" * (group_size // 4), data, group_offset
            )
            # GRP_MASKOS and GRP_MASKPROC are reserved for ABI-specific use.
            allowed_group_flags = 0x1 | 0x0FF00000 | 0xF0000000
            if group_words[0] & ~allowed_group_flags:
                raise ValueError("ELF section group flags are invalid")
            members = group_words[1:]
            if (
                any(member <= group_index or member >= len(sections) for member in members)
                or len(set(members)) != len(members)
                or any(member in grouped_members for member in members)
            ):
                raise ValueError("ELF section group member index is invalid")
            # Every listed member must carry SHF_GROUP and cannot be shared
            # with a second SHT_GROUP section.
            if any(not (sections[member][2] & 0x200) for member in members):
                raise ValueError("ELF section group member is missing SHF_GROUP")
            grouped_members.update(members)
        # SHF_GROUP is meaningful only for ET_REL and every flagged section
        # must be accounted for by exactly one group above.
        for member_index, member_section in enumerate(sections):
            if member_section[2] & 0x200:
                if elf_type != 1:
                    raise ValueError("ELF SHF_GROUP is only valid in ET_REL files")
                if member_index not in grouped_members:
                    raise ValueError("ELF SHF_GROUP section is not referenced by a group")
        # File-backed sections must remain within the input. SHT_NOBITS
        # occupies memory but has no bytes in the ELF file; section zero can
        # carry extended-numbering metadata in sh_size.
        for index, section in enumerate(sections):
            if index == 0 or section[1] == 8:  # SHT_NULL / SHT_NOBITS
                continue
            section_data_offset, section_data_size = section[4], section[5]
            if (
                section_data_offset > len(data)
                or section_data_size > len(data) - section_data_offset
            ):
                raise ValueError("ELF section data is out of bounds")
    else:
        if section_count:
            raise ValueError("ELF section table offset is missing")
        if header[13] != 0:
            raise ValueError("ELF section-name index requires a section table")
        sections = []
    dynamic_symbols = 0
    jni_symbols = 0
    jni_onload = False
    dynsym_found = False
    for section in sections:
        if section[1] != 11:
            continue
        dynsym_found = True
        symbol_offset, symbol_size, string_index, entry_size = section[4], section[5], section[6], section[9]
        if string_index >= len(sections) or entry_size < expected_symbol:
            raise ValueError("ELF dynamic symbol metadata is invalid")
        if symbol_size > _MAX_DYNAMIC_SYMBOL_TABLE_BYTES:
            raise ValueError("ELF dynamic symbol table exceeds the analysis limit")
        if symbol_offset > len(data) or symbol_size > len(data) - symbol_offset:
            raise ValueError("ELF dynamic symbol table is out of bounds")
        if symbol_size % entry_size:
            raise ValueError("ELF dynamic symbol table has an invalid size")
        string_section = sections[string_index]
        if string_section[1] != 3:  # SHT_STRTAB
            raise ValueError("ELF dynamic symbol string table has an invalid section type")
        string_offset, string_size = string_section[4], string_section[5]
        if string_offset > len(data) or string_size > len(data) - string_offset:
            raise ValueError("ELF dynamic string table is out of bounds")
        strings = data[string_offset:string_offset + string_size]
        # ELF string-table index zero is the empty string. A dynamic symbol
        # table must reference a non-empty string table with that NUL byte.
        if not strings or strings[0] != 0:
            raise ValueError("ELF dynamic string table is missing its leading NUL")
        count = symbol_size // entry_size
        if section[7] > count:
            raise ValueError("ELF dynamic symbol local-symbol boundary is invalid")
        for index in range(count):
            symbol = struct.unpack_from(symbol_fmt, data, symbol_offset + index * entry_size)
            if elf_class == 2:
                name_offset, info, other, section_index = symbol[:4]
            else:
                name_offset, _value, _size, info, other, section_index = symbol
            dynamic_symbols += 1
            if name_offset >= len(strings):
                raise ValueError("ELF symbol name offset is invalid")
            end = strings.find(b"\x00", name_offset)
            if end < 0:
                raise ValueError("ELF symbol name is not terminated")
            name = strings[name_offset:end]
            binding, symbol_type, visibility = info >> 4, info & 0x0F, other & 0x3
            if not section_index or binding not in (1, 2) or visibility not in (0, 3):
                continue
            # JNI entry points are functions; a data object with a Java_-like
            # name is not a callable JNI export.
            if symbol_type != 2:  # STT_FUNC
                continue
            if name == b"JNI_OnLoad":
                jni_onload = True
            elif name.startswith(b"Java_"):
                jni_symbols += 1
    return {
        "elf_valid": True,
        "elf_class": 64 if elf_class == 2 else 32,
        "endianness": "little" if encoding == 1 else "big",
        "machine": machine,
        "machine_name": _MACHINE_NAMES.get(machine, "unknown"),
        "file_type": elf_type,
        "dynamic_symbol_table_present": dynsym_found,
        "dynamic_symbol_count": dynamic_symbols if dynsym_found else None,
        "jni_exported_symbol_count": jni_symbols if dynsym_found else None,
        "jni_onload_exported": jni_onload if dynsym_found else None,
        "inspection_status": "complete" if dynsym_found else "no_dynamic_symbol_table",
    }


def inspect_apk_native_libraries(apk_path: str | Path, libraries: list[dict[str, Any]]) -> dict[str, Any]:
    """Inspect bounded .so bytes in memory; do not write or execute archive members."""
    results = []
    total_bytes = 0
    skipped = 0
    try:
        archive = zipfile.ZipFile(apk_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("APK is not a readable ZIP archive") from exc
    with archive:
        for item in libraries:
            if len(results) >= _MAX_ANALYZED_LIBRARIES:
                skipped += 1
                continue
            name = f"lib/{item['abi']}/{item['library_name']}"
            size = item.get("file_size_bytes")
            base = {"abi": item["abi"], "library_name": item["library_name"]}
            if not isinstance(size, int) or size < 0 or size > _MAX_ELF_BYTES:
                results.append({**base, "inspection_status": "skipped_size_limit", "abi_compatible": None, "abi_compatibility_status": "not_checked"})
                skipped += 1
                continue
            if total_bytes + size > _MAX_TOTAL_ELF_BYTES:
                results.append({**base, "inspection_status": "skipped_total_size_limit", "abi_compatible": None, "abi_compatibility_status": "not_checked"})
                skipped += 1
                continue
            try:
                with archive.open(name, "r") as member:
                    data = member.read(_MAX_ELF_BYTES + 1)
                if len(data) > _MAX_ELF_BYTES or len(data) != size:
                    raise ValueError("native library size does not match bounded metadata")
                total_bytes += len(data)
                parsed = inspect_elf_bytes(data)
                results.append({**base, **parsed, **_abi_compatibility(item["abi"], parsed)})
            except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile):
                results.append({**base, "inspection_status": "invalid_or_unreadable", "abi_compatible": None, "abi_compatibility_status": "not_checked"})
                skipped += 1
    return {
        "libraries": results,
        "libraries_inspected": sum(item.get("inspection_status") in ("complete", "no_dynamic_symbol_table") for item in results),
        "abi_compatibility_counts": {
            status: sum(item.get("abi_compatibility_status") == status for item in results)
            for status in ("compatible", "mismatch", "unknown_abi", "not_checked")
        },
        "abi_mismatch_count": sum(item.get("abi_compatibility_status") == "mismatch" for item in results),
        "jni_exported_library_count": sum((item.get("jni_exported_symbol_count") or 0) > 0 for item in results),
        "jni_onload_library_count": sum(item.get("jni_onload_exported") is True for item in results),
        "skipped_library_count": skipped,
        "bytes_read_in_memory": total_bytes,
        "archive_members_written": False,
        "native_code_executed": False,
        "raw_symbol_names_included": False,
    }
