"""Recover a bounded Go 1.18+ pclntab function table from an ELF file.

Offline only: input bytes are parsed, never loaded or executed. Stomped magic
is accepted only with explicit opt-in. All address translations must be unique.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any

_MAX_ELF_BYTES = 64 * 1024 * 1024
_MAX_FUNCTIONS = 1_000_000
_GO_MAGIC = {0xFFFFFFF1, 0xFFFFFFF0, 0xFFFFFFFA, 0xFFFFFFFB}
_PF_X = 1


class _ElfImage:
    def __init__(self, data: bytes) -> None:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise ValueError("input is not a complete ELF image")
        if data[4] != 2 or data[5] != 1 or data[6] != 1:
            raise ValueError("only ELF64 little-endian images are supported")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        if header[2] != 183 or header[1] not in (2, 3) or header[3] != 1 or header[8] != 64:
            raise ValueError("input is not a supported AArch64 ET_EXEC/ET_DYN image")
        phoff, phentsize, phnum = header[5], header[9], header[10]
        if phentsize < 56 or phnum > 4096 or phoff > len(data) or phnum * phentsize > len(data) - phoff:
            raise ValueError("ELF program-header table is invalid or out of bounds")
        self.data = data
        self.loads: list[tuple[int, int, int, int]] = []
        for index in range(phnum):
            p_type, flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", data, phoff + index * phentsize
            )
            if p_type != 1:
                continue
            if p_filesz > p_memsz or p_offset > len(data) or p_filesz > len(data) - p_offset:
                raise ValueError("ELF PT_LOAD segment is invalid or out of bounds")
            self.loads.append((p_vaddr, p_filesz, p_offset, flags))
        if not self.loads:
            raise ValueError("ELF has no file-backed PT_LOAD segment")

    def _matches(self, address: int, size: int) -> list[tuple[int, int, int, int]]:
        if address < 0 or size < 0:
            raise ValueError("negative ELF address or size")
        return [
            segment for segment in self.loads
            if address >= segment[0]
            and address - segment[0] <= segment[1]
            and size <= segment[1] - (address - segment[0])
        ]

    def _unique_mapping(self, address: int, size: int) -> tuple[int, int, int, int]:
        matches = self._matches(address, size)
        if len(matches) != 1:
            reason = "outside file-backed PT_LOAD ranges" if not matches else "ambiguous overlapping PT_LOAD mappings"
            raise ValueError(f"ELF virtual address is {reason}")
        return matches[0]

    def read_va(self, address: int, size: int) -> bytes:
        va, _file_size, offset, _flags = self._unique_mapping(address, size)
        start = offset + address - va
        return self.data[start:start + size]

    def read_c_string_before(self, address: int, end_address: int, maximum: int = 4096) -> bytes:
        if address < 0 or end_address <= address or maximum <= 0:
            raise ValueError("invalid ELF string range")
        va, file_size, offset, _flags = self._unique_mapping(address, 1)
        available = min(maximum, end_address - address, file_size - (address - va))
        if available <= 0:
            raise ValueError("Go function name has no readable bytes")
        raw = self.data[offset + address - va:offset + address - va + available]
        terminator = raw.find(b"\0")
        if terminator <= 0:
            raise ValueError("Go function name is empty or not NUL-terminated inside funcnametab")
        return raw[:terminator]

    def is_executable_va(self, address: int, size: int = 1) -> bool:
        matches = self._matches(address, size)
        return len(matches) == 1 and bool(matches[0][3] & _PF_X)


def recover_go_pclntab(data: bytes, pclntab_va: int, allow_stomped_magic: bool = False) -> dict[str, Any]:
    if len(data) > _MAX_ELF_BYTES:
        raise ValueError("ELF image exceeds the analysis size limit")
    image = _ElfImage(data)
    header = image.read_va(pclntab_va, 72)
    magic = struct.unpack_from("<I", header, 0)[0]
    if magic not in _GO_MAGIC and not allow_stomped_magic:
        raise ValueError("Go pclntab magic is unknown; explicit stomped-magic mode is required")
    pad1, pad2, quantum, pointer_size = header[4:8]
    if pad1 or pad2 or quantum not in (1, 2, 4) or pointer_size != 8:
        raise ValueError("Go pclntab header byte fields are inconsistent")
    nfunc, nfiles, text_start, funcname_off, cu_off, file_off, pctab_off, pcln_off = struct.unpack_from("<8Q", header, 8)
    if not 0 < nfunc <= _MAX_FUNCTIONS or nfiles > _MAX_FUNCTIONS:
        raise ValueError("Go pclntab function/file counts exceed bounds")
    if not (0 < funcname_off < cu_off < file_off < pctab_off < pcln_off):
        raise ValueError("Go pclntab offset fields are not strictly ordered")
    if pcln_off >= 0xFFFFFFFF or funcname_off >= pcln_off:
        raise ValueError("Go pclntab offsets are outside supported bounds")
    funcname_start = pclntab_va + funcname_off
    funcname_end = pclntab_va + cu_off
    table_size = (2 * nfunc + 1) * 4
    table_va = pclntab_va + pcln_off
    table = image.read_va(table_va, table_size)
    # The function records must be inside the same mapped metadata segment as
    # pclntab; a readable arbitrary PT_LOAD elsewhere is not sufficient.
    metadata_segment = image._unique_mapping(pclntab_va, 72)
    metadata_end = metadata_segment[0] + metadata_segment[1]
    records: list[dict[str, Any]] = []
    previous_entry = -1
    for index in range(nfunc):
        entry_off, func_off = struct.unpack_from("<II", table, index * 8)
        if entry_off <= previous_entry or func_off < pcln_off + table_size:
            raise ValueError("Go functab entries are not strictly ordered or function offsets are invalid")
        func_va = pclntab_va + func_off
        if func_va + 8 > metadata_end:
            raise ValueError("Go function record is outside the pclntab metadata segment")
        func_record = image.read_va(func_va, 8)
        name_off = struct.unpack_from("<i", func_record, 4)[0]
        name_va = funcname_start + name_off
        if name_off < 0 or name_va < funcname_start or name_va >= funcname_end:
            raise ValueError("Go function name offset is outside funcnametab")
        name_bytes = image.read_c_string_before(name_va, funcname_end)
        name = name_bytes.decode("utf-8", errors="strict")
        if any(ord(char) < 0x20 for char in name):
            raise ValueError("Go function name contains control characters")
        code_va = text_start + entry_off
        if not image.is_executable_va(code_va):
            raise ValueError("Go function entry does not map uniquely to executable PT_LOAD")
        records.append({"index": index, "entry_offset": entry_off, "function_offset": func_off, "name": name})
        previous_entry = entry_off
    end_entry = struct.unpack_from("<I", table, nfunc * 8)[0]
    if end_entry <= previous_entry or not image.is_executable_va(text_start + end_entry - 1):
        raise ValueError("Go functab terminal PC offset is outside the executable code range")
    return {
        "format": "apnawin-go-pclntab-recovery-v2",
        "elf_class": 64, "machine": "AArch64",
        "pclntab_va": hex(pclntab_va), "magic": hex(magic),
        "magic_stomped": magic not in _GO_MAGIC,
        "go_pc_quantum": quantum, "pointer_size": pointer_size,
        "nfunc": nfunc, "nfiles": nfiles, "text_start": hex(text_start),
        "functab_va": hex(table_va), "functab_bytes": table_size,
        "terminal_entry_offset": end_entry, "recovered_function_count": len(records),
        "functions": records, "binary_executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--pclntab-va", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--allow-stomped-magic", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = recover_go_pclntab(args.elf.read_bytes(), args.pclntab_va, args.allow_stomped_magic)
    except (OSError, ValueError, struct.error) as exc:
        print(f"Go pclntab recovery failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
