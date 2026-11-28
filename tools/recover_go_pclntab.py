"""Recover a bounded Go 1.18+ pclntab function table from an ELF file.

This is an offline parser: it never loads or executes the input binary. A
stomped magic word may be tolerated only when explicitly requested; the
remaining Go header, table bounds, function records and names are still checked.
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


class _ElfImage:
    def __init__(self, data: bytes) -> None:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise ValueError("input is not a complete ELF image")
        if data[4] != 2 or data[5] != 1 or data[6] != 1:
            raise ValueError("only ELF64 little-endian images are supported")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        if header[2] != 183 or header[3] not in (2, 3) or header[8] != 64:
            raise ValueError("input is not a supported AArch64 ET_EXEC/ET_DYN image")
        phoff, phentsize, phnum = header[5], header[9], header[10]
        if phentsize < 56 or phnum > 4096 or phoff > len(data) or phnum * phentsize > len(data) - phoff:
            raise ValueError("ELF program-header table is invalid or out of bounds")
        self.data = data
        self.loads: list[tuple[int, int, int]] = []
        for index in range(phnum):
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", data, phoff + index * phentsize
            )
            if p_type != 1:
                continue
            if p_filesz > p_memsz or p_offset > len(data) or p_filesz > len(data) - p_offset:
                raise ValueError("ELF PT_LOAD segment is invalid or out of bounds")
            self.loads.append((p_vaddr, p_filesz, p_offset))
        if not self.loads:
            raise ValueError("ELF has no file-backed PT_LOAD segment")

    def read_c_string(self, address: int, maximum: int = 4096) -> bytes:
        if address < 0 or maximum <= 0:
            raise ValueError("invalid ELF string address or limit")
        for va, file_size, offset in self.loads:
            if va <= address < va + file_size:
                available = min(maximum, file_size - (address - va))
                start = offset + address - va
                raw = self.data[start:start + available]
                terminator = raw.find(bytes([0]))
                if terminator <= 0:
                    raise ValueError("Go function name is empty or not NUL-terminated within the limit")
                return raw[:terminator]
        raise ValueError("Go function name is outside file-backed PT_LOAD ranges")

    def read_va(self, address: int, size: int) -> bytes:
        if address < 0 or size < 0:
            raise ValueError("negative ELF address or size")
        for va, file_size, offset in self.loads:
            if address >= va and address - va <= file_size and size <= file_size - (address - va):
                start = offset + address - va
                return self.data[start:start + size]
        raise ValueError("requested Go metadata is outside file-backed PT_LOAD ranges")


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
    words = struct.unpack_from("<8Q", header, 8)
    nfunc, nfiles, text_start, funcname_off, cu_off, file_off, pctab_off, pcln_off = words
    if not 0 < nfunc <= _MAX_FUNCTIONS or nfiles > _MAX_FUNCTIONS:
        raise ValueError("Go pclntab function/file counts exceed bounds")
    if not (0 < funcname_off < cu_off < file_off < pctab_off < pcln_off):
        raise ValueError("Go pclntab offset fields are not strictly ordered")
    if pcln_off >= 0xFFFFFFFF or funcname_off >= pcln_off:
        raise ValueError("Go pclntab offsets are outside supported bounds")
    table_size = (2 * nfunc + 1) * 4
    table_va = pclntab_va + pcln_off
    table = image.read_va(table_va, table_size)
    records: list[dict[str, Any]] = []
    previous_entry = -1
    previous_func = -1
    for index in range(nfunc):
        entry_off, func_off = struct.unpack_from("<II", table, index * 8)
        if entry_off <= previous_entry or func_off <= previous_func or func_off < 8:
            raise ValueError("Go functab entries are not strictly increasing or valid")
        func_va = pclntab_va + func_off
        func_record = image.read_va(func_va, 8)
        name_off = struct.unpack_from("<i", func_record, 4)[0]
        name_va = pclntab_va + funcname_off + name_off
        if name_off < 0 or name_va < pclntab_va + funcname_off:
            raise ValueError("Go function name offset is invalid")
        name_bytes = image.read_c_string(name_va)
        name = name_bytes.decode("utf-8", errors="replace")
        if any(ord(char) < 0x20 for char in name):
            raise ValueError("Go function name contains control characters")
        records.append({"index": index, "entry_offset": entry_off, "function_offset": func_off, "name": name})
        previous_entry, previous_func = entry_off, func_off
    end_entry = struct.unpack_from("<I", table, nfunc * 8)[0]
    if end_entry <= previous_entry:
        raise ValueError("Go functab terminal PC offset is invalid")
    return {
        "format": "apnawin-go-pclntab-recovery-v1",
        "elf_class": 64,
        "machine": "AArch64",
        "pclntab_va": hex(pclntab_va),
        "magic": hex(magic),
        "magic_stomped": magic not in _GO_MAGIC,
        "go_pc_quantum": quantum,
        "pointer_size": pointer_size,
        "nfunc": nfunc,
        "nfiles": nfiles,
        "text_start": hex(text_start),
        "functab_va": hex(table_va),
        "functab_bytes": table_size,
        "terminal_entry_offset": end_entry,
        "recovered_function_count": len(records),
        "functions": records,
        "binary_executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--pclntab-va", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--allow-stomped-magic", action="store_true")
    args = parser.parse_args(argv)
    try:
        data = args.elf.read_bytes()
        report = recover_go_pclntab(data, args.pclntab_va, args.allow_stomped_magic)
    except (OSError, ValueError, struct.error) as exc:
        print(f"Go pclntab recovery failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
