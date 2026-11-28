"""Read-only inventory of native ELF members across APK splits."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

from apnawin.services.apk_elf import inspect_elf_bytes

_MAX_APKS = 64
_MAX_ENTRIES_PER_APK = 100_000
_MAX_NATIVE_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_NATIVE_BYTES = 256 * 1024 * 1024
_NATIVE_PATH = re.compile(r"^lib/([A-Za-z0-9_.+-]{1,64})/(lib[A-Za-z0-9_.+-]{1,120}\\.so)$")


def inventory_native_libraries(apk_paths: list[str | Path]) -> dict[str, Any]:
    """Hash and inspect embedded .so members without writing or executing them."""
    if not apk_paths or len(apk_paths) > _MAX_APKS:
        raise ValueError("APK input count is outside the allowed range")
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    for raw_path in sorted((Path(p) for p in apk_paths), key=lambda p: p.as_posix()):
        if not raw_path.is_file():
            raise ValueError("every APK input must be an existing regular file")
        with zipfile.ZipFile(raw_path) as archive:
            entries = archive.infolist()
            if len(entries) > _MAX_ENTRIES_PER_APK:
                raise ValueError("APK contains too many ZIP entries")
            names = [item.filename for item in entries]
            if len(names) != len(set(names)):
                raise ValueError("APK contains duplicate ZIP entry names")
            for info in entries:
                match = _NATIVE_PATH.fullmatch(info.filename)
                if not match:
                    continue
                if info.flag_bits & 1 or info.file_size > _MAX_NATIVE_MEMBER_BYTES:
                    raise ValueError("native member is encrypted or exceeds the size limit")
                total_bytes += info.file_size
                if total_bytes > _MAX_TOTAL_NATIVE_BYTES:
                    raise ValueError("native members exceed the aggregate analysis limit")
                digest = hashlib.sha256()
                chunks = bytearray()
                with archive.open(info, "r") as member:
                    while True:
                        chunk = member.read(1024 * 1024)
                        if not chunk:
                            break
                        chunks.extend(chunk)
                        digest.update(chunk)
                        if len(chunks) > _MAX_NATIVE_MEMBER_BYTES:
                            raise ValueError("native member expanded beyond the size limit")
                if len(chunks) != info.file_size:
                    raise ValueError("native member size does not match ZIP metadata")
                try:
                    elf = inspect_elf_bytes(bytes(chunks))
                    elf_error = None
                except ValueError as exc:
                    elf = None
                    elf_error = str(exc)
                rows.append({
                    "apk": raw_path.name,
                    "entry": info.filename,
                    "abi": match.group(1),
                    "library": match.group(2),
                    "size_bytes": len(chunks),
                    "sha256": digest.hexdigest(),
                    "elf": elf,
                    "elf_error": elf_error,
                    "executed": False,
                })
    rows.sort(key=lambda row: (row["apk"], row["abi"], row["library"], row["entry"]))
    return {
        "format": "apnawin-native-elf-inventory-v1",
        "apk_count": len(apk_paths),
        "native_library_count": len(rows),
        "total_native_bytes_analyzed": total_bytes,
        "libraries": rows,
        "executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apks", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = inventory_native_libraries(args.apks)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"native inventory failed: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
