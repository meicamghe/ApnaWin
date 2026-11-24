#!/usr/bin/env python3
"""Safely inventory native ELF candidates in APK and XAPK archives.

The tool never installs or executes Android code. Nested APK members are read
in memory; only explicitly selected .so files are written when --extract is
provided. Output hashes let investigators compare exact library samples.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_NESTED_APKS = 256
MAX_LIBRARY_BYTES = 64 * 1024 * 1024
MAX_LIBRARIES = 4096
TARGET_NAME = "libudpqtwo.so"
ABI_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$", re.IGNORECASE)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "item"


def inventory_zip(
    data: bytes,
    source: str,
    extract_dir: Path | None,
    nested_name: str | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return results

    with archive:
        for info in archive.infolist():
            match = ABI_RE.match(info.filename)
            if not match:
                continue
            abi, library_name = match.groups()
            item: dict[str, Any] = {
                "source": source,
                "nested_apk": nested_name,
                "archive_member": info.filename,
                "abi": abi,
                "library_name": library_name,
                "uncompressed_size": info.file_size,
                "encrypted": bool(info.flag_bits & 0x1),
            }
            if item["encrypted"]:
                item["status"] = "encrypted_member"
                results.append(item)
                continue
            if info.file_size > MAX_LIBRARY_BYTES:
                item["status"] = "size_limit"
                results.append(item)
                continue
            try:
                with archive.open(info, "r") as stream:
                    blob = stream.read(MAX_LIBRARY_BYTES + 1)
                if len(blob) != info.file_size or len(blob) > MAX_LIBRARY_BYTES:
                    item["status"] = "size_mismatch_or_limit"
                    results.append(item)
                    continue
            except (RuntimeError, OSError, zipfile.BadZipFile):
                item["status"] = "unreadable"
                results.append(item)
                continue

            item["size"] = len(blob)
            item["sha256"] = sha256(blob)
            item["elf_magic"] = blob.startswith(b"\\x7fELF")
            item["status"] = "read"
            if library_name.lower() == TARGET_NAME:
                item["target_match"] = True
            if extract_dir is not None:
                extract_dir.mkdir(parents=True, exist_ok=True)
                label = safe_label(Path(nested_name or source).stem)
                filename = f"{label}__{safe_label(abi)}__{safe_label(library_name)}__{item['sha256'][:12]}.so"
                destination = extract_dir / filename
                destination.write_bytes(blob)
                item["extracted_to"] = str(destination)
            results.append(item)
            if len(results) >= MAX_LIBRARIES:
                return results
    return results


def inspect_path(path: Path, extract_dir: Path | None) -> list[dict[str, Any]]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [{"source": str(path), "status": f"stat_error: {exc}"}]
    if size > MAX_ARCHIVE_BYTES:
        return [{"source": str(path), "status": "archive_size_limit", "size": size}]
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [{"source": str(path), "status": f"read_error: {exc}"}]

    results = inventory_zip(data, str(path), extract_dir)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as outer:
            nested_count = 0
            for info in outer.infolist():
                if not info.filename.lower().endswith(".apk"):
                    continue
                nested_count += 1
                if nested_count > MAX_NESTED_APKS:
                    results.append({"source": str(path), "status": "nested_apk_limit"})
                    break
                if info.flag_bits & 0x1 or info.file_size > MAX_ARCHIVE_BYTES:
                    results.append({
                        "source": str(path),
                        "nested_apk": info.filename,
                        "status": "nested_apk_encrypted_or_too_large",
                        "size": info.file_size,
                    })
                    continue
                try:
                    with outer.open(info, "r") as stream:
                        nested = stream.read(MAX_ARCHIVE_BYTES + 1)
                    if len(nested) != info.file_size or len(nested) > MAX_ARCHIVE_BYTES:
                        raise ValueError("nested APK size mismatch or limit")
                except (RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
                    results.append({
                        "source": str(path),
                        "nested_apk": info.filename,
                        "status": f"nested_apk_read_error: {exc}",
                    })
                    continue
                results.extend(inventory_zip(
                    nested, str(path), extract_dir, nested_name=info.filename
                ))
    except (zipfile.BadZipFile, OSError):
        if not results:
            return [{"source": str(path), "status": "not_a_zip_archive"}]
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory .so files in APK/XAPK archives without executing them."
    )
    parser.add_argument("archives", nargs="+", type=Path, help="APK/XAPK file paths")
    parser.add_argument(
        "--extract", type=Path, default=None,
        help="optionally extract inventoried .so files into this directory",
    )
    parser.add_argument(
        "--target-only", action="store_true",
        help=f"show only {TARGET_NAME} matches (does not change scanning)",
    )
    args = parser.parse_args()

    all_results: list[dict[str, Any]] = []
    for archive in args.archives:
        all_results.extend(inspect_path(archive, args.extract))
    if args.target_only:
        all_results = [
            item for item in all_results
            if item.get("library_name", "").lower() == TARGET_NAME
            or item.get("target_match") is True
        ]
    print(json.dumps({
        "archives_scanned": [str(p) for p in args.archives],
        "target_library": TARGET_NAME,
        "libraries_found": len(all_results),
        "target_matches": sum(item.get("target_match") is True for item in all_results),
        "results": all_results,
        "native_code_executed": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
