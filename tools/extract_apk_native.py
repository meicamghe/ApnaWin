"""Safely extract every native ELF member from a bounded APK split set."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.inventory_apk_native import inventory_native_libraries  # noqa: E402

_MAX_NATIVE_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_NATIVE_BYTES = 256 * 1024 * 1024
_APK_BASENAME = re.compile(r"^[A-Za-z0-9_.+-]{1,128}\.apk$")
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.+-]{1,120}$")


def extract_native_libraries(
    apk_paths: list[str | Path],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Extract all inventoried native members and verify each recorded digest."""
    report = inventory_native_libraries(apk_paths)
    root = Path(output_dir)
    if root.is_symlink():
        raise ValueError("output directory must not be a symlink")
    if root.exists() and not root.is_dir():
        raise ValueError("output path must be a directory")
    if root.exists() and any(root.iterdir()):
        raise ValueError("output directory must be empty")
    root.mkdir(parents=True, exist_ok=True)

    by_basename: dict[str, Path] = {}
    for raw_path in apk_paths:
        path = Path(raw_path)
        if not _APK_BASENAME.fullmatch(path.name):
            raise ValueError("APK basename contains unsupported path characters")
        if path.name in by_basename:
            raise ValueError("APK inputs must have unique basenames")
        by_basename[path.name] = path

    rows: list[dict[str, Any]] = []
    total_written = 0
    for apk_name in sorted({row["apk"] for row in report["libraries"]}):
        with zipfile.ZipFile(by_basename[apk_name]) as archive:
            for item in (row for row in report["libraries"] if row["apk"] == apk_name):
                abi = item["abi"]
                library = item["library"]
                if not _SAFE_COMPONENT.fullmatch(abi) or not _SAFE_COMPONENT.fullmatch(library):
                    raise ValueError("native member path contains an unsafe component")
                apk_dir = root / apk_name
                if apk_dir.is_symlink():
                    raise ValueError("native extraction path contains a symlink")
                apk_dir.mkdir(parents=True, exist_ok=True)
                target_dir = apk_dir / abi
                target_dir.mkdir(parents=True, exist_ok=True)
                if target_dir.is_symlink():
                    raise ValueError("native extraction path contains a symlink")
                target = target_dir / library
                digest = hashlib.sha256()
                written = 0
                try:
                    with archive.open(item["entry"], "r") as source, target.open("xb") as sink:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            written += len(chunk)
                            total_written += len(chunk)
                            if written > _MAX_NATIVE_MEMBER_BYTES:
                                raise ValueError("native member expanded beyond the size limit")
                            if total_written > _MAX_TOTAL_NATIVE_BYTES:
                                raise ValueError("native members exceed the aggregate extraction limit")
                            digest.update(chunk)
                            sink.write(chunk)
                    if written != item["size_bytes"] or digest.hexdigest() != item["sha256"]:
                        raise ValueError("extracted native member failed size or SHA-256 verification")
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
                rows.append({
                    "apk": apk_name,
                    "abi": abi,
                    "library": library,
                    "relative_path": target.relative_to(root).as_posix(),
                    "size_bytes": written,
                    "sha256": digest.hexdigest(),
                    "elf_error": item["elf_error"],
                    "executed": False,
                })

    result = {
        "format": "apnawin-native-extraction-v1",
        "extracted_library_count": len(rows),
        "total_bytes_written": total_written,
        "libraries": rows,
        "native_code_executed": False,
    }
    (root / "manifest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apks", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = extract_native_libraries(args.apks, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"native extraction failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "extracted_library_count": result["extracted_library_count"],
        "total_bytes_written": result["total_bytes_written"],
        "native_code_executed": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
