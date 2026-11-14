"""Privacy-conscious static APK inventory (metadata only; never extracts or executes)."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

_MAX_APK_FILE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_ZIP_ENTRIES = 100_000
_MAX_ENTRY_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1_000
_ABI_RE = re.compile(r"^lib/([A-Za-z0-9_.+-]{1,64})/([^/]+[.]so)$")
_NATIVE_LIBRARY_RE = re.compile(r"^lib[A-Za-z0-9_.+-]{1,120}[.]so$")
_MAX_NATIVE_LIBRARIES = 2_048
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _validate_entry(info: zipfile.ZipInfo) -> None:
    """Reject ZIP metadata that is unsafe or unreasonable without reading members."""
    name = info.filename
    path = PurePosixPath(name)
    if (
        not name
        or chr(92) in name
        or chr(0) in name
        or name.startswith("/")
        or _WINDOWS_DRIVE_RE.match(name)
        or any(part in {".", ".."} for part in name.split("/"))
        or path.is_absolute()
    ):
        raise ValueError("APK contains an unsafe ZIP entry path")
    if info.flag_bits & 0x1:
        raise ValueError("APK contains an encrypted ZIP entry")
    if stat.S_ISLNK(info.external_attr >> 16):
        raise ValueError("APK contains a symbolic-link ZIP entry")
    if info.file_size < 0 or info.compress_size < 0:
        raise ValueError("APK contains invalid ZIP size metadata")
    if info.file_size > _MAX_ENTRY_UNCOMPRESSED_BYTES:
        raise ValueError("APK contains an oversized ZIP entry")
    if info.file_size and (
        info.compress_size == 0
        or info.file_size / info.compress_size > _MAX_COMPRESSION_RATIO
    ):
        raise ValueError("APK contains a suspiciously compressed ZIP entry")


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    """Detect ordinary concurrent replacement or mutation of the opened file."""
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def inspect_apk(path: str | Path) -> dict[str, Any]:
    """Return minimal non-content APK metadata from one stable open file descriptor."""
    apk_path = Path(path)
    try:
        stream = apk_path.open("rb")
    except OSError as exc:
        raise ValueError("APK path must refer to an existing regular file") from exc

    with stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("APK path must refer to an existing regular file")
        if before.st_size > _MAX_APK_FILE_BYTES:
            raise ValueError("APK file exceeds the allowed size")

        digest = hashlib.sha256()
        file_size = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            file_size += len(chunk)
            if file_size > _MAX_APK_FILE_BYTES:
                raise ValueError("APK file exceeds the allowed size")
            digest.update(chunk)
        if file_size != before.st_size:
            raise ValueError("APK file changed while it was being inspected")

        stream.seek(0)
        try:
            with zipfile.ZipFile(stream) as archive:
                entries = archive.infolist()
                if len(entries) > _MAX_ZIP_ENTRIES:
                    raise ValueError("APK contains too many ZIP entries")
                names: list[str] = []
                total_uncompressed = 0
                for entry in entries:
                    _validate_entry(entry)
                    total_uncompressed += entry.file_size
                    if total_uncompressed > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                        raise ValueError("APK expands beyond the allowed aggregate size")
                    names.append(entry.filename)
                if len(names) != len(set(names)):
                    raise ValueError("APK contains duplicate ZIP entry names")

                native_abis: set[str] = set()
                native_libraries: list[dict[str, Any]] = []
                entry_sizes = {entry.filename: entry.file_size for entry in entries}
                dex_count = 0
                signature_file_count = 0
                has_manifest = False
                for name in names:
                    if name == "AndroidManifest.xml":
                        has_manifest = True
                    if re.fullmatch(r"classes(?:[0-9]+)?[.]dex", name):
                        dex_count += 1
                    match = _ABI_RE.fullmatch(name)
                    if match and _NATIVE_LIBRARY_RE.fullmatch(match.group(2)):
                        native_abis.add(match.group(1))
                        if len(native_libraries) >= _MAX_NATIVE_LIBRARIES:
                            raise ValueError("APK contains too many native libraries")
                        native_libraries.append({
                            "abi": match.group(1),
                            "library_name": match.group(2),
                            "file_size_bytes": entry_sizes[name],
                        })
                    upper = name.upper()
                    if upper.startswith("META-INF/") and upper.endswith(
                        (".RSA", ".DSA", ".EC")
                    ):
                        signature_file_count += 1
        except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
            raise ValueError("APK is not a readable ZIP archive") from exc

        after = os.fstat(stream.fileno())
        if not _same_file_snapshot(before, after):
            raise ValueError("APK file changed while it was being inspected")

    return {
        "format": "apnawin-apk-inventory-v1",
        "file_size_bytes": file_size,
        "sha256": digest.hexdigest(),
        "manifest_present": has_manifest,
        "dex_file_count": dex_count,
        "native_abis": sorted(native_abis),
        "native_libraries": sorted(
            native_libraries, key=lambda item: (item["abi"], item["library_name"])
        ),
        "signature_file_count": signature_file_count,
        "zip_entry_count": len(names),
        "content_extracted": False,
        "executed": False,
    }
