"""Privacy-conscious static APK inventory (metadata only; never extracts or executes)."""
from __future__ import annotations

import hashlib
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

_MAX_ZIP_ENTRIES = 100_000
_MAX_ENTRY_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1_000
_ABI_RE = re.compile(r"^lib/([^/]+)/[^/]+[.]so$")
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


def inspect_apk(path: str | Path) -> dict[str, Any]:
    """Return a minimal, non-content APK inventory suitable for reproducible analysis."""
    apk_path = Path(path)
    if not apk_path.is_file():
        raise ValueError("APK path must refer to an existing regular file")

    digest = hashlib.sha256()
    with apk_path.open("rb") as stream:
        file_size = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            file_size += len(chunk)
            digest.update(chunk)

    try:
        with zipfile.ZipFile(apk_path) as archive:
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
            dex_count = 0
            signature_file_count = 0
            has_manifest = False
            for name in names:
                if name == "AndroidManifest.xml":
                    has_manifest = True
                if re.fullmatch(r"classes(?:[0-9]+)?[.]dex", name):
                    dex_count += 1
                match = _ABI_RE.fullmatch(name)
                if match:
                    native_abis.add(match.group(1))
                upper = name.upper()
                if upper.startswith("META-INF/") and upper.endswith((".RSA", ".DSA", ".EC")):
                    signature_file_count += 1
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise ValueError("APK is not a readable ZIP archive") from exc

    return {
        "format": "apnawin-apk-inventory-v1",
        "file_size_bytes": file_size,
        "sha256": digest.hexdigest(),
        "manifest_present": has_manifest,
        "dex_file_count": dex_count,
        "native_abis": sorted(native_abis),
        "signature_file_count": signature_file_count,
        "zip_entry_count": len(names),
        "content_extracted": False,
        "executed": False,
    }
