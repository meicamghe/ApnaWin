"""Privacy-conscious static APK inventory (metadata only; never extracts or executes)."""
from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path
from typing import Any

_MAX_ZIP_ENTRIES = 100_000
_ABI_RE = re.compile(r"^lib/([^/]+)/[^/]+\.so$")


def inspect_apk(path: str | Path) -> dict[str, Any]:
    """Return a minimal, non-content APK inventory suitable for reproducible analysis."""
    apk_path = Path(path)
    if not apk_path.is_file():
        raise ValueError("APK path must refer to an existing regular file")

    digest = hashlib.sha256()
    with apk_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    try:
        with zipfile.ZipFile(apk_path) as archive:
            entries = archive.infolist()
            if len(entries) > _MAX_ZIP_ENTRIES:
                raise ValueError("APK contains too many ZIP entries")
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                raise ValueError("APK contains duplicate ZIP entry names")

            native_abis: set[str] = set()
            dex_count = 0
            signature_file_count = 0
            has_manifest = False
            for name in names:
                normalized = name.replace("\\", "/")
                if normalized == "AndroidManifest.xml":
                    has_manifest = True
                if re.fullmatch(r"classes(?:[0-9]+)?\.dex", normalized):
                    dex_count += 1
                match = _ABI_RE.fullmatch(normalized)
                if match:
                    native_abis.add(match.group(1))
                upper = normalized.upper()
                if upper.startswith("META-INF/") and upper.endswith((".RSA", ".DSA", ".EC")):
                    signature_file_count += 1
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise ValueError("APK is not a readable ZIP archive") from exc

    return {
        "format": "apnawin-apk-inventory-v1",
        "file_size_bytes": apk_path.stat().st_size,
        "sha256": digest.hexdigest(),
        "manifest_present": has_manifest,
        "dex_file_count": dex_count,
        "native_abis": sorted(native_abis),
        "signature_file_count": signature_file_count,
        "zip_entry_count": len(names),
        "content_extracted": False,
        "executed": False,
    }
