"""Integrity verification for the pinned Xray and Wintun runtime bundle."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


_HASH = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 16 * 1024


class VpnRuntimeIntegrityError(RuntimeError):
    """Raised when the installed Xray/Wintun runtime is incomplete or modified."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise VpnRuntimeIntegrityError(f"Could not read verified runtime file: {path.name}") from exc
    return digest.hexdigest()


def verify_vpn_runtime(engine_dir: str | Path) -> dict:
    """Verify installed engine binaries against the protected install manifest."""
    root = Path(engine_dir)
    if root.is_symlink() or not root.is_dir():
        raise VpnRuntimeIntegrityError("VPN runtime directory is missing or unsafe")
    manifest_path = root / "runtime-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise VpnRuntimeIntegrityError("VPN runtime manifest is missing or unsafe")
    try:
        with manifest_path.open("rb") as stream:
            raw = stream.read(_MAX_MANIFEST_BYTES + 1)
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise ValueError("manifest too large")
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise VpnRuntimeIntegrityError("VPN runtime manifest is invalid") from exc

    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "xray", "wintun"}:
        raise VpnRuntimeIntegrityError("VPN runtime manifest schema is invalid")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise VpnRuntimeIntegrityError("VPN runtime manifest version is unsupported")

    specs = (
        ("xray", "xray.exe", "executable_sha256", {"version", "archive_sha256", "executable_sha256"}),
        ("wintun", "wintun.dll", "dll_sha256", {"version", "archive_sha256", "dll_sha256", "signer"}),
    )
    for section_name, filename, digest_key, expected_keys in specs:
        section = manifest[section_name]
        if not isinstance(section, dict) or set(section) != expected_keys:
            raise VpnRuntimeIntegrityError(f"{section_name} runtime manifest entry is invalid")
        if not isinstance(section["version"], str) or not section["version"].strip():
            raise VpnRuntimeIntegrityError(f"{section_name} runtime version is invalid")
        for key in ("archive_sha256", digest_key):
            value = section.get(key)
            if not isinstance(value, str) or not _HASH.fullmatch(value):
                raise VpnRuntimeIntegrityError(f"{section_name} runtime hash is invalid")
        if section_name == "wintun":
            signer = section.get("signer")
            if not isinstance(signer, str) or "WireGuard" not in signer:
                raise VpnRuntimeIntegrityError("Wintun signer is not the expected publisher")
        binary = root / filename
        if binary.is_symlink() or not binary.is_file():
            raise VpnRuntimeIntegrityError(f"Required runtime binary is missing or unsafe: {filename}")
        if _sha256(binary) != section[digest_key]:
            raise VpnRuntimeIntegrityError(f"Runtime binary hash mismatch: {filename}")
    return manifest


