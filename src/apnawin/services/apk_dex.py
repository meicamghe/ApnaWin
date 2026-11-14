"""Optional Android SDK-backed DEX metadata inspection.

Uses apkanalyzer's documented dex list, dex references and dex packages
commands. It does not extract or execute DEX files and never returns methods,
fields, bytecode, or raw tool output.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from apnawin.services.apk_tool import run_apkanalyzer

_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 30
_MAX_DEX_FILES = 128
_MAX_CLASSES = 100_000
_MAX_RELEVANT_CLASSES = 2_000
_DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z")
_CLASS_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")
_SIGNAL = re.compile(
    r"(?:vpn|tunnel|tun2socks|tun|socks|xray|openvpn|wireguard|"
    r"dns|proxy|shadowsocks|v2ray|trojan|service|connectivity)",
    re.IGNORECASE,
)


def _run(executable: str, args: list[str], timeout: float) -> str:
    output = run_apkanalyzer(
        executable,
        args,
        timeout,
        _MAX_OUTPUT_BYTES,
        "apkanalyzer failed during DEX inspection",
        "apkanalyzer timed out during DEX inspection",
        "apkanalyzer DEX output exceeds the allowed size",
    )
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("apkanalyzer DEX output is not UTF-8") from exc


def parse_dex_file_list(output: str) -> list[str]:
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX file list exceeds the allowed size")
    names: list[str] = []
    for line in output.splitlines():
        name = line.strip()
        if not name:
            continue
        if not _DEX_NAME.fullmatch(name):
            raise ValueError("apkanalyzer returned an unexpected DEX file name")
        names.append(name)
        if len(names) > _MAX_DEX_FILES:
            raise ValueError("APK contains too many DEX files")
    if len(names) != len(set(names)):
        raise ValueError("apkanalyzer returned duplicate DEX file names")
    return names


def _parse_defined_class_metadata(
    output: str,
) -> tuple[int, list[str], dict[str, dict[str, int]]]:
    """Parse defined classes and bounded numeric metadata for exact manifest joins."""
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX class listing exceeds the allowed size")
    count = 0
    relevant: set[str] = set()
    defined: dict[str, dict[str, int]] = {}
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "C":
            continue
        # Documented format: C d <defined-methods> <referenced-methods> <bytes> <name>
        if len(fields) != 6 or fields[1] not in {"d", "r"}:
            raise ValueError("apkanalyzer returned an unexpected class row")
        if any(not value.isdigit() for value in fields[2:5]):
            raise ValueError("apkanalyzer returned invalid class metadata")
        name = fields[5]
        if not _CLASS_NAME.fullmatch(name):
            raise ValueError("apkanalyzer returned an unexpected class name")
        if fields[1] != "d":
            continue
        if name in defined:
            raise ValueError("apkanalyzer returned a duplicate defined class")
        count += 1
        if count > _MAX_CLASSES:
            raise ValueError("APK contains too many defined classes")
        defined[name] = {
            "defined_method_count": int(fields[2]),
            "referenced_method_count": int(fields[3]),
            "byte_count": int(fields[4]),
        }
        if _SIGNAL.search(name):
            relevant.add(name)
    if len(relevant) > _MAX_RELEVANT_CLASSES:
        raise ValueError("too many potentially relevant class names")
    return count, sorted(relevant), defined


def _parse_defined_class_details(
    output: str,
) -> tuple[int, list[str], set[str]]:
    """Compatibility helper retaining the exact set of defined class names."""
    count, relevant, metadata = _parse_defined_class_metadata(output)
    return count, relevant, set(metadata)


def parse_defined_classes(output: str) -> tuple[int, list[str]]:
    """Parse defined class count and likely VPN/network class names."""
    count, relevant, _ = _parse_defined_class_details(output)
    return count, relevant


def _resolve_manifest_class(name: str, package_name: str | None) -> str | None:
    """Resolve Android component names without guessing when package context is absent."""
    if not isinstance(name, str) or not name or len(name) > 255:
        raise ValueError("manifest service name is invalid")
    if name.startswith("."):
        suffix = name[1:]
        if not _CLASS_NAME.fullmatch(suffix):
            raise ValueError("manifest service name is invalid")
        if not package_name:
            return None
        if not _PACKAGE_NAME.fullmatch(package_name):
            raise ValueError("manifest package name is invalid")
        return package_name + name
    if not _CLASS_NAME.fullmatch(name):
        raise ValueError("manifest service name is invalid")
    if "." not in name:
        if not package_name:
            return None
        if not _PACKAGE_NAME.fullmatch(package_name):
            raise ValueError("manifest package name is invalid")
        return package_name + "." + name
    return name


def parse_reference_counts(output: str) -> dict[str, int]:
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX reference listing exceeds the allowed size")
    counts: dict[str, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2 or not _DEX_NAME.fullmatch(fields[0]):
            raise ValueError("apkanalyzer returned an unexpected DEX reference row")
        if not fields[1].isdigit():
            raise ValueError("apkanalyzer returned an invalid DEX reference count")
        if fields[0] in counts:
            raise ValueError("apkanalyzer returned duplicate DEX reference rows")
        counts[fields[0]] = int(fields[1])
    return counts


def inspect_apk_dex(
    apk_path: str | Path,
    executable: str = "apkanalyzer",
    timeout: float = _MAX_TIMEOUT_SECONDS,
    manifest_services: list[str] | None = None,
    package_name: str | None = None,
) -> dict[str, Any]:
    """Return DEX file counts and candidate VPN/network class names."""
    path = Path(apk_path)
    if not path.is_file():
        raise ValueError("APK path must refer to an existing regular file")
    if timeout <= 0 or timeout > _MAX_TIMEOUT_SECONDS:
        raise ValueError("apkanalyzer timeout is outside the allowed range")
    resolved = shutil.which(executable)
    if resolved is None and Path(executable).is_file():
        resolved = str(Path(executable).resolve())
    if resolved is None:
        raise RuntimeError("Android SDK apkanalyzer was not found on PATH")

    apk = str(path.resolve())
    dex_files = parse_dex_file_list(_run(resolved, ["dex", "list", apk], timeout))
    if not dex_files:
        return {
            "format": "apnawin-apk-dex-v1",
            "dex_files": [],
            "dex_file_count": 0,
            "defined_class_count": 0,
            "method_references": {},
            "candidate_classes": [],
            "manifest_service_classes": [
                {
                    "manifest_name": service,
                    "resolved_class_name": _resolve_manifest_class(service, package_name),
                    "defined_in_dex": False,
                    "defined_method_count": None,
                    "referenced_method_count": None,
                    "byte_count": None,
                }
                for service in (manifest_services or [])
            ],
            "source": "apkanalyzer",
            "raw_dex_output_included": False,
        }

    class_output = _run(resolved, ["dex", "packages", "--defined-only", apk], timeout)
    class_count, candidates, class_metadata = _parse_defined_class_metadata(class_output)
    service_matches = []
    for service in manifest_services or []:
        resolved_name = _resolve_manifest_class(service, package_name)
        evidence = class_metadata.get(resolved_name) if resolved_name else None
        service_matches.append({
            "manifest_name": service,
            "resolved_class_name": resolved_name,
            "defined_in_dex": evidence is not None,
            "defined_method_count": evidence["defined_method_count"] if evidence else None,
            "referenced_method_count": evidence["referenced_method_count"] if evidence else None,
            "byte_count": evidence["byte_count"] if evidence else None,
        })
    reference_output = _run(resolved, ["dex", "references", apk], timeout)
    references = parse_reference_counts(reference_output)
    if set(references) - set(dex_files):
        raise ValueError("DEX reference output contains an unknown DEX file")
    return {
        "format": "apnawin-apk-dex-v1",
        "dex_files": dex_files,
        "dex_file_count": len(dex_files),
        "defined_class_count": class_count,
        "method_references": references,
        "candidate_classes": candidates,
        "manifest_service_classes": service_matches,
        "source": "apkanalyzer",
        "raw_dex_output_included": False,
    }
