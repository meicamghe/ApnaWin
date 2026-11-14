"""Optional Android SDK-backed DEX metadata inspection.

Uses apkanalyzer's documented dex list, dex references and dex packages
commands. It does not extract or execute DEX files and never returns methods,
fields, bytecode, or raw tool output.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 30
_MAX_DEX_FILES = 128
_MAX_CLASSES = 100_000
_MAX_RELEVANT_CLASSES = 2_000
_DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z")
_CLASS_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$/]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
_SIGNAL = re.compile(
    r"(?:vpn|tunnel|tun2socks|tun|socks|xray|openvpn|wireguard|"
    r"dns|proxy|shadowsocks|v2ray|trojan|service|connectivity)",
    re.IGNORECASE,
)


def _run(executable: str, args: list[str], timeout: float) -> str:
    try:
        result = subprocess.run(
            [executable, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("apkanalyzer timed out during DEX inspection") from exc
    except OSError as exc:
        raise RuntimeError("apkanalyzer could not be started") from exc
    if len(result.stdout) > _MAX_OUTPUT_BYTES or len(result.stderr) > _MAX_OUTPUT_BYTES:
        raise RuntimeError("apkanalyzer DEX output exceeds the allowed size")
    if result.returncode != 0:
        raise RuntimeError("apkanalyzer failed during DEX inspection")
    try:
        return result.stdout.decode("utf-8")
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


def parse_defined_classes(output: str) -> tuple[int, list[str]]:
    """Parse only defined class records from dex packages --defined-only output."""
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX class listing exceeds the allowed size")
    count = 0
    relevant: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "C":
            continue
        # Documented format: C d <defined-methods> <referenced-methods> <bytes> <name>
        if len(fields) != 6 or fields[1] != "d":
            continue
        name = fields[5]
        if not _CLASS_NAME.fullmatch(name):
            raise ValueError("apkanalyzer returned an unexpected class name")
        count += 1
        if count > _MAX_CLASSES:
            raise ValueError("APK contains too many defined classes")
        if _SIGNAL.search(name):
            relevant.add(name)
    if len(relevant) > _MAX_RELEVANT_CLASSES:
        raise ValueError("too many potentially relevant class names")
    return count, sorted(relevant)


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
            "source": "apkanalyzer",
            "raw_dex_output_included": False,
        }

    class_output = _run(resolved, ["dex", "packages", "--defined-only", apk], timeout)
    class_count, candidates = parse_defined_classes(class_output)
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
        "source": "apkanalyzer",
        "raw_dex_output_included": False,
    }
