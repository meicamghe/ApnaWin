#!/usr/bin/env python3
"""Compare Go ELF metadata and symbol fingerprints without executing either input."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

MAX_ELF_BYTES = 64 * 1024 * 1024
MAX_TOOL_OUTPUT = 24 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 60

_PACKAGE_RE = re.compile(rb"github\.com/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
_GO_TAG_RE = re.compile(rb'json:"[A-Za-z0-9_,.-]+"')
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{5,}")
_WIRE_NAMES = {
    "clientHello",
    "serverHello",
    "clientRequest",
    "serverResponse",
    "udpMessage",
    "maxRate",
}
_CONFIG_TAGS = {
    "server", "protocol", "auth", "auth_str", "alpn", "server_name",
    "insecure", "socks5", "tun", "up", "down", "up_mbps", "down_mbps",
    "obfs", "hop_interval", "fast_open", "lazy_start", "recv_window_conn",
    "relay_tcps", "relay_udps", "tproxy_udp", "redirect_tcp",
    "disable_mtu_discovery",
}


def _run(args: list[str], *, required: bool = True) -> tuple[str, str | None]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        if required:
            raise RuntimeError(f"Required analysis tool is missing: {args[0]}")
        return "", f"tool not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return "", f"tool timed out after {TOOL_TIMEOUT_SECONDS}s: {args[0]}"
    output = result.stdout
    if len(output) > MAX_TOOL_OUTPUT:
        return "", f"tool output exceeded {MAX_TOOL_OUTPUT} bytes: {args[0]}"
    if result.returncode != 0:
        detail = result.stderr.strip()[:1000] or f"exit code {result.returncode}"
        return output, f"{args[0]}: {detail}"
    return output, None


def _validate_input(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Input must be a regular, non-symlink file: {path}")
    size = path.stat().st_size
    if size < 64 or size > MAX_ELF_BYTES:
        raise ValueError(f"ELF input size is outside the 64..{MAX_ELF_BYTES} byte limit: {path}")
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError(f"Input is not an ELF file: {path}")
    return path.resolve()


def parse_readelf(text: str) -> dict:
    result = {
        "elf_class": None,
        "endianness": None,
        "type": None,
        "machine": None,
        "entry_point": None,
        "interpreter": None,
        "build_id": None,
        "needed_libraries": [],
    }
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Class:"):
            result["elf_class"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Data:"):
            result["endianness"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Type:"):
            result["type"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Machine:"):
            result["machine"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Entry point address:"):
            result["entry_point"] = stripped.split(":", 1)[1].strip()
        elif "Requesting program interpreter:" in stripped:
            result["interpreter"] = stripped.split(":", 1)[1].strip().strip("[]")
        elif stripped.startswith("Build ID:"):
            result["build_id"] = stripped.split(":", 1)[1].strip()
        elif "(NEEDED)" in stripped:
            match = re.search(r"Shared library: \[([^\]]+)\]", stripped)
            if match:
                result["needed_libraries"].append(match.group(1))
    return result


def parse_go_symbols(text: str) -> set[str]:
    symbols = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        name = fields[-1]
        kind = fields[-2]
        if len(kind) == 1 and kind.isalpha() and (
            "." in name or name.startswith(("main", "type:", "go:"))
        ):
            symbols.add(name)
    return symbols


def extract_fingerprints(data: bytes) -> dict:
    printable = b"\n".join(_PRINTABLE_RE.findall(data))
    packages = {item.decode("ascii", "replace") for item in _PACKAGE_RE.findall(printable)}
    tags = {item.decode("ascii", "replace") for item in _GO_TAG_RE.findall(printable)}
    words = {
        word.decode("ascii", "replace")
        for word in re.findall(rb"[A-Za-z][A-Za-z0-9_./:-]{3,}", printable)
    }
    wire_names = sorted(name for name in _WIRE_NAMES if name.encode() in printable)
    config_tags = sorted(tag for tag in _CONFIG_TAGS if any(
        (b'json:"' + tag.encode() + b'"') in item for item in _GO_TAG_RE.findall(printable)
    ))
    return {
        "go_packages": sorted(packages),
        "go_json_tags": sorted(tags),
        "wire_struct_names": wire_names,
        "config_json_tags": config_tags,
        "network_keyword_count": sum(
            1 for word in words
            if any(key in word.casefold() for key in ("quic", "socks", "pion", "dtls", "proxy", "udp"))
        ),
    }


def inspect(path: Path) -> dict:
    resolved = _validate_input(path)
    data = resolved.read_bytes()
    readelf, readelf_error = _run(
        ["readelf", "-h", "-l", "-d", "-n", str(resolved)]
    )
    go_build, build_error = _run(["go", "version", "-m", str(resolved)], required=False)
    nm_output, nm_error = _run(["go", "tool", "nm", str(resolved)], required=False)
    return {
        "path": str(resolved),
        "size_bytes": len(data),
        "sha256": __import__("hashlib").sha256(data).hexdigest(),
        "elf": parse_readelf(readelf),
        "go_build_info": go_build.strip() or None,
        "go_build_info_error": build_error,
        "go_symbols": sorted(parse_go_symbols(nm_output)),
        "go_symbols_error": nm_error,
        "fingerprints": extract_fingerprints(data),
        "native_code_executed": False,
    }


def compare(left: dict, right: dict) -> dict:
    left_symbols = set(left["go_symbols"])
    right_symbols = set(right["go_symbols"])
    common_symbols = left_symbols & right_symbols
    union_symbols = left_symbols | right_symbols
    left_packages = set(left["fingerprints"]["go_packages"])
    right_packages = set(right["fingerprints"]["go_packages"])
    common_packages = left_packages & right_packages
    left_tags = set(left["fingerprints"]["go_json_tags"])
    right_tags = set(right["fingerprints"]["go_json_tags"])
    common_tags = left_tags & right_tags
    return {
        "same_sha256": left["sha256"] == right["sha256"],
        "go_symbol_counts": {"left": len(left_symbols), "right": len(right_symbols)},
        "common_go_symbol_count": len(common_symbols),
        "go_symbol_jaccard": (
            round(len(common_symbols) / len(union_symbols), 6) if union_symbols else None
        ),
        "common_go_packages": sorted(common_packages),
        "common_go_json_tags": sorted(common_tags),
        "common_wire_struct_names": sorted(
            set(left["fingerprints"]["wire_struct_names"])
            & set(right["fingerprints"]["wire_struct_names"])
        ),
        "common_config_json_tags": sorted(
            set(left["fingerprints"]["config_json_tags"])
            & set(right["fingerprints"]["config_json_tags"])
        ),
        "interpretation": (
            "Fingerprint similarity only; not proof of identical source, service ownership, "
            "wire-protocol configuration, authentication compatibility, or server acceptance."
        ),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare Go symbol and package fingerprints in two ELF files; never execute them."
    )
    parser.add_argument("left", type=Path, help="APNA ARM64 libudpqtwo.so")
    parser.add_argument("right", type=Path, help="comparison libudpqtwo.so sample")
    args = parser.parse_args(argv)
    try:
        left = inspect(args.left)
        right = inspect(args.right)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"analysis failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "left": left,
        "right": right,
        "comparison": compare(left, right),
    }, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
