"""Fingerprint embedded native engines from verified extracted APK libraries.

Only allowlisted protocol/runtime markers and their occurrence counts are
reported. Arbitrary strings, credentials, raw binary data and code are never
copied into the report. No binary is loaded or executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

_MAX_FILES = 4096
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MARKERS = {
    "protocol_family": {
        "vless": re.compile(rb"vless", re.I),
        "vmess": re.compile(rb"vmess", re.I),
        "trojan": re.compile(rb"trojan", re.I),
        "shadowsocks": re.compile(rb"shadowsocks|shadowsocksr", re.I),
        "hysteria": re.compile(rb"hysteria", re.I),
        "starudp": re.compile(rb"starudp", re.I),
        "quic": re.compile(rb"quic", re.I),
        "openvpn": re.compile(rb"openvpn", re.I),
        "wireguard": re.compile(rb"wireguard", re.I),
        "socks": re.compile(rb"socks[45]", re.I),
        "tun2socks": re.compile(rb"tun2socks", re.I),
        "udp": re.compile(rb"udp", re.I),
        "tcp": re.compile(rb"tcp", re.I),
        "tls": re.compile(rb"tls", re.I),
        "dtls": re.compile(rb"dtls", re.I),
        "kcp": re.compile(rb"kcp", re.I),
        "websocket": re.compile(rb"websocket", re.I),
        "grpc": re.compile(rb"grpc", re.I),
        "obfuscation": re.compile(rb"obfs|obfusc", re.I),
    },
    "go_runtime": {
        "go_buildinfo": re.compile(rb"go\.buildinfo", re.I),
        "gopclntab": re.compile(rb"gopclntab|pclntab", re.I),
        "moduledata": re.compile(rb"moduledata", re.I),
        "go_runtime_main": re.compile(rb"runtime\.main", re.I),
        "go_version_string": re.compile(rb"go1\.[0-9]+(?:\.[0-9]+)?", re.I),
        "go_type_metadata": re.compile(rb"\*\[\]\*?runtime\.type|type\.\*", re.I),
    },
    "starudp_wire_types": {
        "client_hello": re.compile(rb"\bclientHello\b"),
        "server_hello": re.compile(rb"\bserverHello\b"),
        "client_request": re.compile(rb"\bclientRequest\b"),
        "server_response": re.compile(rb"\bserverResponse\b"),
        "udp_message": re.compile(rb"\budpMessage\b"),
        "sizeof_auth": re.compile(rb"sizeof=Auth"),
        "sizeof_host": re.compile(rb"sizeof=Host"),
        "sizeof_message": re.compile(rb"sizeof=Message"),
        "sizeof_data": re.compile(rb"sizeof=Data"),
    },
    "starudp_config_keys": {
        "server": re.compile(rb"\bserver\b"),
        "protocol": re.compile(rb"\bprotocol\b"),
        "auth": re.compile(rb"\bauth\b"),
        "alpn": re.compile(rb"\balpn\b"),
        "server_name": re.compile(rb"\bserver_name\b"),
        "insecure": re.compile(rb"\binsecure\b"),
        "socks5": re.compile(rb"\bsocks5\b"),
        "tun": re.compile(rb"\btun\b"),
        "upload_rate": re.compile(rb"\bup\b"),
        "download_rate": re.compile(rb"\bdown\b"),
        "obfuscation": re.compile(rb"\bobfs\b"),
        "fast_open": re.compile(rb"\bfast_open\b"),
        "lazy_start": re.compile(rb"\blazy_start\b"),
    },
    "transport_dependencies": {
        "quic_go": re.compile(rb"quic-go|quicgo", re.I),
        "pion_dtls": re.compile(rb"pion[/_-]dtls|github\.com/pion/dtls", re.I),
        "txthinking_socks5": re.compile(rb"txthinking[/_-]socks5|github\.com/txthinking/socks5", re.I),
        "goproxy": re.compile(rb"goproxy", re.I),
        "routedns": re.compile(rb"routedns", re.I),
        "tproxy": re.compile(rb"tproxy", re.I),
    },
    "engine_components": {
        "libliapp": re.compile(rb"liapp", re.I),
        "pdnsd": re.compile(rb"pdnsd", re.I),
        "tun2socks": re.compile(rb"tun2socks", re.I),
        "pion": re.compile(rb"pion", re.I),
        "quic_go": re.compile(rb"quic-go|quicgo", re.I),
        "goproxy": re.compile(rb"goproxy", re.I),
        "routedns": re.compile(rb"routedns", re.I),
        "xray": re.compile(rb"xray", re.I),
        "v2ray": re.compile(rb"v2ray", re.I),
    },
}
_APK_NAME = re.compile(r"^[A-Za-z0-9_.+-]{1,128}\.apk$")
_ABI_COMPONENT = re.compile(r"^[A-Za-z0-9_+-]{1,64}$")
_LIBRARY_NAME = re.compile(r"^lib[A-Za-z0-9_.+-]{1,120}\.so$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def analyze_native_fingerprints(extraction_dir: str | Path) -> dict[str, Any]:
    root = Path(extraction_dir)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("extraction directory must be a real directory")
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("native extraction manifest is missing or unsafe")
    manifest_size = manifest_path.stat().st_size
    if manifest_size > _MAX_MANIFEST_BYTES:
        raise ValueError("native extraction manifest exceeds the analysis limit")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("native extraction manifest is not valid UTF-8 JSON") from exc
    if not isinstance(manifest, dict):
        raise ValueError("native extraction manifest root must be an object")
    if manifest.get("format") != "apnawin-native-extraction-v1":
        raise ValueError("unsupported native extraction manifest")
    entries = manifest.get("libraries")
    if not isinstance(entries, list) or len(entries) > _MAX_FILES:
        raise ValueError("native extraction manifest has an invalid library list")

    rows = []
    total = 0
    seen_paths: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("native extraction manifest row is invalid")
        apk, abi, library = item.get("apk"), item.get("abi"), item.get("library")
        relative = item.get("relative_path")
        expected_size, expected_hash = item.get("size_bytes"), item.get("sha256")
        if (
            not isinstance(apk, str) or not _APK_NAME.fullmatch(apk)
            or not isinstance(abi, str) or not _ABI_COMPONENT.fullmatch(abi)
            or not isinstance(library, str) or not _LIBRARY_NAME.fullmatch(library)
            or not isinstance(relative, str)
            or relative != f"{apk}/{abi}/{library}"
            or not isinstance(expected_size, int) or not 0 <= expected_size <= _MAX_FILE_BYTES
            or not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash)
            or relative in seen_paths
        ):
            raise ValueError("native extraction manifest contains an unsafe row")
        seen_paths.add(relative)
        apk_dir = root / apk
        abi_dir = apk_dir / abi
        path = abi_dir / library
        resolved_root = root.resolve()
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError):
            raise ValueError("an extracted native library is missing or unsafe") from None
        if (
            apk_dir.is_symlink() or abi_dir.is_symlink()
            or path.is_symlink() or not path.is_file()
            or not resolved_path.is_file()
        ):
            raise ValueError("an extracted native library is missing or unsafe")
        actual_size = path.stat().st_size
        total += actual_size
        if actual_size > _MAX_FILE_BYTES or total > _MAX_TOTAL_BYTES:
            raise ValueError("native analysis exceeds the configured size limit")
        data = path.read_bytes()
        if len(data) != expected_size or len(data) != actual_size or hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError("an extracted native library failed manifest verification")
        if len(data) > _MAX_FILE_BYTES or total > _MAX_TOTAL_BYTES:
            raise ValueError("native analysis exceeds the configured size limit")

        marker_groups: dict[str, dict[str, int]] = {}
        for group, patterns in _MARKERS.items():
            found = {
                name: len(pattern.findall(data))
                for name, pattern in patterns.items()
            }
            found = {name: count for name, count in found.items() if count}
            if found:
                marker_groups[group] = found
        rows.append({
            "apk": apk,
            "abi": abi,
            "library": library,
            "size_bytes": len(data),
            "sha256": expected_hash,
            "elf_magic": data.startswith(b"\x7fELF"),
            "marker_groups": marker_groups,
            "native_code_executed": False,
        })

    rows.sort(key=lambda row: (row["apk"], row["abi"], row["library"]))
    return {
        "format": "apnawin-native-fingerprints-v1",
        "library_count": len(rows),
        "total_bytes_analyzed": total,
        "libraries": rows,
        "arbitrary_strings_included": False,
        "native_code_executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extraction_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = analyze_native_fingerprints(args.extraction_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"native fingerprint analysis failed: {exc}", file=sys.stderr)
        return 2
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
