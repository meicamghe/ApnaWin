"""Build a privacy-conscious combined APK analysis report."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from apnawin.services.apk_dex import inspect_apk_dex
from apnawin.services.apk_inventory import inspect_apk
from apnawin.services.apk_manifest import inspect_apk_manifest

_NATIVE_ENGINE_MARKERS = {
    "xray": ("xray",),
    "tun2socks": ("tun2socks", "hev-socks", "badvpn"),
    "openvpn": ("openvpn",),
    "wireguard": ("wireguard", "wg-go"),
    "shadowsocks": ("shadowsocks", "sslocal", "ssr"),
    "v2ray": ("v2ray",),
    "sing-box": ("singbox", "sing-box"),
    "trojan": ("trojan",),
    "dns-proxy": ("pdnsd", "dnsproxy", "dns-proxy"),
}


def _name_tokens(library_name: str) -> tuple[str, ...]:
    """Split a native basename into conservative alphanumeric name tokens."""
    stem = library_name.lower()
    if stem.startswith("lib"):
        stem = stem[3:]
    if stem.endswith(".so"):
        stem = stem[:-3]
    return tuple(token for token in re.split(r"[-_.]+", stem) if token)


def _marker_matches(tokens: tuple[str, ...], marker: str) -> bool:
    expected = tuple(part for part in re.split(r"[-_.]+", marker.lower()) if part)
    if not expected or len(tokens) < len(expected):
        return False
    for actual, wanted in zip(tokens, expected):
        if actual == wanted:
            continue
        # Android libraries commonly append an ABI/API variant number, e.g. socks5.
        if wanted == "socks" and actual.startswith("socks") and actual[5:].isdigit():
            continue
        return False
    return True


def _native_engine_candidates(libraries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return token-boundary filename leads; names never prove runtime behavior."""
    candidates = []
    for item in libraries:
        tokens = _name_tokens(item["library_name"])
        for engine, markers in _NATIVE_ENGINE_MARKERS.items():
            if any(_marker_matches(tokens, marker) for marker in markers):
                candidates.append({
                    "abi": item["abi"],
                    "library_name": item["library_name"],
                    "candidate": engine,
                    "candidate_only": True,
                })
                break
    return candidates


def inspect_apk_report(
    apk_path: str | Path,
    executable: str = "apkanalyzer",
    timeout: float = 30,
) -> dict[str, Any]:
    """Combine inventory, manifest and DEX metadata with exact service/class joins."""
    inventory = inspect_apk(apk_path)
    manifest = inspect_apk_manifest(apk_path, executable=executable, timeout=timeout)
    dex = inspect_apk_dex(
        apk_path,
        executable=executable,
        timeout=timeout,
        manifest_services=manifest["vpn_services"],
        package_name=manifest["package_name"],
    )
    if inventory["dex_file_count"] != dex["dex_file_count"]:
        raise ValueError("APK inventory and Android SDK disagree on DEX file count")

    abi_library_counts: dict[str, int] = {}
    for library in inventory["native_libraries"]:
        abi = library["abi"]
        abi_library_counts[abi] = abi_library_counts.get(abi, 0) + 1

    service_matches = dex["manifest_service_classes"]
    matched_services = sum(bool(item["defined_in_dex"]) for item in service_matches)
    unresolved_services = sum(item["resolved_class_name"] is None for item in service_matches)
    unmatched_services = len(service_matches) - matched_services - unresolved_services
    engine_candidates = _native_engine_candidates(inventory["native_libraries"])
    engine_candidate_counts: dict[str, int] = {}
    engine_candidate_abi_counts: dict[str, dict[str, int]] = {}
    for candidate in engine_candidates:
        engine = candidate["candidate"]
        abi = candidate["abi"]
        engine_candidate_counts[engine] = engine_candidate_counts.get(engine, 0) + 1
        per_abi = engine_candidate_abi_counts.setdefault(engine, {})
        per_abi[abi] = per_abi.get(abi, 0) + 1

    return {
        "format": "apnawin-apk-analysis-v1",
        "sha256": inventory["sha256"],
        "file_size_bytes": inventory["file_size_bytes"],
        "inventory": inventory,
        "manifest": manifest,
        "dex": dex,
        "native": {
            "library_count": len(inventory["native_libraries"]),
            "abi_library_counts": dict(sorted(abi_library_counts.items())),
            "libraries": inventory["native_libraries"],
            "engine_candidates": engine_candidates,
            "engine_candidate_counts": dict(sorted(engine_candidate_counts.items())),
            "engine_candidate_abi_counts": {
                engine: dict(sorted(counts.items()))
                for engine, counts in sorted(engine_candidate_abi_counts.items())
            },
            "windows_binary_reuse_verified": False,
        },
        "interpretation": {
            "vpn_service_declared": bool(manifest["vpn_services"]),
            "vpn_service_class_found_in_dex": matched_services > 0,
            "vpn_service_class_match_count": matched_services,
            "vpn_service_class_unmatched_count": unmatched_services,
            "vpn_service_class_unresolved_count": unresolved_services,
            "vpn_service_class_resolution_complete": unresolved_services == 0,
            "native_engine_candidates_present": bool(engine_candidates),
            "vpn_service_and_native_engine_candidates_co_present": (
                matched_services > 0 and bool(engine_candidates)
            ),
            "native_service_linkage_verified": False,
            "runtime_behavior_verified": False,
            "server_endpoints_discovered": False,
        },
    }
