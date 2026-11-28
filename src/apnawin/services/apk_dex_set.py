"""Aggregate static DEX linkage evidence across APK base/split packages."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from apnawin.services.apk_dex import inspect_apk_dex
from apnawin.services.apk_manifest import inspect_apk_manifest

_MAX_APK_SPLITS = 64


def inspect_apk_dex_set(
    apk_paths: list[str | Path],
    executable: str = "apkanalyzer",
    timeout: float = 30,
) -> dict[str, Any]:
    """Inspect every APK split and join manifest services to classes across splits."""
    if not apk_paths or len(apk_paths) > _MAX_APK_SPLITS:
        raise ValueError("APK split count is outside the allowed range")
    paths = sorted((Path(path) for path in apk_paths), key=lambda path: path.name)
    if any(not path.is_file() for path in paths):
        raise ValueError("every APK split must be an existing regular file")
    names = [path.name for path in paths]
    if len(names) != len(set(names)):
        raise ValueError("APK split basenames must be unique")

    manifests = [
        (path, inspect_apk_manifest(path, executable=executable, timeout=timeout))
        for path in paths
    ]
    package_names = sorted({
        manifest["package_name"]
        for _, manifest in manifests
        if manifest["package_name"] is not None
    })
    if len(package_names) > 1:
        raise ValueError("APK splits declare inconsistent package names")
    package_name = package_names[0] if package_names else None
    services = sorted({
        service
        for _, manifest in manifests
        for service in manifest["vpn_services"]
    })

    per_apk: list[dict[str, Any]] = []
    for path, manifest in manifests:
        dex = inspect_apk_dex(
            path,
            executable=executable,
            timeout=timeout,
            manifest_services=services,
            package_name=package_name,
        )
        per_apk.append({
            "apk": path.name,
            "manifest": {
                "package_name": manifest["package_name"],
                "version_code": manifest["version_code"],
                "min_sdk": manifest["min_sdk"],
                "target_sdk": manifest["target_sdk"],
                "vpn_services": manifest["vpn_services"],
            },
            "dex": dex,
        })

    service_locations = []
    for service in services:
        resolved_names = {
            item["resolved_class_name"]
            for apk in per_apk
            for item in apk["dex"]["manifest_service_classes"]
            if item["manifest_name"] == service and item["resolved_class_name"]
        }
        resolved_name = next(iter(resolved_names), None)
        matching_rows = [
            (apk["apk"], item)
            for apk in per_apk
            for item in apk["dex"]["manifest_service_classes"]
            if item["manifest_name"] == service
        ]
        service_locations.append({
            "manifest_name": service,
            "resolved_class_name": resolved_name,
            "defined_in_apks": sorted(
                apk_name for apk_name, item in matching_rows if item["defined_in_dex"]
            ),
            "native_method_counts_by_apk": {
                apk_name: item["native_method_count"]
                for apk_name, item in matching_rows
                if item["native_method_inspection_completed"]
            },
        })

    return {
        "format": "apnawin-apk-dex-split-set-v1",
        "apk_count": len(paths),
        "package_name": package_name,
        "manifest_services": services,
        "dex_file_count_total": sum(
            apk["dex"]["dex_file_count"] for apk in per_apk
        ),
        "defined_class_count_total": sum(
            apk["dex"]["defined_class_count"] for apk in per_apk
        ),
        "service_class_locations": service_locations,
        "per_apk": per_apk,
        "static_analysis_only": True,
        "android_device_required": False,
        "raw_dex_output_included": False,
    }
