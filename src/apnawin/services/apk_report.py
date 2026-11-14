"""Build a privacy-conscious combined APK analysis report."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from apnawin.services.apk_dex import inspect_apk_dex
from apnawin.services.apk_inventory import inspect_apk
from apnawin.services.apk_manifest import inspect_apk_manifest


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
    return {
        "format": "apnawin-apk-analysis-v1",
        "sha256": inventory["sha256"],
        "file_size_bytes": inventory["file_size_bytes"],
        "inventory": inventory,
        "manifest": manifest,
        "dex": dex,
        "interpretation": {
            "vpn_service_declared": bool(manifest["vpn_services"]),
            "vpn_service_class_found_in_dex": any(
                item["defined_in_dex"] for item in dex["manifest_service_classes"]
            ),
            "runtime_behavior_verified": False,
            "server_endpoints_discovered": False,
        },
    }
