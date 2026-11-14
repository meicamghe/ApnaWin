"""Optional Android SDK-backed APK manifest inspection.

The APK is passed to the installed apkanalyzer executable; archive members are
never extracted or executed by ApnaWin. Only selected manifest metadata is
returned, never arbitrary manifest text or resource values.
"""
from __future__ import annotations

import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from apnawin.services.apk_tool import run_apkanalyzer

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_MAX_APKANALYZER_OUTPUT = 4 * 1024 * 1024
_MAX_APKANALYZER_TIMEOUT_SECONDS = 30
_MAX_REPORTED_ITEMS = 512
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
_VPN_BIND_PERMISSION = "android.permission.BIND_VPN_SERVICE"
_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")
_CLASS_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")


def _valid_component_name(value: str) -> bool:
    candidate = value[1:] if value.startswith(".") else value
    return bool(candidate and _CLASS_NAME.fullmatch(candidate))


def _android_attr(element: ET.Element, name: str) -> str | None:
    return element.attrib.get(_ANDROID_NS + name)


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        try:
            parsed = int(value, 10)
        except ValueError:
            return None
    return parsed if parsed >= 0 else None


def parse_manifest_xml(xml_text: str) -> dict[str, Any]:
    """Parse apkanalyzer's textual XML into a small allowlisted metadata report."""
    if len(xml_text.encode("utf-8")) > _MAX_APKANALYZER_OUTPUT:
        raise ValueError("apkanalyzer output exceeds the allowed size")
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("manifest XML declarations are not allowed")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("apkanalyzer did not return valid manifest XML") from exc
    if root.tag != "manifest":
        raise ValueError("apkanalyzer output is not an Android manifest")

    package_name = root.attrib.get("package")
    if (
        not package_name
        or len(package_name) > 255
        or not _PACKAGE_NAME.fullmatch(package_name)
    ):
        package_name = None
    uses_sdk = root.find("uses-sdk")
    permissions: set[str] = set()
    for node in root:
        if node.tag in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
            name = _android_attr(node, "name")
            if name and len(name) <= 255:
                permissions.add(name)

    components: list[dict[str, Any]] = []
    vpn_services: list[str] = []
    application = root.find("application")
    if application is not None:
        for node in application:
            if node.tag not in _COMPONENT_TAGS:
                continue
            name = _android_attr(node, "name")
            if not name or len(name) > 255 or not _valid_component_name(name):
                continue
            permission = _android_attr(node, "permission")
            exported_text = _android_attr(node, "exported")
            exported = exported_text == "true" if exported_text in {"true", "false"} else None
            components.append({
                "type": node.tag,
                "name": name,
                "exported": exported,
                "permission": permission if permission and len(permission) <= 255 else None,
            })
            if node.tag == "service" and permission == _VPN_BIND_PERMISSION:
                vpn_services.append(name)
            if len(components) > _MAX_REPORTED_ITEMS:
                raise ValueError("manifest contains too many components")
    if len(permissions) > _MAX_REPORTED_ITEMS:
        raise ValueError("manifest contains too many permissions")

    return {
        "format": "apnawin-apk-manifest-v1",
        "package_name": package_name,
        "version_code": _safe_int(_android_attr(root, "versionCode")),
        "version_name_present": _android_attr(root, "versionName") is not None,
        "min_sdk": _safe_int(_android_attr(uses_sdk, "minSdkVersion")) if uses_sdk is not None else None,
        "target_sdk": _safe_int(_android_attr(uses_sdk, "targetSdkVersion")) if uses_sdk is not None else None,
        "permissions": sorted(permissions),
        "components": components,
        "vpn_services": sorted(set(vpn_services)),
        "source": "apkanalyzer",
        "raw_manifest_included": False,
    }


def inspect_apk_manifest(
    apk_path: str | Path,
    executable: str = "apkanalyzer",
    timeout: float = _MAX_APKANALYZER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run Android SDK apkanalyzer without a shell and return allowlisted metadata."""
    path = Path(apk_path)
    if not path.is_file():
        raise ValueError("APK path must refer to an existing regular file")
    if timeout <= 0 or timeout > _MAX_APKANALYZER_TIMEOUT_SECONDS:
        raise ValueError("apkanalyzer timeout is outside the allowed range")
    resolved = shutil.which(executable)
    if resolved is None and Path(executable).is_file():
        resolved = str(Path(executable).resolve())
    if resolved is None:
        raise RuntimeError("Android SDK apkanalyzer was not found on PATH")

    output = run_apkanalyzer(
        resolved,
        ["manifest", "print", str(path.resolve())],
        timeout,
        _MAX_APKANALYZER_OUTPUT,
        "apkanalyzer failed to inspect the APK",
        "apkanalyzer timed out",
        "apkanalyzer output exceeds the allowed size",
    )
    try:
        xml_text = output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("apkanalyzer output is not UTF-8 XML") from exc
    return parse_manifest_xml(xml_text)
