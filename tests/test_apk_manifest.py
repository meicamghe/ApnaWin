import pytest

from apnawin.services import apk_manifest


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.example.client" android:versionCode="51" android:versionName="1.2.3">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
  <application>
    <service android:name=".TunnelService"
      android:permission="android.permission.BIND_VPN_SERVICE"
      android:exported="true" />
    <activity android:name=".MainActivity" android:exported="false" />
  </application>
</manifest>
"""


def test_parse_manifest_returns_allowlisted_metadata():
    report = apk_manifest.parse_manifest_xml(MANIFEST)

    assert report["package_name"] == "org.example.client"
    assert report["version_code"] == 51
    assert report["version_name_present"] is True
    assert report["min_sdk"] == 24
    assert report["target_sdk"] == 36
    assert report["permissions"] == [
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.INTERNET",
    ]
    assert report["vpn_services"] == [".TunnelService"]
    assert report["components"][0]["exported"] is True
    assert report["raw_manifest_included"] is False
    assert "1.2.3" not in str(report)


@pytest.mark.parametrize("xml", [
    "<not-manifest />",
    "<manifest",
    '<!DOCTYPE manifest [<!ENTITY x "bad">]><manifest />',
])
def test_parser_rejects_invalid_or_unsafe_xml(xml):
    with pytest.raises(ValueError):
        apk_manifest.parse_manifest_xml(xml)


def test_parser_rejects_excessive_components():
    components = "".join(
        f'<service xmlns:android="http://schemas.android.com/apk/res/android" android:name=".S{i}" />'
        for i in range(apk_manifest._MAX_REPORTED_ITEMS + 1)
    )
    xml = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        f"<application>{components}</application></manifest>"
    )
    with pytest.raises(ValueError, match="too many components"):
        apk_manifest.parse_manifest_xml(xml)


def test_inspector_uses_argv_without_shell_and_parses_output(tmp_path, monkeypatch):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"placeholder apk")
    calls = {}

    def fake_run(executable, args, timeout, limit, failure, timed_out, overflow):
        calls["args"] = [executable, *args]
        calls["timeout"] = timeout
        calls["limit"] = limit
        return MANIFEST.encode()

    monkeypatch.setattr(apk_manifest.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_manifest, "run_apkanalyzer", fake_run)

    report = apk_manifest.inspect_apk_manifest(apk)

    assert report["package_name"] == "org.example.client"
    assert calls["args"][:3] == ["/sdk/apkanalyzer", "manifest", "print"]
    assert calls["timeout"] == 30
    assert calls["limit"] == apk_manifest._MAX_APKANALYZER_OUTPUT


def test_inspector_reports_missing_sdk_tool(tmp_path, monkeypatch):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"placeholder")
    monkeypatch.setattr(apk_manifest.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="not found"):
        apk_manifest.inspect_apk_manifest(apk)


def test_inspector_redacts_tool_errors(tmp_path, monkeypatch):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"placeholder")

    monkeypatch.setattr(apk_manifest.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_manifest, "run_apkanalyzer", lambda *a: (_ for _ in ()).throw(RuntimeError("apkanalyzer failed to inspect the APK")))

    with pytest.raises(RuntimeError, match="failed to inspect"):
        apk_manifest.inspect_apk_manifest(apk)
