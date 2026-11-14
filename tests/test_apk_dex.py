import subprocess

import pytest

from apnawin.services import apk_dex


def test_parse_dex_file_list():
    assert apk_dex.parse_dex_file_list("classes.dex\nclasses2.dex\nclasses10.dex\n") == [
        "classes.dex", "classes2.dex", "classes10.dex"
    ]


@pytest.mark.parametrize("output", [
    "../classes.dex\n",
    "classes.dex\nclasses.dex\n",
    "classes1.dex\n",
    "classes2.dex/evil\n",
])
def test_rejects_unsafe_or_duplicate_dex_names(output):
    with pytest.raises(ValueError):
        apk_dex.parse_dex_file_list(output)


def test_parse_defined_classes_selects_network_candidates_only():
    output = (
        "P d 1 1 10 com.example\n"
        "C d 3 2 80 com.example.TunnelVpnService\n"
        "C d 2 1 60 com.example.ui.HomeActivity\n"
        "C r 0 1 30 android.net.VpnService\n"
    )
    count, candidates = apk_dex.parse_defined_classes(output)
    assert count == 2
    assert candidates == ["com.example.TunnelVpnService"]


def test_parse_defined_classes_rejects_malformed_defined_class():
    with pytest.raises(ValueError):
        apk_dex.parse_defined_classes("C d 1 1 20 ../BadName\n")


def test_parse_reference_counts():
    assert apk_dex.parse_reference_counts(
        "classes.dex 59598\nclasses2.dex 8042\n"
    ) == {"classes.dex": 59598, "classes2.dex": 8042}


def test_inspector_invokes_documented_commands(tmp_path, monkeypatch):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"placeholder")
    commands = []

    def fake_run(args, **kwargs):
        commands.append(args[1:-1])
        if args[1:3] == ["dex", "list"]:
            stdout = b"classes.dex\nclasses2.dex\n"
        elif args[1:3] == ["dex", "packages"]:
            stdout = b"C d 1 1 20 com.example.TunnelService\n"
        else:
            stdout = b"classes.dex 100\nclasses2.dex 200\n"

        class Completed:
            returncode = 0
            stderr = b""

        result = Completed()
        result.stdout = stdout
        return result

    monkeypatch.setattr(apk_dex.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_dex.subprocess, "run", fake_run)
    report = apk_dex.inspect_apk_dex(apk)

    assert report["dex_file_count"] == 2
    assert report["defined_class_count"] == 1
    assert report["candidate_classes"] == ["com.example.TunnelService"]
    assert commands == [
        ["dex", "list"],
        ["dex", "packages", "--defined-only"],
        ["dex", "references"],
    ]


def test_dex_tool_failure_is_sanitized(tmp_path, monkeypatch):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"placeholder")

    class Failed:
        returncode = 2
        stdout = b""
        stderr = b"private data"

    monkeypatch.setattr(apk_dex.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_dex.subprocess, "run", lambda *a, **k: Failed())
    with pytest.raises(RuntimeError, match="failed during DEX"):
        apk_dex.inspect_apk_dex(apk)


def test_manifest_vpn_service_is_joined_to_defined_dex_class():
    output = (
        "C d 1 1 20 com.example.TunnelService\\n"
        "C d 1 1 20 com.example.Other\\n"
    )
    count, candidates, defined = apk_dex._parse_defined_class_details(output)
    assert count == 2
    assert "com.example.TunnelService" in defined
    assert candidates == ["com.example.TunnelService"]
    assert apk_dex._resolve_manifest_class(".TunnelService", "com.example") == (
        "com.example.TunnelService"
    )
    assert apk_dex._resolve_manifest_class("TunnelService", "com.example") == (
        "com.example.TunnelService"
    )


def test_manifest_service_join_does_not_claim_missing_class():
    output = "C d 1 1 20 com.example.Other\\n"
    _, _, defined = apk_dex._parse_defined_class_details(output)
    assert "com.example.TunnelService" not in defined
