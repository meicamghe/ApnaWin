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

    def fake_run(executable, args, timeout, limit, failure, timed_out, overflow):
        commands.append(args[:-1])
        if args[:2] == ["dex", "list"]:
            return b"classes.dex\nclasses2.dex\n"
        if args[:2] == ["dex", "packages"]:
            return b"C d 1 1 20 com.example.TunnelService\n"
        return b"classes.dex 100\nclasses2.dex 200\n"

    monkeypatch.setattr(apk_dex.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_dex, "run_apkanalyzer", fake_run)
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

    monkeypatch.setattr(apk_dex.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_dex, "run_apkanalyzer", lambda *a: (_ for _ in ()).throw(RuntimeError("apkanalyzer failed during DEX inspection")))
    with pytest.raises(RuntimeError, match="failed during DEX"):
        apk_dex.inspect_apk_dex(apk)


def test_manifest_vpn_service_is_joined_to_defined_dex_class():
    output = (
        "C d 1 1 20 com.example.TunnelService\n"
        "C d 1 1 20 com.example.Other\n"
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
    output = "C d 1 1 20 com.example.Other\n"
    _, _, defined = apk_dex._parse_defined_class_details(output)
    assert "com.example.TunnelService" not in defined


def test_no_dex_report_still_includes_manifest_service_join(tmp_path, monkeypatch):
    apk = tmp_path / "empty-dex.apk"
    apk.write_bytes(b"placeholder")
    outputs = iter([b""])
    monkeypatch.setattr(apk_dex.shutil, "which", lambda _: "/sdk/apkanalyzer")

    def fake_run(*args):
        return next(outputs)

    monkeypatch.setattr(apk_dex, "run_apkanalyzer", fake_run)
    report = apk_dex.inspect_apk_dex(
        apk, manifest_services=[".TunnelService"], package_name="com.example"
    )
    assert report["dex_file_count"] == 0
    assert report["manifest_service_classes"] == [{
        "manifest_name": ".TunnelService",
        "resolved_class_name": "com.example.TunnelService",
        "defined_in_dex": False,
        "defined_method_count": None,
        "referenced_method_count": None,
        "byte_count": None,
    }]



@pytest.mark.parametrize(
    "row",
    [
        "C d nope 1 20 com.example.TunnelService",
        "C d 1 1 20 com/example/TunnelService",
        "C x 1 1 20 com.example.TunnelService",
        "C d 1 1 20 com.example.TunnelService extra",
    ],
)
def test_parse_defined_classes_rejects_malformed_class_rows(row):
    with pytest.raises(ValueError, match="unexpected|invalid"):
        apk_dex.parse_defined_classes(row)


def test_parse_defined_classes_rejects_duplicate_defined_class_names():
    output = (
        "C d 1 1 20 com.example.TunnelService\n"
        "C d 2 1 30 com.example.TunnelService\n"
    )
    with pytest.raises(ValueError, match="duplicate defined class"):
        apk_dex.parse_defined_classes(output)


def test_parse_defined_classes_ignores_valid_referenced_class_rows():
    output = "C r 0 1 30 android.net.VpnService\n"
    assert apk_dex.parse_defined_classes(output) == (0, [])



def test_manifest_class_resolution_supports_nested_classes():
    assert apk_dex._resolve_manifest_class(
        ".vpn.Outer$TunnelService", "com.example"
    ) == "com.example.vpn.Outer$TunnelService"
    assert apk_dex._resolve_manifest_class(
        "com.example.vpn.Outer$TunnelService", "com.example"
    ) == "com.example.vpn.Outer$TunnelService"


@pytest.mark.parametrize("name", ["", ".", "bad/name", "bad name", "bad\\Name"])
def test_manifest_class_resolution_rejects_invalid_names(name):
    with pytest.raises(ValueError, match="invalid"):
        apk_dex._resolve_manifest_class(name, "com.example")


@pytest.mark.parametrize("name", [".TunnelService", "TunnelService"])
def test_relative_manifest_class_without_package_is_not_guessed(name):
    assert apk_dex._resolve_manifest_class(name, None) is None


def test_manifest_service_join_without_package_reports_unresolved_class(tmp_path, monkeypatch):
    apk = tmp_path / "missing-package.apk"
    apk.write_bytes(b"placeholder")
    outputs = iter([
        b"classes.dex\n",
        b"C d 1 1 20 com.example.TunnelService\n",
        b"classes.dex 10\n",
    ])
    monkeypatch.setattr(apk_dex.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_dex, "run_apkanalyzer", lambda *args: next(outputs))
    report = apk_dex.inspect_apk_dex(
        apk, manifest_services=[".TunnelService"], package_name=None
    )
    assert report["manifest_service_classes"] == [{
        "manifest_name": ".TunnelService",
        "resolved_class_name": None,
        "defined_in_dex": False,
        "defined_method_count": None,
        "referenced_method_count": None,
        "byte_count": None,
    }]

def test_manifest_service_join_includes_only_numeric_class_metadata(tmp_path, monkeypatch):
    apk = tmp_path / "service-evidence.apk"
    apk.write_bytes(b"placeholder")
    outputs = iter([
        b"classes.dex\n",
        b"C d 7 3 256 com.example.TunnelService\nC d 1 0 40 com.example.Other\n",
        b"classes.dex 100\n",
    ])
    monkeypatch.setattr(apk_dex.shutil, "which", lambda _: "/sdk/apkanalyzer")
    monkeypatch.setattr(apk_dex, "run_apkanalyzer", lambda *args: next(outputs))
    report = apk_dex.inspect_apk_dex(
        apk, manifest_services=[".TunnelService", ".Missing"], package_name="com.example"
    )
    assert report["manifest_service_classes"] == [
        {
            "manifest_name": ".TunnelService",
            "resolved_class_name": "com.example.TunnelService",
            "defined_in_dex": True,
            "defined_method_count": 7,
            "referenced_method_count": 3,
            "byte_count": 256,
        },
        {
            "manifest_name": ".Missing",
            "resolved_class_name": "com.example.Missing",
            "defined_in_dex": False,
            "defined_method_count": None,
            "referenced_method_count": None,
            "byte_count": None,
        },
    ]


def test_defined_class_metadata_keeps_referenced_rows_out_of_join():
    output = (
        "C d 4 2 128 com.example.TunnelService\\n"
        "C r 99 99 999 com.example.ReferencedOnly\\n"
    )
    count, candidates, metadata = apk_dex._parse_defined_class_metadata(output)
    assert count == 1
    assert candidates == ["com.example.TunnelService"]
    assert metadata == {
        "com.example.TunnelService": {
            "defined_method_count": 4,
            "referenced_method_count": 2,
            "byte_count": 128,
        }
    }

