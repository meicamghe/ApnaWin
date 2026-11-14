from unittest.mock import patch

import pytest

from apnawin.services import apk_report


def test_native_engine_candidates_are_filename_only_heuristics():
    libraries = [
        {"abi": "arm64-v8a", "library_name": "libxray.so", "file_size_bytes": 10},
        {"abi": "x86_64", "library_name": "libhev-socks5-tunnel.so", "file_size_bytes": 20},
        {"abi": "arm64-v8a", "library_name": "libordinary.so", "file_size_bytes": 30},
    ]

    result = apk_report._native_engine_candidates(libraries)

    assert result == [
        {
            "abi": "arm64-v8a",
            "library_name": "libxray.so",
            "candidate": "xray",
            "candidate_only": True,
        },
        {
            "abi": "x86_64",
            "library_name": "libhev-socks5-tunnel.so",
            "candidate": "tun2socks",
            "candidate_only": True,
        },
    ]
    assert all("file_size_bytes" not in item for item in result)


def test_native_engine_candidates_do_not_mutate_inventory():
    libraries = [
        {"abi": "arm64-v8a", "library_name": "libwireguard.so", "file_size_bytes": 42}
    ]
    original = [dict(item) for item in libraries]

    apk_report._native_engine_candidates(libraries)

    assert libraries == original


@pytest.mark.parametrize(
    "name",
    ["libassets.so", "libclassroom.so", "libssrhelperx.so", "libtrojanhorse.so",
     "libdnsproxyhelper.so", "libnotxray.so"],
)
def test_native_engine_candidates_reject_embedded_substrings(name):
    assert apk_report._native_engine_candidates(
        [{"abi": "arm64-v8a", "library_name": name}]
    ) == []


@pytest.mark.parametrize(
    ("name", "engine"),
    [
        ("libssr.so", "shadowsocks"),
        ("libssr_helper.so", "shadowsocks"),
        ("libxray_core.so", "xray"),
        ("libdns-proxy.so", "dns-proxy"),
        ("libsing-box.so", "sing-box"),
        ("libhev-socks5-tunnel.so", "tun2socks"),
    ],
)
def test_native_engine_candidates_accept_token_boundaries(name, engine):
    result = apk_report._native_engine_candidates(
        [{"abi": "arm64-v8a", "library_name": name}]
    )
    assert len(result) == 1
    assert result[0]["candidate"] == engine
    assert result[0]["candidate_only"] is True


def _report_fixtures(dex_count=2):
    inventory = {
        "format": "apnawin-apk-inventory-v1",
        "sha256": "a" * 64,
        "file_size_bytes": 1234,
        "dex_file_count": 2,
        "native_libraries": [
            {"abi": "arm64-v8a", "library_name": "libxray.so", "file_size_bytes": 10},
            {"abi": "x86_64", "library_name": "libordinary.so", "file_size_bytes": 20},
            {"abi": "x86_64", "library_name": "libordinary2.so", "file_size_bytes": 30},
        ],
    }
    manifest = {"package_name": "org.example.app", "vpn_services": [".TunnelService"]}
    dex = {
        "dex_file_count": dex_count,
        "manifest_service_classes": [
            {
                "manifest_name": ".TunnelService",
                "resolved_class_name": "org.example.app.TunnelService",
                "defined_in_dex": True,
            }
        ],
    }
    return inventory, manifest, dex


def test_combined_report_correlates_evidence_and_summarizes_abis():
    inventory, manifest, dex = _report_fixtures()
    with (
        patch.object(apk_report, "inspect_apk", return_value=inventory),
        patch.object(apk_report, "inspect_apk_manifest", return_value=manifest),
        patch.object(apk_report, "inspect_apk_dex", return_value=dex) as inspect_dex,
    ):
        report = apk_report.inspect_apk_report("sample.apk", executable="apkanalyzer")

    inspect_dex.assert_called_once_with(
        "sample.apk",
        executable="apkanalyzer",
        timeout=30,
        manifest_services=[".TunnelService"],
        package_name="org.example.app",
    )
    assert report["native"]["library_count"] == 3
    assert report["native"]["abi_library_counts"] == {
        "arm64-v8a": 1,
        "x86_64": 2,
    }
    assert report["native"]["engine_candidates"][0]["candidate"] == "xray"
    assert report["interpretation"]["vpn_service_declared"] is True
    assert report["interpretation"]["vpn_service_class_found_in_dex"] is True
    assert report["interpretation"]["runtime_behavior_verified"] is False
    assert report["interpretation"]["server_endpoints_discovered"] is False


def test_combined_report_rejects_dex_count_disagreement():
    inventory, manifest, dex = _report_fixtures(dex_count=1)
    with (
        patch.object(apk_report, "inspect_apk", return_value=inventory),
        patch.object(apk_report, "inspect_apk_manifest", return_value=manifest),
        patch.object(apk_report, "inspect_apk_dex", return_value=dex),
        pytest.raises(ValueError, match="disagree on DEX file count"),
    ):
        apk_report.inspect_apk_report("sample.apk")



@pytest.mark.parametrize(
    ("service_rows", "expected"),
    [
        (
            [{"manifest_name": ".TunnelService", "resolved_class_name": "org.example.app.TunnelService", "defined_in_dex": False}],
            {"vpn_service_class_match_count": 0, "vpn_service_class_unmatched_count": 1, "vpn_service_class_unresolved_count": 0, "vpn_service_class_resolution_complete": True},
        ),
        (
            [{"manifest_name": ".TunnelService", "resolved_class_name": None, "defined_in_dex": False}],
            {"vpn_service_class_match_count": 0, "vpn_service_class_unmatched_count": 0, "vpn_service_class_unresolved_count": 1, "vpn_service_class_resolution_complete": False},
        ),
        (
            [
                {"manifest_name": ".TunnelService", "resolved_class_name": "org.example.app.TunnelService", "defined_in_dex": True},
                {"manifest_name": ".OtherService", "resolved_class_name": None, "defined_in_dex": False},
            ],
            {"vpn_service_class_match_count": 1, "vpn_service_class_unmatched_count": 0, "vpn_service_class_unresolved_count": 1, "vpn_service_class_resolution_complete": False},
        ),
    ],
)
def test_combined_report_distinguishes_matched_missing_and_unresolved_services(service_rows, expected):
    inventory, manifest, dex = _report_fixtures()
    dex["manifest_service_classes"] = service_rows
    with (
        patch.object(apk_report, "inspect_apk", return_value=inventory),
        patch.object(apk_report, "inspect_apk_manifest", return_value=manifest),
        patch.object(apk_report, "inspect_apk_dex", return_value=dex),
    ):
        report = apk_report.inspect_apk_report("sample.apk")
    interpretation = report["interpretation"]
    for key, value in expected.items():
        assert interpretation[key] == value
    assert interpretation["vpn_service_class_found_in_dex"] is (
        expected["vpn_service_class_match_count"] > 0
    )
