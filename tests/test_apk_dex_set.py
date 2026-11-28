from pathlib import Path

import pytest

from apnawin.services import apk_dex_set


def _manifest(services=None, package="com.example"):
    return {
        "package_name": package,
        "version_code": 51,
        "min_sdk": 23,
        "target_sdk": 35,
        "vpn_services": services or [],
    }


def _dex(service, defined):
    return {
        "dex_files": ["classes.dex"],
        "dex_file_count": 1,
        "defined_class_count": 3,
        "candidate_classes": ["com.example.vpn.TunnelService"],
        "method_references": {"classes.dex": 100},
        "manifest_service_classes": [{
            "manifest_name": service,
            "resolved_class_name": "com.example.vpn.TunnelService",
            "defined_in_dex": defined,
            "native_method_count": 1 if defined else None,
            "native_method_inspection_completed": defined,
        }],
        "native_linkage_evidence": [{
            "class_name": "com.example.vpn.TunnelService",
            "methods_with_evidence": [{
                "method_ordinal": 4,
                "invocation_kinds": ["dynamic_dex_loader", "runtime_exec", "system_load_library"],
                "invocation_counts": {"dynamic_dex_loader": 1, "runtime_exec": 1, "system_load_library": 1},
                "native_library_literals": ["libtun2socks.so"],
                "system_load_library_names": ["pdnsd"],
                "system_load_path_basenames": ["libudpqtwo.so"],
                "runtime_exec_library_basenames": ["libtun2socks.so"],
                "process_builder_library_basenames": ["libpdnsd.so"],
                "dynamic_dex_loader_path_extensions": ["dex"],
            }],
        }] if defined else [],
        "linkage_scan_classes_inspected": 1,
        "linkage_scan_truncated": False,
    }


def test_split_set_finds_service_class_defined_in_non_base_split(tmp_path, monkeypatch):
    base = tmp_path / "base.apk"
    split = tmp_path / "split_feature.apk"
    base.write_bytes(b"placeholder")
    split.write_bytes(b"placeholder")
    manifests = {
        "base.apk": _manifest([".vpn.TunnelService"]),
        "split_feature.apk": _manifest(),
    }

    monkeypatch.setattr(
        apk_dex_set,
        "inspect_apk_manifest",
        lambda path, **kwargs: manifests[Path(path).name],
    )
    monkeypatch.setattr(
        apk_dex_set,
        "inspect_apk_dex",
        lambda path, manifest_services, package_name, **kwargs: _dex(
            manifest_services[0], Path(path).name == "split_feature.apk"
        ),
    )

    report = apk_dex_set.inspect_apk_dex_set([split, base])

    assert report["apk_count"] == 2
    assert report["package_name"] == "com.example"
    assert report["manifest_services"] == [".vpn.TunnelService"]
    assert report["dex_file_count_total"] == 2
    assert report["defined_class_count_total"] == 6
    assert report["service_class_locations"] == [{
        "manifest_name": ".vpn.TunnelService",
        "resolved_class_name": "com.example.vpn.TunnelService",
        "defined_in_apks": ["split_feature.apk"],
        "native_method_counts_by_apk": {"split_feature.apk": 1},
    }]
    assert report["native_library_literal_references"] == [{
        "apk": "split_feature.apk",
        "class_name": "com.example.vpn.TunnelService",
        "method_ordinal": 4,
        "library_literal": "libtun2socks.so",
        "invocation_kinds": ["runtime_exec", "system_load_library"],
        "invocation_counts": {"runtime_exec": 1, "system_load_library": 1},
    }]
    assert report["system_load_path_references"] == [{
        "apk": "split_feature.apk",
        "class_name": "com.example.vpn.TunnelService",
        "method_ordinal": 4,
        "library_basename": "libudpqtwo.so",
        "loading_basis": "exact System.load path argument register",
    }]
    assert report["runtime_exec_library_references"] == [{
        "apk": "split_feature.apk",
        "class_name": "com.example.vpn.TunnelService",
        "method_ordinal": 4,
        "library_basename": "libtun2socks.so",
        "launch_basis": "exact Runtime.exec command argument register",
    }]
    assert report["process_builder_library_references"] == [{
        "apk": "split_feature.apk",
        "class_name": "com.example.vpn.TunnelService",
        "method_ordinal": 4,
        "library_basename": "libpdnsd.so",
        "launch_basis": "exact ProcessBuilder constructor argument register",
    }]
    assert report["system_load_library_references"] == [{
        "apk": "split_feature.apk",
        "class_name": "com.example.vpn.TunnelService",
        "method_ordinal": 4,
        "library_name_argument": "pdnsd",
        "mapped_library_basename": "libpdnsd.so",
        "mapping_basis": "Android System.loadLibrary naming convention",
    }]
    assert report["dynamic_dex_loader_references"] == [{
        "apk": "split_feature.apk",
        "class_name": "com.example.vpn.TunnelService",
        "method_ordinal": 4,
        "path_extensions": ["dex"],
        "path_basis": "exact DexClassLoader/PathClassLoader constructor path argument when directly literal",
    }]
    assert report["static_analysis_only"] is True
    assert report["android_device_required"] is False


def test_split_set_rejects_inconsistent_package_names(tmp_path, monkeypatch):
    first = tmp_path / "base.apk"
    second = tmp_path / "split.apk"
    first.write_bytes(b"x")
    second.write_bytes(b"y")
    manifests = {
        "base.apk": _manifest(package="com.example"),
        "split.apk": _manifest(package="com.other"),
    }
    monkeypatch.setattr(
        apk_dex_set,
        "inspect_apk_manifest",
        lambda path, **kwargs: manifests[Path(path).name],
    )

    with pytest.raises(ValueError, match="inconsistent package"):
        apk_dex_set.inspect_apk_dex_set([first, second])


def test_split_set_rejects_duplicate_basenames(tmp_path):
    first_dir = tmp_path / "one"
    second_dir = tmp_path / "two"
    first_dir.mkdir()
    second_dir.mkdir()
    first = first_dir / "base.apk"
    second = second_dir / "base.apk"
    first.write_bytes(b"x")
    second.write_bytes(b"y")

    with pytest.raises(ValueError, match="basenames must be unique"):
        apk_dex_set.inspect_apk_dex_set([first, second])


def test_split_set_requires_existing_inputs():
    with pytest.raises(ValueError, match="split count"):
        apk_dex_set.inspect_apk_dex_set([])


def test_split_set_rejects_conflicting_service_class_resolution(tmp_path, monkeypatch):
    base = tmp_path / "base.apk"
    split = tmp_path / "split.apk"
    base.write_bytes(b"x")
    split.write_bytes(b"y")
    manifests = {
        "base.apk": _manifest([".vpn.TunnelService"]),
        "split.apk": _manifest(),
    }
    monkeypatch.setattr(
        apk_dex_set,
        "inspect_apk_manifest",
        lambda path, **kwargs: manifests[Path(path).name],
    )

    def inspect(path, manifest_services, **kwargs):
        result = _dex(manifest_services[0], True)
        result["manifest_service_classes"][0]["resolved_class_name"] = (
            "com.example.vpn.TunnelService"
            if Path(path).name == "base.apk"
            else "com.example.other.TunnelService"
        )
        return result

    monkeypatch.setattr(apk_dex_set, "inspect_apk_dex", inspect)
    with pytest.raises(ValueError, match="resolve the same manifest service inconsistently"):
        apk_dex_set.inspect_apk_dex_set([base, split])
