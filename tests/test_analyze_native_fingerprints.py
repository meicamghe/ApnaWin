import hashlib
import json

import pytest

from tools.analyze_native_fingerprints import analyze_native_fingerprints


def _fixture(root, payload=b"\x7fELF" + b" quic quic runtime.main secret-token"):
    apk = "base.apk"
    abi = "arm64-v8a"
    library = "libengine.so"
    target = root / apk / abi
    target.mkdir(parents=True)
    (target / library).write_bytes(payload)
    manifest = {
        "format": "apnawin-native-extraction-v1",
        "libraries": [{
            "apk": apk,
            "abi": abi,
            "library": library,
            "relative_path": f"{apk}/{abi}/{library}",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return target / library


def test_reports_only_allowlisted_protocol_and_runtime_markers(tmp_path):
    _fixture(tmp_path)
    report = analyze_native_fingerprints(tmp_path)

    assert report["library_count"] == 1
    row = report["libraries"][0]
    assert row["elf_magic"] is True
    assert row["marker_groups"]["protocol_family"]["quic"] == 2
    assert row["marker_groups"]["go_runtime"]["go_runtime_main"] == 1
    assert "secret-token" not in json.dumps(report)
    assert report["arbitrary_strings_included"] is False
    assert report["native_code_executed"] is False


def test_rejects_hash_mismatch_before_fingerprinting(tmp_path):
    target = _fixture(tmp_path)
    target.write_bytes(target.read_bytes() + b"tampered")

    with pytest.raises(ValueError, match="failed manifest verification"):
        analyze_native_fingerprints(tmp_path)


def test_rejects_symlinked_library_parent(tmp_path):
    target = tmp_path / "real" / "arm64-v8a"
    target.mkdir(parents=True)
    payload = b"\\x7fELF quic"
    lib = target / "libengine.so"
    lib.write_bytes(payload)
    (tmp_path / "base.apk").symlink_to(tmp_path / "real", target_is_directory=True)
    manifest = {
        "format": "apnawin-native-extraction-v1",
        "libraries": [{
            "apk": "base.apk",
            "abi": "arm64-v8a",
            "library": "libengine.so",
            "relative_path": "base.apk/arm64-v8a/libengine.so",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="missing or unsafe"):
        analyze_native_fingerprints(tmp_path)


def test_rejects_unsafe_manifest_relative_path(tmp_path):
    _fixture(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["libraries"][0]["relative_path"] = "../libengine.so"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe row"):
        analyze_native_fingerprints(tmp_path)


def test_reports_allowlisted_starudp_wire_types_config_and_dependencies(tmp_path):
    payload = (
        b"clientHello serverHello clientRequest serverResponse udpMessage "
        b"sizeof=Auth sizeof=Host sizeof=Message sizeof=Data "
        b"server protocol auth alpn server_name insecure socks5 tun up down "
        b"obfs fast_open lazy_start quic-go github.com/pion/dtls "
        b"github.com/txthinking/socks5 goproxy routedns tproxy "
        b"provider-secret.example:443"
    )
    _fixture(tmp_path, payload=payload)
    report = analyze_native_fingerprints(tmp_path)
    groups = report["libraries"][0]["marker_groups"]

    assert groups["starudp_wire_types"] == {
        "client_hello": 1,
        "server_hello": 1,
        "client_request": 1,
        "server_response": 1,
        "udp_message": 1,
        "sizeof_auth": 1,
        "sizeof_host": 1,
        "sizeof_message": 1,
        "sizeof_data": 1,
    }
    assert groups["starudp_config_keys"]["server_name"] == 1
    assert groups["starudp_config_keys"]["upload_rate"] == 1
    assert groups["starudp_config_keys"]["download_rate"] == 1
    assert groups["transport_dependencies"]["quic_go"] == 1
    assert groups["transport_dependencies"]["pion_dtls"] == 1
    assert groups["transport_dependencies"]["txthinking_socks5"] == 1
    assert "provider-secret.example" not in json.dumps(report)



@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("abi", ".."),
        ("abi", "."),
        ("library", ".."),
        ("library", "manifest.json"),
        ("library", "libengine.so/../../outside"),
    ],
)
def test_rejects_manifest_path_components_that_are_not_native_names(tmp_path, field, value):
    _fixture(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["libraries"][0][field] = value
    manifest["libraries"][0]["relative_path"] = (
        f'{manifest["libraries"][0]["apk"]}/'
        f'{manifest["libraries"][0]["abi"]}/'
        f'{manifest["libraries"][0]["library"]}'
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe row"):
        analyze_native_fingerprints(tmp_path)


def test_rejects_oversized_manifest_before_json_parsing(tmp_path, monkeypatch):
    _fixture(tmp_path)
    monkeypatch.setattr("tools.analyze_native_fingerprints._MAX_MANIFEST_BYTES", 16)

    with pytest.raises(ValueError, match="manifest exceeds"):
        analyze_native_fingerprints(tmp_path)


@pytest.mark.parametrize("payload", [b"not-json", b"[]", b"null"])
def test_rejects_malformed_or_non_object_manifest(tmp_path, payload):
    _fixture(tmp_path)
    (tmp_path / "manifest.json").write_bytes(payload)

    with pytest.raises(ValueError, match="manifest"):
        analyze_native_fingerprints(tmp_path)
