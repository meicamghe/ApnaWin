from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from apnawin.services.udpq_sidecar import (
    UdpqClientConfig,
    UdpqSidecarSupervisor,
    load_udpq_runtime_sha256,
    parse_server_port_spec,
)


def _config(tmp_path: Path, **overrides) -> UdpqClientConfig:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("test-ca", encoding="utf-8")
    values = {
        "server_host": "vpn.example.test",
        "server_port": 443,
        "auth_str": "secret-for-tests",
        "alpn": "hysteria",
        "server_name": "vpn.example.test",
        "up_mbps": 10,
        "down_mbps": 20,
        "socks_host": "127.0.0.1",
        "socks_port": 10808,
        "ca_file": str(ca_file),
    }
    values.update(overrides)
    return UdpqClientConfig(**values)


class _FakeProcess:
    def __init__(self, exit_code: int | None = None) -> None:
        self.exit_code = exit_code
        self.terminated = False
        self.killed = False
        self.waited = False
        self.closed = False

    def poll(self):
        return self.exit_code

    def terminate(self):
        self.terminated = True
        self.exit_code = 0

    def kill(self):
        self.killed = True
        self.exit_code = 1

    def wait(self, timeout=None):
        self.waited = True
        return self.exit_code

    def close(self):
        self.closed = True


def test_udpq_config_serializes_verified_tls_and_udp_socks(tmp_path):
    config = _config(tmp_path)
    payload = json.loads(config.to_json_bytes())

    assert payload["server"] == "vpn.example.test:443"
    assert payload["protocol"] == "udp"
    assert payload["auth_str"] == "secret-for-tests"
    assert payload["alpn"] == "hysteria"
    assert payload["server_name"] == "vpn.example.test"
    assert payload["insecure"] is False
    assert payload["ca"] == str(tmp_path / "ca.pem")
    assert payload["socks5"] == {
        "listen": "127.0.0.1:10808",
        "disable_udp": False,
    }


def test_udpq_config_formats_ipv6_endpoints(tmp_path):
    config = _config(
        tmp_path,
        server_host="2001:db8::1",
        socks_host="::1",
        server_name="2001:db8::1",
    )
    payload = json.loads(config.to_json_bytes())

    assert payload["server"] == "[2001:db8::1]:443"
    assert payload["socks5"]["listen"] == "[::1]:10808"


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.10", "localhost", ""])
def test_udpq_socks_listener_must_be_loopback(tmp_path, host):
    with pytest.raises(ValueError, match="loopback"):
        _config(tmp_path, socks_host=host)


@pytest.mark.parametrize("protocol", ["faketcp", "unknown", ""])
def test_windows_unsupported_packet_transports_are_rejected(tmp_path, protocol):
    with pytest.raises(ValueError, match="Only the verified UDP"):
        _config(tmp_path, protocol=protocol)


def test_udpq_config_rejects_control_chars_and_weak_tls_option(tmp_path):
    with pytest.raises(ValueError, match="control"):
        _config(tmp_path, auth_str="secret\ninjected")
    with pytest.raises(TypeError):
        UdpqClientConfig(**{
            "server_host": "vpn.example.test",
            "server_port": 443,
            "auth_str": "secret",
            "alpn": "hysteria",
            "server_name": "vpn.example.test",
            "up_mbps": 10,
            "down_mbps": 10,
            "socks_host": "127.0.0.1",
            "socks_port": 10808,
            "insecure": True,
        })


def test_udpq_supervisor_starts_probes_and_removes_plaintext_config(tmp_path):
    executable = tmp_path / "udpq-client.exe"
    executable.write_bytes(b"MZtest-executable")
    process = _FakeProcess()
    captured = {}

    def factory(path, args):
        captured["path"] = path
        captured["args"] = args
        captured["config_path"] = Path(args[-1])
        captured["config"] = json.loads(captured["config_path"].read_text(encoding="utf-8"))
        return process

    supervisor = UdpqSidecarSupervisor(
        executable,
        private_dir=tmp_path / "private",
        process_factory=factory,
        socks_probe=lambda host, port, timeout: (host, port) == ("127.0.0.1", 10808),
        platform_name="nt",
    )

    assert supervisor.start(_config(tmp_path)) == ("127.0.0.1", 10808)
    assert supervisor.is_running
    assert captured["args"][:3] == ["--no-check", "client", "--config"]
    assert captured["config"]["insecure"] is False
    assert not captured["config_path"].exists()
    assert supervisor.socks_address == ("127.0.0.1", 10808)

    supervisor.stop()
    assert process.terminated
    assert process.waited
    assert process.closed
    assert not supervisor.is_running
    assert supervisor.socks_address is None


def test_udpq_supervisor_fails_closed_if_sidecar_exits_before_ready(tmp_path):
    executable = tmp_path / "udpq-client.exe"
    executable.write_bytes(b"MZtest-executable")
    process = _FakeProcess(exit_code=17)
    supervisor = UdpqSidecarSupervisor(
        executable,
        private_dir=tmp_path / "private",
        process_factory=lambda _path, _args: process,
        socks_probe=lambda _host, _port, _timeout: False,
        platform_name="nt",
    )

    with pytest.raises(RuntimeError, match="exit code 17"):
        supervisor.start(_config(tmp_path))

    assert process.closed
    assert not list((tmp_path / "private").glob("udpq-*.json"))
    assert supervisor.socks_address is None


def test_udpq_supervisor_times_out_and_terminates_process(tmp_path):
    executable = tmp_path / "udpq-client.exe"
    executable.write_bytes(b"MZtest-executable")
    process = _FakeProcess()
    clock = [0.0]

    def monotonic():
        return clock[0]

    def sleep(seconds):
        clock[0] += seconds

    supervisor = UdpqSidecarSupervisor(
        executable,
        private_dir=tmp_path / "private",
        startup_timeout=0.2,
        process_factory=lambda _path, _args: process,
        socks_probe=lambda _host, _port, _timeout: False,
        sleeper=sleep,
        monotonic=monotonic,
        platform_name="nt",
    )

    with pytest.raises(TimeoutError, match="SOCKS5 listener"):
        supervisor.start(_config(tmp_path))

    assert process.terminated
    assert process.waited
    assert process.closed
    assert not list((tmp_path / "private").glob("udpq-*.json"))


def test_udpq_config_normalizes_dns_and_ca_path(tmp_path):
    config = _config(
        tmp_path,
        server_host="VPN.Example.Test",
        server_name="VPN.Example.Test",
        ca_file=str(tmp_path / "." / "ca.pem"),
    )
    payload = json.loads(config.to_json_bytes())

    assert config.server_host == "vpn.example.test"
    assert config.server_name == "vpn.example.test"
    assert Path(payload["ca"]).is_absolute()


def test_udpq_supervisor_rejects_non_pe_sidecar(tmp_path):
    executable = tmp_path / "not-a-pe.exe"
    executable.write_bytes(b"not-a-windows-executable")
    supervisor = UdpqSidecarSupervisor(
        executable,
        private_dir=tmp_path / "private",
        process_factory=lambda _path, _args: pytest.fail("must not launch"),
        platform_name="nt",
    )

    with pytest.raises(ValueError, match="Windows PE"):
        supervisor.start(_config(tmp_path))


@pytest.mark.parametrize("protocol", ["udp", "wechat", "wechat-video"])
def test_windows_supported_packet_transports_are_serialized(tmp_path, protocol):
    payload = json.loads(_config(tmp_path, protocol=protocol).to_json_bytes())
    assert payload["protocol"] == protocol


def test_udpq_supervisor_checks_manifest_sha256_before_launch(tmp_path):
    executable = tmp_path / "udpq-client.exe"
    executable.write_bytes(b"MZtest-executable")
    supervisor = UdpqSidecarSupervisor(
        executable,
        private_dir=tmp_path / "private",
        expected_sha256="0" * 64,
        process_factory=lambda _path, _args: pytest.fail("must not launch"),
        platform_name="nt",
    )

    with pytest.raises(ValueError, match="SHA-256"):
        supervisor.start(_config(tmp_path))


def test_runtime_manifest_loads_udpq_hash_strictly(tmp_path):
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": 1,
        "xray": {},
        "wintun": {},
        "udpq": {
            "source_commit": "23fa29bb4fad600330b30e2b703b8029ef091446",
            "patch_sha256": "82f7db651860fe94129a4cd2931459dc8f70973a261261af3943b9ac6a23ea52",
            "executable_sha256": "A" * 64,
        },
    }), encoding="utf-8")
    assert load_udpq_runtime_sha256(manifest) == "a" * 64


@pytest.mark.parametrize(
    "document",
    [
        '{"schema_version":1,"udpq":{"source_commit":"23fa29bb4fad600330b30e2b703b8029ef091446","patch_sha256":"82f7db651860fe94129a4cd2931459dc8f70973a261261af3943b9ac6a23ea52","executable_sha256":"bad"}}',
        '{"schema_version":1,"udpq":{"source_commit":"23fa29bb4fad600330b30e2b703b8029ef091446","patch_sha256":"82f7db651860fe94129a4cd2931459dc8f70973a261261af3943b9ac6a23ea52","executable_sha256":"' + "0" * 64 + '"},"schema_version":1}',
        '{"schema_version":NaN,"udpq":{"source_commit":"23fa29bb4fad600330b30e2b703b8029ef091446","patch_sha256":"82f7db651860fe94129a4cd2931459dc8f70973a261261af3943b9ac6a23ea52","executable_sha256":"' + "0" * 64 + '"}}',
    ],
)
def test_runtime_manifest_rejects_invalid_or_ambiguous_udpq_hash(tmp_path, document):
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError):
        load_udpq_runtime_sha256(manifest)


def test_runtime_manifest_rejects_float_schema_version(tmp_path):
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_text(
        '{"schema_version":1.0,"udpq":{"source_commit":"23fa29bb4fad600330b30e2b703b8029ef091446","patch_sha256":"82f7db651860fe94129a4cd2931459dc8f70973a261261af3943b9ac6a23ea52","executable_sha256":"' + "0" * 64 + '"}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no UDPQ entry"):
        load_udpq_runtime_sha256(manifest)


def test_runtime_manifest_rejects_unreviewed_udpq_source_patch(tmp_path):
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": 1,
        "udpq": {
            "source_commit": "23fa29bb4fad600330b30e2b703b8029ef091446",
            "patch_sha256": "0" * 64,
            "executable_sha256": "a" * 64,
        },
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="provenance"):
        load_udpq_runtime_sha256(manifest)


@pytest.mark.parametrize("interval", [1, 2, 7, 86401])
def test_udpq_rejects_upstream_invalid_port_hop_intervals(tmp_path, interval):
    with pytest.raises(ValueError, match="hop_interval"):
        _config(tmp_path, hop_interval=interval)


def test_udpq_serializes_bounded_multi_port_ranges(tmp_path):
    config = _config(tmp_path, server_port_spec="443,8443-8445")
    payload = json.loads(config.to_json_bytes())
    assert payload["server"] == "vpn.example.test:443,8443-8445"
    assert config.server_port == 443
    assert config.server_port_spec == "443,8443-8445"


@pytest.mark.parametrize(
    "spec",
    ["", "443,", "443,,8443", "8445-8443", "0", "65536", "443-475", "443,443", "443-445,445-446", "443/udp", "443 8443"],
)
def test_udpq_rejects_invalid_or_unbounded_port_specs(spec):
    with pytest.raises(ValueError):
        parse_server_port_spec(spec)


def test_udpq_rejects_port_hopping_with_wechat_modes(tmp_path):
    with pytest.raises(ValueError, match="only with the UDP"):
        _config(tmp_path, protocol="wechat", server_port_spec="443,8443")


def test_udpq_normalizes_single_port_spec_to_default(tmp_path):
    config = _config(tmp_path, server_port_spec="00443")
    assert config.server_port == 443
    assert config.server_port_spec is None


def test_udpq_supervisor_cleans_orphaned_plaintext_configs(tmp_path):
    executable = tmp_path / "udpq-client.exe"
    executable.write_bytes(b"MZtest-executable")
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    stale = private_dir / "udpq-stale.json"
    fresh = private_dir / "udpq-fresh.json"
    stale.write_text('{"auth_str":"orphaned-secret"}', encoding="utf-8")
    fresh.write_text('{"auth_str":"active-secret"}', encoding="utf-8")
    old = time.time() - 7200
    os.utime(stale, (old, old))

    supervisor = UdpqSidecarSupervisor(
        executable,
        private_dir=private_dir,
        process_factory=lambda _path, _args: pytest.fail("must not launch"),
        platform_name="nt",
    )
    new_path = supervisor._write_private_config(b'{"auth_str":"new-secret"}')

    assert not stale.exists()
    assert fresh.exists()
    assert new_path.exists()
    new_path.unlink()
