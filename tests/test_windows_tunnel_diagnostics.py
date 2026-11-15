import json
import os
import subprocess

import pytest

from apnawin.services.windows_tunnel_diagnostics import WindowsTunnelDiagnostics


def payload(**overrides):
    result = {
        "adapter_present": True,
        "adapter_status": "Up",
        "interface_index": 23,
        "ipv4_default_route": True,
        "ipv6_default_route": True,
        "dns_servers": ["1.1.1.1", "2606:4700:4700::1111"],
    }
    result.update(overrides)
    return result


def fake_runner_for(document, returncode=0):
    def runner(command, **kwargs):
        assert command[0] == "powershell.exe"
        assert command[-2] == "-EncodedCommand"
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(command, returncode, json.dumps(document), "")
    return runner


def test_snapshot_reports_dual_stack_routes_dns_and_adapter(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    diagnostics = WindowsTunnelDiagnostics(runner=fake_runner_for(payload()))
    snapshot = diagnostics.snapshot()
    assert snapshot.adapter_up
    assert snapshot.routes_ready
    assert snapshot.dns_ready
    assert snapshot.routing_ready
    assert snapshot.interface_index == 23
    assert snapshot.dns_servers == ("1.1.1.1", "2606:4700:4700::1111")


def test_snapshot_reports_absent_adapter_as_not_ready(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    document = payload(
        adapter_present=False,
        adapter_status="",
        interface_index=None,
        ipv4_default_route=False,
        ipv6_default_route=False,
        dns_servers=[],
    )
    snapshot = WindowsTunnelDiagnostics(runner=fake_runner_for(document)).snapshot()
    assert not snapshot.adapter_present
    assert not snapshot.routing_ready


def test_snapshot_rejects_incomplete_routes(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    document = payload(ipv6_default_route=False)
    snapshot = WindowsTunnelDiagnostics(runner=fake_runner_for(document)).snapshot()
    assert snapshot.adapter_up
    assert not snapshot.routes_ready
    assert not snapshot.routing_ready


def test_snapshot_rejects_invalid_dns_and_schema(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(ValueError, match="invalid DNS"):
        WindowsTunnelDiagnostics(
            runner=fake_runner_for(payload(dns_servers=["not-an-ip"]))
        ).snapshot()
    with pytest.raises(ValueError, match="invalid schema"):
        WindowsTunnelDiagnostics(
            runner=fake_runner_for({"adapter_present": True})
        ).snapshot()


def test_snapshot_rejects_nonzero_powershell_exit(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(RuntimeError, match="PowerShell"):
        WindowsTunnelDiagnostics(runner=fake_runner_for(payload(), returncode=1)).snapshot()


def test_snapshot_translates_timeout(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")

    def timeout_runner(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("powershell.exe", 5)

    with pytest.raises(TimeoutError, match="timed out"):
        WindowsTunnelDiagnostics(runner=timeout_runner).snapshot()


def test_diagnostics_are_windows_only(monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(OSError, match="Windows tunnel diagnostics"):
        WindowsTunnelDiagnostics().snapshot()


@pytest.mark.parametrize("alias", ["", "bad'alias", "bad;command", "x" * 129])
def test_rejects_unsafe_adapter_alias(alias):
    with pytest.raises(ValueError, match="adapter alias"):
        WindowsTunnelDiagnostics(adapter_name=alias)


def test_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="positive finite"):
        WindowsTunnelDiagnostics(timeout=float("nan"))


def test_snapshot_script_checks_effective_route_and_interface_metrics(monkeypatch):
    import base64

    monkeypatch.setattr(os, "name", "nt")
    observed = {}

    def runner(command, **kwargs):
        observed["script"] = base64.b64decode(command[-1]).decode("utf-16le")
        return subprocess.CompletedProcess(command, 0, json.dumps(payload()), "")

    WindowsTunnelDiagnostics(runner=runner).snapshot()
    script = observed["script"]
    assert "Get-NetIPInterface" in script
    assert "RouteMetric" in script
    assert "InterfaceMetric" in script
    assert "$best4" in script and "$best6" in script
    assert "Where-Object { $_ -ne $idx }" in script


def test_snapshot_accepts_single_dns_address_as_string(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    document = payload(dns_servers="1.1.1.1")
    snapshot = WindowsTunnelDiagnostics(runner=fake_runner_for(document)).snapshot()
    assert snapshot.dns_servers == ("1.1.1.1",)
    assert snapshot.dns_ready
