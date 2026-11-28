import socket
from types import SimpleNamespace

import pytest

from apnawin.services.windows_tunnel_traffic_probe import WindowsTunnelTrafficProbe


class Diagnostics:
    def __init__(self, **_kwargs):
        pass

    def snapshot(self):
        return SimpleNamespace(
            routing_ready=True,
            interface_index=12,
        )


class Completed:
    returncode = 0
    stdout = "12"


def test_probe_refuses_https_when_windows_route_does_not_use_apnawin():
    calls = []

    def route_runner(*_args, **_kwargs):
        return Completed()

    probe = WindowsTunnelTrafficProbe(
        diagnostics_factory=Diagnostics,
        runner=route_runner,
        resolver=lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.9", 443))
        ],
        connector=lambda *_args, **_kwargs: calls.append("connected"),
    )
    # A selected route must match the TUN adapter. A mismatch must stop before TCP.
    probe._route_interface = lambda _address: 7
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("apnawin.services.windows_tunnel_traffic_probe.os.name", "nt")
    try:
        with pytest.raises(RuntimeError, match="No HTTPS traffic probe"):
            probe.verify()
    finally:
        monkeypatch.undo()
    assert calls == []


def test_probe_rejects_unresolved_probe_host_before_opening_sockets():
    probe = WindowsTunnelTrafficProbe(
        diagnostics_factory=Diagnostics,
        resolver=lambda *_args, **_kwargs: [],
        connector=lambda *_args, **_kwargs: pytest.fail("must not connect"),
    )
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("apnawin.services.windows_tunnel_traffic_probe.os.name", "nt")
    try:
        with pytest.raises(RuntimeError, match="did not resolve"):
            probe.verify()
    finally:
        monkeypatch.undo()
