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
            dns_servers=("1.1.1.1",),
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
        with pytest.raises(RuntimeError, match="Configured DNS server"):
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
    probe._route_interface = lambda _address: 12
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("apnawin.services.windows_tunnel_traffic_probe.os.name", "nt")
    try:
        with pytest.raises(RuntimeError, match="did not resolve"):
            probe.verify()
    finally:
        monkeypatch.undo()



def test_probe_completes_tls_http_only_after_dns_and_destination_routes_use_tun(monkeypatch):
    import apnawin.services.windows_tunnel_traffic_probe as probe_module

    class RawSocket:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    class SecureSocket:
        def __init__(self):
            self.request = b""
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def selected_alpn_protocol(self):
            return "http/1.1"
        def sendall(self, payload):
            self.request = payload
        def recv(self, _size):
            return b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"

    class Context:
        def __init__(self):
            self.secure = SecureSocket()
        def set_alpn_protocols(self, protocols):
            assert protocols == ["http/1.1"]
        def wrap_socket(self, _raw, *, server_hostname):
            assert server_hostname == "www.cloudflare.com"
            return self.secure

    context = Context()
    monkeypatch.setattr(probe_module.os, "name", "nt")
    monkeypatch.setattr(probe_module.ssl, "create_default_context", lambda: context)
    probe = WindowsTunnelTrafficProbe(
        diagnostics_factory=Diagnostics,
        resolver=lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.9", 443))
        ],
        connector=lambda *_args, **_kwargs: RawSocket(),
    )
    checked = []
    probe._route_interface = lambda address: checked.append(address) or 12

    result = probe.verify()

    assert result.destination_ip == "203.0.113.9"
    assert result.interface_index == 12
    assert result.http_status == 204
    assert checked == ["1.1.1.1", "203.0.113.9"]
    assert b"Host: www.cloudflare.com" in context.secure.request


def test_probe_rejects_dns_route_outside_tun_before_resolving_host(monkeypatch):
    import apnawin.services.windows_tunnel_traffic_probe as probe_module

    monkeypatch.setattr(probe_module.os, "name", "nt")
    probe = WindowsTunnelTrafficProbe(
        diagnostics_factory=Diagnostics,
        resolver=lambda *_args, **_kwargs: pytest.fail("DNS lookup must not proceed"),
        connector=lambda *_args, **_kwargs: pytest.fail("socket must not open"),
    )
    probe._route_interface = lambda _address: 7

    with pytest.raises(RuntimeError, match="Configured DNS server"):
        probe.verify()
