from __future__ import annotations

import json

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.udpq_tunnel import UdpqTunnelEngine
from apnawin.services.udpq_sidecar import UdpqClientConfig


def _config() -> UdpqClientConfig:
    return UdpqClientConfig(
        server_host="vpn.example.test",
        server_port=443,
        auth_str="secret",
        alpn="hysteria",
        server_name="vpn.example.test",
        up_mbps=10,
        down_mbps=20,
        socks_host="127.0.0.1",
        socks_port=10808,
    )


def _profile(transport: Transport = Transport.UDPQ) -> ConnectionProfile:
    return ConnectionProfile(
        name="udpq-test",
        transport=transport,
        endpoint_host="vpn.example.test",
        endpoint_port=443,
    )


class _FakeSidecar:
    def __init__(self) -> None:
        self.is_running = False
        self.started_config = None
        self.stop_calls = 0
        self.fail_start = False
        self.fail_stop = False

    def start(self, config):
        if self.fail_start:
            raise RuntimeError("sidecar start failed")
        self.started_config = config
        self.is_running = True
        port = config.socks_port or 23456
        return config.socks_host, port

    def stop(self):
        self.stop_calls += 1
        if self.fail_stop:
            raise RuntimeError("sidecar stop failed")
        self.is_running = False


class _FakeXrayEngine:
    def __init__(self) -> None:
        self.state = ConnectionState.DISCONNECTED
        self.validated_profile = None
        self.active_profile = None
        self.fail_connect = False
        self.fail_disconnect = False

    def validate_profile(self, profile):
        assert profile.transport is Transport.XRAY
        self.validated_profile = profile

    def connect(self, profile):
        self.active_profile = profile
        if self.fail_connect:
            self.state = ConnectionState.ERROR
            raise RuntimeError("xray start failed")
        self.state = ConnectionState.CONNECTED

    def refresh(self):
        return self.state

    def disconnect(self):
        if self.fail_disconnect:
            raise RuntimeError("xray stop failed")
        self.state = ConnectionState.DISCONNECTED
        self.active_profile = None


class _FakeConfigStore:
    def __init__(self) -> None:
        self.saved = {}
        self.removed = []

    def save(self, name, config):
        self.saved[name] = config

    def remove(self, name):
        self.removed.append(name)
        self.saved.pop(name, None)


def _engine(sidecar=None, xray=None, store=None):
    sidecar = sidecar or _FakeSidecar()
    xray = xray or _FakeXrayEngine()
    store = store or _FakeConfigStore()
    engine = UdpqTunnelEngine(
        sidecar,
        xray,
        store,
        lambda _name: _config(),
    )
    return engine, sidecar, xray, store


def test_udpq_tunnel_composes_sidecar_with_xray_tun():
    engine, sidecar, xray, store = _engine()
    profile = _profile()

    engine.validate_profile(profile)
    engine.connect(profile)

    assert engine.state is ConnectionState.CONNECTED
    assert engine.active_profile == profile
    assert sidecar.is_running
    assert xray.validated_profile.transport is Transport.XRAY
    assert xray.validated_profile.endpoint_host == "127.0.0.1"
    assert xray.validated_profile.endpoint_port == 10808
    config = json.loads(store.saved[xray.validated_profile.name])
    assert config["outbounds"][0]["tag"] == "udpq-socks"
    assert config["inbounds"][0]["settings"]["desc"] == "ApnaWin UDPQ tunnel"

    assert engine.refresh() is ConnectionState.CONNECTED
    engine.disconnect()

    assert engine.state is ConnectionState.DISCONNECTED
    assert not sidecar.is_running
    assert xray.state is ConnectionState.DISCONNECTED
    assert store.removed == [xray.validated_profile.name]


def test_udpq_tunnel_rejects_endpoint_mismatch():
    engine, _, _, _ = _engine()
    profile = ConnectionProfile(
        name="udpq-test",
        transport=Transport.UDPQ,
        endpoint_host="other.example.test",
        endpoint_port=443,
    )

    with pytest.raises(ValueError, match="endpoint"):
        engine.validate_profile(profile)


def test_udpq_tunnel_rejects_non_udpq_profile():
    engine, _, _, _ = _engine()

    with pytest.raises(ValueError, match="UDPQ profiles"):
        engine.validate_profile(_profile(Transport.XRAY))


def test_udpq_tunnel_start_failure_cleans_sidecar_and_config():
    xray = _FakeXrayEngine()
    xray.fail_connect = True
    engine, sidecar, _, store = _engine(xray=xray)

    with pytest.raises(RuntimeError, match="xray start failed"):
        engine.connect(_profile())

    assert engine.state is ConnectionState.ERROR
    assert not sidecar.is_running
    assert sidecar.stop_calls == 1
    assert xray.state is ConnectionState.DISCONNECTED
    assert store.removed == [xray.validated_profile.name]
    assert engine.active_profile is None

    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED


def test_udpq_tunnel_retains_sidecar_if_xray_cleanup_is_uncertain():
    xray = _FakeXrayEngine()
    xray.fail_disconnect = True
    engine, sidecar, _, _ = _engine(xray=xray)
    engine.connect(_profile())

    with pytest.raises(RuntimeError, match="Xray/Wintun cleanup failed"):
        engine.disconnect()

    assert engine.state is ConnectionState.ERROR
    assert sidecar.is_running
    assert sidecar.stop_calls == 0


def test_udpq_tunnel_detects_sidecar_exit_and_stops_in_safe_order():
    engine, sidecar, xray, store = _engine()
    engine.connect(_profile())
    sidecar.is_running = False

    assert engine.refresh() is ConnectionState.ERROR
    assert "sidecar exited" in engine.last_error

    engine.disconnect()
    assert xray.state is ConnectionState.DISCONNECTED
    assert store.removed == [xray.validated_profile.name]


def test_udpq_tunnel_uses_supervisor_allocated_socks_port():
    sidecar = _FakeSidecar()
    xray = _FakeXrayEngine()
    store = _FakeConfigStore()
    engine = UdpqTunnelEngine(
        sidecar,
        xray,
        store,
        lambda _name: _config(socks_port=0),
    )
    profile = _profile()

    engine.connect(profile)

    assert xray.validated_profile.endpoint_host == "127.0.0.1"
    assert xray.validated_profile.endpoint_port == 23456
    assert engine.state is ConnectionState.CONNECTED
    engine.disconnect()
