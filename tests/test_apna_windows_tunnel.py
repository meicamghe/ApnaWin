from __future__ import annotations

import json

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode
from apnawin.engines.apna_ssh_session import ApnaSshConfig
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig
from apnawin.engines.apna_windows_tunnel import (
    ApnaWindowsTunnelEngine,
    ApnaWindowsTunnelError,
)


def _profile():
    return ConnectionProfile(
        name="APNA test",
        transport=Transport.APNA_SSH,
        endpoint_host="ssh.example.test",
        endpoint_port=443,
    )


def _session_config(**overrides):
    values = {
        "ssh": ApnaSshConfig(
            "ssh.example.test", 443, "test-user", password="test-secret"
        ),
        "payload": PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="ssh.example.test",
            connect_port=443,
            target_host="ssh.example.test",
            target_port=443,
        ),
        "udpgw_host": "udpgw.example.test",
        "udpgw_port": 7300,
        "transparent_dns": True,
    }
    values.update(overrides)
    return ApnaTunnelSessionConfig(**values)


class _ConfigStore:
    def __init__(self, events=None):
        self.records = {}
        self.events = events if events is not None else []

    def save(self, name, config):
        self.events.append("config-save")
        self.records[name] = config

    def remove(self, name):
        self.events.append("config-remove")
        self.records.pop(name, None)

    def has_config(self, name):
        return name in self.records


class _FakeSession:
    def __init__(self, config, *, events, fail_disconnect=False):
        self.config = config
        self.events = events
        self.fail_disconnect = fail_disconnect
        self.address = ("127.0.0.1", 23145)

    @property
    def local_socks_address(self):
        return self.address

    def connect(self):
        self.events.append("session-connect")
        return self.address

    def disconnect(self):
        self.events.append("session-disconnect")
        if self.fail_disconnect:
            self.fail_disconnect = False
            raise OSError("session cleanup busy")


class _FakeXrayEngine:
    def __init__(self, store, *, events, fail_connect=False, fail_disconnect=False):
        self.store = store
        self.events = events
        self.fail_connect = fail_connect
        self.fail_disconnect = fail_disconnect
        self.state = ConnectionState.DISCONNECTED
        self.last_error = None
        self.profile = None

    def validate_profile(self, profile):
        self.events.append("xray-validate")
        assert profile.transport is Transport.XRAY
        assert self.store.has_config(profile.name)
        config = json.loads(self.store.records[profile.name])
        assert config["outbounds"][0]["protocol"] == "socks"\n    assert config["outbounds"][0]["settings"]["servers"][0]["address"] == "127.0.0.1"
        assert config["outbounds"][0]["settings"]["servers"][0]["port"] == 23145

    def connect(self, profile):
        self.events.append("xray-connect")
        self.profile = profile
        self.state = ConnectionState.CONNECTING
        if self.fail_connect:
            self.state = ConnectionState.ERROR
            raise OSError("Xray failed to start")
        self.state = ConnectionState.CONNECTED

    def refresh(self):
        self.events.append("xray-refresh")
        return self.state

    def disconnect(self):
        self.events.append("xray-disconnect")
        if self.fail_disconnect:
            self.fail_disconnect = False
            self.state = ConnectionState.ERROR
            raise OSError("Xray cleanup busy")
        self.state = ConnectionState.DISCONNECTED
        self.profile = None


def _engine(events, *, xray=None, session=None, session_config=None):
    store = _ConfigStore(events)
    config = session_config or _session_config()
    xray_engine = xray or _FakeXrayEngine(store, events=events)
    sessions = []

    def make_session(value):
        instance = session or _FakeSession(value, events=events)
        sessions.append(instance)
        return instance

    engine = ApnaWindowsTunnelEngine(
        session_config_provider=lambda profile: config,
        config_store=store,
        xray_engine=xray_engine,
        session_factory=make_session,
        platform_name="nt",
    )
    return engine, store, xray_engine, sessions


def test_apna_profile_connects_session_then_xray_tun_over_loopback_socks():
    events = []
    engine, store, xray, sessions = _engine(events)
    engine.validate_profile(_profile())
    engine.connect(_profile())
    assert engine.state is ConnectionState.CONNECTED
    assert engine.active_profile == _profile()
    assert engine.local_socks_address == ("127.0.0.1", 23145)
    assert events == [
        "session-connect",
        "config-save",
        "xray-validate",
        "xray-connect",
    ]
    assert len(store.records) == 1
    config = json.loads(next(iter(store.records.values())))
    assert config["inbounds"][0]["protocol"] == "tun"
    assert config["inbounds"][0]["settings"]["autoSystemRoutingTable"] == [
        "0.0.0.0/0",
        "::/0",
    ]
    assert config["outbounds"][0]["protocol"] == "socks"


def test_disconnect_stops_xray_before_config_and_ssh_cleanup():
    events = []
    engine, store, xray, sessions = _engine(events)
    engine.connect(_profile())
    engine.disconnect()
    assert events[-3:] == [
        "xray-disconnect",
        "config-remove",
        "session-disconnect",
    ]
    assert not store.records
    assert engine.state is ConnectionState.DISCONNECTED
    assert engine.local_socks_address is None


def test_xray_start_failure_rolls_back_config_and_ssh_session():
    events = []
    store = _ConfigStore(events)
    xray = _FakeXrayEngine(store, events=events, fail_connect=True)
    engine, store, xray, sessions = _engine(events, xray=xray)
    with pytest.raises(OSError, match="Xray failed"):
        engine.connect(_profile())
    assert events[-4:] == [
        "xray-connect",
        "xray-disconnect",
        "config-remove",
        "session-disconnect",
    ]
    assert not store.records
    assert engine.state is ConnectionState.ERROR
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED


def test_failed_xray_cleanup_retains_config_and_ssh_until_retry():
    events = []
    store = _ConfigStore(events)
    xray = _FakeXrayEngine(store, events=events, fail_disconnect=True)
    engine, store, xray, sessions = _engine(events, xray=xray)
    engine.connect(_profile())
    with pytest.raises(ApnaWindowsTunnelError, match="resources are retained"):
        engine.disconnect()
    assert store.records
    assert sessions[0] is not None
    assert "session-disconnect" not in events
    engine.disconnect()
    assert not store.records
    assert events[-3:] == [
        "xray-disconnect",
        "config-remove",
        "session-disconnect",
    ]


def test_session_cleanup_failure_retains_handle_for_retry():
    events = []
    flaky_session = _FakeSession(_session_config(), events=events, fail_disconnect=True)
    engine, store, xray, sessions = _engine(events, session=flaky_session)
    engine.connect(_profile())
    with pytest.raises(ApnaWindowsTunnelError, match="cleanup incomplete"):
        engine.disconnect()
    assert engine.state is ConnectionState.ERROR
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED


def test_validate_rejects_profile_endpoint_mismatch_and_missing_udpgw():
    events = []
    engine, store, xray, sessions = _engine(events)
    wrong = ConnectionProfile(
        name="wrong",
        transport=Transport.APNA_SSH,
        endpoint_host="other.example.test",
        endpoint_port=443,
    )
    with pytest.raises(ValueError, match="does not match"):
        engine.validate_profile(wrong)

    no_udp_engine, _, _, _ = _engine(
        events, session_config=_session_config(udpgw_host=None, udpgw_port=None)
    )
    with pytest.raises(ValueError, match="requires a verified UDPGW"):
        no_udp_engine.validate_profile(_profile())


def test_refresh_propagates_xray_tunnel_failure_without_closing_transport():
    events = []
    engine, store, xray, sessions = _engine(events)
    engine.connect(_profile())
    xray.state = ConnectionState.ERROR
    xray.last_error = "egress probe failed"
    assert engine.refresh() is ConnectionState.ERROR
    assert engine.state is ConnectionState.ERROR
    assert "session-disconnect" not in events
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED
