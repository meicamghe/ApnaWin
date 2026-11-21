from __future__ import annotations

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.transport_router import TransportEngineRouter


class _FakeEngine:
    def __init__(self, name):
        self.name = name
        self.state = ConnectionState.DISCONNECTED
        self.events = []
        self.fail_connect = False
        self.fail_disconnect = False

    def validate_profile(self, profile):
        self.events.append(("validate", profile.transport))

    def connect(self, profile):
        self.events.append(("connect", profile.transport))
        self.state = ConnectionState.CONNECTING
        if self.fail_connect:
            self.state = ConnectionState.ERROR
            raise OSError("connect failed")
        self.state = ConnectionState.CONNECTED

    def refresh(self):
        self.events.append(("refresh",))
        return self.state

    def disconnect(self):
        self.events.append(("disconnect",))
        if self.fail_disconnect:
            self.state = ConnectionState.ERROR
            raise OSError("disconnect failed")
        self.state = ConnectionState.DISCONNECTED


def _profile(name, transport):
    return ConnectionProfile(name, transport, "server.example.test", 443)


def test_routes_each_profile_to_matching_engine_and_retains_active_owner():
    xray = _FakeEngine("xray")
    apna = _FakeEngine("apna")
    router = TransportEngineRouter(
        {Transport.XRAY: xray, Transport.APNA_SSH: apna}
    )
    profile = _profile("APNA", Transport.APNA_SSH)
    router.validate_profile(profile)
    router.connect(profile)
    assert router.state is ConnectionState.CONNECTED
    assert router.active_engine is apna
    assert router.active_profile == profile
    assert xray.events == []
    assert apna.events == [("validate", Transport.APNA_SSH), ("connect", Transport.APNA_SSH)]
    router.disconnect()
    assert router.state is ConnectionState.DISCONNECTED
    assert router.active_engine is None


def test_router_keeps_engine_ownership_when_connect_cleanup_is_needed():
    apna = _FakeEngine("apna")
    apna.fail_connect = True
    router = TransportEngineRouter({Transport.APNA_SSH: apna})
    with pytest.raises(OSError, match="connect failed"):
        router.connect(_profile("APNA", Transport.APNA_SSH))
    assert router.state is ConnectionState.ERROR
    assert router.active_engine is apna
    router.disconnect()
    assert router.state is ConnectionState.DISCONNECTED


def test_router_retains_engine_if_disconnect_fails_and_allows_retry():
    apna = _FakeEngine("apna")
    router = TransportEngineRouter({Transport.APNA_SSH: apna})
    router.connect(_profile("APNA", Transport.APNA_SSH))
    apna.fail_disconnect = True
    with pytest.raises(OSError, match="disconnect failed"):
        router.disconnect()
    assert router.active_engine is apna
    assert router.state is ConnectionState.ERROR
    apna.fail_disconnect = False
    router.disconnect()
    assert router.active_engine is None


def test_router_rejects_unsupported_transport_and_second_active_engine():
    router = TransportEngineRouter({Transport.APNA_SSH: _FakeEngine("apna")})
    with pytest.raises(ValueError, match="No connection engine"):
        router.validate_profile(_profile("SOCKS", Transport.SOCKS))
    profile = _profile("APNA", Transport.APNA_SSH)
    router.connect(profile)
    with pytest.raises(RuntimeError, match="Another transport"):
        router.validate_profile(profile)
