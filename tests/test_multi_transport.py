from __future__ import annotations

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.multi_transport import MultiTransportTunnelEngine


class _FakeEngine:
    def __init__(self, *, fail_connect=False, fail_disconnect=False):
        self.fail_connect = fail_connect
        self.fail_disconnect = fail_disconnect
        self.validated = []
        self.connected = []
        self.disconnects = 0
        self._state = ConnectionState.DISCONNECTED
        self.active_profile = None

    @property
    def state(self):
        return self._state

    def validate_profile(self, profile):
        self.validated.append(profile)

    def connect(self, profile):
        self.connected.append(profile)
        self.active_profile = profile
        self._state = ConnectionState.CONNECTING
        if self.fail_connect:
            self._state = ConnectionState.ERROR
            raise OSError("connect failed")
        self._state = ConnectionState.CONNECTED

    def refresh(self):
        return self._state

    def disconnect(self):
        self.disconnects += 1
        if self.fail_disconnect:
            self._state = ConnectionState.ERROR
            raise OSError("cleanup failed")
        self._state = ConnectionState.DISCONNECTED
        self.active_profile = None


def _profile(transport):
    return ConnectionProfile("test", transport, "vpn.example.test", 443)


def test_dispatches_validation_and_connection_by_transport():
    xray = _FakeEngine()
    apna = _FakeEngine()
    engine = MultiTransportTunnelEngine({
        Transport.XRAY: xray,
        Transport.APNA_SSH: apna,
    })
    profile = _profile(Transport.APNA_SSH)
    engine.validate_profile(profile)
    engine.connect(profile)
    assert apna.validated == [profile]
    assert apna.connected == [profile]
    assert xray.validated == []
    assert engine.state is ConnectionState.CONNECTED
    engine.disconnect()
    assert apna.disconnects == 1
    assert engine.state is ConnectionState.DISCONNECTED


def test_connect_failure_keeps_engine_ownership_for_cleanup_retry():
    selected = _FakeEngine(fail_connect=True, fail_disconnect=True)
    engine = MultiTransportTunnelEngine({Transport.APNA_SSH: selected})
    profile = _profile(Transport.APNA_SSH)
    engine.validate_profile(profile)
    with pytest.raises(OSError, match="connect failed"):
        engine.connect(profile)
    assert engine.state is ConnectionState.ERROR
    with pytest.raises(OSError, match="cleanup failed"):
        engine.disconnect()
    assert engine.state is ConnectionState.ERROR
    selected.fail_disconnect = False
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED


def test_rejects_unregistered_transport():
    engine = MultiTransportTunnelEngine({Transport.APNA_SSH: _FakeEngine()})
    with pytest.raises(ValueError, match="No connection engine"):
        engine.validate_profile(_profile(Transport.XRAY))


def test_refresh_propagates_selected_engine_state():
    selected = _FakeEngine()
    engine = MultiTransportTunnelEngine({Transport.APNA_SSH: selected})
    profile = _profile(Transport.APNA_SSH)
    engine.validate_profile(profile)
    engine.connect(profile)
    selected._state = ConnectionState.ERROR
    assert engine.refresh() is ConnectionState.ERROR


def test_refresh_rejects_invalid_state_without_releasing_engine_ownership():
    selected = _FakeEngine()
    engine = MultiTransportTunnelEngine({Transport.APNA_SSH: selected})
    profile = _profile(Transport.APNA_SSH)
    engine.validate_profile(profile)
    engine.connect(profile)

    selected.refresh = lambda: "connected"
    with pytest.raises(TypeError, match="refresh\\(\\).*ConnectionState"):
        engine.refresh()

    assert engine.state is ConnectionState.ERROR
    selected.refresh = lambda: ConnectionState.CONNECTED
    assert engine.refresh() is ConnectionState.CONNECTED
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED
