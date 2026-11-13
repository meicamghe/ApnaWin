import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.mock import MockTunnelEngine


@pytest.fixture
def profile():
    return ConnectionProfile("Test profile", Transport.SOCKS, "127.0.0.1", 1080)


def test_mock_engine_has_explicit_non_network_name():
    engine = MockTunnelEngine()
    assert "no network" in engine.name.lower()
    assert engine.state is ConnectionState.DISCONNECTED


def test_mock_engine_lifecycle(profile):
    engine = MockTunnelEngine()
    engine.connect(profile)
    assert engine.state is ConnectionState.CONNECTED
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED


def test_mock_engine_rejects_duplicate_connect(profile):
    engine = MockTunnelEngine()
    engine.connect(profile)
    with pytest.raises(RuntimeError):
        engine.connect(profile)


def test_mock_engine_disconnect_is_idempotent():
    engine = MockTunnelEngine()
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED
