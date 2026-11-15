import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.mock import MockTunnelEngine
from apnawin.services.connection_controller import (
    ConnectionController,
    ConnectionLifecycleError,
)


@pytest.fixture
def profile():
    return ConnectionProfile("Test profile", Transport.SOCKS, "127.0.0.1", 1080)


class RecordingEngine(MockTunnelEngine):
    def __init__(self):
        super().__init__()
        self.connect_error = None
        self.disconnect_error = None
        self.validations = 0
        self.disconnect_calls = 0
        self.confirm_connected = True

    def validate_profile(self, profile):
        self.validations += 1
        super().validate_profile(profile)

    def connect(self, profile):
        if self.connect_error:
            self._state = ConnectionState.CONNECTING
            raise self.connect_error
        super().connect(profile)
        if not self.confirm_connected:
            self._state = ConnectionState.CONNECTING

    def disconnect(self):
        self.disconnect_calls += 1
        if self.disconnect_error:
            raise self.disconnect_error
        super().disconnect()


def test_controller_connects_only_after_engine_confirms_connected(profile):
    engine = RecordingEngine()
    controller = ConnectionController(engine)
    controller.connect(profile)
    assert controller.state is ConnectionState.CONNECTED
    assert controller.active_profile == profile
    assert engine.validations == 1


def test_controller_rejects_duplicate_connect(profile):
    controller = ConnectionController(RecordingEngine())
    controller.connect(profile)
    with pytest.raises(ConnectionLifecycleError, match="Cannot connect"):
        controller.connect(profile)


def test_controller_failed_connect_requests_cleanup_and_enters_error(profile):
    engine = RecordingEngine()
    engine.connect_error = OSError("start failed")
    controller = ConnectionController(engine)
    with pytest.raises(ConnectionLifecycleError, match="start failed.*cleanup was requested"):
        controller.connect(profile)
    assert engine.disconnect_calls == 1
    assert controller.state is ConnectionState.ERROR
    assert controller.active_profile is None


def test_controller_retains_cleanup_failure_and_profile_for_retry(profile):
    engine = RecordingEngine()
    engine.connect_error = OSError("start failed")
    engine.disconnect_error = OSError("cleanup failed")
    controller = ConnectionController(engine)
    with pytest.raises(ConnectionLifecycleError) as captured:
        controller.connect(profile)
    assert isinstance(captured.value.cleanup_error, OSError)
    assert "cleanup failed" in str(captured.value)
    assert controller.state is ConnectionState.ERROR
    assert controller.active_profile == profile


def test_controller_rejects_engine_that_does_not_confirm_connected(profile):
    engine = RecordingEngine()
    engine.confirm_connected = False
    controller = ConnectionController(engine)
    with pytest.raises(ConnectionLifecycleError, match="without confirming"):
        controller.connect(profile)
    assert engine.disconnect_calls == 1
    assert controller.state is ConnectionState.ERROR
    assert controller.active_profile is None


def test_controller_validation_failure_does_not_change_state_or_cleanup():
    engine = RecordingEngine()
    controller = ConnectionController(engine)
    with pytest.raises(TypeError, match="ConnectionProfile"):
        controller.connect(object())
    assert controller.state is ConnectionState.DISCONNECTED
    assert controller.active_profile is None
    assert engine.disconnect_calls == 0


def test_controller_disconnects_and_clears_profile(profile):
    controller = ConnectionController(RecordingEngine())
    controller.connect(profile)
    controller.disconnect()
    assert controller.state is ConnectionState.DISCONNECTED
    assert controller.active_profile is None


def test_controller_disconnect_failure_keeps_error_state_and_profile(profile):
    engine = RecordingEngine()
    controller = ConnectionController(engine)
    controller.connect(profile)
    engine.disconnect_error = OSError("stop failed")
    with pytest.raises(ConnectionLifecycleError, match="resources may still be active"):
        controller.disconnect()
    assert controller.state is ConnectionState.ERROR
    assert controller.active_profile == profile


def test_controller_disconnect_is_idempotent():
    engine = RecordingEngine()
    controller = ConnectionController(engine)
    controller.disconnect()
    assert engine.disconnect_calls == 0
    assert controller.state is ConnectionState.DISCONNECTED
