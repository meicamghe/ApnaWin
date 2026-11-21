from pathlib import Path

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.xray_tunnel import XrayTunnelEngine


def profile(transport=Transport.XRAY):
    return ConnectionProfile("Office", transport, "vpn.example.test", 443)


class Store:
    def __init__(self, present=True):
        self.present = present

    def has_config(self, _name):
        return self.present


class Supervisor:
    def __init__(self, *, running=True, exit_code=None, stop_error=None):
        self.running = running
        self.exit_code = exit_code
        self.stop_error = stop_error
        self.starts = []
        self.stops = 0

    def start(self, selected):
        self.starts.append(selected)
        self.running = True

    @property
    def is_running(self):
        return self.running

    def poll(self):
        if self.exit_code is not None:
            self.running = False
        return self.exit_code

    def stop(self):
        self.stops += 1
        if self.stop_error:
            raise self.stop_error
        self.running = False


def make_engine(tmp_path, **kwargs):
    helper = tmp_path / "ApnaWinElevator.exe"
    helper.write_bytes(b"helper")
    supervisor = kwargs.pop("supervisor", Supervisor())
    engine = XrayTunnelEngine(
        supervisor,
        helper,
        Store(kwargs.pop("config_present", True)),
        runtime_verifier=kwargs.pop("runtime_verifier", lambda _path: {}),
        platform_name=kwargs.pop("platform_name", "nt"),
        **kwargs,
    )
    return engine, supervisor, helper


def test_validation_requires_windows_xray_helper_runtime_and_config(tmp_path):
    engine, _supervisor, _helper = make_engine(tmp_path)
    engine.validate_profile(profile())
    with pytest.raises(ValueError, match="XRAY"):
        engine.validate_profile(profile(Transport.SOCKS))
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(OSError, match="only on Windows"):
        make_engine(other, platform_name="posix")[0].validate_profile(profile())


def test_validation_fails_closed_when_runtime_or_config_missing(tmp_path):
    engine, _supervisor, _helper = make_engine(
        tmp_path, runtime_verifier=lambda _path: (_ for _ in ()).throw(RuntimeError("hash mismatch"))
    )
    with pytest.raises(RuntimeError, match="hash mismatch"):
        engine.validate_profile(profile())
    engine, _supervisor, _helper = make_engine(tmp_path, config_present=False)
    with pytest.raises(ValueError, match="Import a validated"):
        engine.validate_profile(profile())


def test_connect_reports_connected_only_after_helper_is_running(tmp_path):
    engine, supervisor, _helper = make_engine(tmp_path)
    engine.validate_profile(profile())
    engine.connect(profile())
    assert supervisor.starts == [profile()]
    assert engine.state is ConnectionState.CONNECTED
    assert engine.active_profile == profile()


def test_connect_failure_enters_error_and_retains_profile_for_controller_cleanup(tmp_path):
    class BrokenSupervisor(Supervisor):
        def start(self, selected):
            raise TimeoutError("TUN egress not ready")

    engine, _supervisor, _helper = make_engine(tmp_path, supervisor=BrokenSupervisor())
    with pytest.raises(TimeoutError, match="egress"):
        engine.connect(profile())
    assert engine.state is ConnectionState.ERROR
    assert engine.active_profile == profile()
    assert "TUN egress" in engine.last_error


def test_refresh_detects_unexpected_helper_exit(tmp_path):
    engine, supervisor, _helper = make_engine(tmp_path, supervisor=Supervisor(exit_code=14))
    engine.connect(profile())
    assert engine.refresh() is ConnectionState.ERROR
    assert "unexpectedly" in engine.last_error
    assert engine.active_profile == profile()


def test_disconnect_clears_session_and_stop_failure_keeps_error(tmp_path):
    engine, supervisor, _helper = make_engine(tmp_path)
    engine.connect(profile())
    engine.disconnect()
    assert supervisor.stops == 1
    assert engine.state is ConnectionState.DISCONNECTED
    assert engine.active_profile is None

    broken, _supervisor, _helper = make_engine(
        tmp_path, supervisor=Supervisor(stop_error=OSError("restore failed"))
    )
    broken.connect(profile())
    with pytest.raises(OSError, match="restore failed"):
        broken.disconnect()
    assert broken.state is ConnectionState.ERROR
    assert "cleanup failed" in broken.last_error
