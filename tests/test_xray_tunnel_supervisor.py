from pathlib import Path

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.services.xray_tunnel_supervisor import XrayTunnelSupervisor


class FakeStore:
    def __init__(self, path, present=True):
        self.path = Path(path)
        self.present = present

    def has_config(self, _profile_name):
        return self.present


class FakeProcess:
    def __init__(self, pid=1234, exit_code=None):
        self.pid = pid
        self.exit_code = exit_code
        self.terminated = []
        self.closed = False

    def poll(self):
        return self.exit_code

    def terminate(self, *, timeout):
        self.terminated.append(timeout)
        self.exit_code = 0

    def close(self):
        self.closed = True


def xray_profile():
    return ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)


def test_supervisor_starts_fixed_helper_with_selected_profile_and_store(tmp_path):
    store = FakeStore(tmp_path / "xray-configs.json")
    helper = tmp_path / "ApnaWinElevator.exe"
    observed = {}
    process = FakeProcess()

    def factory(helper_arg, store_arg, profile_name, *, readiness_timeout):
        observed.update(
            helper=helper_arg,
            store=store_arg,
            profile=profile_name,
            readiness_timeout=readiness_timeout,
        )
        return process

    supervisor = XrayTunnelSupervisor(
        helper, store, process_factory=factory, readiness_timeout=12
    )

    assert supervisor.start(xray_profile()) == 1234
    assert observed == {
        "helper": helper,
        "store": store.path,
        "profile": "Office",
        "readiness_timeout": 12.0,
    }
    assert supervisor.is_running


def test_supervisor_prevents_two_simultaneous_sessions(tmp_path):
    process = FakeProcess()
    supervisor = XrayTunnelSupervisor(
        tmp_path / "ApnaWinElevator.exe",
        FakeStore(tmp_path / "xray-configs.json"),
        process_factory=lambda *_args, **_kwargs: process,
    )
    supervisor.start(xray_profile())
    with pytest.raises(RuntimeError, match="already running"):
        supervisor.start(xray_profile())


def test_supervisor_requires_xray_profile_and_imported_config(tmp_path):
    supervisor = XrayTunnelSupervisor(
        tmp_path / "ApnaWinElevator.exe",
        FakeStore(tmp_path / "xray-configs.json", present=False),
        process_factory=lambda *_args, **_kwargs: pytest.fail("must not launch helper"),
    )
    socks = ConnectionProfile("Local", Transport.SOCKS, "127.0.0.1", 1080)
    with pytest.raises(ValueError, match="XRAY profiles"):
        supervisor.start(socks)
    with pytest.raises(ValueError, match="Import a validated"):
        supervisor.start(xray_profile())


def test_supervisor_retains_abnormally_exited_helper_and_refuses_restart(tmp_path):
    store = FakeStore(tmp_path / "xray-configs.json")
    first_process = FakeProcess(exit_code=7)
    launches = []

    def factory(*_args, **_kwargs):
        launches.append(True)
        return first_process

    supervisor = XrayTunnelSupervisor(
        tmp_path / "ApnaWinElevator.exe", store, process_factory=factory
    )
    supervisor.start(xray_profile())

    assert supervisor.poll() == 7
    assert first_process.closed is False
    assert supervisor._process is first_process
    assert supervisor.is_running is False
    with pytest.raises(RuntimeError, match="cleanup is unverified"):
        supervisor.start(xray_profile())
    with pytest.raises(RuntimeError, match="cleanup cannot be confirmed"):
        supervisor.stop()
    assert launches == [True]
    assert first_process.closed is False


def test_supervisor_clean_exit_is_released_only_on_explicit_stop(tmp_path):
    store = FakeStore(tmp_path / "xray-configs.json")
    processes = [FakeProcess(exit_code=0), FakeProcess()]
    first_process = processes[0]

    def factory(*_args, **_kwargs):
        return processes.pop(0)

    supervisor = XrayTunnelSupervisor(
        tmp_path / "ApnaWinElevator.exe", store, process_factory=factory
    )
    supervisor.start(xray_profile())
    assert supervisor.poll() == 0
    assert first_process.closed is False
    supervisor.stop()
    assert first_process.closed is True
    assert supervisor._process is None
    assert supervisor.start(xray_profile()) == 1234


def test_supervisor_stop_signals_and_closes_helper(tmp_path):
    process = FakeProcess()
    supervisor = XrayTunnelSupervisor(
        tmp_path / "ApnaWinElevator.exe",
        FakeStore(tmp_path / "xray-configs.json"),
        process_factory=lambda *_args, **_kwargs: process,
        stop_timeout=9,
    )
    supervisor.start(xray_profile())
    supervisor.stop()
    assert process.terminated == [9.0]
    assert process.closed
    assert supervisor._process is None


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True])
def test_supervisor_rejects_invalid_timeouts(tmp_path, value):
    with pytest.raises(ValueError, match="positive finite"):
        XrayTunnelSupervisor(
            tmp_path / "helper.exe", FakeStore(tmp_path / "store.json"),
            readiness_timeout=value,
        )
