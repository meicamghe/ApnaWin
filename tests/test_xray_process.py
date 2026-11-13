import json
import subprocess
from pathlib import Path

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.xray_process import XrayProcessError, XrayProcessRunner


@pytest.fixture
def files(tmp_path):
    executable = tmp_path / "xray.exe"
    executable.write_bytes(b"test executable placeholder")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"inbounds": [], "outbounds": []}), encoding="utf-8")
    profile = ConnectionProfile("Test Xray", Transport.XRAY, "127.0.0.1", 443)
    return executable, config, profile


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def test_validate_uses_xray_config_test_without_shell(monkeypatch, files):
    executable, config, profile = files
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = XrayProcessRunner(executable, config)
    runner.validate(profile)

    command, kwargs = calls[0]
    assert command == [str(executable), "run", "-test", "-c", str(config)]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] == subprocess.DEVNULL


def test_validate_rejects_non_xray_profile(files):
    executable, config, _ = files
    profile = ConnectionProfile("SOCKS", Transport.SOCKS, "localhost", 1080)
    with pytest.raises(ValueError, match="Xray profile"):
        XrayProcessRunner(executable, config).validate(profile)


def test_validate_rejects_invalid_json(tmp_path):
    executable = tmp_path / "xray.exe"
    executable.touch()
    config = tmp_path / "bad.json"
    config.write_text("{broken", encoding="utf-8")
    profile = ConnectionProfile("X", Transport.XRAY, "localhost", 443)

    with pytest.raises(ValueError, match="UTF-8 JSON"):
        XrayProcessRunner(executable, config).validate(profile)


def test_validate_rejects_xray_config(monkeypatch, files):
    executable, config, profile = files
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 23, b"", b"secret"),
    )
    runner = XrayProcessRunner(executable, config)

    with pytest.raises(XrayProcessError, match="exit code 23") as error:
        runner.validate(profile)
    assert "secret" not in str(error.value)


def test_start_and_stop_process(monkeypatch, files):
    executable, config, profile = files
    process = FakeProcess()
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, b"", b""),
    )
    monkeypatch.setattr(subprocess, "Popen", lambda command, **kwargs: process)
    runner = XrayProcessRunner(executable, config)

    runner.start(profile)
    assert runner.is_running
    with pytest.raises(XrayProcessError, match="already running"):
        runner.start(profile)

    runner.stop()
    assert process.terminated
    assert not runner.is_running
    runner.stop()


def test_start_rejects_process_that_exits_immediately(monkeypatch, files):
    executable, config, profile = files
    process = FakeProcess(returncode=7)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, b"", b""),
    )
    monkeypatch.setattr(subprocess, "Popen", lambda command, **kwargs: process)

    with pytest.raises(XrayProcessError, match="exited during startup"):
        XrayProcessRunner(executable, config).start(profile)


def test_missing_executable_is_reported(tmp_path):
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    profile = ConnectionProfile("X", Transport.XRAY, "localhost", 443)

    with pytest.raises(FileNotFoundError, match="executable"):
        XrayProcessRunner(tmp_path / "missing.exe", config).validate(profile)
