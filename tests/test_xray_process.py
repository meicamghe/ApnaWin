import json
import socket
import subprocess
from pathlib import Path

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines.xray_process import (
    LocalSocksInbound,
    XrayProcessError,
    XrayProcessRunner,
    inspect_local_socks_inbound,
)


@pytest.fixture
def files(tmp_path):
    executable = tmp_path / "xray.exe"
    executable.write_bytes(b"test executable placeholder")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({
            "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}],
            "outbounds": [],
        }),
        encoding="utf-8",
    )
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


def test_inspect_local_socks_inbound(files):
    _, config, _ = files
    runner = XrayProcessRunner("xray.exe", config)
    assert runner.local_socks_inbound() == LocalSocksInbound("127.0.0.1", 10808)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10"])
def test_inspect_rejects_non_loopback_socks_bind(host):
    config = {"inbounds": [{"listen": host, "port": 10808, "protocol": "socks"}]}
    with pytest.raises(ValueError, match="loopback"):
        inspect_local_socks_inbound(config)


@pytest.mark.parametrize("port", [0, 65536, True, "1080", None])
def test_inspect_rejects_invalid_socks_port(port):
    config = {"inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks"}]}
    with pytest.raises(ValueError, match="port"):
        inspect_local_socks_inbound(config)


def test_inspect_requires_exactly_one_socks_inbound():
    with pytest.raises(ValueError, match="exactly one"):
        inspect_local_socks_inbound({"inbounds": []})


def test_socks_readiness_checks_configured_listener(monkeypatch, files):
    _, config, _ = files
    observed = []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_create_connection(address, timeout):
        observed.append((address, timeout))
        return FakeConnection()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    runner = XrayProcessRunner("xray.exe", config)

    assert runner.is_socks_ready(connect_timeout=0.2)
    assert observed == [(("127.0.0.1", 10808), 0.2)]


@pytest.mark.parametrize("reply, expected", [(bytes((5, 0)), True), (bytes((5, 2)), False), (bytes((4, 0)), False), (b"", False)])
def test_socks_protocol_probe_negotiates_no_auth(monkeypatch, files, reply, expected):
    _, config, _ = files
    observed = {}

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, value):
            observed["timeout"] = value

        def sendall(self, payload):
            observed["payload"] = payload

        def recv(self, size):
            observed["size"] = size
            return reply

    def fake_create_connection(address, timeout):
        observed["address"] = address
        observed["connect_timeout"] = timeout
        return FakeConnection()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    runner = XrayProcessRunner("xray.exe", config)
    assert runner.is_socks_protocol_ready(timeout=0.7) is expected
    assert observed["address"] == ("127.0.0.1", 10808)
    assert observed["payload"] == bytes((5, 1, 0))
    assert observed["size"] == 2
    assert observed["timeout"] == 0.7


@pytest.mark.parametrize(
    "destination_host, expected_address",
    [
        ("example.com", bytes((3, 11)) + b"example.com"),
        ("192.0.2.10", bytes((1, 192, 0, 2, 10))),
        ("2001:db8::1", bytes((4,)) + bytes.fromhex("20010db8000000000000000000000001")),
    ],
)
def test_socks_connect_sends_correct_destination(monkeypatch, files, destination_host, expected_address):
    _, config, _ = files
    sent = []

    class FakeConnection:
        replies = [bytes((5, 0)), bytes((5, 0, 0, 1)), bytes((127, 0, 0, 1, 0x1F, 0x90))]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, value):
            self.timeout = value

        def sendall(self, payload):
            sent.append(payload)

        def recv(self, size):
            if not self.replies:
                return b""
            chunk = self.replies[0][:size]
            self.replies[0] = self.replies[0][len(chunk):]
            if not self.replies[0]:
                self.replies.pop(0)
            return chunk

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: FakeConnection())
    runner = XrayProcessRunner("xray.exe", config)
    assert runner.socks_connect(destination_host, 8080)
    assert sent == [bytes((5, 1, 0)), bytes((5, 1, 0)) + expected_address + (8080).to_bytes(2, "big")]


def test_socks_connect_returns_false_for_rejected_destination(monkeypatch, files):
    _, config, _ = files

    class FakeConnection:
        replies = [bytes((5, 0)), bytes((5, 5, 0, 1)), bytes((0, 0, 0, 0, 0, 0))]

        def __enter__(self): return self
        def __exit__(self, *args): return False
        def settimeout(self, value): pass
        def sendall(self, payload): pass
        def recv(self, size):
            chunk = self.replies[0][:size]
            self.replies[0] = self.replies[0][len(chunk):]
            if not self.replies[0]: self.replies.pop(0)
            return chunk

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: FakeConnection())
    assert not XrayProcessRunner("xray.exe", config).socks_connect("example.com", 443)


@pytest.mark.parametrize("port", [0, 65536, True, "443"])
def test_socks_connect_rejects_invalid_destination_port(files, port):
    _, config, _ = files
    with pytest.raises(ValueError, match="destination_port"):
        XrayProcessRunner("xray.exe", config).socks_connect("example.com", port)


def test_socks_connect_rejects_auth_required(monkeypatch, files):
    _, config, _ = files

    class FakeConnection:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def settimeout(self, value): pass
        def sendall(self, payload): pass
        def recv(self, size): return bytes((5, 2))

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: FakeConnection())
    assert not XrayProcessRunner("xray.exe", config).socks_connect("example.com", 443)


def test_socks_protocol_probe_returns_false_on_socket_error(monkeypatch, files):
    _, config, _ = files

    def unavailable(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", unavailable)
    assert not XrayProcessRunner("xray.exe", config).is_socks_protocol_ready()

def test_socks_readiness_returns_false_when_listener_is_unavailable(monkeypatch, files):
    _, config, _ = files

    def unavailable(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", unavailable)
    assert not XrayProcessRunner("xray.exe", config).is_socks_ready()


class FakeExchangeConnection:
    def __init__(self, response=b"HTTP/1.1 200 OK\\r\\n\\r\\nhello"):
        self.replies = [bytes((5, 0)), bytes((5, 0, 0, 1)), bytes((127, 0, 0, 1, 0x1F, 0x90))]
        self.response = response
        self.sent = []
        self.shutdown_how = None

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def settimeout(self, value): self.timeout = value
    def sendall(self, payload): self.sent.append(payload)
    def shutdown(self, how): self.shutdown_how = how
    def recv(self, size):
        if self.replies:
            chunk = self.replies[0][:size]
            self.replies[0] = self.replies[0][len(chunk):]
            if not self.replies[0]: self.replies.pop(0)
            return chunk
        chunk = self.response[:size]
        self.response = self.response[len(chunk):]
        return chunk


def test_socks_exchange_sends_payload_and_reads_response_to_eof(monkeypatch, files):
    _, config, _ = files
    connection = FakeExchangeConnection()
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: connection)

    result = XrayProcessRunner("xray.exe", config).socks_exchange(
        "example.com", 80, b"GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n"
    )

    assert result == b"HTTP/1.1 200 OK\\r\\n\\r\\nhello"
    assert connection.sent[0] == bytes((5, 1, 0))
    assert connection.sent[1] == bytes((5, 1, 0, 3, 11)) + b"example.com" + (80).to_bytes(2, "big")
    assert connection.sent[2].startswith(b"GET / HTTP/1.0")
    assert connection.shutdown_how == socket.SHUT_WR


def test_socks_exchange_rejects_response_over_limit(monkeypatch, files):
    _, config, _ = files
    connection = FakeExchangeConnection(response=b"0123456789")
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: connection)

    with pytest.raises(ValueError, match="max_response_bytes"):
        XrayProcessRunner("xray.exe", config).socks_exchange(
            "example.com", 80, b"request", max_response_bytes=5
        )


def test_socks_exchange_validates_payload_and_limit(files):
    _, config, _ = files
    runner = XrayProcessRunner("xray.exe", config)
    with pytest.raises(TypeError, match="payload"):
        runner.socks_exchange("example.com", 80, "not bytes")
    with pytest.raises(ValueError, match="max_response_bytes"):
        runner.socks_exchange("example.com", 80, b"x", max_response_bytes=0)


def test_socks_exchange_returns_none_when_proxy_rejects(monkeypatch, files):
    _, config, _ = files
    connection = FakeExchangeConnection()
    connection.replies = [bytes((5, 0)), bytes((5, 5, 0, 1)), bytes((0, 0, 0, 0, 0, 0))]
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: connection)
    assert XrayProcessRunner("xray.exe", config).socks_exchange(
        "example.com", 80, b"request"
    ) is None
