import json
import socket
import subprocess
from pathlib import Path

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines import xray_process as xray_module
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
    monkeypatch.setattr(xray_module.WindowsJobProcess, "launch", lambda *args: process)
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
    monkeypatch.setattr(xray_module.WindowsJobProcess, "launch", lambda *args: process)

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
    def __init__(self, response=b"HTTP/1.1 200 OK\r\n\r\nhello"):
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
        "example.com", 80, b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
    )

    assert result == b"HTTP/1.1 200 OK\r\n\r\nhello"
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


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True, "1"])
def test_socks_connect_rejects_invalid_timeout(files, timeout):
    _, config, _ = files
    with pytest.raises(ValueError, match="timeout"):
        XrayProcessRunner("xray.exe", config).socks_connect(
            "example.com", 443, timeout=timeout
        )


def test_socks_exchange_localhost_integration_round_trip(files):
    import threading

    executable, config, _ = files
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    port = listener.getsockname()[1]
    config.write_text(json.dumps({
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks"}],
        "outbounds": [],
    }), encoding="utf-8")
    received = {}
    response = b"HTTP/1.1 200 OK\\r\\nContent-Length: 5\\r\\n\\r\\nhello"

    def read_exact(connection, count):
        data = bytearray()
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise OSError("unexpected EOF")
            data.extend(chunk)
        return bytes(data)

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                received["greeting"] = read_exact(connection, 3)
                connection.sendall(bytes((5, 0)))
                request_prefix = read_exact(connection, 5)
                assert request_prefix == bytes((5, 1, 0, 3, 11))
                received["host"] = read_exact(connection, 11)
                received["port"] = read_exact(connection, 2)
                connection.sendall(bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 80)))
                body = bytearray()
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    body.extend(chunk)
                received["payload"] = bytes(body)
                connection.sendall(response)
        except Exception as exc:
            received["server_error"] = repr(exc)
        finally:
            listener.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        result = XrayProcessRunner(executable, config).socks_exchange(
            "example.com", 80, b"GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n",
            timeout=2.0, max_response_bytes=1024,
        )
        worker.join(timeout=4)
        assert not worker.is_alive(), "local SOCKS fixture did not finish"
        assert "server_error" not in received, received.get("server_error")
        assert result == response
        assert received["greeting"] == bytes((5, 1, 0))
        assert received["host"] == b"example.com"
        assert received["port"] == (80).to_bytes(2, "big")
        assert received["payload"].startswith(b"GET / HTTP/1.0")
    finally:
        listener.close()
        worker.join(timeout=1)


class FragmentedReplyConnection:
    def __init__(self, data):
        self.data = data

    def recv(self, size):
        chunk = self.data[: min(size, 2)]
        self.data = self.data[len(chunk):]
        return chunk


@pytest.mark.parametrize(
    "reply, expected",
    [
        (bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 80)), 0),
        (bytes((5, 5, 0, 3, 3)) + b"abc" + bytes((0, 80)), 5),
        (bytes((5, 0, 0, 4)) + bytes(16) + bytes((0, 80)), 0),
    ],
)
def test_socks_reply_parser_accepts_fragmented_ipv4_domain_and_ipv6(reply, expected):
    assert XrayProcessRunner._read_socks_reply(FragmentedReplyConnection(reply)) == expected


@pytest.mark.parametrize(
    "reply",
    [
        b"\x04\x00\x00\x01" + bytes(6),  # unsupported version
        b"\x05\x00\x01\x01" + bytes(7),  # non-zero reserved byte
        b"\x05\x00\x00\x09",  # unknown address type
        b"\x05\x00\x00\x03\x00",  # empty domain
        b"\x05\x00\x00\x01\x7f\x00",  # truncated IPv4 reply
        b"\x05\x00\x00\x03\x05ab",  # truncated domain reply
    ],
)
def test_socks_reply_parser_rejects_malformed_or_truncated_reply(reply):
    with pytest.raises(OSError):
        XrayProcessRunner._read_socks_reply(FragmentedReplyConnection(reply))


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True, "1"])
def test_socks_readiness_rejects_invalid_timeouts(files, timeout):
    _, config, _ = files
    runner = XrayProcessRunner("xray.exe", config)
    with pytest.raises(ValueError, match="timeout"):
        runner.is_socks_ready(connect_timeout=timeout)
    with pytest.raises(ValueError, match="timeout"):
        runner.is_socks_protocol_ready(timeout=timeout)


@pytest.mark.parametrize("timeout_name", ["validation_timeout", "stop_timeout"])
@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True, "1"])
def test_runner_rejects_invalid_process_timeouts(files, timeout_name, timeout):
    executable, config, _ = files
    with pytest.raises(ValueError, match=timeout_name):
        XrayProcessRunner(executable, config, **{timeout_name: timeout})


def test_stop_retains_process_when_terminate_fails(files):
    executable, config, _ = files

    class TerminateFailure(FakeProcess):
        def terminate(self):
            raise OSError("access denied")

    process = TerminateFailure()
    runner = XrayProcessRunner(executable, config)
    runner._process = process

    with pytest.raises(XrayProcessError, match="request Xray termination"):
        runner.stop()
    assert runner._process is process
    assert runner.is_running


def test_stop_escalates_to_kill_after_timeout(files):
    executable, config, _ = files

    class NeedsKill(FakeProcess):
        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired("xray", timeout)
            self.returncode = -9
            return self.returncode

    process = NeedsKill()
    runner = XrayProcessRunner(executable, config, stop_timeout=0.25)
    runner._process = process

    runner.stop()
    assert process.terminated
    assert process.killed
    assert runner._process is None
    assert not runner.is_running


def test_stop_retains_process_when_kill_does_not_finish(files):
    executable, config, _ = files

    class Unstoppable(FakeProcess):
        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("xray", timeout)

        def kill(self):
            self.killed = True

    process = Unstoppable()
    runner = XrayProcessRunner(executable, config, stop_timeout=0.01)
    runner._process = process

    with pytest.raises(XrayProcessError, match="did not exit"):
        runner.stop()
    assert process.killed
    assert runner._process is process
    assert runner.is_running


def test_stop_clears_already_exited_process(files):
    executable, config, _ = files
    process = FakeProcess(returncode=0)
    runner = XrayProcessRunner(executable, config)
    runner._process = process

    runner.stop()

    assert runner._process is None
    assert not process.terminated


def test_windows_stop_uses_taskkill_tree_before_direct_kill(monkeypatch, files):
    import apnawin.engines.xray_process as xray_module

    executable, config, _ = files

    class TreeProcess(FakeProcess):
        pid = 4321

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired("xray", timeout)
            self.returncode = -9
            return self.returncode

    process = TreeProcess()
    calls = []
    monkeypatch.setattr(xray_module.os, "name", "nt")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: (
            calls.append((command, kwargs))
            or subprocess.CompletedProcess(command, 0, b"", b"")
        ),
    )
    runner = XrayProcessRunner(executable, config, stop_timeout=0.1)
    runner._process = process

    runner.stop()

    assert calls[0][0] == ["taskkill", "/PID", "4321", "/T", "/F"]
    assert calls[0][1]["shell"] is False
    assert process.killed
    assert runner._process is None



def test_windows_stop_falls_back_when_taskkill_is_unavailable(monkeypatch, files):
    import apnawin.engines.xray_process as xray_module

    executable, config, _ = files

    class TreeProcess(FakeProcess):
        pid = 4322

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired("xray", timeout)
            self.returncode = -9
            return self.returncode

    process = TreeProcess()
    commands = []

    def unavailable(command, **kwargs):
        commands.append(command)
        raise FileNotFoundError("taskkill unavailable")

    monkeypatch.setattr(xray_module.os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", unavailable)
    runner = XrayProcessRunner(executable, config, stop_timeout=0.1)
    runner._process = process

    runner.stop()

    assert commands == [["taskkill", "/PID", "4322", "/T", "/F"]]
    assert process.killed
    assert runner._process is None


def test_windows_stop_falls_back_when_taskkill_returns_failure(monkeypatch, files):
    import apnawin.engines.xray_process as xray_module

    executable, config, _ = files

    class TreeProcess(FakeProcess):
        pid = 4323

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired("xray", timeout)
            self.returncode = -9
            return self.returncode

    process = TreeProcess()
    commands = []

    def rejected(command, **kwargs):
        commands.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, b"", b"access denied")

    monkeypatch.setattr(xray_module.os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", rejected)
    runner = XrayProcessRunner(executable, config, stop_timeout=0.1)
    runner._process = process

    runner.stop()

    assert commands[0][0] == ["taskkill", "/PID", "4323", "/T", "/F"]
    assert commands[0][1]["shell"] is False
    assert process.killed
    assert runner._process is None


@pytest.mark.parametrize(
    "inbounds",
    [
        [{"listen": "0.0.0.0", "port": 10808, "protocol": "socks"}],
        [{"listen": "::", "port": 10808, "protocol": "socks"}],
        [],
        [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
            {"listen": "127.0.0.1", "port": 10809, "protocol": "socks"},
        ],
        [{"listen": "0.0.0.0", "port": 10808, "protocol": "http"}],
        [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks"},
            {"listen": "0.0.0.0", "port": 10809, "protocol": "http"},
        ],
        [None],
    ],
)
def test_validate_rejects_unsafe_or_ambiguous_socks_inbound_before_execution(
    monkeypatch, files, inbounds
):
    executable, config, profile = files
    config.write_text(json.dumps({"inbounds": inbounds, "outbounds": []}), encoding="utf-8")
    called = False

    def unexpected_execution(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("Xray must not execute with an unsupported inbound topology")

    monkeypatch.setattr(subprocess, "run", unexpected_execution)
    with pytest.raises(ValueError):
        XrayProcessRunner(executable, config).validate(profile)
    assert not called

@pytest.mark.parametrize(
    "raw_config",
    [
        '{"inbounds": [], "inbounds": []}',
        '{"inbounds": [{"listen": "127.0.0.1", "listen": "0.0.0.0", "port": 10808, "protocol": "socks"}]}',
        '{"inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}], "outbounds": [NaN]}',
        '{"inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}], "outbounds": [Infinity]}',
    ],
)
def test_read_config_rejects_duplicate_keys_and_non_finite_constants(tmp_path, raw_config):
    executable = tmp_path / "xray.exe"
    executable.touch()
    config = tmp_path / "config.json"
    config.write_text(raw_config, encoding="utf-8")
    runner = XrayProcessRunner(executable, config)

    with pytest.raises(ValueError, match="readable UTF-8 JSON"):
        runner._read_config()


def test_read_config_rejects_non_object_root(tmp_path):
    executable = tmp_path / "xray.exe"
    executable.touch()
    config = tmp_path / "config.json"
    config.write_text('["not", "an", "object"]', encoding="utf-8")

    with pytest.raises(ValueError, match="root must be a JSON object"):
        XrayProcessRunner(executable, config)._read_config()
