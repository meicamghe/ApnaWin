from __future__ import annotations

import base64
import hashlib
import socket
import threading

import paramiko
import pytest

from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode
from apnawin.engines.apna_ssh_session import (
    ApnaSshConfig,
    ApnaSshError,
    ApnaSshSession,
    _PinnedHostKeyPolicy,
    _relay_tcp,
)


def _payload_config() -> PayloadSocketConfig:
    return PayloadSocketConfig(
        mode=PayloadSocketMode.DIRECT,
        connect_host="ssh.example.test",
        connect_port=22,
        target_host="ssh.example.test",
        target_port=22,
    )


def test_config_requires_credentials_and_loopback_listener() -> None:
    with pytest.raises(ValueError, match="password or private-key"):
        ApnaSshConfig("ssh.example.test", 22, "user")
    with pytest.raises(ValueError, match="loopback"):
        ApnaSshConfig("ssh.example.test", 22, "user", password="secret", local_host="0.0.0.0")


def test_connect_enforces_host_key_policy_and_starts_loopback_socks(monkeypatch) -> None:
    client_socket, peer = socket.socketpair()
    observed = {}

    class FakeTransport:
        def is_active(self):
            return True

        def is_authenticated(self):
            return True

    class FakeSshClient:
        def load_system_host_keys(self):
            observed["system_hosts"] = True

        def load_host_keys(self, path):
            observed["known_hosts"] = path

        def set_missing_host_key_policy(self, policy):
            observed["policy"] = type(policy).__name__

        def connect(self, **kwargs):
            observed["connect"] = kwargs

        def get_transport(self):
            return FakeTransport()

        def close(self):
            observed["closed"] = True

    session = ApnaSshSession(
        ApnaSshConfig(
            "ssh.example.test", 22, "user", password="secret",
            known_hosts_files=("known_hosts.test",),
        ),
        _payload_config(),
        connector=type("Connector", (), {"connect": lambda self, config: client_socket})(),
        ssh_client_factory=FakeSshClient,
    )
    address = session.connect()
    assert address[0] == "127.0.0.1"
    assert address[1] > 0
    assert observed["policy"] == "RejectPolicy"
    assert observed["known_hosts"] == "known_hosts.test"
    assert observed["connect"]["allow_agent"] is False
    assert observed["connect"]["look_for_keys"] is False
    assert session.is_authenticated
    session.close()
    peer.close()


def test_connect_rejects_payload_target_mismatch() -> None:
    session = ApnaSshSession(
        ApnaSshConfig("ssh.example.test", 22, "user", password="secret"),
        PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="proxy.example.test",
            connect_port=22,
            target_host="other.example.test",
            target_port=22,
        ),
    )
    with pytest.raises(ValueError, match="match the SSH host"):
        session.connect()


def test_local_socks5_connect_is_forwarded_over_authenticated_ssh_channel() -> None:
    client_socket, peer = socket.socketpair()
    channels = []

    class FakeChannel:
        def __init__(self):
            self.sent = bytearray()
            self.reply = bytearray(b"remote-reply")
            self.closed = False
            self.closed_event = threading.Event()

        def recv(self, size):
            if self.reply:
                result = bytes(self.reply[:size])
                del self.reply[:size]
                return result
            return b""

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown_write(self):
            return None

        def close(self):
            self.closed = True
            self.closed_event.set()

    class FakeTransport:
        def is_active(self):
            return True

        def is_authenticated(self):
            return True

        def open_channel(self, kind, destination, source, timeout):
            assert kind == "direct-tcpip"
            assert destination == ("example.com", 443)
            channel = FakeChannel()
            channels.append(channel)
            return channel

    class FakeSshClient:
        def load_system_host_keys(self):
            return None

        def load_host_keys(self, path):
            return None

        def set_missing_host_key_policy(self, policy):
            return None

        def connect(self, **kwargs):
            return None

        def get_transport(self):
            return FakeTransport()

        def close(self):
            return None

    session = ApnaSshSession(
        ApnaSshConfig("ssh.example.test", 22, "user", password="secret"),
        _payload_config(),
        connector=type("Connector", (), {"connect": lambda self, config: client_socket})(),
        ssh_client_factory=FakeSshClient,
    )
    host, port = session.connect()
    local = socket.create_connection((host, port), timeout=2)
    try:
        local.sendall(b"\x05\x01\x00")
        assert local.recv(2) == b"\x05\x00"
        local.sendall(b"\x05\x01\x00\x03\x0bexample.com\x01\xbb")
        assert local.recv(10) == b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        assert local.recv(12) == b"remote-reply"
        assert channels and channels[0].closed_event.wait(2)
    finally:
        local.close()
        session.close()
        peer.close()


def test_session_can_reconnect_after_close_and_close_new_resources() -> None:
    peers = []
    endpoints = []
    clients = []

    class FakeTransport:
        def is_active(self):
            return True

        def is_authenticated(self):
            return True

    class FakeSshClient:
        def __init__(self):
            self.closed = False
            clients.append(self)

        def load_system_host_keys(self):
            return None

        def set_missing_host_key_policy(self, policy):
            return None

        def connect(self, **kwargs):
            return None

        def get_transport(self):
            return FakeTransport()

        def close(self):
            self.closed = True

    class Connector:
        def connect(self, config):
            endpoint, peer = socket.socketpair()
            endpoints.append(endpoint)
            peers.append(peer)
            return endpoint

    session = ApnaSshSession(
        ApnaSshConfig("ssh.example.test", 22, "user", password="secret"),
        _payload_config(),
        connector=Connector(),
        ssh_client_factory=FakeSshClient,
    )
    try:
        first_address = session.connect()
        session.close()
        assert clients[-1].closed
        assert endpoints[-1].fileno() == -1

        second_address = session.connect()
        assert second_address[0] == "127.0.0.1"
        assert second_address[1] > 0
        assert session.is_authenticated
        session.close()
        assert clients[-1].closed
        assert endpoints[-1].fileno() == -1
        assert len(clients) == 2
        assert first_address[0] == second_address[0]
    finally:
        session.close()
        for peer in peers:
            peer.close()


def test_close_is_idempotent() -> None:
    session = ApnaSshSession(
        ApnaSshConfig("ssh.example.test", 22, "user", password="secret"),
        _payload_config(),
    )
    session.close()
    session.close()


def test_open_direct_channel_requires_authenticated_ssh_and_validates_destination() -> None:
    observed = {}

    class FakeChannel:
        pass

    class FakeTransport:
        def is_active(self):
            return True

        def is_authenticated(self):
            return True

        def open_channel(self, kind, destination, source, timeout):
            observed.update(kind=kind, destination=destination, source=source, timeout=timeout)
            return FakeChannel()

    class FakeSshClient:
        def get_transport(self):
            return FakeTransport()

    session = ApnaSshSession(
        ApnaSshConfig("ssh.example.test", 22, "user", password="secret"),
        _payload_config(),
    )
    with pytest.raises(ApnaSshError, match="not authenticated"):
        session.open_direct_channel("gateway.example.test", 7300)
    session._ssh_client = FakeSshClient()
    channel = session.open_direct_channel("gateway.example.test", 7300)
    assert isinstance(channel, FakeChannel)
    assert observed == {
        "kind": "direct-tcpip",
        "destination": ("gateway.example.test", 7300),
        "source": ("127.0.0.1", 0),
        "timeout": 10.0,
    }
    with pytest.raises(ValueError, match="destination_host"):
        session.open_direct_channel("bad host", 7300)
    with pytest.raises(ValueError, match="valid port range"):
        session.open_direct_channel("gateway.example.test", 0)


def test_host_key_pin_accepts_only_the_expected_sha256_fingerprint():
    key = paramiko.RSAKey.generate(1024)
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
    fingerprint = "SHA256:" + digest
    policy = _PinnedHostKeyPolicy(fingerprint)
    policy.missing_host_key(None, "ssh.example.test", key)

    wrong = "SHA256:" + base64.b64encode(b"x" * 32).decode("ascii").rstrip("=")
    with pytest.raises(paramiko.SSHException, match="fingerprint mismatch"):
        _PinnedHostKeyPolicy(wrong).missing_host_key(None, "ssh.example.test", key)


def test_ssh_config_validates_openssh_sha256_fingerprint():
    with pytest.raises(ValueError, match="OpenSSH SHA256"):
        ApnaSshConfig(
            "ssh.example.test", 22, "user", password="secret",
            host_key_sha256="not-a-fingerprint",
        )


@pytest.mark.parametrize("field", ["connect_timeout", "auth_timeout", "banner_timeout"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 0, -1, True])
def test_ssh_config_rejects_non_finite_or_non_positive_timeouts(field, value):
    with pytest.raises(ValueError, match="finite and positive"):
        ApnaSshConfig("ssh.example.test", 22, "user", password="secret", **{field: value})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 0, -1, True])
def test_ssh_session_rejects_invalid_channel_timeout(value):
    with pytest.raises(ValueError, match="channel_timeout must be finite and positive"):
        ApnaSshSession(
            ApnaSshConfig("ssh.example.test", 22, "user", password="secret"),
            _payload_config(),
            channel_timeout=value,
        )



@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (
            paramiko.SSHException("Error reading SSH protocol banner"),
            "SSH protocol banner was not received",
        ),
        (
            paramiko.AuthenticationException("Authentication failed"),
            "SSH authentication was rejected",
        ),
        (
            paramiko.SSHException("Incompatible ssh peer"),
            "SSH protocol negotiation failed: Incompatible ssh peer",
        ),
        (
            paramiko.SSHException("Server ssh.example.test not found in known_hosts"),
            "SSH host identity could not be verified",
        ),
    ],
)
def test_connect_preserves_actionable_ssh_stage_errors(failure, message):
    client_socket, peer = socket.socketpair()

    class RaisingSshClient:
        def load_system_host_keys(self):
            return None

        def load_host_keys(self, _path):
            return None

        def set_missing_host_key_policy(self, _policy):
            return None

        def connect(self, **_kwargs):
            raise failure

        def close(self):
            return None

    session = ApnaSshSession(
        ApnaSshConfig(
            "ssh.example.test",
            22,
            "user",
            password="secret",
            host_key_sha256=(
                "SHA256:" + base64.b64encode(b"x" * 32).decode("ascii").rstrip("=")
            ),
        ),
        _payload_config(),
        connector=type(
            "Connector",
            (),
            {"connect": lambda self, config: client_socket},
        )(),
        ssh_client_factory=RaisingSshClient,
    )
    try:
        with pytest.raises(ApnaSshError, match=message):
            session.connect()
        assert client_socket.fileno() == -1
    finally:
        peer.close()


def test_tcp_relay_preserves_remote_response_after_client_half_close() -> None:
    client, relay_peer = socket.socketpair()
    response_ready = threading.Event()

    class HalfCloseChannel:
        def __init__(self):
            self.received = bytearray()
            self.reply_sent = False

        def recv(self, _size):
            if not response_ready.wait(2):
                return b""
            if not self.reply_sent:
                self.reply_sent = True
                return b"server-response"
            return b""

        def sendall(self, data):
            self.received.extend(data)

        def shutdown_write(self):
            response_ready.set()

    channel = HalfCloseChannel()
    worker = threading.Thread(target=_relay_tcp, args=(relay_peer, channel), daemon=True)
    worker.start()
    try:
        client.sendall(b"client-request")
        client.shutdown(socket.SHUT_WR)
        received = bytearray()
        while len(received) < len(b"server-response"):
            chunk = client.recv(64)
            if not chunk:
                break
            received.extend(chunk)
        assert bytes(channel.received) == b"client-request"
        assert bytes(received) == b"server-response"
        worker.join(timeout=2)
        assert not worker.is_alive()
    finally:
        client.close()
        relay_peer.close()
