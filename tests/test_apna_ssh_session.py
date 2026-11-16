from __future__ import annotations

import socket
import pytest

from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode
from apnawin.engines.apna_ssh_session import ApnaSshConfig, ApnaSshError, ApnaSshSession


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
        assert channels and channels[0].closed
    finally:
        local.close()
        session.close()
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
