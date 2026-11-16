from __future__ import annotations

import socket

import pytest

from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode
from apnawin.engines.apna_ssh_session import ApnaSshConfig
from apnawin.engines.apna_tunnel_session import (
    ApnaTunnelSession,
    ApnaTunnelSessionConfig,
    ApnaTunnelSessionError,
)


def _config(**overrides):
    values = {
        "ssh": ApnaSshConfig("ssh.example.test", 22, "user", password="secret"),
        "payload": PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="ssh.example.test",
            connect_port=22,
            target_host="ssh.example.test",
            target_port=22,
        ),
        "udpgw_host": "udpgw.example.test",
        "udpgw_port": 7300,
    }
    values.update(overrides)
    return ApnaTunnelSessionConfig(**values)


class _FakeSshSession:
    def __init__(self, config, payload, *, events, address=("127.0.0.1", 1081), fail=False):
        self.events = events
        self.address = address
        self.fail = fail

    def connect(self):
        self.events.append("ssh-connect")
        if self.fail:
            raise OSError("ssh refused")
        return self.address

    def close(self):
        self.events.append("ssh-close")


class _FakeGateway:
    def __init__(self, config, *, events, fail=False):
        self.config = config
        self.events = events
        self.fail = fail
        self._address = ("127.0.0.1", 12000)

    def start(self):
        self.events.append("gateway-start")
        if self.fail:
            raise OSError("gateway bind failed")
        return self

    @property
    def address(self):
        return self._address

    def close(self):
        self.events.append("gateway-close")


def test_connect_preflights_udpgw_and_starts_gateway_after_ssh():
    events = []
    probes = []

    def preflight(config):
        events.append("udpgw-preflight")
        probes.append(config)
        return socket.socketpair()[0]

    session = ApnaTunnelSession(
        _config(),
        ssh_session_factory=lambda *args: _FakeSshSession(*args, events=events),
        gateway_factory=lambda config: _FakeGateway(config, events=events),
        preflight_connector=preflight,
    )
    address = session.connect()
    assert address == ("127.0.0.1", 12000)
    assert session.is_connected
    assert session.local_socks_address == address
    assert events == ["ssh-connect", "udpgw-preflight", "gateway-start"]
    assert probes[0].target_host == "udpgw.example.test"
    assert probes[0].target_port == 7300
    session.disconnect()
    assert events[-2:] == ["gateway-close", "ssh-close"]
    assert not session.is_connected


def test_tcp_only_profile_skips_udpgw_preflight():
    events = []
    session = ApnaTunnelSession(
        _config(udpgw_host=None, udpgw_port=None),
        ssh_session_factory=lambda *args: _FakeSshSession(*args, events=events),
        gateway_factory=lambda config: _FakeGateway(config, events=events),
        preflight_connector=lambda config: pytest.fail("unexpected UDPGW preflight"),
    )
    session.connect()
    assert events == ["ssh-connect", "gateway-start"]
    session.disconnect()


def test_preflight_failure_closes_ssh_and_does_not_start_gateway():
    events = []
    session = ApnaTunnelSession(
        _config(),
        ssh_session_factory=lambda *args: _FakeSshSession(*args, events=events),
        gateway_factory=lambda config: _FakeGateway(config, events=events),
        preflight_connector=lambda config: (_ for _ in ()).throw(OSError("UDPGW unreachable")),
    )
    with pytest.raises(ApnaTunnelSessionError, match="startup failed"):
        session.connect()
    assert events == ["ssh-connect", "ssh-close"]
    assert not session.is_connected


def test_gateway_start_failure_closes_ssh_and_gateway():
    events = []
    session = ApnaTunnelSession(
        _config(),
        ssh_session_factory=lambda *args: _FakeSshSession(*args, events=events),
        gateway_factory=lambda config: _FakeGateway(config, events=events, fail=True),
        preflight_connector=lambda config: socket.socketpair()[0],
    )
    with pytest.raises(ApnaTunnelSessionError, match="startup failed"):
        session.connect()
    assert events == ["ssh-connect", "gateway-start", "gateway-close", "ssh-close"]


def test_non_loopback_ssh_proxy_endpoint_is_rejected():
    events = []
    session = ApnaTunnelSession(
        _config(udpgw_host=None, udpgw_port=None),
        ssh_session_factory=lambda *args: _FakeSshSession(
            *args, events=events, address=("0.0.0.0", 1081)
        ),
        gateway_factory=lambda config: _FakeGateway(config, events=events),
    )
    with pytest.raises(ApnaTunnelSessionError, match="not loopback"):
        session.connect()
    assert events == ["ssh-connect", "ssh-close"]


def test_config_requires_udpgw_pair_and_dns_gateway():
    with pytest.raises(ValueError, match="supplied together"):
        _config(udpgw_host="udpgw.example.test", udpgw_port=None)
    with pytest.raises(ValueError, match="requires a UDPGW"):
        _config(udpgw_host=None, udpgw_port=None, transparent_dns=True)


def test_disconnect_is_idempotent():
    session = ApnaTunnelSession(
        _config(udpgw_host=None, udpgw_port=None),
        ssh_session_factory=lambda *args: _FakeSshSession(*args, events=[]),
        gateway_factory=lambda config: _FakeGateway(config, events=[]),
    )
    session.disconnect()
    session.disconnect()


def test_failed_gateway_cleanup_retains_both_handles_for_retry():
    events = []
    class FlakyGateway(_FakeGateway):
        def __init__(self, config, *, events):
            super().__init__(config, events=events)
            self.fail_close = True

        def close(self):
            events.append("gateway-close")
            if self.fail_close:
                self.fail_close = False
                raise OSError("busy")
    ssh_instances = []
    def make_ssh(*args):
        instance = _FakeSshSession(*args, events=events)
        ssh_instances.append(instance)
        return instance
    session = ApnaTunnelSession(
        _config(udpgw_host=None, udpgw_port=None),
        ssh_session_factory=make_ssh,
        gateway_factory=lambda config: FlakyGateway(config, events=events),
    )
    session.connect()
    with pytest.raises(ApnaTunnelSessionError, match="ownership is retained"):
        session.disconnect()
    assert events[-1] == "gateway-close"
    session.disconnect()
    assert events[-2:] == ["gateway-close", "ssh-close"]
