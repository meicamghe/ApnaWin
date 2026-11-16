from __future__ import annotations

import json

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig
from apnawin.engines.apna_xray_config import build_apna_xray_tun_config
from apnawin.engines.apna_tunnel_engine import ApnaTunnelEngine, ApnaTunnelEngineError
from apnawin.engines.apna_ssh_session import ApnaSshConfig
from apnawin.engines.apna_payload_socket import PayloadSocketConfig, PayloadSocketMode


def test_builder_creates_strict_dual_stack_tun_with_local_socks_outbound():
    raw = build_apna_xray_tun_config(("127.0.0.1", 12345))
    config = json.loads(raw)
    assert config["inbounds"][0]["protocol"] == "tun"
    assert config["inbounds"][0]["settings"]["autoSystemRoutingTable"] == [
        "0.0.0.0/0", "::/0"
    ]
    assert config["inbounds"][0]["settings"]["autoSystemWfpBlockLeak"] == [
        "allexceptlan", "dns"
    ]
    assert config["outbounds"] == [{
        "tag": "apna-ssh-socks",
        "protocol": "socks",
        "settings": {"servers": [{"address": "127.0.0.1", "port": 12345}]},
    }]


@pytest.mark.parametrize(
    "address",
    [("0.0.0.0", 1080), ("192.0.2.1", 1080), ("127.0.0.1", 0), ("127.0.0.1", True)],
)
def test_builder_rejects_non_loopback_or_invalid_socks_endpoint(address):
    with pytest.raises(ValueError):
        build_apna_xray_tun_config(address)


def test_builder_rejects_invalid_dns_and_adapter_name():
    with pytest.raises(ValueError, match="DNS servers"):
        build_apna_xray_tun_config(("127.0.0.1", 1080), dns_servers=("dns.example.test",))
    with pytest.raises(ValueError, match="adapter_name"):
        build_apna_xray_tun_config(("127.0.0.1", 1080), adapter_name="bad/name")


class _FakeSession:
    def __init__(self, config, *, events, fail_disconnect=False):
        self.config = config
        self.events = events
        self.fail_disconnect = fail_disconnect
        self.healthy = True

    @property
    def is_healthy(self):
        return self.healthy

    def connect(self):
        self.events.append("session-connect")
        return ("127.0.0.1", 12345)

    def disconnect(self):
        self.events.append("session-disconnect")
        if self.fail_disconnect:
            raise OSError("socket close failed")


class _FakeConfigStore:
    def __init__(self, events):
        self.events = events
        self.saved = {}

    def save(self, name, raw):
        self.events.append("config-save")
        self.saved[name] = raw

    def remove(self, name):
        self.events.append("config-remove")
        self.saved.pop(name, None)


class _FakeSupervisor:
    def __init__(self, events, *, fail_start=False, fail_stop=False, exit_after_start=False):
        self.events = events
        self.fail_start = fail_start
        self.fail_stop = fail_stop
        self.exit_after_start = exit_after_start
        self.running = False
        self.started_profile = None

    def start(self, profile):
        self.events.append("xray-start")
        self.started_profile = profile
        if self.fail_start:
            raise OSError("Xray failed to start")
        self.running = True

    def poll(self):
        if self.exit_after_start:
            return 1
        return None if self.running else 1

    def stop(self):
        self.events.append("xray-stop")
        if self.fail_stop:
            raise OSError("routes not restored")
        self.running = False


def _profile():
    return ConnectionProfile("APNA test", Transport.APNA_SSH, "ssh.example.test", 443)


def _session_config():
    return ApnaTunnelSessionConfig(
        ssh=ApnaSshConfig("ssh.example.test", 443, "user", password="secret", host_key_sha256="SHA256:" + "A" * 43),
        payload=PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="ssh.example.test",
            connect_port=443,
            target_host="ssh.example.test",
            target_port=443,
        ),
        udpgw_host="udpgw.example.test",
        udpgw_port=7300,
        transparent_dns=True,
    )


def _engine(events, *, fail_xray_start=False, fail_xray_stop=False, fail_session_disconnect=False, exit_after_start=False, fail_tcp_egress=False):
    store = _FakeConfigStore(events)
    supervisor = _FakeSupervisor(
        events, fail_start=fail_xray_start, fail_stop=fail_xray_stop,
        exit_after_start=exit_after_start,
    )
    sessions = []
    def make_session(config):
        session = _FakeSession(
            config, events=events, fail_disconnect=fail_session_disconnect
        )
        sessions.append(session)
        return session
    def probe_tcp_egress():
        events.append("tcp-tls-egress-probe")
        if fail_tcp_egress:
            raise OSError("IPv6 TLS egress timed out")

    engine = ApnaTunnelEngine(
        lambda profile: _session_config(),
        store,  # type: ignore[arg-type]
        supervisor,  # type: ignore[arg-type]
        session_factory=make_session,
        udp_dns_probe=lambda servers: events.append("udp-dns-probe"),
        tcp_egress_probe=probe_tcp_egress,
        platform_name="nt",
    )
    return engine, store, supervisor, sessions


def test_engine_starts_ssh_then_encrypted_xray_tun_and_reports_connected():
    events = []
    engine, store, supervisor, _sessions = _engine(events)
    engine.connect(_profile())
    assert engine.state is ConnectionState.CONNECTED
    assert events == ["session-connect", "config-save", "xray-start", "udp-dns-probe", "tcp-tls-egress-probe"]
    assert store.saved
    assert supervisor.started_profile.transport is Transport.XRAY
    assert supervisor.started_profile.endpoint_port == 12345
    engine.disconnect()
    assert events[-3:] == ["xray-stop", "session-disconnect", "config-remove"]
    assert engine.state is ConnectionState.DISCONNECTED
    assert not store.saved


def test_engine_wires_ipv4_and_ipv6_dns_resolvers_into_tun_and_probe():
    events = []
    captured = {}

    def build_config(address, *, dns_servers):
        captured["config_dns"] = dns_servers
        return b"{}"

    def probe_dns(dns_servers):
        captured["probe_dns"] = dns_servers
        events.append("udp-dns-probe")

    store = _FakeConfigStore(events)
    supervisor = _FakeSupervisor(events)
    engine = ApnaTunnelEngine(
        lambda profile: _session_config(),
        store,  # type: ignore[arg-type]
        supervisor,  # type: ignore[arg-type]
        session_factory=lambda config: _FakeSession(config, events=events),
        config_builder=build_config,
        udp_dns_probe=probe_dns,
        tcp_egress_probe=lambda: events.append("tcp-tls-egress-probe"),
        platform_name="nt",
    )

    engine.connect(_profile())

    expected = ("1.1.1.1", "2606:4700:4700::1111")
    assert captured == {"config_dns": expected, "probe_dns": expected}
    assert events[-1] == "tcp-tls-egress-probe"
    assert engine.state is ConnectionState.CONNECTED
    engine.disconnect()



def test_engine_rolls_back_when_dual_stack_tls_egress_probe_fails():
    events = []
    engine, store, _supervisor, _sessions = _engine(events, fail_tcp_egress=True)
    with pytest.raises(ApnaTunnelEngineError, match="startup failed"):
        engine.connect(_profile())
    assert events == [
        "session-connect",
        "config-save",
        "xray-start",
        "udp-dns-probe",
        "tcp-tls-egress-probe",
        "xray-stop",
        "session-disconnect",
        "config-remove",
    ]
    assert engine.state is ConnectionState.DISCONNECTED
    assert not store.saved

def test_engine_rejects_wrong_transport():
    engine, _store, _supervisor, _sessions = _engine([])
    wrong = ConnectionProfile("wrong", Transport.XRAY, "ssh.example.test", 443)
    with pytest.raises(ValueError, match="APNA_SSH"):
        engine.validate_profile(wrong)


def test_engine_rejects_secure_loader_endpoint_mismatch():
    events = []
    engine, _store, _supervisor, _sessions = _engine(events)
    bad_config = ApnaTunnelSessionConfig(
        ssh=ApnaSshConfig("other.example.test", 443, "user", password="secret"),
        payload=PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="other.example.test",
            connect_port=443,
            target_host="other.example.test",
            target_port=443,
        ),
        udpgw_host="udpgw.example.test",
        udpgw_port=7300,
        transparent_dns=True,
    )
    engine = ApnaTunnelEngine(
        lambda profile: bad_config,
        _FakeConfigStore(events),  # type: ignore[arg-type]
        _FakeSupervisor(events),  # type: ignore[arg-type]
        session_factory=lambda config: pytest.fail("session must not start"),
        platform_name="nt",
        udp_dns_probe=lambda servers: None,
    )
    with pytest.raises(ValueError, match="does not match"):
        engine.connect(_profile())
    assert engine.state is ConnectionState.DISCONNECTED


def test_engine_start_failure_cleans_up_session_and_config():
    events = []
    engine, store, _supervisor, _sessions = _engine(events, fail_xray_start=True)
    with pytest.raises(ApnaTunnelEngineError, match="startup failed"):
        engine.connect(_profile())
    assert events == [
        "session-connect", "config-save", "xray-start",
        "session-disconnect", "config-remove",
    ]
    assert engine.state is ConnectionState.DISCONNECTED
    assert not store.saved


def test_engine_retains_ssh_when_xray_cleanup_fails():
    events = []
    engine, _store, _supervisor, sessions = _engine(
        events, fail_xray_stop=True, exit_after_start=True
    )
    with pytest.raises(ApnaTunnelEngineError, match="cleanup also failed"):
        engine.connect(_profile())
    assert engine.state is ConnectionState.ERROR
    assert sessions[0] is not None
    assert "session-disconnect" not in events
    with pytest.raises(ApnaTunnelEngineError, match="Xray TUN cleanup failed"):
        engine.disconnect()


def test_engine_retains_session_when_session_cleanup_fails():
    events = []
    engine, _store, _supervisor, sessions = _engine(
        events, fail_session_disconnect=True
    )
    engine.connect(_profile())
    with pytest.raises(ApnaTunnelEngineError, match="ownership is retained"):
        engine.disconnect()
    assert engine.state is ConnectionState.ERROR
    assert sessions[0] is not None
    with pytest.raises(ApnaTunnelEngineError, match="ownership is retained"):
        engine.disconnect()


def test_engine_refresh_marks_unexpected_helper_exit_as_error():
    events = []
    engine, _store, supervisor, _sessions = _engine(events)
    engine.connect(_profile())
    supervisor.running = False
    assert engine.refresh() is ConnectionState.ERROR


def test_engine_rejects_missing_udpgw_before_starting_any_network_resources():
    events = []
    store = _FakeConfigStore(events)
    supervisor = _FakeSupervisor(events)
    base = _session_config()
    no_udp = ApnaTunnelSessionConfig(
        ssh=base.ssh,
        payload=base.payload,
        udpgw_host=None,
        udpgw_port=None,
    )
    engine = ApnaTunnelEngine(
        lambda profile: no_udp,
        store,  # type: ignore[arg-type]
        supervisor,  # type: ignore[arg-type]
        platform_name="nt",
    )
    with pytest.raises(ValueError, match="requires a configured UDPGW"):
        engine.validate_profile(_profile())
    assert events == []


def test_engine_rolls_back_if_post_tun_udp_dns_probe_fails():
    events = []
    store = _FakeConfigStore(events)
    supervisor = _FakeSupervisor(events)

    def fail_udp_probe(servers):
        events.append("udp-dns-probe")
        raise OSError("DNS over UDP timed out")

    engine = ApnaTunnelEngine(
        lambda profile: _session_config(),
        store,  # type: ignore[arg-type]
        supervisor,  # type: ignore[arg-type]
        session_factory=lambda config: _FakeSession(config, events=events),
        udp_dns_probe=fail_udp_probe,
        platform_name="nt",
    )
    with pytest.raises(ApnaTunnelEngineError, match="startup failed"):
        engine.connect(_profile())
    assert events == [
        "session-connect",
        "config-save",
        "xray-start",
        "udp-dns-probe",
        "xray-stop",
        "session-disconnect",
        "config-remove",
    ]
    assert engine.state is ConnectionState.DISCONNECTED
    assert not store.saved


def test_engine_refresh_marks_lost_apna_ssh_session_as_error():
    events = []
    engine, _store, _supervisor, sessions = _engine(events)
    engine.connect(_profile())
    sessions[0].healthy = False
    assert engine.refresh() is ConnectionState.ERROR
    assert "APNA SSH" in engine.last_error
    engine.disconnect()
    assert engine.state is ConnectionState.DISCONNECTED
