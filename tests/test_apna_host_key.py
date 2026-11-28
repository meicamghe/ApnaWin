from __future__ import annotations

import base64
import hashlib

import paramiko
import pytest

from apnawin.engines.apna_host_key import (
    ApnaHostKeyProbeError,
    ApnaPayloadTransportProbeError,
    scan_apna_ssh_host_key,
)
from apnawin.engines.apna_payload_socket import (
    PayloadSocketConfig,
    PayloadSocketMode,
    PayloadTransportError,
)
from apnawin.engines.apna_ssh_session import ApnaSshConfig
from apnawin.engines.apna_tunnel_session import ApnaTunnelSessionConfig


class _FakeKey:
    def asbytes(self):
        return b"synthetic-ssh-host-key"


class _FakeTransport:
    def __init__(self, sock):
        self.sock = sock
        self.started = None
        self.closed = False

    def start_client(self, *, timeout):
        self.started = timeout

    def get_remote_server_key(self):
        return _FakeKey()

    def close(self):
        self.closed = True


class _FakeSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _FakeConnector:
    def __init__(self, sock):
        self.sock = sock
        self.configs = []

    def connect(self, config):
        self.configs.append(config)
        return self.sock


def _config():
    return ApnaTunnelSessionConfig(
        ssh=ApnaSshConfig(
            "ssh.example.test", 1194, "user", password="secret",
            host_key_sha256="SHA256:" + "A" * 43,
        ),
        payload=PayloadSocketConfig(
            mode=PayloadSocketMode.TLS_DIRECT,
            connect_host="ssh.example.test",
            connect_port=443,
            target_host="ssh.example.test",
            target_port=1194,
            sni="amtun.example.test",
        ),
        udpgw_host="ssh.example.test",
        udpgw_port=53,
    )


def test_scans_and_formats_host_key_fingerprint_without_authentication():
    sock = _FakeSocket()
    connector = _FakeConnector(sock)
    transports = []
    def factory(active_sock):
        transport = _FakeTransport(active_sock)
        transports.append(transport)
        return transport
    fingerprint = scan_apna_ssh_host_key(
        _config(), connector=connector, transport_factory=factory
    )
    expected = "SHA256:" + base64.b64encode(
        hashlib.sha256(b"synthetic-ssh-host-key").digest()
    ).decode("ascii").rstrip("=")
    assert fingerprint == expected
    assert connector.configs == [_config().payload]
    assert transports[0].started == _config().ssh.connect_timeout
    assert transports[0].closed is True
    assert sock.closed is True


def test_probe_reports_cipher_mismatch_without_enabling_legacy_ciphers():
    sock = _FakeSocket()
    connector = _FakeConnector(sock)

    class IncompatibleCipherTransport(_FakeTransport):
        def start_client(self, *, timeout):
            raise paramiko.SSHException(
                "Incompatible ssh server (no acceptable ciphers); server cipher offers: "
                "client->server=[aes128-cbc]; server->client=[3des-cbc]; "
                "client enabled=[aes128-ctr]"
            )

    with pytest.raises(ApnaHostKeyProbeError, match="no mutually supported encryption cipher") as error:
        scan_apna_ssh_host_key(
            _config(),
            connector=connector,
            transport_factory=IncompatibleCipherTransport,
        )
    assert "aes128-cbc" in str(error.value)
    assert "3des-cbc" in str(error.value)
    assert "client enabled=[aes128-ctr]" in str(error.value)
    assert sock.closed is True


def test_probe_closes_socket_when_transport_construction_fails():
    sock = _FakeSocket()
    connector = _FakeConnector(sock)
    def fail_factory(active_sock):
        raise OSError("transport unavailable")
    with pytest.raises(ApnaHostKeyProbeError, match="key exchange failed"):
        scan_apna_ssh_host_key(
            _config(), connector=connector, transport_factory=fail_factory
        )
    assert sock.closed is True



@pytest.mark.parametrize(
    ("transport_detail", "transport_stage"),
    [
        ("DNS resolution failed before TCP connection; endpoint=proxy.example.test:80; gaierror: [Errno 11001]", "dns"),
        ("TLS certificate verification failed: tls_direct endpoint=ssh.example.test:443; SNI amtun.example.test", "tls"),
        (
            "Proxy returned HTTP 403. CloudFront returned an edge-level HTTP denial. "
            "Request details: mode=http_proxy; request=GET / HTTP/1.1; "
            "Host=front.example.test; endpoint=proxy.example.test:80; "
            "target=ssh.example.test:1194. Response headers: server=CloudFront, x-cache=Error from cloudfront.",
            "http_proxy",
        ),
    ],
)
def test_probe_keeps_payload_transport_failures_out_of_ssh_key_exchange_stage(
    transport_detail, transport_stage,
):
    class FailingConnector:
        def connect(self, config):
            raise PayloadTransportError(transport_detail, stage=transport_stage)

    with pytest.raises(ApnaHostKeyProbeError) as error:
        scan_apna_ssh_host_key(_config(), connector=FailingConnector())

    assert isinstance(error.value, ApnaPayloadTransportProbeError)
    assert error.value.stage == "payload_transport"
    assert error.value.transport_stage == transport_stage
    assert str(error.value).startswith("Payload transport failed before SSH key exchange:")
    assert "SSH host-key exchange failed" not in str(error.value)
    assert transport_detail in str(error.value)
