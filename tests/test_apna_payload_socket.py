from __future__ import annotations

import socket
import ssl
import threading

import pytest

from apnawin.engines.apna_payload_socket import (
    ApnaPayloadSocketConnector,
    PayloadSocketConfig,
    PayloadSocketMode,
    PayloadTransportError,
)


def _socket_pair_factory(server_callback):
    client, server = socket.socketpair()
    worker = threading.Thread(target=server_callback, args=(server,), daemon=True)
    worker.start()
    return client, worker


def test_http_proxy_payload_is_sent_and_success_response_is_consumed() -> None:
    received = []

    def server(server_socket):
        received.append(server_socket.recv(4096))
        server_socket.sendall(b"HTTP/1.1 200 Connection established\r\nX-Test: yes\r\n\r\n")
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="proxy.example.test",
        connect_port=8080,
        target_host="ssh.example.test",
        target_port=443,
        payload="CONNECT [host_port] [protocol][crlf][crlf]",
    )
    connected = connector.connect(config)
    assert connected is client
    connected.close()
    worker.join(timeout=1)
    assert received == [b"CONNECT ssh.example.test:443 HTTP/1.0\r\n\r\n"]


def test_http_proxy_rejection_fails_closed_and_closes_socket(monkeypatch) -> None:
    def server(server_socket):
        server_socket.recv(4096)
        server_socket.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="proxy.example.test",
        connect_port=8080,
        target_host="ssh.example.test",
        target_port=443,
        payload="CONNECT [host_port] [protocol][crlf][crlf]",
    )
    with pytest.raises(PayloadTransportError, match="HTTP 407"):
        connector.connect(config)
    worker.join(timeout=1)
    assert client.fileno() == -1


def test_dropbear_mode_returns_after_payload_without_waiting_for_http(monkeypatch) -> None:
    received = []

    def server(server_socket):
        received.append(server_socket.recv(4096))
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="proxy.example.test",
        connect_port=8080,
        target_host="ssh.example.test",
        target_port=443,
        payload="CUSTOM [host_port][crlf]",
        dropbear_no_response=True,
    )
    connected = connector.connect(config)
    assert connected is client
    connected.close()
    worker.join(timeout=1)
    assert received == [b"CUSTOM ssh.example.test:443\r\n"]


def test_direct_mode_does_not_inject_payload(monkeypatch) -> None:
    client, server = socket.socketpair()
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.DIRECT,
        connect_host="ssh.example.test",
        connect_port=22,
        target_host="ssh.example.test",
        target_port=22,
    )
    connected = connector.connect(config)
    server.settimeout(0.05)
    with pytest.raises(TimeoutError):
        server.recv(1)
    connected.close()
    server.close()


def test_config_rejects_invalid_endpoint_and_port() -> None:
    with pytest.raises(ValueError):
        PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="ssh.example.test",
            connect_port=70000,
            target_host="ssh.example.test",
            target_port=22,
        )


def test_http_proxy_can_explicitly_accept_websocket_upgrade_101() -> None:
    received = []

    def server(server_socket):
        received.append(server_socket.recv(4096))
        server_socket.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="proxy.example.test",
        connect_port=8080,
        target_host="ssh.example.test",
        target_port=443,
        payload="GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]",
        expected_http_statuses=(101,),
    )
    connected = connector.connect(config)
    assert connected is client
    connected.close()
    worker.join(timeout=1)
    assert received == [b"GET / HTTP/1.1\r\nHost: ssh.example.test\r\n\r\n"]


def test_http_101_is_not_accepted_for_non_websocket_payload_and_explains_mismatch() -> None:
    def server(server_socket):
        server_socket.recv(4096)
        server_socket.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="proxy.example.test",
        connect_port=8080,
        target_host="ssh.example.test",
        target_port=443,
        payload="CONNECT [host_port] [protocol][crlf][crlf]",
    )
    with pytest.raises(PayloadTransportError, match="not configured to accept a WebSocket Upgrade"):
        connector.connect(config)
    worker.join(timeout=1)
    assert client.fileno() == -1


def test_config_rejects_invalid_http_status_policy() -> None:
    with pytest.raises(ValueError, match="invalid HTTP status"):
        PayloadSocketConfig(
            mode=PayloadSocketMode.HTTP_PROXY,
            connect_host="proxy.example.test",
            connect_port=8080,
            target_host="ssh.example.test",
            target_port=443,
            payload="GET / HTTP/1.1[crlf][crlf]",
            expected_http_statuses=(200, 700),
        )


def test_tls_direct_wraps_socket_and_sends_no_http_payload() -> None:
    client, server = socket.socketpair()
    seen = {}
    class TlsContext:
        def wrap_socket(self, sock, *, server_hostname):
            seen["sni"] = server_hostname
            return sock
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client,
        tls_context=TlsContext(),
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.TLS_DIRECT,
        connect_host="ssh.example.test",
        connect_port=443,
        target_host="ssh.example.test",
        target_port=1194,
        sni="amtun.example.test",
    )
    connected = connector.connect(config)
    assert connected is client
    assert seen["sni"] == "amtun.example.test"
    server.settimeout(0.05)
    with pytest.raises(TimeoutError):
        server.recv(1)
    connected.close()
    server.close()


def test_tls_http_proxy_uses_proxy_sni_and_expands_cf_and_brand() -> None:
    received = []
    def server(server_socket):
        received.append(server_socket.recv(4096))
        server_socket.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        server_socket.close()
    client, worker = _socket_pair_factory(server)
    seen = {}
    class TlsContext:
        def wrap_socket(self, sock, *, server_hostname):
            seen["sni"] = server_hostname
            return sock
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client,
        tls_context=TlsContext(),
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.TLS_HTTP_PROXY,
        connect_host="front.example.test",
        connect_port=443,
        target_host="ssh.example.test",
        target_port=1194,
        payload="GET / HTTP/1.1[crlf]Host: [cf][crlf]X-Brand: [brand][crlf][crlf]",
        sni="front.example.test",
        brand="ApnaWin",
        expected_http_statuses=(101,),
    )
    connected = connector.connect(config)
    assert connected is client
    assert seen["sni"] == "front.example.test"
    connected.close()
    worker.join(timeout=1)
    assert received == [
        b"GET / HTTP/1.1\r\nHost: front.example.test\r\nX-Brand: ApnaWin\r\n\r\n"
    ]


@pytest.mark.parametrize("field", ["connect_timeout", "read_timeout"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 0, -1, True])
def test_payload_socket_config_rejects_non_finite_or_non_positive_timeouts(field, value):
    with pytest.raises(ValueError, match="finite and positive"):
        PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="ssh.example.test",
            connect_port=22,
            target_host="ssh.example.test",
            target_port=22,
            **{field: value},
        )



def test_http_redirect_is_reported_with_location_and_not_accepted():
    def server(server_socket):
        server_socket.recv(4096)
        server_socket.sendall(
            b"HTTP/1.1 301 Moved Permanently\r\n"
            b"Location: https://front.example.test/new-path\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="proxy.example.test",
        connect_port=8080,
        target_host="ssh.example.test",
        target_port=443,
        payload="GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]",
    )
    with pytest.raises(PayloadTransportError, match="HTTP 301 redirect") as error:
        connector.connect(config)
    assert "https://front.example.test/new-path" in str(error.value)
    assert "not followed" in str(error.value)
    worker.join(timeout=1)
    assert client.fileno() == -1



def test_tls_direct_reports_underlying_tls_error_and_endpoint():
    client, server = socket.socketpair()

    class FailingTlsContext:
        def wrap_socket(self, sock, *, server_hostname):
            raise ssl.SSLError("CERTIFICATE_VERIFY_FAILED: hostname mismatch")

    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client,
        tls_context=FailingTlsContext(),
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.TLS_DIRECT,
        connect_host="front.example.test",
        connect_port=443,
        target_host="ssh.example.test",
        target_port=1194,
        sni="amtun.example.test",
    )
    with pytest.raises(
        PayloadTransportError,
        match=r"tls_direct.*front.example.test:443.*SNI amtun.example.test.*SSLError.*hostname mismatch",
    ):
        connector.connect(config)
    assert client.fileno() == -1
    server.close()



@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (socket.gaierror(-2, "name or service not known"), "DNS resolution failed"),
        (ConnectionRefusedError(111, "connection refused"), "TCP connection failed"),
        (ssl.SSLCertVerificationError("hostname mismatch"), "TLS certificate hostname/SNI mismatch"),
        (ssl.SSLError("handshake failure"), "TLS handshake failed"),
    ],
)
def test_transport_errors_are_classified_with_endpoint_and_sni(error, expected):
    class FailingSocket:
        def settimeout(self, _timeout):
            return None
        def close(self):
            return None

    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda *_args, **_kwargs: FailingSocket()
    )
    # Fail after TCP setup for TLS cases; fail at socket creation for DNS/TCP.
    if isinstance(error, (ssl.SSLError, ssl.SSLCertVerificationError)):
        class FailingTlsContext:
            def wrap_socket(self, _sock, *, server_hostname):
                raise error
        connector = ApnaPayloadSocketConnector(
            socket_factory=lambda *_args, **_kwargs: FailingSocket(),
            tls_context=FailingTlsContext(),
        )
        config = PayloadSocketConfig(
            mode=PayloadSocketMode.TLS_DIRECT,
            connect_host="front.example.test",
            connect_port=443,
            target_host="ssh.example.test",
            target_port=1194,
            sni="sni.example.test",
        )
    else:
        connector = ApnaPayloadSocketConnector(
            socket_factory=lambda *_args, **_kwargs: (_ for _ in ()).throw(error)
        )
        config = PayloadSocketConfig(
            mode=PayloadSocketMode.DIRECT,
            connect_host="front.example.test",
            connect_port=443,
            target_host="ssh.example.test",
            target_port=1194,
        )
    with pytest.raises(PayloadTransportError) as caught:
        connector.connect(config)
    assert expected in str(caught.value)
    assert "front.example.test:443" in str(caught.value)
    if config.mode is PayloadSocketMode.TLS_DIRECT:
        assert "SNI sni.example.test" in str(caught.value)


def test_cloudfront_403_identifies_edge_denial_without_accepting_it():
    def server(server_socket):
        server_socket.recv(4096)
        server_socket.sendall(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/html\r\n"
            b"Server: CloudFront\r\n"
            b"Via: 1.1 edge-id.cloudfront.net (CloudFront)\r\n"
            b"X-Cache: Error from cloudfront\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="d7xhi9ly8dk8w.cloudfront.net",
        connect_port=1194,
        target_host="ssh.example.test",
        target_port=1194,
        payload="CONNECT [host_port] [protocol][crlf][crlf]",
    )
    with pytest.raises(PayloadTransportError) as caught:
        connector.connect(config)
    message = str(caught.value)
    assert "CloudFront returned an edge-level HTTP denial" in message
    assert "no SSH stream was established" in message
    assert "server=CloudFront" in message
    assert "x-cache=Error from cloudfront" in message
    worker.join(timeout=1)
    assert client.fileno() == -1


def test_cloudflare_403_identifies_edge_denial_and_cf_ray():
    def server(server_socket):
        server_socket.recv(4096)
        server_socket.sendall(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain; charset=UTF-8\r\n"
            b"Server: cloudflare\r\n"
            b"CF-Ray: a5c4acb96f2a4d3a-FRA\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="xm5.researchmaster.guru",
        connect_port=1194,
        target_host="ssh.example.test",
        target_port=1194,
        payload="CONNECT [host_port] [protocol][crlf][crlf]",
    )
    with pytest.raises(PayloadTransportError) as caught:
        connector.connect(config)
    message = str(caught.value)
    assert "Cloudflare returned an HTTP 403" in message
    assert "no SSH stream was established" in message
    assert "cf-ray=a5c4acb96f2a4d3a-FRA" in message
    worker.join(timeout=1)
    assert client.fileno() == -1


@pytest.mark.parametrize(
    ("status", "diagnosis"),
    [
        (400, "malformed"),
        (403, "denied"),
        (409, "conflict"),
        (429, "rate-limited"),
        (502, "upstream service failed"),
    ],
)
def test_http_failures_have_actionable_status_specific_diagnostics(status, diagnosis):
    def server(server_socket):
        server_socket.recv(4096)
        server_socket.sendall(
            f"HTTP/1.1 {status} Test Failure\r\n"
            "Server: test-proxy\r\n"
            "Via: edge-gateway\r\n"
            "Set-Cookie: secret=must-not-leak\r\n"
            "Content-Length: 0\r\n\r\n".encode("ascii")
        )
        server_socket.close()

    client, worker = _socket_pair_factory(server)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda address, timeout: client
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.HTTP_PROXY,
        connect_host="proxy.example.test",
        connect_port=8080,
        target_host="ssh.example.test",
        target_port=443,
        payload="CONNECT [host_port] [protocol][crlf][crlf]",
    )
    with pytest.raises(PayloadTransportError) as caught:
        connector.connect(config)
    message = str(caught.value)
    assert f"HTTP {status}" in message
    assert diagnosis in message
    assert "server=test-proxy" in message
    assert "via=edge-gateway" in message
    assert "must-not-leak" not in message
    worker.join(timeout=1)
    assert client.fileno() == -1


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ssl.SSLCertVerificationError("self-signed certificate"), "self-signed or its issuer is not trusted"),
        (ssl.SSLCertVerificationError("certificate has expired"), "expired or not yet valid"),
        (ssl.SSLCertVerificationError("unable to get local issuer certificate"), "chain is incomplete"),
        (ssl.SSLCertVerificationError("hostname mismatch"), "hostname/SNI mismatch"),
    ],
)
def test_tls_certificate_failures_have_specific_safe_diagnostics(error, expected):
    class FailingSocket:
        def settimeout(self, _timeout):
            return None
        def close(self):
            return None

    class FailingTlsContext:
        def wrap_socket(self, _sock, *, server_hostname):
            raise error

    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda *_args, **_kwargs: FailingSocket(),
        tls_context=FailingTlsContext(),
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.TLS_DIRECT,
        connect_host="xm76.tumsongcloud.xyz",
        connect_port=443,
        target_host="xm76.tumsongcloud.xyz",
        target_port=443,
        sni="104.17.208.5",
    )
    with pytest.raises(PayloadTransportError) as caught:
        connector.connect(config)
    message = str(caught.value)
    assert expected in message
    assert "endpoint=xm76.tumsongcloud.xyz:443" in message
    assert "SNI 104.17.208.5" in message
    assert "SNI is an IP literal while the endpoint is a DNS hostname" in message
    assert "disable" not in message.lower()



def test_tls_direct_can_add_only_an_explicit_provider_ca_without_disabling_system_trust(monkeypatch):
    client, peer = socket.socketpair()
    observed = {}

    class TrustedContext:
        def load_verify_locations(self, *, cafile):
            observed["cafile"] = cafile

        def wrap_socket(self, sock, *, server_hostname):
            observed["sni"] = server_hostname
            return sock

    def create_default_context():
        observed["default_context"] = True
        return TrustedContext()

    monkeypatch.setattr(ssl, "create_default_context", create_default_context)
    connector = ApnaPayloadSocketConnector(
        socket_factory=lambda *_args, **_kwargs: client,
        tls_context=TrustedContext(),
    )
    config = PayloadSocketConfig(
        mode=PayloadSocketMode.TLS_DIRECT,
        connect_host="front.example.test",
        connect_port=443,
        target_host="ssh.example.test",
        target_port=1194,
        sni="front.example.test",
        ca_bundle_file="trusted-provider-ca.pem",
    )
    connected = connector.connect(config)
    assert connected is client
    assert observed == {
        "default_context": True,
        "cafile": "trusted-provider-ca.pem",
        "sni": "front.example.test",
    }
    connected.close()
    peer.close()


def test_payload_socket_config_rejects_invalid_provider_ca_path():
    with pytest.raises(ValueError, match="trusted CA bundle path"):
        PayloadSocketConfig(
            mode=PayloadSocketMode.TLS_DIRECT,
            connect_host="front.example.test",
            connect_port=443,
            target_host="ssh.example.test",
            target_port=1194,
            ca_bundle_file="bad\npath",
        )
