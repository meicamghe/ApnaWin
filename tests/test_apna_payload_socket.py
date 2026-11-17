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
