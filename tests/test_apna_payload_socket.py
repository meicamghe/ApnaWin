from __future__ import annotations

import socket
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
        payload="must not be sent",
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
            expected_http_statuses=(200, 700),
        )
