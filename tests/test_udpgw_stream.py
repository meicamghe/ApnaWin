from __future__ import annotations

import socket
import struct
import threading

import pytest

from apnawin.engines.udpgw_protocol import decode_udpgw_payload, encode_datagram, encode_keepalive
from apnawin.engines.udpgw_stream import (
    Socks5ConnectConfig,
    Socks5ProtocolError,
    UdpGwStreamClient,
    UdpGwTransportError,
    open_socks5_connect,
)


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data.extend(chunk)
    return bytes(data)


def _socket_pair_server(callback):
    client, server = socket.socketpair()
    worker = threading.Thread(target=callback, args=(server,), daemon=True)
    worker.start()
    return client, worker


def _read_socks5_request(sock: socket.socket) -> tuple[int, bytes, int]:
    version, command, reserved, address_type = _read_exact(sock, 4)
    assert version == 5 and command == 1 and reserved == 0
    if address_type == 1:
        address = _read_exact(sock, 4)
    elif address_type == 4:
        address = _read_exact(sock, 16)
    else:
        length = _read_exact(sock, 1)[0]
        address = _read_exact(sock, length)
    port = struct.unpack("!H", _read_exact(sock, 2))[0]
    return address_type, address, port


@pytest.mark.parametrize(
    "host",
    [
        "",
        "bad..example",
        "-bad.example",
        "bad-.example",
        "bad_name.example",
        "a" * 64 + ".example",
        "bad\u00e9.example",
        "fe80::1%eth0",
    ],
)
@pytest.mark.parametrize("field", ["proxy_host", "target_host"])
def test_socks5_connect_config_rejects_malformed_hosts(host: str, field: str) -> None:
    values = {
        "proxy_host": "127.0.0.1",
        "proxy_port": 1080,
        "target_host": "udpgw.example.test",
        "target_port": 7300,
    }
    values[field] = host
    with pytest.raises(ValueError, match=field):
        Socks5ConnectConfig(**values)


def test_socks5_connect_negotiates_domain_target() -> None:
    seen = []

    def server(server_socket):
        seen.append(_read_exact(server_socket, 3))
        server_socket.sendall(b"\x05\x00")
        seen.append(_read_socks5_request(server_socket))
        server_socket.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        server_socket.close()

    client, worker = _socket_pair_server(server)
    config = Socks5ConnectConfig(
        proxy_host="127.0.0.1",
        proxy_port=1080,
        target_host="udpgw.example.test",
        target_port=7300,
    )
    connected = open_socks5_connect(
        config,
        socket_factory=lambda address, timeout: client,
    )
    assert connected is client
    connected.close()
    worker.join(timeout=1)
    assert seen == [
        b"\x05\x01\x00",
        (3, b"udpgw.example.test", 7300),
    ]


def test_socks5_connect_rejects_unsupported_authentication() -> None:
    def server(server_socket):
        _read_exact(server_socket, 3)
        server_socket.sendall(b"\x05\x02")
        server_socket.close()

    client, worker = _socket_pair_server(server)
    config = Socks5ConnectConfig("127.0.0.1", 1080, "udpgw.example.test", 7300)
    with pytest.raises(Socks5ProtocolError, match="authentication method"):
        open_socks5_connect(config, socket_factory=lambda address, timeout: client)
    worker.join(timeout=1)
    assert client.fileno() == -1


def test_socks5_connect_rejects_remote_failure_reply() -> None:
    def server(server_socket):
        _read_exact(server_socket, 3)
        server_socket.sendall(b"\x05\x00")
        _read_socks5_request(server_socket)
        server_socket.sendall(b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00")
        server_socket.close()

    client, worker = _socket_pair_server(server)
    config = Socks5ConnectConfig("127.0.0.1", 1080, "192.0.2.1", 7300)
    with pytest.raises(Socks5ProtocolError, match="reply code 5"):
        open_socks5_connect(config, socket_factory=lambda address, timeout: client)
    worker.join(timeout=1)


def test_udpgw_stream_uses_ssh_socks_and_roundtrips_a_datagram() -> None:
    received = []

    def server(server_socket):
        assert _read_exact(server_socket, 3) == b"\x05\x01\x00"
        server_socket.sendall(b"\x05\x00")
        address_type, address, port = _read_socks5_request(server_socket)
        received.append((address_type, address, port))
        server_socket.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        frame_length = struct.unpack("<H", _read_exact(server_socket, 2))[0]
        request = decode_udpgw_payload(_read_exact(server_socket, frame_length))
        received.append(request)
        response = encode_datagram(
            connection_id=request.connection_id,
            address="203.0.113.10",
            port=request.port,
            data=b"udp-reply",
        )
        server_socket.sendall(response)
        server_socket.close()

    client, worker = _socket_pair_server(server)
    stream = UdpGwStreamClient(
        Socks5ConnectConfig("127.0.0.1", 1080, "udpgw.example.test", 7300),
        socket_factory=lambda address, timeout: client,
    ).connect()
    stream.send_datagram(
        connection_id=41,
        address="198.51.100.8",
        port=53,
        data=b"dns-query",
        is_dns=True,
        rebind=True,
    )
    response = stream.receive_packet(timeout=2)
    assert response.connection_id == 41
    assert response.address == __import__("ipaddress").ip_address("203.0.113.10")
    assert response.port == 53
    assert response.data == b"udp-reply"
    assert received[0] == (3, b"udpgw.example.test", 7300)
    assert received[1].is_dns and received[1].is_rebind
    stream.close()
    worker.join(timeout=1)


def test_udpgw_stream_requires_connection_before_sending() -> None:
    stream = UdpGwStreamClient(
        Socks5ConnectConfig("127.0.0.1", 1080, "udpgw.example.test", 7300)
    )
    with pytest.raises(UdpGwTransportError, match="not connected"):
        stream.send_keepalive()


def test_receive_packet_restores_socket_timeout_after_temporary_override() -> None:
    class TimeoutSocket:
        def __init__(self):
            self.timeout = 9.0
            self.chunks = [encode_keepalive()]

        def fileno(self):
            return 123

        def gettimeout(self):
            return self.timeout

        def settimeout(self, value):
            self.timeout = value

        def recv(self, size):
            return self.chunks.pop(0)

    fake_socket = TimeoutSocket()
    stream = UdpGwStreamClient(
        Socks5ConnectConfig("127.0.0.1", 1080, "udpgw.example.test", 7300)
    )
    stream._socket = fake_socket

    packet = stream.receive_packet(timeout=0.05)

    assert packet.is_keepalive
    assert fake_socket.timeout == 9.0

def test_close_retains_udpgw_socket_when_close_fails_and_can_retry() -> None:
    class FlakySocket:
        def __init__(self):
            self.close_calls = 0
            self.closed = False

        def fileno(self):
            return -1 if self.closed else 123

        def shutdown(self, _how):
            raise OSError("socket already shut down")

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError("temporary close failure")
            self.closed = True

    fake_socket = FlakySocket()
    stream = UdpGwStreamClient(
        Socks5ConnectConfig("127.0.0.1", 1080, "udpgw.example.test", 7300)
    )
    stream._socket = fake_socket

    with pytest.raises(UdpGwTransportError, match="ownership is retained"):
        stream.close()

    assert stream.socket is fake_socket
    assert stream.connected
    assert fake_socket.close_calls == 1

    stream.close()

    assert stream._socket is None
    assert fake_socket.closed
    assert fake_socket.close_calls == 2
