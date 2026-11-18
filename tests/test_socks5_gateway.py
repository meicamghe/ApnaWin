from __future__ import annotations

import ipaddress
import select
import socket
import socketserver
import struct
import threading
import time

import pytest

from apnawin.engines.socks5_gateway import (
    Socks5Gateway,
    Socks5GatewayConfig,
    Socks5GatewayError,
    encode_socks5_udp_datagram,
    parse_socks5_udp_datagram,
)
from apnawin.engines.udpgw_protocol import decode_udpgw_payload, encode_datagram


def test_parse_and_encode_socks5_ipv4_udp_datagram() -> None:
    request = b"\x00\x00\x00\x01" + ipaddress.ip_address("8.8.8.8").packed
    request += struct.pack("!H", 53) + b"dns"
    assert parse_socks5_udp_datagram(request) == ("8.8.8.8", 53, b"dns")
    response = encode_socks5_udp_datagram("1.1.1.1", 53, b"answer")
    assert response == (
        b"\x00\x00\x00\x01"
        + ipaddress.ip_address("1.1.1.1").packed
        + struct.pack("!H", 53)
        + b"answer"
    )


def test_parse_socks5_ipv6_and_domain_udp_datagrams() -> None:
    ipv6 = b"\x00\x00\x00\x04" + ipaddress.ip_address("2001:4860:4860::8888").packed
    ipv6 += struct.pack("!H", 443) + b"v6"
    assert parse_socks5_udp_datagram(ipv6) == (
        "2001:4860:4860::8888",
        443,
        b"v6",
    )
    domain = b"\x00\x00\x00\x03" + bytes((len(b"dns.example"),))
    domain += b"dns.example" + struct.pack("!H", 53) + b"query"
    assert parse_socks5_udp_datagram(domain) == ("dns.example", 53, b"query")


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"\x00\x01\x00\x01\x08\x08\x08\x08\x00\x35",
        b"\x00\x00\x01\x01\x08\x08\x08\x08\x00\x35",
        b"\x00\x00\x00\x01\x08\x08\x08\x08\x00",
        b"\x00\x00\x00\x01\x08\x08\x08\x08\x00\x00",
    ],
)
def test_parse_socks5_udp_rejects_malformed_datagrams(packet: bytes) -> None:
    with pytest.raises(Socks5GatewayError):
        parse_socks5_udp_datagram(packet)


def test_gateway_config_requires_loopback_and_valid_udp_endpoint() -> None:
    with pytest.raises(ValueError, match="loopback"):
        Socks5GatewayConfig("127.0.0.1", 1080, listen_host="0.0.0.0")
    with pytest.raises(ValueError, match="udpgw_port"):
        Socks5GatewayConfig("127.0.0.1", 1080, udpgw_host="udpgw.example", udpgw_port=0)


def test_gateway_refuses_udp_associate_without_udpgw_configuration() -> None:
    gateway = Socks5Gateway(
        Socks5GatewayConfig(
            ssh_proxy_host="127.0.0.1",
            ssh_proxy_port=1080,
        )
    ).start()
    client = socket.create_connection(gateway.address, timeout=2)
    try:
        client.sendall(b"\x05\x01\x00")
        assert client.recv(2) == b"\x05\x00"
        client.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        response = client.recv(10)
        assert response[:3] == b"\x05\x07\x00"
    finally:
        client.close()
        gateway.close()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError
        result.extend(chunk)
    return bytes(result)


class _FakeUdpGwHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            try:
                length = struct.unpack("<H", _recv_exact(self.request, 2))[0]
                packet = decode_udpgw_payload(_recv_exact(self.request, length))
            except (EOFError, OSError):
                return
            if packet.is_keepalive:
                continue
            self.server.received.append(packet)
            self.request.sendall(
                encode_datagram(
                    connection_id=packet.connection_id,
                    address=str(packet.address),
                    port=packet.port,
                    data=b"reply:" + packet.data,
                )
            )


class _FakeUdpGwServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address):
        self.received = []
        super().__init__(address, _FakeUdpGwHandler)


class _FakeSshSocksHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        upstream = None
        try:
            greeting = _recv_exact(self.request, 3)
            if greeting != b"\x05\x01\x00":
                return
            self.request.sendall(b"\x05\x00")
            version, command, reserved, address_type = _recv_exact(self.request, 4)
            if version != 5 or command != 1 or reserved != 0:
                return
            if address_type == 1:
                _recv_exact(self.request, 4)
            elif address_type == 4:
                _recv_exact(self.request, 16)
            elif address_type == 3:
                _recv_exact(self.request, _recv_exact(self.request, 1)[0])
            else:
                return
            _recv_exact(self.request, 2)
            upstream = socket.create_connection(self.server.target_address, timeout=2)
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            peers = (self.request, upstream)
            while True:
                readable, _, _ = select.select(peers, [], [], 1)
                if not readable:
                    continue
                for source in readable:
                    destination = upstream if source is self.request else self.request
                    data = source.recv(64 * 1024)
                    if not data:
                        return
                    destination.sendall(data)
        except (EOFError, OSError):
            return
        finally:
            if upstream is not None:
                upstream.close()


class _FakeSshSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, target_address):
        self.target_address = target_address
        super().__init__(address, _FakeSshSocksHandler)


def test_udp_associate_roundtrips_through_ssh_socks_and_udpgw() -> None:
    udp_server = _FakeUdpGwServer(("127.0.0.1", 0))
    udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
    udp_thread.start()
    ssh_server = _FakeSshSocksServer(("127.0.0.1", 0), udp_server.server_address)
    ssh_thread = threading.Thread(target=ssh_server.serve_forever, daemon=True)
    ssh_thread.start()
    gateway = Socks5Gateway(
        Socks5GatewayConfig(
            ssh_proxy_host="127.0.0.1",
            ssh_proxy_port=ssh_server.server_address[1],
            udpgw_host="udpgw.example.test",
            udpgw_port=7300,
            transparent_dns=True,
            dns_resolver="8.8.8.8",
            keepalive_interval=5,
            udp_idle_timeout=10,
        )
    ).start()
    control = socket.create_connection(gateway.address, timeout=2)
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client.settimeout(3)
    try:
        control.sendall(b"\x05\x01\x00")
        assert _recv_exact(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        response = _recv_exact(control, 10)
        assert response[:3] == b"\x05\x00\x00"
        relay_host = str(ipaddress.IPv4Address(response[4:8]))
        relay_port = struct.unpack("!H", response[8:10])[0]

        domain_packet = b"\x00\x00\x00\x03" + bytes((len(b"dns.example"),))
        domain_packet += b"dns.example" + struct.pack("!H", 53) + b"query"
        udp_client.sendto(domain_packet, (relay_host, relay_port))
        reply, _ = udp_client.recvfrom(4096)
        assert parse_socks5_udp_datagram(reply) == ("8.8.8.8", 53, b"reply:query")

        deadline = time.monotonic() + 2
        while not udp_server.received and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(udp_server.received) == 1
        sent = udp_server.received[0]
        assert sent.is_dns
        assert sent.address == ipaddress.ip_address("8.8.8.8")
        assert sent.data == b"query"
    finally:
        udp_client.close()
        control.close()
        gateway.close()
        ssh_server.shutdown()
        ssh_server.server_close()
        udp_server.shutdown()
        udp_server.server_close()
        ssh_thread.join(timeout=1)
        udp_thread.join(timeout=1)


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class _EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


def test_gateway_rejects_zero_destination_port_without_crashing_handler() -> None:
    gateway = Socks5Gateway(
        Socks5GatewayConfig(
            ssh_proxy_host="127.0.0.1",
            ssh_proxy_port=1080,
        )
    ).start()
    client = socket.create_connection(gateway.address, timeout=2)
    client.settimeout(2)
    try:
        client.sendall(b"\x05\x01\x00")
        assert _recv_exact(client, 2) == b"\x05\x00"
        request = b"\x05\x01\x00\x03" + bytes((len(b"example.test"),))
        request += b"example.test" + b"\x00\x00"
        client.sendall(request)
        response = _recv_exact(client, 10)
        assert response[:3] == b"\x05\x01\x00"
    finally:
        client.close()
        gateway.close()


def test_tcp_connect_is_forwarded_through_ssh_socks() -> None:
    echo_server = _EchoServer(("127.0.0.1", 0), _EchoHandler)
    echo_thread = threading.Thread(target=echo_server.serve_forever, daemon=True)
    echo_thread.start()
    ssh_server = _FakeSshSocksServer(("127.0.0.1", 0), echo_server.server_address)
    ssh_thread = threading.Thread(target=ssh_server.serve_forever, daemon=True)
    ssh_thread.start()
    gateway = Socks5Gateway(
        Socks5GatewayConfig(
            ssh_proxy_host="127.0.0.1",
            ssh_proxy_port=ssh_server.server_address[1],
        )
    ).start()
    client = socket.create_connection(gateway.address, timeout=2)
    client.settimeout(2)
    try:
        client.sendall(b"\x05\x01\x00")
        assert _recv_exact(client, 2) == b"\x05\x00"
        request = b"\x05\x01\x00\x03" + bytes((len(b"echo.example.test"),))
        request += b"echo.example.test" + struct.pack("!H", 443)
        client.sendall(request)
        response = _recv_exact(client, 10)
        assert response[:3] == b"\x05\x00\x00"
        client.sendall(b"hello-through-ssh")
        assert _recv_exact(client, len(b"hello-through-ssh")) == b"hello-through-ssh"
    finally:
        client.close()
        gateway.close()
        ssh_server.shutdown()
        ssh_server.server_close()
        echo_server.shutdown()
        echo_server.server_close()
        ssh_thread.join(timeout=1)
        echo_thread.join(timeout=1)


def test_gateway_tcp_relay_preserves_response_after_client_half_close() -> None:
    client, relay_client = socket.socketpair()
    relay_upstream, upstream = socket.socketpair()
    worker = threading.Thread(
        target=Socks5Gateway._relay_tcp,
        args=(relay_client, relay_upstream),
        daemon=True,
    )
    worker.start()
    try:
        client.sendall(b"request-before-fin")
        client.shutdown(socket.SHUT_WR)
        assert _recv_exact(upstream, len(b"request-before-fin")) == b"request-before-fin"
        assert upstream.recv(1) == b""
        upstream.sendall(b"response-after-fin")
        upstream.shutdown(socket.SHUT_WR)
        assert _recv_exact(client, len(b"response-after-fin")) == b"response-after-fin"
        assert client.recv(1) == b""
        worker.join(timeout=2)
        assert not worker.is_alive()
    finally:
        client.close()
        relay_client.close()
        relay_upstream.close()
        upstream.close()


def test_udp_response_rejects_source_endpoint_mismatch() -> None:
    from types import SimpleNamespace

    from apnawin.engines.udpgw_flows import UdpGwFlowTable

    flows = UdpGwFlowTable()
    lease = flows.get_or_create(
        local_address="127.0.0.1",
        local_port=42000,
        remote_address="8.8.8.8",
        remote_port=53,
    )

    class Relay:
        sent = []

        def sendto(self, data, destination):
            self.sent.append((data, destination))

    relay = Relay()
    mismatched = SimpleNamespace(
        is_keepalive=False,
        address=ipaddress.ip_address("1.1.1.1"),
        port=53,
        connection_id=lease.connection_id,
        data=b"spoofed",
    )
    assert not Socks5Gateway._send_udp_response(mismatched, flows, relay)

    wrong_port = SimpleNamespace(
        is_keepalive=False,
        address=ipaddress.ip_address("8.8.8.8"),
        port=443,
        connection_id=lease.connection_id,
        data=b"spoofed",
    )
    assert not Socks5Gateway._send_udp_response(wrong_port, flows, relay)
    assert relay.sent == []


def test_udp_response_uses_the_flow_bound_source_endpoint() -> None:
    from types import SimpleNamespace

    from apnawin.engines.udpgw_flows import UdpGwFlowTable

    flows = UdpGwFlowTable()
    lease = flows.get_or_create(
        local_address="127.0.0.1",
        local_port=42000,
        remote_address="8.8.8.8",
        remote_port=53,
    )

    class Relay:
        sent = []

        def sendto(self, data, destination):
            self.sent.append((data, destination))

    relay = Relay()
    packet = SimpleNamespace(
        is_keepalive=False,
        address=ipaddress.ip_address("8.8.8.8"),
        port=53,
        connection_id=lease.connection_id,
        data=b"dns-reply",
    )
    assert Socks5Gateway._send_udp_response(packet, flows, relay)
    assert len(relay.sent) == 1
    payload, destination = relay.sent[0]
    assert destination == ("127.0.0.1", 42000)
    assert parse_socks5_udp_datagram(payload) == ("8.8.8.8", 53, b"dns-reply")



@pytest.mark.parametrize(
    ("requested_host", "requested_port", "peer_ip", "expected"),
    [
        ("0.0.0.0", 0, "127.0.0.1", None),
        ("127.0.0.1", 43000, "127.0.0.1", ("127.0.0.1", 43000)),
    ],
)
def test_udp_associate_validates_declared_client_endpoint(
    requested_host, requested_port, peer_ip, expected
) -> None:
    from apnawin.engines.socks5_gateway import _validate_udp_client_endpoint

    assert _validate_udp_client_endpoint(
        requested_host, requested_port, peer_ip
    ) == expected


@pytest.mark.parametrize(
    ("requested_host", "requested_port", "peer_ip"),
    [
        ("192.0.2.10", 43000, "127.0.0.1"),
        ("client.example", 43000, "127.0.0.1"),
        ("::", 43000, "127.0.0.1"),
        ("127.0.0.1", -1, "127.0.0.1"),
        ("127.0.0.1", 65536, "127.0.0.1"),
    ],
)
def test_udp_associate_rejects_mismatched_or_invalid_client_endpoint(
    requested_host, requested_port, peer_ip
) -> None:
    from apnawin.engines.socks5_gateway import _validate_udp_client_endpoint

    with pytest.raises(ValueError):
        _validate_udp_client_endpoint(requested_host, requested_port, peer_ip)
