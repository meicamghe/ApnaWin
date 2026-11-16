from __future__ import annotations

import ipaddress
import socket
import struct

import pytest

from apnawin.engines.socks5_gateway import (
    Socks5Gateway,
    Socks5GatewayConfig,
    Socks5GatewayError,
    encode_socks5_udp_datagram,
    parse_socks5_udp_datagram,
)


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
