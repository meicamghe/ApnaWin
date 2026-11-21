from __future__ import annotations

import ipaddress
import struct

import pytest

from apnawin.engines.udpgw_protocol import (
    FLAG_DNS,
    FLAG_IPV6,
    FLAG_KEEPALIVE,
    FLAG_REBIND,
    PacketProtoDecoder,
    UdpGwProtocolError,
    decode_udpgw_payload,
    encode_datagram,
    encode_keepalive,
    encode_packetproto,
)


def test_encode_decode_ipv4_dns_rebind_datagram() -> None:
    frame = encode_datagram(
        connection_id=0x1234,
        address="8.8.8.8",
        port=53,
        data=b"query",
        is_dns=True,
        rebind=True,
    )
    length = struct.unpack_from("<H", frame)[0]
    assert length == len(frame) - 2
    packet = decode_udpgw_payload(frame[2:])
    assert packet.flags == FLAG_DNS | FLAG_REBIND
    assert packet.connection_id == 0x1234
    assert packet.address == ipaddress.ip_address("8.8.8.8")
    assert packet.port == 53
    assert packet.data == b"query"


def test_encode_decode_ipv6_sets_ipv6_flag() -> None:
    frame = encode_datagram(
        connection_id=7,
        address="2001:4860:4860::8888",
        port=443,
        data=b"payload",
    )
    packet = decode_udpgw_payload(frame[2:])
    assert packet.flags == FLAG_IPV6
    assert packet.address == ipaddress.ip_address("2001:4860:4860::8888")
    assert packet.port == 443
    assert packet.data == b"payload"


def test_keepalive_has_only_the_three_byte_udpgw_header() -> None:
    frame = encode_keepalive()
    assert frame == b"\x03\x00\x01\x00\x00"
    packet = decode_udpgw_payload(frame[2:])
    assert packet.is_keepalive
    assert packet.flags == FLAG_KEEPALIVE
    assert packet.address is None
    assert packet.port is None
    assert packet.data == b""


def test_packetproto_decoder_handles_fragmented_and_coalesced_frames() -> None:
    one = encode_keepalive()
    two = encode_datagram(
        connection_id=1,
        address="192.0.2.10",
        port=1234,
        data=b"abc",
    )
    decoder = PacketProtoDecoder()
    assert decoder.feed(one[:1]) == ()
    assert decoder.feed(one[1:3]) == ()
    frames = decoder.feed(one[3:] + two)
    assert len(frames) == 2
    assert decode_udpgw_payload(frames[0]).is_keepalive
    assert decode_udpgw_payload(frames[1]).data == b"abc"
    assert decoder.buffered_bytes == 0


def test_packetproto_decoder_waits_for_complete_frame() -> None:
    frame = encode_keepalive()
    decoder = PacketProtoDecoder()
    assert decoder.feed(frame[:-1]) == ()
    assert decoder.buffered_bytes == len(frame) - 1
    assert decoder.feed(frame[-1:]) == (frame[2:],)


@pytest.mark.parametrize(
    ("connection_id", "address", "port"),
    [
        (-1, "192.0.2.1", 53),
        (65536, "192.0.2.1", 53),
        (1, "192.0.2.1", 0),
        (1, "192.0.2.1", 65536),
        (1, "not-an-ip", 53),
    ],
)
def test_encoder_rejects_invalid_flow_or_destination(
    connection_id: int, address: str, port: int
) -> None:
    with pytest.raises(UdpGwProtocolError):
        encode_datagram(
            connection_id=connection_id,
            address=address,
            port=port,
            data=b"x",
        )


def test_decoder_rejects_reserved_flags_and_short_address() -> None:
    with pytest.raises(UdpGwProtocolError, match="reserved"):
        decode_udpgw_payload(b"\x10\x00\x00")
    with pytest.raises(UdpGwProtocolError, match="address or port"):
        decode_udpgw_payload(b"\x00\x01\x00")


def test_decoder_rejects_malformed_keepalive() -> None:
    with pytest.raises(UdpGwProtocolError, match="keepalive"):
        decode_udpgw_payload(b"\x03\x01\x00\x00")


def test_packetproto_decoder_rejects_invalid_length() -> None:
    decoder = PacketProtoDecoder()
    with pytest.raises(UdpGwProtocolError, match="frame length"):
        decoder.feed(b"\x02\x00abc")


def test_packetproto_encoder_rejects_empty_or_oversized_payload() -> None:
    with pytest.raises(UdpGwProtocolError):
        encode_packetproto(b"")
    with pytest.raises(UdpGwProtocolError):
        encode_packetproto(b"x" * 65536)
