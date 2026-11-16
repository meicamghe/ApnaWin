"""BadVPN-compatible UDPGW packet framing and codec.

This module implements the public PacketProto / UDPGW wire format. It is a
transport codec only: socket lifecycle, flow-ID allocation, DNS policy and the
local SOCKS5 UDP association are implemented by higher layers.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import TypeAlias

IPAddress: TypeAlias = IPv4Address | IPv6Address

FLAG_KEEPALIVE = 0x01
FLAG_REBIND = 0x02
FLAG_DNS = 0x04
FLAG_IPV6 = 0x08
_ALLOWED_FLAGS = FLAG_KEEPALIVE | FLAG_REBIND | FLAG_DNS | FLAG_IPV6
_MAX_PACKET_PAYLOAD = 0xFFFF
_PACKETPROTO_HEADER = struct.Struct("<H")
_UDPGW_HEADER = struct.Struct("<BH")


class UdpGwProtocolError(ValueError):
    """Malformed or out-of-range PacketProto / UDPGW data."""


@dataclass(frozen=True, slots=True)
class UdpGwPacket:
    flags: int
    connection_id: int
    address: IPAddress | None
    port: int | None
    data: bytes

    @property
    def is_keepalive(self) -> bool:
        return bool(self.flags & FLAG_KEEPALIVE)

    @property
    def is_dns(self) -> bool:
        return bool(self.flags & FLAG_DNS)

    @property
    def is_rebind(self) -> bool:
        return bool(self.flags & FLAG_REBIND)


def encode_packetproto(payload: bytes | bytearray | memoryview) -> bytes:
    data = bytes(payload)
    if not 3 <= len(data) <= _MAX_PACKET_PAYLOAD:
        raise UdpGwProtocolError("PacketProto payload length must be 3..65535 bytes")
    return _PACKETPROTO_HEADER.pack(len(data)) + data


def encode_keepalive() -> bytes:
    """Encode the BadVPN zero-connection-ID keepalive frame."""
    return encode_packetproto(_UDPGW_HEADER.pack(FLAG_KEEPALIVE, 0))


def encode_datagram(
    *,
    connection_id: int,
    address: str | IPAddress,
    port: int,
    data: bytes | bytearray | memoryview,
    is_dns: bool = False,
    rebind: bool = False,
) -> bytes:
    if isinstance(connection_id, bool) or not isinstance(connection_id, int):
        raise TypeError("connection_id must be an integer")
    if not 0 <= connection_id <= 0xFFFF:
        raise UdpGwProtocolError("connection_id must be between 0 and 65535")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 0xFFFF:
        raise UdpGwProtocolError("destination port must be between 1 and 65535")
    if not isinstance(is_dns, bool) or not isinstance(rebind, bool):
        raise TypeError("is_dns and rebind must be booleans")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UdpGwProtocolError("UDPGW destination must be an IPv4 or IPv6 address") from exc
    payload = bytes(data)
    flags = (FLAG_DNS if is_dns else 0) | (FLAG_REBIND if rebind else 0)
    if isinstance(ip, IPv6Address):
        flags |= FLAG_IPV6
    body = (
        _UDPGW_HEADER.pack(flags, connection_id)
        + ip.packed
        + struct.pack("!H", port)
        + payload
    )
    return encode_packetproto(body)


def decode_udpgw_payload(payload: bytes | bytearray | memoryview) -> UdpGwPacket:
    body = bytes(payload)
    if len(body) < _UDPGW_HEADER.size:
        raise UdpGwProtocolError("UDPGW payload is shorter than its 3-byte header")
    flags, connection_id = _UDPGW_HEADER.unpack_from(body)
    if flags & ~_ALLOWED_FLAGS:
        raise UdpGwProtocolError("UDPGW payload contains reserved flag bits")

    if flags & FLAG_KEEPALIVE:
        if flags != FLAG_KEEPALIVE or connection_id != 0 or len(body) != 3:
            raise UdpGwProtocolError("Malformed UDPGW keepalive packet")
        return UdpGwPacket(flags, connection_id, None, None, b"")

    address_size = 16 if flags & FLAG_IPV6 else 4
    required = _UDPGW_HEADER.size + address_size + 2
    if len(body) < required:
        raise UdpGwProtocolError("UDPGW payload is missing destination address or port")
    address_start = _UDPGW_HEADER.size
    address_end = address_start + address_size
    address = ipaddress.ip_address(body[address_start:address_end])
    port = struct.unpack_from("!H", body, address_end)[0]
    if port == 0:
        raise UdpGwProtocolError("UDPGW payload contains destination port zero")
    return UdpGwPacket(
        flags=flags,
        connection_id=connection_id,
        address=address,
        port=port,
        data=body[required:],
    )


class PacketProtoDecoder:
    """Incremental decoder for fragmented or coalesced PacketProto TCP reads."""

    def __init__(self, *, max_payload_bytes: int = _MAX_PACKET_PAYLOAD) -> None:
        if (
            isinstance(max_payload_bytes, bool)
            or not isinstance(max_payload_bytes, int)
            or not 3 <= max_payload_bytes <= _MAX_PACKET_PAYLOAD
        ):
            raise ValueError("max_payload_bytes must be between 3 and 65535")
        self._max_payload_bytes = max_payload_bytes
        self._buffer = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes | bytearray | memoryview) -> tuple[bytes, ...]:
        incoming = bytes(data)
        if len(self._buffer) + len(incoming) > self._max_payload_bytes + 2:
            # Complete frames are consumed below; this guard only rejects a
            # single incomplete frame that has grown beyond the configured cap.
            if len(self._buffer) < 2:
                raise UdpGwProtocolError("PacketProto receive buffer exceeds its limit")
        self._buffer.extend(incoming)
        frames: list[bytes] = []
        while len(self._buffer) >= 2:
            frame_length = _PACKETPROTO_HEADER.unpack_from(self._buffer)[0]
            if not 3 <= frame_length <= self._max_payload_bytes:
                raise UdpGwProtocolError("Invalid PacketProto frame length")
            frame_end = 2 + frame_length
            if len(self._buffer) < frame_end:
                break
            frames.append(bytes(self._buffer[2:frame_end]))
            del self._buffer[:frame_end]
        if len(self._buffer) > self._max_payload_bytes + 2:
            raise UdpGwProtocolError("PacketProto receive buffer exceeds its limit")
        return tuple(frames)
