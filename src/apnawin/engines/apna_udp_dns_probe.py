"""Bounded UDP DNS probe intended to run after Xray has installed the TUN routes."""
from __future__ import annotations

import ipaddress
import math
import secrets
import socket
import struct


class UdpDnsProbeError(ConnectionError):
    """UDP DNS traffic did not complete through the active tunnel."""


_QUESTION = b"\\x07example\\x03com\\x00" + struct.pack("!HH", 1, 1)


def _query_bytes(transaction_id: int) -> bytes:
    return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + _QUESTION


def _validate_response(response: bytes, transaction_id: int) -> bool:
    """Accept only a matching, complete standard DNS response with an answer."""
    if not isinstance(response, bytes) or len(response) < 12 + len(_QUESTION):
        return False
    response_id, flags, questions, answers, _authority, _additional = struct.unpack(
        "!HHHHHH", response[:12]
    )
    # QR=1, OPCODE=QUERY, TC=0, RCODE=NOERROR. Other response flags
    # (AA/RD/RA/AD/CD) are not relevant to this reachability check.
    if (
        response_id != transaction_id
        or not flags & 0x8000
        or flags & 0x7800
        or flags & 0x0200
        or flags & 0x000F
        or questions != 1
        or answers == 0
    ):
        return False
    return response[12 : 12 + len(_QUESTION)] == _QUESTION


def probe_udp_dns(
    dns_servers: tuple[str, ...],
    *,
    timeout: float = 3.0,
) -> tuple[int, ...]:
    """Require a successful UDP DNS response for each IP family in dns_servers.

    Call only after Xray has installed the Wintun default routes. This probe is
    made by the unprivileged desktop process, so its UDP socket follows the
    system TUN route and traverses the SOCKS5 UDPGW gateway.
    """
    if not isinstance(dns_servers, tuple) or not dns_servers:
        raise ValueError("dns_servers must be a non-empty tuple of IP literals")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("timeout must be finite and positive")

    grouped: dict[int, list[str]] = {4: [], 6: []}
    for server in dns_servers:
        try:
            address = ipaddress.ip_address(server)
        except (ValueError, TypeError) as exc:
            raise ValueError("DNS probe servers must be IP literals") from exc
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError("DNS probe server must be a usable unicast address")
        normalized = str(address)
        if normalized not in grouped[address.version]:
            grouped[address.version].append(normalized)

    successful_families = set()
    failures = []
    for family, servers in grouped.items():
        if not servers:
            continue
        for server in servers:
            transaction_id = secrets.randbits(16)
            query = _query_bytes(transaction_id)
            socket_family = socket.AF_INET if family == 4 else socket.AF_INET6
            destination = (server, 53) if family == 4 else (server, 53, 0, 0)
            try:
                with socket.socket(socket_family, socket.SOCK_DGRAM) as client:
                    client.settimeout(timeout)
                    client.sendto(query, destination)
                    response, peer = client.recvfrom(4096)
                if (
                    not isinstance(peer, tuple)
                    or len(peer) < 2
                    or str(ipaddress.ip_address(peer[0])) != server
                    or peer[1] != 53
                ):
                    failures.append(f"{server}: response source mismatch")
                    continue
                if not _validate_response(response, transaction_id):
                    failures.append(f"{server}: invalid DNS response")
                    continue
                successful_families.add(family)
                break
            except (OSError, ValueError, TypeError, IndexError) as exc:
                failures.append(f"{server}: {exc}")

    required_families = {family for family, servers in grouped.items() if servers}
    if successful_families != required_families:
        raise UdpDnsProbeError(
            "UDP DNS egress failed for address family "
            + ", ".join(str(family) for family in sorted(required_families - successful_families))
            + ("; " + "; ".join(failures) if failures else "")
        )
    return tuple(sorted(successful_families))
