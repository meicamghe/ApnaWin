"""Bounded UDP DNS probe intended to run after Xray has installed the TUN routes."""
from __future__ import annotations

import ipaddress
import secrets
import socket
import struct


class UdpDnsProbeError(ConnectionError):
    """UDP DNS traffic did not complete through the active tunnel."""


def _query_bytes(transaction_id: int) -> bytes:
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question


def _validate_response(response: bytes, transaction_id: int) -> bool:
    if len(response) < 12:
        return False
    response_id, flags, questions, answers, _authority, _additional = struct.unpack(
        "!HHHHHH", response[:12]
    )
    return (
        response_id == transaction_id
        and bool(flags & 0x8000)
        and (flags & 0x000F) == 0
        and questions == 1
        and answers > 0
    )


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
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout must be positive")

    grouped: dict[int, list[str]] = {4: [], 6: []}
    for server in dns_servers:
        try:
            address = ipaddress.ip_address(server)
        except ValueError as exc:
            raise ValueError("DNS probe servers must be IP literals") from exc
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError("DNS probe server must be a usable unicast address")
        grouped[address.version].append(str(address))

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
                if str(ipaddress.ip_address(peer[0])) != server or peer[1] != 53:
                    failures.append(f"{server}: response source mismatch")
                    continue
                if not _validate_response(response, transaction_id):
                    failures.append(f"{server}: invalid DNS response")
                    continue
                successful_families.add(family)
                break
            except OSError as exc:
                failures.append(f"{server}: {exc}")

    required_families = {family for family, servers in grouped.items() if servers}
    if successful_families != required_families:
        raise UdpDnsProbeError(
            "UDP DNS egress failed for address family "
            + ", ".join(str(family) for family in sorted(required_families - successful_families))
            + ("; " + "; ".join(failures) if failures else "")
        )
    return tuple(sorted(successful_families))
