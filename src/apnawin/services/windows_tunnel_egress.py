"""Independent dual-stack TLS egress probes for the Windows full-tunnel path."""
from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class EgressProbeTarget:
    address: str
    server_name: str
    port: int = 443

    @property
    def ip_version(self) -> int:
        return ipaddress.ip_address(self.address).version


IPV4_TARGETS = (
    EgressProbeTarget("1.1.1.1", "cloudflare-dns.com"),
    EgressProbeTarget("8.8.8.8", "dns.google"),
)

IPV6_TARGETS = (
    EgressProbeTarget("2606:4700:4700::1111", "cloudflare-dns.com"),
    EgressProbeTarget("2001:4860:4860::8888", "dns.google"),
)

# Keep a stable combined list for diagnostics and tests.
TARGETS = IPV4_TARGETS + IPV6_TARGETS


class TunnelEgressError(RuntimeError):
    """Raised when either address family cannot reach a verified TLS endpoint via TUN."""


def _tls_handshake(target: EgressProbeTarget, *, timeout: float = 3.0) -> bool:
    context = ssl.create_default_context()
    with socket.create_connection((target.address, target.port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=target.server_name):
            return True


def _probe_family(
    targets: tuple[EgressProbeTarget, ...],
    checker: Callable[[EgressProbeTarget], bool],
) -> EgressProbeTarget:
    for target in targets:
        try:
            if checker(target):
                return target
        except (OSError, ssl.SSLError, TimeoutError):
            continue
    family = targets[0].ip_version
    raise TunnelEgressError(
        f"No independent IPv{family} TLS endpoint was reachable through the VPN TUN"
    )


def probe_tun_egress(
    *,
    probe: Callable[[EgressProbeTarget], bool] | None = None,
) -> tuple[EgressProbeTarget, EgressProbeTarget]:
    """Require certificate-validated TLS egress over both IPv4 and IPv6.

    The helper process is not Xray, so Xray's WFP leak filters and effective
    default routes must direct these sockets through the TUN. Fixed IP literals
    avoid relying on DNS for the probes; TLS SNI and certificate validation
    verify each independent endpoint identity. Requiring both families prevents
    a tunnel with a broken IPv6 path from being reported as fully connected.
    """
    checker = probe or _tls_handshake
    ipv4 = _probe_family(IPV4_TARGETS, checker)
    ipv6 = _probe_family(IPV6_TARGETS, checker)
    return ipv4, ipv6
