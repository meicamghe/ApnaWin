"""Independent TLS egress probe for the Windows full-tunnel path."""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class EgressProbeTarget:
    address: str
    server_name: str
    port: int = 443


TARGETS = (
    EgressProbeTarget("1.1.1.1", "cloudflare-dns.com"),
    EgressProbeTarget("8.8.8.8", "dns.google"),
)


class TunnelEgressError(RuntimeError):
    """Raised when no independent external TLS endpoint is reachable via TUN."""


def _tls_handshake(target: EgressProbeTarget, *, timeout: float = 3.0) -> bool:
    context = ssl.create_default_context()
    with socket.create_connection((target.address, target.port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=target.server_name):
            return True


def probe_tun_egress(
    *,
    probe: Callable[[EgressProbeTarget], bool] | None = None,
) -> EgressProbeTarget:
    """Require one verified external TLS handshake through the system TUN route.

    The helper process is not Xray, so Xray's WFP leak filters and the effective
    default routes must direct this socket through the TUN. IP literals avoid
    depending on DNS for the probe itself; TLS SNI and certificate validation
    still verify the independent endpoint identity.
    """
    checker = probe or _tls_handshake
    for target in TARGETS:
        try:
            if checker(target):
                return target
        except (OSError, ssl.SSLError, TimeoutError):
            continue
    raise TunnelEgressError(
        "No independent external TLS endpoint was reachable through the VPN TUN"
    )
