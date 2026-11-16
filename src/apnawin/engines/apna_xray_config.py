"""Generate the strict Xray/Wintun TUN config for an APNA SSH SOCKS bridge."""
from __future__ import annotations

import ipaddress
import json
from typing import Iterable

from apnawin.engines.xray_process import inspect_tun_inbound


_DEFAULT_DNS = ("1.1.1.1", "2606:4700:4700::1111")


def build_apna_xray_tun_config(
    local_socks_address: tuple[str, int],
    *,
    dns_servers: Iterable[str] = _DEFAULT_DNS,
    adapter_name: str = "ApnaWin",
    mtu: int = 1500,
) -> bytes:
    """Build an Xray TUN config whose only outbound is the local APNA SOCKS bridge.

    TCP uses SOCKS CONNECT. Xray's SOCKS outbound uses SOCKS5 UDP ASSOCIATE for
    UDP; the local APNA gateway maps that to the SSH-carried BadVPN UDPGW stream.
    """
    if (
        not isinstance(local_socks_address, tuple)
        or len(local_socks_address) != 2
    ):
        raise ValueError("local_socks_address must be a (loopback_host, port) tuple")
    host, port = local_socks_address
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("APNA SOCKS address must be a loopback IP literal") from exc
    if not address.is_loopback:
        raise ValueError("APNA SOCKS outbound must target loopback only")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("APNA SOCKS port must be between 1 and 65535")
    if (
        not isinstance(adapter_name, str)
        or not adapter_name
        or len(adapter_name) > 128
        or adapter_name != adapter_name.strip()
        or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _.-" for char in adapter_name)
    ):
        raise ValueError("adapter_name contains unsupported Windows alias characters")
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 576 <= mtu <= 9000:
        raise ValueError("mtu must be between 576 and 9000")

    dns = []
    for item in dns_servers:
        try:
            parsed = ipaddress.ip_address(item)
        except (ValueError, TypeError) as exc:
            raise ValueError("DNS servers must be IP address literals") from exc
        normalized = str(parsed)
        if parsed.is_unspecified or parsed.is_multicast or parsed.is_link_local:
            raise ValueError("DNS servers must be usable unicast addresses")
        if normalized not in dns:
            dns.append(normalized)
    if not 1 <= len(dns) <= 8:
        raise ValueError("Provide between 1 and 8 unique DNS servers")

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "apna-system-tun",
            "protocol": "tun",
            "port": 0,
            "settings": {
                "name": adapter_name,
                "desc": "ApnaWin APNA SSH tunnel",
                "mtu": mtu,
                "gateway": [
                    "10.255.0.1/30",
                    "fd42:6170:6e61:7769::1/64",
                ],
                "dns": dns,
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto",
                "autoSystemWfpBlockLeak": ["allexceptlan", "dns"],
            },
        }],
        "outbounds": [{
            "tag": "apna-ssh-socks",
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": str(address),
                    "port": port,
                }],
            },
        }],
    }
    inspect_tun_inbound(config)
    return (
        json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
