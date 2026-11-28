"""Compose a strict dual-stack Windows TUN config from a parsed Xray share link.

This creates configuration data only. It does not resolve the endpoint, validate
credentials, launch Xray, alter routes, or establish a tunnel.
"""
from __future__ import annotations

import json

from apnawin.engines.xray_process import inspect_tun_inbound
from apnawin.services.proxy_share_link import ParsedProxyLink

_TUN_SETTINGS = {
    "name": "ApnaWin",
    "desc": "ApnaWin managed tunnel",
    "mtu": 1500,
    "gateway": ["10.255.0.1/30", "fd42:6170:6e61:7769::1/64"],
    "dns": ["1.1.1.1", "2606:4700:4700::1111"],
    "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
    "autoOutboundsInterface": "auto",
    "autoSystemWfpBlockLeak": ["allexceptlan", "dns"],
}


def build_tun_config(parsed: ParsedProxyLink) -> dict[str, object]:
    """Build a fail-closed full-tunnel Xray config for one parsed share link."""
    if not isinstance(parsed, ParsedProxyLink):
        raise TypeError("parsed must be a ParsedProxyLink")
    config: dict[str, object] = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "system-tun",
            "protocol": "tun",
            "port": 0,
            "settings": {
                key: list(value) if isinstance(value, list) else value
                for key, value in _TUN_SETTINGS.items()
            },
        }],
        # Keep the proxy as the sole/default outbound. No direct fallback is
        # emitted: a failed proxy must not silently leak traffic to the WAN.
        "outbounds": [parsed.to_outbound(tag="proxy")],
    }
    inspect_tun_inbound(config)
    return config


def serialize_tun_config(parsed: ParsedProxyLink) -> bytes:
    """Return bounded UTF-8 JSON bytes suitable for the encrypted config store."""
    encoded = json.dumps(
        build_tun_config(parsed),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if not encoded or len(encoded) > 16 * 1024 * 1024:
        raise ValueError("Generated Xray config exceeds the supported size limit")
    return encoded
