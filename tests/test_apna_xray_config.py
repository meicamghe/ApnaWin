from __future__ import annotations

import json

import pytest

from apnawin.engines.apna_xray_config import (
    ApnaXrayTunConfig,
    build_apna_xray_tun_config,
)
from apnawin.engines.xray_process import inspect_tun_inbound


def test_builds_full_dual_stack_tun_with_loopback_socks_outbound() -> None:
    raw = build_apna_xray_tun_config(("127.0.0.1", 23456))
    config = json.loads(raw)
    inbound = inspect_tun_inbound(config)
    assert inbound.routes == ("0.0.0.0/0", "::/0")
    assert inbound.auto_outbounds_interface == "auto"
    assert set(inbound.leak_protection) == {"allexceptlan", "dns"}
    assert config["outbounds"] == [
        {
            "tag": "apna-ssh-socks",
            "protocol": "socks",
            "settings": {"address": "127.0.0.1", "port": 23456},
        }
    ]


@pytest.mark.parametrize(
    "address",
    [("0.0.0.0", 1080), ("192.0.2.1", 1080), ("localhost", 1080), ("127.0.0.1", 0)],
)
def test_rejects_non_loopback_or_invalid_socks_gateway(address) -> None:
    with pytest.raises(ValueError):
        build_apna_xray_tun_config(address)


def test_accepts_custom_ipv6_loopback_socks_gateway_and_tun_dns() -> None:
    raw = build_apna_xray_tun_config(
        ("::1", 1081),
        tun=ApnaXrayTunConfig(dns_servers=("2606:4700:4700::1111",)),
    )
    config = json.loads(raw)
    assert config["outbounds"][0]["settings"] == {"address": "::1", "port": 1081}
    assert config["inbounds"][0]["settings"]["dns"] == ["2606:4700:4700::1111"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"gateway": ("10.0.0.1/30", "10.0.0.2/30")},
        {"gateway": ("10.0.0.1/30", "fd00::1/126",)},
        {"dns_servers": ()},
        {"dns_servers": ("localhost",)},
        {"dns_servers": ("1.1.1.1", "1.1.1.1")},
        {"mtu": 500},
        {"name": "bad/name"},
    ],
)
def test_tun_options_are_validated(kwargs) -> None:
    with pytest.raises(ValueError):
        ApnaXrayTunConfig(**kwargs)
