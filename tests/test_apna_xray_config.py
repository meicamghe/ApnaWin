from __future__ import annotations

import json

import pytest

from apnawin.engines.apna_xray_config import build_apna_xray_tun_config
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
            "settings": {
                "servers": [{"address": "127.0.0.1", "port": 23456}],
            },
        }
    ]


@pytest.mark.parametrize(
    "address",
    [
        ("0.0.0.0", 1080),
        ("192.0.2.1", 1080),
        ("localhost", 1080),
        ("127.0.0.1", 0),
    ],
)
def test_rejects_non_loopback_or_invalid_socks_gateway(address) -> None:
    with pytest.raises(ValueError):
        build_apna_xray_tun_config(address)


def test_accepts_custom_ipv6_loopback_socks_gateway_and_dns() -> None:
    raw = build_apna_xray_tun_config(
        ("::1", 1081),
        dns_servers=("2606:4700:4700::1111",),
    )
    config = json.loads(raw)
    assert config["outbounds"][0]["settings"]["servers"] == [
        {"address": "::1", "port": 1081}
    ]
    assert config["inbounds"][0]["settings"]["dns"] == ["2606:4700:4700::1111"]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"dns_servers": ()}, "DNS"),
        ({"dns_servers": ("localhost",)}, "DNS"),
        ({"mtu": 500}, "mtu"),
        ({"adapter_name": "bad/name"}, "adapter_name"),
    ],
)
def test_rejects_invalid_tun_options(kwargs, message) -> None:
    with pytest.raises(ValueError, match=message):
        build_apna_xray_tun_config(("127.0.0.1", 1080), **kwargs)


def test_supports_named_sidecar_description_and_outbound_tag() -> None:
    raw = build_apna_xray_tun_config(
        ("127.0.0.1", 23457),
        description="ApnaWin UDPQ tunnel",
        outbound_tag="udpq-socks",
    )
    config = json.loads(raw)
    assert config["inbounds"][0]["settings"]["desc"] == "ApnaWin UDPQ tunnel"
    assert config["outbounds"][0]["tag"] == "udpq-socks"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"description": ""}, "description"),
        ({"description": "bad\\nvalue"}, "description"),
        ({"outbound_tag": "bad/tag"}, "outbound_tag"),
    ],
)
def test_rejects_unsafe_sidecar_tun_labels(kwargs, message) -> None:
    with pytest.raises(ValueError, match=message):
        build_apna_xray_tun_config(("127.0.0.1", 1080), **kwargs)
