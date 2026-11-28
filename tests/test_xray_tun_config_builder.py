import json

import pytest

from apnawin.engines.xray_process import inspect_tun_inbound
from apnawin.services.proxy_share_link import parse_proxy_link
from apnawin.services.xray_tun_config import build_tun_config, serialize_tun_config


@pytest.mark.parametrize(
    "link, protocol",
    [
        ("vless://user@vless.example:443?security=tls", "vless"),
        ("vmess://eyJ2IjoiMiIsImFkZCI6InZtZXNzLmV4YW1wbGUiLCJwb3J0Ijo0NDMsImlkIjoidXNlciIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AifQ", "vmess"),
        ("trojan://secret@trojan.example:443", "trojan"),
        ("ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example:8388", "shadowsocks"),
        ("hy2://secret@hy.example:443", "hysteria"),
    ],
)
def test_builder_creates_valid_dual_stack_tun_config_without_direct_fallback(link, protocol):
    parsed = parse_proxy_link(link)
    config = build_tun_config(parsed)

    inbound = inspect_tun_inbound(config)
    assert inbound.routes == ("0.0.0.0/0", "::/0")
    assert inbound.auto_outbounds_interface == "auto"
    assert set(inbound.leak_protection) == {"allexceptlan", "dns"}
    assert len(config["inbounds"]) == 1
    assert len(config["outbounds"]) == 1
    assert config["outbounds"][0]["protocol"] == protocol
    assert config["outbounds"][0]["tag"] == "proxy"
    assert "direct" not in {item.get("tag") for item in config["outbounds"]}


def test_builder_preserves_hysteria2_auth_and_salamander_settings():
    parsed = parse_proxy_link(
        "hy2://auth-secret@hy.example:443?obfs=salamander&obfs-password=mask-secret"
    )
    config = build_tun_config(parsed)
    outbound = config["outbounds"][0]
    assert outbound["streamSettings"]["hysteriaSettings"]["auth"] == "auth-secret"
    assert outbound["streamSettings"]["finalmask"]["udp"][0]["settings"]["password"] == "mask-secret"


def test_builder_rejects_non_parsed_input():
    with pytest.raises(TypeError, match="ParsedProxyLink"):
        build_tun_config({"protocol": "vless"})


def test_serialized_config_is_valid_utf8_json_and_revalidates_tun_policy():
    parsed = parse_proxy_link("vless://user@vpn.example:443?security=tls#دفتر")
    encoded = serialize_tun_config(parsed)
    decoded = json.loads(encoded.decode("utf-8"))
    assert decoded["outbounds"][0]["settings"]["address"] == "vpn.example"
    assert decoded["outbounds"][0]["tag"] == "proxy"
    inspect_tun_inbound(decoded)


def test_builder_does_not_mutate_shared_tun_defaults_between_calls():
    first = build_tun_config(parse_proxy_link("vless://user@one.example:443?security=tls"))
    first["inbounds"][0]["settings"]["dns"].append("8.8.8.8")
    second = build_tun_config(parse_proxy_link("vless://user@two.example:443?security=tls"))
    assert second["inbounds"][0]["settings"]["dns"] == [
        "1.1.1.1", "2606:4700:4700::1111"
    ]
