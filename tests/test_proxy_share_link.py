import base64
import json

import pytest

from apnawin.services.proxy_share_link import parse_proxy_link, parse_proxy_links


def vmess_link(config):
    payload = base64.urlsafe_b64encode(json.dumps(config).encode()).decode().rstrip("=")
    return "vmess://" + payload


def ss_userinfo(method="aes-256-gcm", password="secret"):
    return base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")


def test_parse_vless_tls_and_flow_into_current_xray_outbound():
    parsed = parse_proxy_link(
        "vless://123e4567-e89b-12d3-a456-426614174000@vpn.example:443"
        "?encryption=none&flow=xtls-rprx-vision&type=tcp&security=tls"
        "&sni=cdn.example&fp=chrome#Office%20VPN"
    )
    outbound = parsed.to_outbound()
    assert parsed.name == "Office VPN"
    assert parsed.protocol == "vless"
    assert outbound["settings"] == {
        "address": "vpn.example",
        "port": 443,
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "encryption": "none",
        "level": 0,
        "flow": "xtls-rprx-vision",
    }
    assert outbound["streamSettings"]["method"] == "raw"
    assert outbound["streamSettings"]["tlsSettings"]["serverName"] == "cdn.example"


def test_parse_vless_reality_requires_and_maps_public_parameters():
    parsed = parse_proxy_link(
        "vless://user-id@reality.example:443?security=reality&type=grpc"
        "&sni=cover.example&fp=chrome&pbk=public-key&sid=abcd&serviceName=tunnel"
    )
    outbound = parsed.to_outbound()
    assert outbound["streamSettings"]["security"] == "reality"
    assert outbound["streamSettings"]["realitySettings"] == {
        "serverName": "cover.example",
        "fingerprint": "chrome",
        "publicKey": "public-key",
        "shortId": "abcd",
    }
    assert outbound["streamSettings"]["grpcSettings"]["serviceName"] == "tunnel"


def test_parse_vless_websocket_host_and_path():
    parsed = parse_proxy_link(
        "vless://user@vpn.example:443?type=ws&security=tls"
        "&host=cdn.example&path=%2Fedge#ws"
    )
    stream = parsed.to_outbound()["streamSettings"]
    assert stream["method"] == "websocket"
    assert stream["wsSettings"] == {
        "path": "/edge",
        "headers": {"Host": "cdn.example"},
    }


def test_parse_trojan_requires_tls_and_keeps_password_out_of_repr():
    parsed = parse_proxy_link(
        "trojan://very-secret@vpn.example:443?security=tls&sni=cdn.example&type=ws"
        "&host=cdn.example&path=%2Fws#Trojan"
    )
    assert parsed.protocol == "trojan"
    assert parsed.name == "Trojan"
    assert "very-secret" not in repr(parsed)
    outbound = parsed.to_outbound()
    assert outbound["settings"] == {
        "address": "vpn.example",
        "port": 443,
        "password": "very-secret",
    }
    assert outbound["streamSettings"]["tlsSettings"]["serverName"] == "cdn.example"


def test_parse_vmess_base64_json_with_tls_and_websocket():
    parsed = parse_proxy_link(vmess_link({
        "v": "2", "ps": "VMess node", "add": "vmess.example",
        "port": "8443", "id": "123e4567-e89b-12d3-a456-426614174000",
        "aid": "0", "scy": "auto", "net": "ws", "host": "cdn.example",
        "path": "/vmess", "tls": "tls", "sni": "vmess.example",
    }))
    outbound = parsed.to_outbound()
    assert parsed.name == "VMess node"
    assert outbound["protocol"] == "vmess"
    assert outbound["settings"]["address"] == "vmess.example"
    assert outbound["settings"]["security"] == "auto"
    assert outbound["streamSettings"]["method"] == "websocket"
    assert outbound["streamSettings"]["tlsSettings"]["serverName"] == "vmess.example"
    assert outbound["streamSettings"]["wsSettings"]["path"] == "/vmess"


def test_parse_vmess_rejects_nonzero_legacy_alter_id():
    with pytest.raises(ValueError, match="alterId"):
        parse_proxy_link(vmess_link({
            "add": "vmess.example", "port": 443, "id": "user",
            "aid": "16", "net": "tcp",
        }))


def test_parse_shadowsocks_sip002_base64_userinfo():
    parsed = parse_proxy_link(
        "ss://" + ss_userinfo() + "@ss.example:8388#SS%20Office"
    )
    assert parsed.name == "SS Office"
    assert parsed.protocol == "shadowsocks"
    assert parsed.to_outbound()["settings"] == {
        "address": "ss.example",
        "port": 8388,
        "method": "aes-256-gcm",
        "password": "secret",
    }


def test_parse_shadowsocks_plain_sip002_userinfo():
    parsed = parse_proxy_link("ss://chacha20-poly1305:secret@ss.example:443#plain")
    assert parsed.to_outbound()["settings"]["method"] == "chacha20-poly1305"


def test_parse_shadowsocks_legacy_base64_whole_payload():
    payload = base64.urlsafe_b64encode(
        b"aes-128-gcm:secret@ss.example:443"
    ).decode().rstrip("=")
    parsed = parse_proxy_link("ss://" + payload + "#legacy")
    assert parsed.to_outbound()["settings"] == {
        "address": "ss.example",
        "port": 443,
        "method": "aes-128-gcm",
        "password": "secret",
    }


@pytest.mark.parametrize("link", [
    "http://vpn.example:443",
    "vless://@vpn.example:443?security=tls",
    "vless://user@vpn.example:0?security=tls",
    "vless://user@vpn.example:443?security=tls&security=none",
    "vless://user@vpn.example:443?security=tls&allowInsecure=1",
    "vless://user@vpn.example:443?security=reality&type=ws&sni=x&fp=chrome&pbk=key",
    "trojan://password@vpn.example:443?security=none",
    "trojan://password@vpn.example:443?plugin=obfs",
    "trojan://password@vpn.example:443?security=tls&flow=xtls-rprx-vision",
    "vless://user@vpn.example:443?type=tcp&security=tls&path=%2Fignored",
    "vless://user@vpn.example:443?security=none&sni=cdn.example",
    "ss://aes-128-cfb:password@vpn.example:443",
    "vmess://not-base64",
])
def test_unsupported_or_malformed_links_fail_closed(link):
    with pytest.raises((ValueError, TypeError)):
        parse_proxy_link(link)


def test_link_size_is_bounded():
    with pytest.raises(ValueError, match="16 KiB"):
        parse_proxy_link("vless://" + "x" * (16 * 1024))


def test_credentials_are_not_in_repr():
    parsed = parse_proxy_link("trojan://secret-password@vpn.example:443#node")
    assert "secret-password" not in repr(parsed)
    assert "secret-password" in parsed.to_outbound()["settings"]["password"]


def test_vmess_rejects_unknown_fields_instead_of_silently_ignoring_them():
    with pytest.raises(ValueError, match="unsupported fields"):
        parse_proxy_link(vmess_link({
            "add": "vmess.example", "port": 443, "id": "user",
            "aid": "0", "net": "tcp", "allowInsecure": True,
        }))


def test_vmess_rejects_non_string_host_and_user_id():
    with pytest.raises(ValueError, match="must be strings"):
        parse_proxy_link(vmess_link({
            "add": None, "port": 443, "id": "user", "aid": "0",
        }))


def test_parse_vless_tcp_reality_uses_raw_transport():
    parsed = parse_proxy_link(
        "vless://user@reality.example:443?security=reality&type=tcp"
        "&sni=cover.example&fp=chrome&pbk=public-key"
    )
    stream = parsed.to_outbound()["streamSettings"]
    assert stream["method"] == "raw"
    assert stream["realitySettings"]["publicKey"] == "public-key"


def test_parse_proxy_links_supports_atomic_multiline_import():
    links = "\n".join([
        "# ApnaWin test import",
        "vless://user@vpn.example:443?security=tls#first",
        "",
        "trojan://password@trojan.example:443#second",
        "ss://" + ss_userinfo() + "@ss.example:8388#third",
    ])
    parsed = parse_proxy_links(links)
    assert [item.protocol for item in parsed] == ["vless", "trojan", "shadowsocks"]
    assert [item.name for item in parsed] == ["first", "second", "third"]


def test_parse_proxy_links_rejects_entire_batch_when_one_line_is_invalid():
    with pytest.raises(ValueError, match="line 3"):
        parse_proxy_links(
            "vless://user@vpn.example:443?security=tls\n\nnot-a-proxy-link"
        )


def test_parse_proxy_links_rejects_empty_and_oversized_batches():
    with pytest.raises(ValueError, match="no supported profiles"):
        parse_proxy_links("# comment only\n\n")
    with pytest.raises(ValueError, match="1 MiB"):
        parse_proxy_links(b"x" * (1024 * 1024 + 1))


def test_parse_proxy_links_enforces_profile_count_limit():
    link = "vless://user@vpn.example:443?security=tls"
    with pytest.raises(ValueError, match="500-profile"):
        parse_proxy_links("\n".join([link] * 501))


@pytest.mark.parametrize("link", [
    "vless://user@bad%20host:443?security=tls",
    "trojan://password@bad%20host:443",
])
def test_proxy_links_reject_invalid_endpoint_hostnames(link):
    with pytest.raises(ValueError, match="DNS hostname"):
        parse_proxy_link(link)


def test_parse_vless_ipv6_endpoint():
    parsed = parse_proxy_link("vless://user@[2001:db8::1]:443?security=tls")
    assert parsed.server == "2001:db8::1"


def test_parse_vless_grpc_rejects_unknown_mode():
    with pytest.raises(ValueError, match="mode must be multi or gun"):
        parse_proxy_link(
            "vless://user@vpn.example:443?type=grpc&security=tls&mode=invalid"
        )


def test_parse_shadowsocks_legacy_base64_payload_with_slash():
    password = "\U00092aff𬎋"
    payload = base64.b64encode(
        f"aes-256-gcm:{password}@ss.example:443".encode("utf-8")
    ).decode("ascii")
    assert "/" in payload
    parsed = parse_proxy_link("ss://" + payload + "#legacy-slash")
    assert parsed.to_outbound()["settings"]["password"] == password

@pytest.mark.parametrize("link", [
    "trojan://secret%C2%85@vpn.example:443",
    "vless://user%C2%85@vpn.example:443?security=tls",
])
def test_proxy_links_reject_unicode_control_characters_in_credentials(link):
    with pytest.raises(ValueError, match="control characters"):
        parse_proxy_link(link)


@pytest.mark.parametrize("link", [
    "vless://user@vpn.example:443#office\u0085vpn",
    "trojan://secret@vpn.example:443?security=tls\u0085",
])
def test_proxy_links_reject_raw_unicode_control_characters(link):
    with pytest.raises(ValueError, match="control characters"):
        parse_proxy_link(link)


def test_profile_name_strips_encoded_unicode_control_characters():
    parsed = parse_proxy_link("vless://user@vpn.example:443#office%C2%85vpn")
    assert parsed.name == "officevpn"
