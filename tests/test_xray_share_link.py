import base64
import json
import os
import subprocess
from urllib.parse import quote

import pytest

from apnawin.domain.profile import Transport
from apnawin.engines.xray_process import inspect_tun_inbound
from apnawin.engines.xray_share_link import (
    XrayShareLinkError,
    import_xray_share_link,
    import_wireguard_config,
    import_masque_config,
)


UUID = "00000000-0000-4000-8000-000000000001"


def outbound_for(result):
    config = json.loads(result.config_bytes)
    inspect_tun_inbound(config)
    assert config["inbounds"][0]["protocol"] == "tun"
    assert config["inbounds"][0]["settings"]["autoSystemWfpBlockLeak"] == [
        "allexceptlan",
        "dns",
    ]
    return config["outbounds"][0]


@pytest.mark.parametrize(
    "uri",
    [
        f"vless://{UUID}:unexpected@edge.example.test:443?security=tls",
        "trojan://secret%7Fpassword@edge.example.test:443?security=tls",
    ],
)
def test_rejects_ambiguous_or_controlled_user_credentials(uri):
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)


@pytest.mark.parametrize(
    "uri",
    [
        f"vless://{UUID}@edge.example.test:443/ignored?security=tls",
        "trojan://secret@edge.example.test:443/ignored?security=tls",
    ],
)
def test_rejects_ignored_paths_in_authority_based_share_links(uri):
    with pytest.raises(XrayShareLinkError, match="unsupported URL path"):
        import_xray_share_link(uri)


def test_grpc_service_name_rejects_delete_control_character():
    uri = (
        f"vless://{UUID}@edge.example.test:443?type=grpc&security=tls"
        "&serviceName=bridge%7FInjected"
    )
    with pytest.raises(XrayShareLinkError, match="gRPC service name"):
        import_xray_share_link(uri)


def test_import_vless_tls_alpn_values():
    result = import_xray_share_link(
        f"vless://{UUID}@edge.example.test:443?security=tls&alpn=h2%2Chttp%2F1.1"
    )
    outbound = outbound_for(result)
    assert outbound["streamSettings"]["tlsSettings"]["alpn"] == ["h2", "http/1.1"]


@pytest.mark.parametrize(
    "alpn",
    [
        "h2%2C%2Chttp%2F1.1",
        "%2Ch2",
        "h2%2C",
        "%0A",
        "a" * 33,
        "%2C".join(["h2"] * 9),
    ],
)
def test_rejects_malformed_tls_alpn_list(alpn):
    uri = f"vless://{UUID}@edge.example.test:443?security=tls&alpn={alpn}"
    with pytest.raises(XrayShareLinkError, match="TLS ALPN"):
        import_xray_share_link(uri)


def test_import_vless_ws_tls_creates_encrypted_store_ready_profile():
    result = import_xray_share_link(
        f"vless://{UUID}@edge.example.test:443"
        "?encryption=none&type=ws&security=tls&sni=cdn.example.test"
        "&host=cdn.example.test&path=%2Fgateway#Branch%20VLESS"
    )

    assert result.profile.name == "Branch VLESS"
    assert result.profile.transport is Transport.XRAY
    assert (result.profile.endpoint_host, result.profile.endpoint_port) == (
        "edge.example.test",
        443,
    )
    outbound = outbound_for(result)
    assert outbound["protocol"] == "vless"
    assert outbound["settings"]["vnext"][0]["users"][0]["id"] == UUID
    assert outbound["streamSettings"]["network"] == "ws"
    assert outbound["streamSettings"]["security"] == "tls"
    assert outbound["streamSettings"]["tlsSettings"]["allowInsecure"] is False
    assert outbound["streamSettings"]["wsSettings"]["path"] == "/gateway"


def test_import_vless_reality_requires_public_key_sni_and_fingerprint():
    result = import_xray_share_link(
        f"vless://{UUID}@edge.example.test:443?type=tcp&security=reality"
        "&sni=front.example.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome#Reality"
    )
    outbound = outbound_for(result)
    reality = outbound["streamSettings"]["realitySettings"]
    assert reality["serverName"] == "front.example.test"
    assert reality["publicKey"] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert reality["shortId"] == "abcd"
    assert reality["fingerprint"] == "chrome"

def test_import_vless_xhttp_reality_settings():
    result = import_xray_share_link(
        f"vless://{UUID}@edge.example.test:443?type=xhttp&security=reality"
        "&sni=front.example.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome"
        "&host=cdn.example.test&path=%2Fedge&mode=packet-up#XHTTP"
    )
    outbound = outbound_for(result)
    stream = outbound["streamSettings"]
    assert stream["network"] == "xhttp"
    assert stream["xhttpSettings"] == {
        "path": "/edge",
        "mode": "packet-up",
        "host": "cdn.example.test",
    }
    assert stream["realitySettings"]["serverName"] == "front.example.test"


@pytest.mark.parametrize("mode", ["auto", "packet-up", "stream-up", "stream-one"])
def test_xhttp_accepts_supported_modes(mode):
    result = import_xray_share_link(
        f"vless://{UUID}@edge.example.test:443?type=xhttp&security=tls&mode={mode}"
    )
    assert outbound_for(result)["streamSettings"]["xhttpSettings"]["mode"] == mode


def test_xhttp_rejects_unknown_mode():
    with pytest.raises(XrayShareLinkError, match="XHTTP mode"):
        import_xray_share_link(
            f"vless://{UUID}@edge.example.test:443?type=xhttp&security=tls&mode=unknown"
        )


def test_import_vmess_base64_json():
    payload = {
        "v": "2",
        "ps": "VMess Branch",
        "add": "vmess.example.test",
        "port": "8443",
        "id": UUID,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "host": "cdn.example.test",
        "path": "/vmess",
        "tls": "tls",
        "sni": "cdn.example.test",
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    result = import_xray_share_link(f"vmess://{encoded}")
    outbound = outbound_for(result)
    assert result.profile.name == "VMess Branch"
    assert outbound["protocol"] == "vmess"
    assert "alterId" not in outbound["settings"]["vnext"][0]["users"][0]
    assert outbound["streamSettings"]["network"] == "ws"
    assert outbound["streamSettings"]["tlsSettings"]["allowInsecure"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("port", True),
        ("port", "443/tcp"),
        ("aid", True),
        ("aid", 1.5),
        ("aid", "1"),
        ("scy", "none"),
        ("scy", "zero"),
        ("tls", "xtls"),
        ("tls", True),
    ],
)
def test_vmess_rejects_invalid_numeric_and_tls_fields(field, value):
    payload = {
        "v": "2",
        "ps": "VMess invalid",
        "add": "vmess.example.test",
        "port": "443",
        "id": UUID,
        "aid": "0",
        "scy": "auto",
        "net": "tcp",
        "tls": "tls",
    }
    payload[field] = value
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(f"vmess://{encoded}")


def test_import_trojan_tls_grpc():
    result = import_xray_share_link(
        "trojan://secret-pass@trojan.example.test:443"
        "?security=tls&type=grpc&serviceName=bridge&sni=front.example.test#Trojan"
    )
    outbound = outbound_for(result)
    assert outbound["protocol"] == "trojan"
    assert outbound["settings"]["servers"][0]["password"] == "secret-pass"
    assert outbound["streamSettings"]["grpcSettings"]["serviceName"] == "bridge"


def test_import_shadowsocks_sip002_base64_userinfo():
    credentials = base64.urlsafe_b64encode(
        b"chacha20-ietf-poly1305:secret-pass"
    ).decode().rstrip("=")
    result = import_xray_share_link(
        f"ss://{credentials}@ss.example.test:8388#Shadowsocks"
    )
    outbound = outbound_for(result)
    assert outbound["protocol"] == "shadowsocks"
    assert outbound["settings"]["servers"][0]["method"] == "chacha20-ietf-poly1305"
    assert outbound["settings"]["servers"][0]["password"] == "secret-pass"


@pytest.mark.parametrize(
    "uri",
    [
        f"vless://{UUID}@edge.example.test:443?type=unknown",
        f"vless://{UUID}@edge.example.test:443?security=tls&allowInsecure=true",
        f"vless://{UUID}@edge.example.test:443?type=ws&type=grpc",
        "trojan://password@edge.example.test:443?security=none",
        "ss://YWVzLTEyOC1nY206cGFzcw==@ss.example.test:8388?plugin=obfs-local",
    ],
)
def test_rejects_unsupported_or_unsafe_share_links(uri):
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)


@pytest.mark.parametrize(
    "document",
    [
        (
            '{"add":"vmess.example.test","add":"other.example.test",'
            '"port":"443","id":"' + UUID + '","aid":"0","net":"tcp","tls":"tls"}'
        ),
        (
            '{"add":"vmess.example.test","port":"443","id":"' + UUID
            + '","aid":"0","net":"tcp","tls":"tls","extra":NaN}'
        ),
    ],
)
def test_vmess_rejects_duplicate_fields_and_non_finite_json(document):
    encoded = base64.urlsafe_b64encode(document.encode()).decode().rstrip("=")
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(f"vmess://{encoded}")


def test_share_link_query_has_a_bounded_parameter_count():
    parameters = "&".join(f"x{index}=1" for index in range(129))
    uri = f"vless://{UUID}@edge.example.test:443?{parameters}"
    with pytest.raises(XrayShareLinkError, match="too many parameters"):
        import_xray_share_link(uri)


def test_trojan_rejects_unescaped_second_userinfo_field():
    with pytest.raises(XrayShareLinkError, match="single URL user-info"):
        import_xray_share_link("trojan://secret:ignored@edge.example.test:443?security=tls")


def test_trojan_accepts_colon_when_percent_encoded_in_password():
    result = import_xray_share_link(
        "trojan://secret%3Avalue@edge.example.test:443?security=tls"
    )
    outbound = outbound_for(result)
    assert outbound["settings"]["servers"][0]["password"] == "secret:value"


@pytest.mark.parametrize(
    "uri",
    [
        "ss://aes-256-gcm:secret%0Ainjected@ss.example.test:8388",
        "ss://aes-256-gcm:secret%7Finjected@ss.example.test:8388",
    ],
)
def test_shadowsocks_rejects_control_characters_in_password(uri):
    with pytest.raises(XrayShareLinkError, match="control characters"):
        import_xray_share_link(uri)


def test_shadowsocks_invalid_utf8_credentials_raise_safe_import_error():
    encoded = base64.urlsafe_b64encode(
        bytes([0xFF]) + b"@ss.example.test:8388"
    ).decode().rstrip("=")
    with pytest.raises(XrayShareLinkError, match="UTF-8"):
        import_xray_share_link(f"ss://{encoded}")


def test_trojan_rejects_case_insensitive_no_tls_security():
    uri = "trojan://secret@edge.example.test:443?security=NONE"
    with pytest.raises(XrayShareLinkError, match="TLS or Reality"):
        import_xray_share_link(uri)


def test_invalid_vmess_payload_does_not_leak_payload_in_error():
    with pytest.raises(XrayShareLinkError) as error:
        import_xray_share_link("vmess://not-base64")
    assert "not-base64" not in str(error.value)

@pytest.mark.parametrize(
    "uri",
    [
        "vless://[broken-ipv6:443",
        "vmess://[broken-ipv6",
        f"vless://{UUID}@edge.example.test:443?type=ws&path=%2Fbad%0Apath",
        f"trojan://secret@edge.example.test:443\n?security=tls",
    ],
)
def test_rejects_malformed_urls_and_control_characters(uri):
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)

@pytest.mark.parametrize(
    ("userinfo", "expected_password"),
    [
        ("aes-256-gcm:p%40ss%3Aword", "p@ss:word"),
        ("aes-256-gcm%3Ap%40ss%3Aword", "p@ss:word"),
    ],
)
def test_shadowsocks_decodes_percent_encoded_sip002_credentials(userinfo, expected_password):
    result = import_xray_share_link(
        f"ss://{userinfo}@ss.example.test:8388#Encoded%20credentials"
    )
    outbound = outbound_for(result)
    assert outbound["settings"]["servers"][0]["method"] == "aes-256-gcm"
    assert outbound["settings"]["servers"][0]["password"] == expected_password

@pytest.mark.parametrize(
    "uri",
    [
        f"vless://{UUID}@edge.example.test:443?type=ws&security=reality&sni=front.example.test&pbk=key&fp=chrome",
        f"trojan://secret@edge.example.test:443?type=httpupgrade&security=reality&sni=front.example.test&pbk=key&fp=chrome",
        f"vless://{UUID}@edge.example.test:443?type=ws&security=tls&flow=xtls-rprx-vision",
        f"vless://{UUID}@edge.example.test:443?type=tcp&security=none&flow=xtls-rprx-vision",
    ],
)
def test_rejects_runtime_incompatible_reality_and_vision_combinations(uri):
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)


@pytest.mark.parametrize(
    "uri",
    [
        f"vless://{UUID}@edge.example.test:443?type=httpupgrade&path=%2F" + ("a" * 2049),
        f"vless://{UUID}@edge.example.test:443?type=httpupgrade&path=%2Fbad%7Fpath",
        f"vless://{UUID}@edge.example.test:443?type=ws&path=%2Fbad%01path",
    ],
)
def test_rejects_invalid_or_oversized_transport_paths(uri):
    with pytest.raises(XrayShareLinkError, match="path is invalid"):
        import_xray_share_link(uri)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ("security=tls&sni=front.example.test%0Aevil", "TLS server name"),
        (
            "security=reality&sni=front.example.test%7Fevil"
            "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome",
            "Reality server name",
        ),
        ("type=grpc&security=tls&authority=front.example.test%0DInjected", "gRPC authority"),
        (
            "security=reality&sni=front.example.test"
            "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&spx=%2Fpath%0AInjected",
            "Reality spiderX",
        ),
    ],
)
def test_rejects_control_characters_in_xray_transport_options(options, message):
    uri = f"vless://{UUID}@edge.example.test:443?{options}"
    with pytest.raises(XrayShareLinkError, match=message):
        import_xray_share_link(uri)


def test_vless_vision_flow_accepts_tcp_with_reality():
    result = import_xray_share_link(
        f"vless://{UUID}@edge.example.test:443?type=tcp&security=reality"
        "&sni=front.example.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&flow=xtls-rprx-vision"
    )
    outbound = outbound_for(result)
    assert outbound["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"

@pytest.mark.parametrize(
    "parameters",
    [
        "pbk=key&sid=abcd",
        "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+&sid=abcd",
        "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abc",
        "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef00",
    ],
)
def test_reality_rejects_invalid_public_key_or_short_id(parameters):
    uri = (
        f"vless://{UUID}@edge.example.test:443?type=tcp&security=reality"
        f"&sni=front.example.test&fp=chrome&{parameters}"
    )
    with pytest.raises(XrayShareLinkError, match="Reality"):
        import_xray_share_link(uri)

@pytest.mark.parametrize(
    "method",
    [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-poly1305",
        "chacha20-ietf-poly1305",
        "xchacha20-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ],
)
def test_imports_documented_xray_shadowsocks_cipher_methods(method):
    result = import_xray_share_link(
        f"ss://{method}:secret-pass@ss.example.test:8388#Cipher%20test"
    )
    outbound = outbound_for(result)
    assert outbound["settings"]["servers"][0]["method"] == method

@pytest.mark.skipif(
    not os.environ.get("APNAWIN_XRAY_EXECUTABLE"),
    reason="Pinned Xray runtime validation is enabled only in the dedicated CI job",
)
@pytest.mark.parametrize(
    "uri",
    [
        # VLESS: TCP/WS TLS, gRPC REALITY, and Vision over REALITY.
        f"vless://{UUID}@vless.example.test:443?type=tcp&security=tls&sni=vless.example.test",
        f"vless://{UUID}@vless.example.test:443?type=ws&security=tls&sni=cdn.example.test&host=cdn.example.test&path=%2Fvless",
        f"vless://{UUID}@vless.example.test:443?type=grpc&security=reality&sni=vless.example.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd1234&fp=chrome&serviceName=vless-grpc",
        f"vless://{UUID}@vless.example.test:443?type=tcp&security=reality&sni=vless.example.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd1234&fp=chrome&flow=xtls-rprx-vision",
        f"vless://{UUID}@vless.example.test:443?type=xhttp&security=reality&sni=vless.example.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd1234&fp=chrome&path=%2Fvless&mode=packet-up",
        # VMess: TCP, WebSocket, gRPC, HTTPUpgrade and XHTTP over TLS.
        f"vmess://{base64.urlsafe_b64encode(json.dumps({'v':'2','ps':'runtime-vmess-tcp','add':'vmess.example.test','port':'443','id':UUID,'aid':'0','scy':'auto','net':'tcp','tls':'tls','sni':'vmess.example.test'}).encode()).decode().rstrip('=')}",
        f"vmess://{base64.urlsafe_b64encode(json.dumps({'v':'2','ps':'runtime-vmess-ws','add':'vmess.example.test','port':'443','id':UUID,'aid':'0','scy':'auto','net':'ws','host':'cdn.example.test','path':'/vmess','tls':'tls','sni':'cdn.example.test'}).encode()).decode().rstrip('=')}",
        f"vmess://{base64.urlsafe_b64encode(json.dumps({'v':'2','ps':'runtime-vmess-grpc','add':'vmess.example.test','port':'443','id':UUID,'aid':'0','scy':'auto','net':'grpc','path':'vmess-grpc','tls':'tls','sni':'vmess.example.test'}).encode()).decode().rstrip('=')}",
        f"vmess://{base64.urlsafe_b64encode(json.dumps({'v':'2','ps':'runtime-vmess-xhttp','add':'vmess.example.test','port':'443','id':UUID,'aid':'0','scy':'auto','net':'xhttp','host':'cdn.example.test','path':'/xhttp','mode':'packet-up','tls':'tls','sni':'vmess.example.test'}).encode()).decode().rstrip('=')}",
        # Trojan: TCP, WebSocket, gRPC, HTTPUpgrade and XHTTP over TLS.
        "trojan://runtime-password@trojan.example.test:443?security=tls&type=tcp&sni=trojan.example.test",
        "trojan://runtime-password@trojan.example.test:443?security=tls&type=ws&sni=trojan.example.test&host=cdn.example.test&path=%2Ftrojan",
        "trojan://runtime-password@trojan.example.test:443?security=tls&type=grpc&sni=trojan.example.test&serviceName=trojan-grpc",
        "trojan://runtime-password@trojan.example.test:443?security=tls&type=httpupgrade&sni=trojan.example.test&host=cdn.example.test&path=%2Fupgrade",
        "trojan://runtime-password@trojan.example.test:443?security=tls&type=xhttp&sni=trojan.example.test&path=%2Ftrojan&mode=stream-up",
        # Shadowsocks: representative AEAD and XChaCha20 cipher implementations.
        "ss://chacha20-ietf-poly1305:runtime-password@ss.example.test:8388",
        "ss://aes-256-gcm:runtime-password@ss.example.test:8388",
        "ss://xchacha20-ietf-poly1305:runtime-password@ss.example.test:8388",
        # Shadowsocks 2022 requires a correctly sized Base64-encoded master key.
        f"ss://{base64.urlsafe_b64encode(b'2022-blake3-aes-128-gcm:' + base64.b64encode(b'A' * 16)).decode().rstrip('=')}@ss.example.test:8388",
        f"ss://{base64.urlsafe_b64encode(b'2022-blake3-aes-256-gcm:' + base64.b64encode(b'B' * 32)).decode().rstrip('=')}@ss.example.test:8388",
        f"ss://{base64.urlsafe_b64encode(b'2022-blake3-chacha20-poly1305:' + base64.b64encode(b'C' * 32)).decode().rstrip('=')}@ss.example.test:8388",
    ],
)
def test_generated_config_is_accepted_by_pinned_xray_runtime(uri, tmp_path):
    executable = os.environ["APNAWIN_XRAY_EXECUTABLE"]
    result = import_xray_share_link(uri)
    config_path = tmp_path / "xray-runtime-config.json"
    config_path.write_bytes(result.config_bytes)
    completed = subprocess.run(
        [executable, "run", "-test", "-c", str(config_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, (
        f"Xray rejected {result.protocol} config: "
        f"{completed.stdout[-2000:]} {completed.stderr[-2000:]}"
    )


def _wireguard_sample() -> str:
    private_key = base64.b64encode(b"A" * 32).decode()
    public_key = base64.b64encode(b"B" * 32).decode()
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        "Address = 10.66.0.2/32, fd00::2/128\n"
        "DNS = 1.1.1.1, 2606:4700:4700::1111\n"
        "MTU = 1380\n\n"
        "[Peer]\n"
        f"PublicKey = {public_key}\n"
        "Endpoint = wg.example.test:51820\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )


def test_import_hysteria2_uri_builds_tls_quic_outbound():
    result = import_xray_share_link(
        "hysteria2://my%3Asecret@hy.example.test:443"
        "?sni=front.example.test#HY2%20Primary"
    )
    outbound = outbound_for(result)
    assert result.profile.name == "HY2 Primary"
    assert outbound["protocol"] == "hysteria"
    assert outbound["settings"] == {
        "version": 2, "address": "hy.example.test", "port": 443
    }
    assert outbound["streamSettings"]["method"] == "hysteria"
    assert outbound["streamSettings"]["hysteriaSettings"] == {
        "version": 2, "auth": "my:secret"
    }
    assert outbound["streamSettings"]["tlsSettings"] == {
        "serverName": "front.example.test", "allowInsecure": False
    }


def test_hysteria2_defaults_port_and_rejects_insecure_or_unmapped_features():
    result = import_xray_share_link("hy2://secret@hy.example.test#DefaultPort")
    assert result.profile.endpoint_port == 443
    for uri in (
        "hy2://secret@hy.example.test?insecure=1",
        "hy2://secret@hy.example.test?obfs=salamander&obfs-password=secret",
        "hy2://secret@hy.example.test?pinSHA256=deadbeef",
        "hy2://secret@hy.example.test?ech=YWJj",
    ):
        with pytest.raises(XrayShareLinkError):
            import_xray_share_link(uri)


def test_import_wireguard_ini_builds_xray_wireguard_outbound():
    result = import_wireguard_config(_wireguard_sample(), profile_name="WG Branch")
    outbound = outbound_for(result)
    assert result.profile.name == "WG Branch"
    assert result.profile.transport is Transport.XRAY
    assert outbound["protocol"] == "wireguard"
    settings = outbound["settings"]
    assert settings["address"] == ["10.66.0.2", "fd00::2"]
    assert settings["mtu"] == 1380
    assert settings["remoteDNS"] == ["1.1.1.1", "2606:4700:4700::1111"]
    assert settings["peers"][0]["endpoint"] == "wg.example.test:51820"
    assert settings["peers"][0]["keepAlive"] == 25
    assert settings["peers"][0]["allowedIPs"] == ["0.0.0.0/0", "::/0"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("PrivateKey =", "PrivateKey = invalid #"),
        lambda text: text.replace("Endpoint = wg.example.test:51820", "Endpoint = wg.example.test"),
        lambda text: text.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = not-a-prefix"),
        lambda text: text.replace("MTU = 1380", "MTU = 99999"),
        lambda text: text.replace("PersistentKeepalive = 25", "PersistentKeepalive = -1"),
    ],
)
def test_wireguard_import_rejects_invalid_settings(mutation):
    with pytest.raises(XrayShareLinkError):
        import_wireguard_config(mutation(_wireguard_sample()))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("DNS = 1.1.1.1, 2606:4700:4700::1111", "DNS = 1.1.1.1, 1.1.1.1"),
        lambda text: text.replace("DNS = 1.1.1.1, 2606:4700:4700::1111", "DNS = 224.0.0.1"),
        lambda text: text.replace("Address = 10.66.0.2/32, fd00::2/128", "Address = 10.66.0.2/32, 10.66.0.2/24"),
        lambda text: text.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/0, 0.0.0.0/0"),
    ],
)
def test_wireguard_import_rejects_duplicate_or_unusable_network_fields(mutation):
    with pytest.raises(XrayShareLinkError):
        import_wireguard_config(mutation(_wireguard_sample()))


@pytest.mark.parametrize(
    "second_public_key,second_allowed_ips,error",
    [
        (base64.b64encode(b"B" * 32).decode(), "192.0.2.0/24", "public keys must be unique"),
        (base64.b64encode(b"C" * 32).decode(), "0.0.0.0/0", "assigned to multiple peers"),
    ],
)
def test_wireguard_rejects_ambiguous_multi_peer_routing(
    second_public_key, second_allowed_ips, error
):
    config = _wireguard_sample() + (
        "\n[Peer]\n"
        f"PublicKey = {second_public_key}\n"
        "Endpoint = wg-backup.example.test:51820\n"
        f"AllowedIPs = {second_allowed_ips}\n"
    )
    with pytest.raises(XrayShareLinkError, match=error):
        import_wireguard_config(config)


@pytest.mark.skipif(
    not os.environ.get("APNAWIN_XRAY_EXECUTABLE"),
    reason="Pinned Xray runtime validation is enabled only in the dedicated CI job",
)
@pytest.mark.parametrize(
    "protocol_input",
    ["hysteria2", "wireguard"],
)
def test_new_protocol_configs_are_accepted_by_pinned_xray_runtime(protocol_input, tmp_path):
    executable = os.environ["APNAWIN_XRAY_EXECUTABLE"]
    if protocol_input == "hysteria2":
        result = import_xray_share_link("hysteria2://runtime-password@hy.example.test:443?sni=hy.example.test")
    else:
        result = import_wireguard_config(_wireguard_sample(), profile_name="runtime-wireguard")
    config_path = tmp_path / f"xray-{protocol_input}.json"
    config_path.write_bytes(result.config_bytes)
    completed = subprocess.run(
        [executable, "run", "-test", "-c", str(config_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, (
        f"Xray rejected {protocol_input} config: "
        f"{completed.stdout[-2000:]} {completed.stderr[-2000:]}"
    )


@pytest.mark.parametrize(
    "uri",
    [
        "hy2://@hy.example.test:443",
        "hy2://secret@hy.example.test:443?unknown-option=1",
    ],
)
def test_hysteria2_rejects_missing_auth_and_unknown_options(uri):
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)


@pytest.mark.parametrize(
    "endpoint",
    [
        "user@wg.example.test:51820",
        "wg.example.test:51820/path",
        "wg.example.test:51820?query=1",
        "wg.example.test:51820#fragment",
    ],
)
def test_wireguard_rejects_non_endpoint_uri_components(endpoint):
    config = _wireguard_sample().replace(
        "wg.example.test:51820", endpoint
    )
    with pytest.raises(XrayShareLinkError, match="Endpoint"):
        import_wireguard_config(config)



@pytest.mark.parametrize(
    "allowed_ips",
    ["0.0.0.0/0", "::/0", "10.0.0.0/8, ::/0", "0.0.0.0/0, 2001:db8::/32"],
)
def test_wireguard_full_tunnel_requires_both_default_routes(allowed_ips):
    config = _wireguard_sample().replace(
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"AllowedIPs = {allowed_ips}",
    )
    with pytest.raises(XrayShareLinkError, match="default AllowedIPs route"):
        import_wireguard_config(config)


def _masque_sample() -> str:
    return json.dumps({
        "protocol": "masque",
        "settings": {
            "address": "masque.example.test",
            "port": 443,
            "remoteDNS": ["1.1.1.1", "2606:4700:4700::1111"],
        },
        "streamSettings": {
            "network": "masque",
            "security": "tls",
            "tlsSettings": {"serverName": "masque.example.test", "alpn": ["h3"]},
            "masqueSettings": {
                "host": "masque.example.test",
                "path": "/.well-known/masque/ip/{target}/{ipproto}/",
                "user": "client@example.test",
                "pass": "runtime-secret",
                "headers": {"X-Client": "apnawin-test"},
            },
        },
    })


def test_import_masque_json_outbound_builds_tls_connect_ip_tun():
    result = import_masque_config(_masque_sample(), profile_name="MASQUE Branch")
    outbound = outbound_for(result)
    assert result.profile.name == "MASQUE Branch"
    assert result.protocol == "masque"
    assert outbound["protocol"] == "masque"
    assert outbound["settings"]["remoteDNS"] == ["1.1.1.1", "2606:4700:4700::1111"]
    assert outbound["streamSettings"]["network"] == "masque"
    assert outbound["streamSettings"]["security"] == "tls"
    assert outbound["streamSettings"]["masqueSettings"]["user"] == "client@example.test"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["streamSettings"].update(security="reality"),
        lambda d: d["streamSettings"].update(network="tcp"),
        lambda d: d["streamSettings"].update(masqueSettings={"path": "/bad/{unknown}/"}),
        lambda d: d["streamSettings"].update(tlsSettings={"allowInsecure": True}),
        lambda d: d.update(mux={"enabled": True}),
        lambda d: d["settings"].update(remoteDNS=["not-an-ip"]),
        lambda d: d["streamSettings"]["masqueSettings"].update(user="bad:user"),
    ],
)
def test_masque_import_rejects_unsupported_or_unsafe_options(mutate):
    document = json.loads(_masque_sample())
    mutate(document)
    with pytest.raises(XrayShareLinkError):
        import_masque_config(json.dumps(document))


@pytest.mark.parametrize(
    "uri,protocol",
    [
        ("socks5://user:pass@socks.example.test:1080#SOCKS", "socks"),
        ("socks://socks.example.test:1080#SOCKS-NoAuth", "socks"),
        ("http://user:pass@proxy.example.test:8080#HTTP", "http"),
        ("https://user:pass@proxy.example.test:443?sni=front.example.test#HTTPS", "http"),
    ],
)
def test_import_tcp_proxy_share_links(uri, protocol):
    result = import_xray_share_link(uri)
    outbound = outbound_for(result)
    assert result.protocol == protocol
    assert outbound["protocol"] == protocol
    assert outbound["settings"]["servers"][0]["address"] in {
        "socks.example.test", "proxy.example.test"
    }


@pytest.mark.parametrize(
    "uri",
    [
        "socks5://user@socks.example.test:1080",
        "socks5://socks.example.test:1080/path",
        "http://proxy.example.test:8080?unknown=1",
        "https://proxy.example.test:443?sni=%0Ainvalid",
    ],
)
def test_proxy_share_links_reject_ambiguous_or_unsupported_fields(uri):
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)


@pytest.mark.skipif(
    not os.environ.get("APNAWIN_XRAY_EXECUTABLE"),
    reason="Pinned Xray runtime validation is enabled only in the dedicated CI job",
)
@pytest.mark.parametrize("kind", ["masque", "socks", "http"])
def test_remaining_xray_protocol_configs_are_accepted_by_pinned_runtime(kind, tmp_path):
    executable = os.environ["APNAWIN_XRAY_EXECUTABLE"]
    if kind == "masque":
        result = import_masque_config(_masque_sample())
    else:
        uri = (
            "socks5://user:pass@socks.example.test:1080"
            if kind == "socks"
            else "https://user:pass@proxy.example.test:443?sni=proxy.example.test"
        )
        result = import_xray_share_link(uri)
    config_path = tmp_path / f"xray-{kind}.json"
    config_path.write_bytes(result.config_bytes)
    completed = subprocess.run(
        [executable, "run", "-test", "-c", str(config_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, (
        f"Xray rejected {kind} config: {completed.stdout[-2000:]} {completed.stderr[-2000:]}"
    )


@pytest.mark.parametrize(
    "network,query",
    [
        ("kcp", "headerType=none"),
        ("mkcp", "mtu=1300&tti=30&uplinkCapacity=10&downlinkCapacity=80"),
        ("kcp", "headerType=dtls"),
        ("kcp", "seed=shared-secret"),
        ("kcp", "headerType=dns&seed=dns.example.test"),
    ],
)
def test_import_mkcp_transport_and_legacy_masks(network, query):
    uri = f"vless://{UUID}@kcp.example.test:443?type={network}&security=tls&{query}"
    result = import_xray_share_link(uri)
    outbound = outbound_for(result)
    stream = outbound["streamSettings"]
    assert stream["network"] == "mkcp"
    assert "kcpSettings" in stream
    if "headerType" in query or "seed=" in query:
        assert stream["finalmask"]["udp"][0]["type"] == "mkcp-legacy"


@pytest.mark.parametrize(
    "query",
    [
        "mtu=575",
        "mtu=1461",
        "tti=9",
        "tti=101",
        "uplinkCapacity=-1",
        "headerType=unknown",
        "headerType=dtls&seed=not-used",
    ],
)
def test_mkcp_rejects_invalid_legacy_or_numeric_options(query):
    uri = f"vless://{UUID}@kcp.example.test:443?type=kcp&security=none&{query}"
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)


@pytest.mark.skipif(
    not os.environ.get("APNAWIN_XRAY_EXECUTABLE"),
    reason="Pinned Xray runtime validation is enabled only in the dedicated CI job",
)
@pytest.mark.parametrize(
    "uri",
    [
        f"vless://{UUID}@kcp.example.test:443?type=mkcp",
        f"vless://{UUID}@kcp.example.test:443?type=kcp&headerType=dtls",
        f"vless://{UUID}@kcp.example.test:443?type=kcp&seed=legacy-seed",
    ],
)
def test_mkcp_configs_are_accepted_by_pinned_xray_runtime(uri, tmp_path):
    executable = os.environ["APNAWIN_XRAY_EXECUTABLE"]
    result = import_xray_share_link(uri)
    config_path = tmp_path / "xray-mkcp.json"
    config_path.write_bytes(result.config_bytes)
    completed = subprocess.run(
        [executable, "run", "-test", "-c", str(config_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, (
        f"Xray rejected mKCP config: {completed.stdout[-2000:]} {completed.stderr[-2000:]}"
    )


def test_xhttp_import_preserves_validated_extra_and_xmux_options():
    extra = {
        "headers": {"User-Agent": "ApnaWin/1.0"},
        "xPaddingBytes": "100-1000",
        "noGRPCHeader": False,
        "scMaxEachPostBytes": 1000000,
        "xmux": {"maxConcurrency": "16-32", "hMaxReusableSecs": "1800-3000"},
    }
    uri = (
        f"vless://{UUID}@xhttp.example.test:443?type=xhttp&security=tls"
        f"&sni=xhttp.example.test&extra={quote(json.dumps(extra))}"
    )
    result = import_xray_share_link(uri)
    xhttp = outbound_for(result)["streamSettings"]["xhttpSettings"]
    assert xhttp["extra"]["headers"]["User-Agent"] == "ApnaWin/1.0"
    assert xhttp["extra"]["xPaddingBytes"] == "100-1000"
    assert xhttp["extra"]["xmux"]["maxConcurrency"] == "16-32"


def test_xhttp_import_supports_tls_download_settings():
    extra = {
        "downloadSettings": {
            "address": "download.example.test",
            "port": 443,
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": {"serverName": "download.example.test", "alpn": ["h2"]},
            "xhttpSettings": {"path": "/down", "mode": "auto"},
        }
    }
    uri = (
        f"vless://{UUID}@xhttp.example.test:443?type=xhttp&security=tls"
        f"&sni=xhttp.example.test&mode=stream-up&extra={quote(json.dumps(extra))}"
    )
    result = import_xray_share_link(uri)
    download = outbound_for(result)["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]
    assert download["address"] == "download.example.test"
    assert download["xhttpSettings"]["path"] == "/down"


@pytest.mark.parametrize(
    "extra",
    [
        {"xPaddingBytes": "1000-100"},
        {"xmux": {"unknownField": 1}},
        {"headers": {"Bad Header": "value"}},
        {"noGRPCHeader": "false"},
        {"downloadSettings": {"address": "download.example.test", "port": 443, "network": "tcp", "security": "tls"}},
        {"downloadSettings": {"address": "download.example.test", "port": 443, "network": "xhttp", "security": "tls", "tlsSettings": {"allowInsecure": True}, "xhttpSettings": {"path": "/down"}}},
    ],
)
def test_xhttp_import_rejects_invalid_extra_options(extra):
    uri = (
        f"vless://{UUID}@xhttp.example.test:443?type=xhttp&security=tls"
        f"&extra={quote(json.dumps(extra))}"
    )
    with pytest.raises(XrayShareLinkError):
        import_xray_share_link(uri)


@pytest.mark.skipif(
    not os.environ.get("APNAWIN_XRAY_EXECUTABLE"),
    reason="Pinned Xray runtime validation is enabled only in the dedicated CI job",
)
@pytest.mark.parametrize("with_download", [False, True])
def test_xhttp_extra_configs_are_accepted_by_pinned_runtime(with_download, tmp_path):
    executable = os.environ["APNAWIN_XRAY_EXECUTABLE"]
    extra = {"headers": {"User-Agent": "ApnaWin/1.0"}, "xmux": {"maxConcurrency": "16-32"}}
    if with_download:
        extra["downloadSettings"] = {
            "address": "download.example.test",
            "port": 443,
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": {"serverName": "download.example.test", "alpn": ["h2"]},
            "xhttpSettings": {"path": "/down", "mode": "auto"},
        }
    uri = (
        f"vless://{UUID}@xhttp.example.test:443?type=xhttp&security=tls"
        f"&sni=xhttp.example.test&extra={quote(json.dumps(extra))}"
    )
    result = import_xray_share_link(uri)
    config_path = tmp_path / "xray-xhttp-extra.json"
    config_path.write_bytes(result.config_bytes)
    completed = subprocess.run(
        [executable, "run", "-test", "-c", str(config_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, (
        f"Xray rejected XHTTP extra config: {completed.stdout[-2000:]} {completed.stderr[-2000:]}"
    )
