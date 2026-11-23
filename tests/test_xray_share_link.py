import base64
import json
import os
import subprocess

import pytest

from apnawin.domain.profile import Transport
from apnawin.engines.xray_process import inspect_tun_inbound
from apnawin.engines.xray_share_link import (
    XrayShareLinkError,
    import_xray_share_link,
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
        "&sni=front.example.test&pbk=public-key&sid=abcd&fp=chrome#Reality"
    )
    outbound = outbound_for(result)
    reality = outbound["streamSettings"]["realitySettings"]
    assert reality["serverName"] == "front.example.test"
    assert reality["publicKey"] == "public-key"
    assert reality["shortId"] == "abcd"
    assert reality["fingerprint"] == "chrome"

def test_import_vless_xhttp_reality_settings():
    result = import_xray_share_link(
        f"vless://{UUID}@edge.example.test:443?type=xhttp&security=reality"
        "&sni=front.example.test&pbk=public-key&sid=abcd&fp=chrome"
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
        "https://edge.example.test:443/",
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
