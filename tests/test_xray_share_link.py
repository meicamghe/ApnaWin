import base64
import json

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
    assert outbound["settings"]["vnext"][0]["users"][0]["alterId"] == 0
    assert outbound["streamSettings"]["network"] == "ws"
    assert outbound["streamSettings"]["tlsSettings"]["allowInsecure"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("port", True),
        ("port", "443/tcp"),
        ("aid", True),
        ("aid", 1.5),
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

