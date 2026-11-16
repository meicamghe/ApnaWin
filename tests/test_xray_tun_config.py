import copy
import json

import pytest

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.engines import xray_process
from apnawin.engines.xray_process import (
    XrayTunInbound,
    XrayProcessRunner,
    inspect_tun_inbound,
    inspect_xray_inbound,
)


def valid_tun_config():
    return {
        "inbounds": [{
            "protocol": "tun",
            "port": 0,
            "tag": "system-tun",
            "settings": {
                "name": "ApnaWin",
                "desc": "Wintun",
                "mtu": 1500,
                "gateway": ["10.255.0.1/30", "fd42:6170:6e61:7769::1/64"],
                "dns": ["1.1.1.1", "2606:4700:4700::1111"],
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto",
                "autoSystemWfpBlockLeak": ["allexceptlan", "dns"],
            },
        }],
        "outbounds": [{"protocol": "vless", "settings": {}}],
    }


def test_inspect_tun_inbound_accepts_full_dual_stack_wfp_protected_config():
    inbound = inspect_tun_inbound(valid_tun_config())
    assert isinstance(inbound, XrayTunInbound)
    assert inbound.name == "ApnaWin"
    assert inbound.mtu == 1500
    assert inbound.gateway == ("10.255.0.1/30", "fd42:6170:6e61:7769::1/64")
    assert inbound.dns == ("1.1.1.1", "2606:4700:4700::1111")
    assert inbound.routes == ("0.0.0.0/0", "::/0")
    assert inbound.auto_outbounds_interface == "auto"
    assert inbound.leak_protection == ("allexceptlan", "dns")


def test_inspect_xray_inbound_selects_tun_mode():
    assert isinstance(inspect_xray_inbound(valid_tun_config()), XrayTunInbound)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda c: c["inbounds"].append(copy.deepcopy(c["inbounds"][0])), "exactly one"),
        (lambda c: c["inbounds"][0].update(protocol="socks"), "TUN protocol"),
        (lambda c: c["inbounds"][0].update(port=1080), "port"),
        (lambda c: c["inbounds"][0].update(port=False), "port"),
        (lambda c: c["inbounds"][0]["settings"].update(listen="0.0.0.0"), "unsupported fields"),
        (lambda c: c["inbounds"][0]["settings"].update(name="bad';command"), "safe Windows adapter alias"),
        (lambda c: c["inbounds"][0]["settings"].update(name="bad\\nalias"), "safe Windows adapter alias"),
        (lambda c: c["inbounds"][0]["settings"].update(mtu=True), "MTU"),
        (lambda c: c["inbounds"][0]["settings"].update(mtu=9001), "MTU"),
        (lambda c: c["inbounds"][0]["settings"].update(gateway=["10.0.0.1/30"]), "one IPv4 and one IPv6"),
        (lambda c: c["inbounds"][0]["settings"].update(gateway=["10.0.0.1/30", "10.0.0.2/30"]), "one prefix per IP family"),
        (lambda c: c["inbounds"][0]["settings"].update(gateway=["169.254.0.1/16", "fd42:6170:6e61:7769::1/64"]), "usable unicast"),
        (lambda c: c["inbounds"][0]["settings"].update(dns=[]), "1 to 8"),
        (lambda c: c["inbounds"][0]["settings"].update(dns=["1.1.1.1", "1.1.1.1"]), "unique"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemRoutingTable=["0.0.0.0/0"]), "both IPv4 and IPv6"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemRoutingTable=["0.0.0.0/1", "::/0"]), "unique IPv4 and IPv6 defaults"),
        (lambda c: c["inbounds"][0]["settings"].update(autoOutboundsInterface=""), "autoOutboundsInterface"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak=[]), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak=None), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak="allexceptlan,dns"), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak=["allexceptlan"]), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak=["allexceptlan", "dns", "extra"]), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak=["allexceptlan", "allexceptlan"]), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak=["allexceptlan", 1]), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemWfpBlockLeak=["allexceptlan", "DNS"]), "allexceptlan and dns"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemDnsToGateway=True), "must be false"),
        (lambda c: c["inbounds"][0]["settings"].update(autoSystemDnsToGateway="false"), "must be false"),
        (lambda c: c["inbounds"][0]["settings"].update(extra="no"), "unsupported fields"),
        (lambda c: c["outbounds"][0].update(protocol="freedom"), "direct or unsupported outbound"),
        (lambda c: c["outbounds"][0].update(protocol="blackhole"), "first Xray TUN outbound must be a remote proxy"),
        (lambda c: c["outbounds"].append({"protocol": "dns", "tag": "dns-out"}), "direct or unsupported outbound"),
        (lambda c: c["outbounds"].append({"protocol": "freedom", "tag": "direct"}), "direct or unsupported outbound"),
        (lambda c: c["outbounds"][0].update(protocol="unknown-protocol"), "direct or unsupported outbound"),
        (lambda c: c["outbounds"][0].update(protocol="tuic"), "direct or unsupported outbound"),
        (lambda c: c["outbounds"][0].update(protocol="hysteria2"), "direct or unsupported outbound"),
        (lambda c: c["outbounds"].clear(), "at least one outbound"),
    ],
)
def test_inspect_tun_inbound_rejects_unsafe_or_incomplete_config(mutate, message):
    config = valid_tun_config()
    mutate(config)
    with pytest.raises(ValueError, match=message):
        inspect_tun_inbound(config)


def test_inspect_tun_inbound_allows_loopback_dns_for_local_resolver():
    config = valid_tun_config()
    config["inbounds"][0]["settings"]["dns"] = ["127.0.0.1"]
    assert inspect_tun_inbound(config).dns == ("127.0.0.1",)


def test_inspect_xray_inbound_keeps_existing_loopback_socks_mode():
    config = {
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}],
        "outbounds": [],
    }
    assert inspect_xray_inbound(config).host == "127.0.0.1"


def test_inspect_xray_inbound_rejects_unknown_protocol():
    with pytest.raises(ValueError, match="SOCKS or TUN"):
        inspect_xray_inbound({"inbounds": [{"protocol": "http"}]})


def test_windows_tun_requires_wintun_dll_beside_xray_executable(monkeypatch, tmp_path):
    executable = tmp_path / "xray.exe"
    executable.touch()
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_tun_config()), encoding="utf-8")
    profile = ConnectionProfile("test", Transport.XRAY, "127.0.0.1", 443)
    runner = XrayProcessRunner(executable, config_path)
    monkeypatch.setattr(xray_process.os, "name", "nt")
    with pytest.raises(FileNotFoundError, match="wintun.dll"):
        runner._validate_inputs(profile)
    (tmp_path / "wintun.dll").write_bytes(b"test dll placeholder")
    monkeypatch.setattr(xray_process, "is_windows_elevated", lambda: True)
    runner._validate_inputs(profile)


def test_windows_tun_rejects_non_elevated_process(monkeypatch, tmp_path):
    executable = tmp_path / "xray.exe"
    executable.touch()
    (tmp_path / "wintun.dll").write_bytes(b"test dll placeholder")
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_tun_config()), encoding="utf-8")
    profile = ConnectionProfile("test", Transport.XRAY, "127.0.0.1", 443)
    runner = XrayProcessRunner(executable, config_path)
    monkeypatch.setattr(xray_process.os, "name", "nt")
    monkeypatch.setattr(xray_process, "is_windows_elevated", lambda: False)
    with pytest.raises(PermissionError, match="elevated administrator token"):
        runner._validate_inputs(profile)


def test_is_windows_elevated_returns_false_outside_windows(monkeypatch):
    monkeypatch.setattr(xray_process.os, "name", "posix")
    assert xray_process.is_windows_elevated() is False


def test_is_windows_elevated_uses_windows_admin_token_api(monkeypatch):
    class FakeFunction:
        def __init__(self, result):
            self.result = result
            self.argtypes = None
            self.restype = None

        def __call__(self):
            return self.result

    class FakeShell32:
        IsUserAnAdmin = FakeFunction(1)

    monkeypatch.setattr(xray_process.os, "name", "nt")
    monkeypatch.setattr(
        xray_process.ctypes,
        "WinDLL",
        lambda name, use_last_error: FakeShell32(),
        raising=False,
    )
    assert xray_process.is_windows_elevated() is True
