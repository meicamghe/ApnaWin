import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

import apnawin.app as app_module
from apnawin.app import MainWindow
from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.storage.profile_store import save_profiles
from apnawin.storage.xray_config_store import XrayConfigStore


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def valid_config_bytes():
    config = {
        "inbounds": [{
            "protocol": "tun",
            "port": 0,
            "settings": {
                "name": "ApnaWin",
                "gateway": ["10.255.0.1/30", "fd42:6170:6e61:7769::1/64"],
                "dns": ["1.1.1.1"],
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto",
                "autoSystemWfpBlockLeak": ["allexceptlan", "dns"],
            },
        }],
        "outbounds": [{"protocol": "vless", "settings": {"id": "secret-value"}}],
    }
    return json.dumps(config).encode("utf-8")


def make_store(path):
    def protect(data):
        return b"encrypted:" + data[::-1]

    def unprotect(data):
        if not data.startswith(b"encrypted:"):
            raise ValueError("bad ciphertext")
        return data[len(b"encrypted:"):][::-1]

    return XrayConfigStore(path, protect=protect, unprotect=unprotect)


def test_xray_config_import_button_only_enabled_for_xray_profile(tmp_path, qapp):
    profiles_path = tmp_path / "profiles.json"
    save_profiles(
        profiles_path,
        [
            ConnectionProfile("Xray", Transport.XRAY, "vpn.example.test", 443),
            ConnectionProfile("SOCKS", Transport.SOCKS, "127.0.0.1", 1080),
        ],
    )
    window = MainWindow(
        profiles_path=profiles_path,
        xray_config_store=make_store(tmp_path / "xray-configs.json"),
    )
    window.profile_list.setCurrentRow(0)
    assert window.import_xray_config_button.isEnabled()
    window.profile_list.setCurrentRow(1)
    assert not window.import_xray_config_button.isEnabled()
    assert not window.connect_button.isEnabled()
    window.close()


def test_import_xray_config_is_validated_and_encrypted(tmp_path, qapp, monkeypatch):
    profile = ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)
    profiles_path = tmp_path / "profiles.json"
    save_profiles(profiles_path, [profile])
    source = tmp_path / "config.json"
    source.write_bytes(valid_config_bytes())
    store = make_store(tmp_path / "xray-configs.json")
    monkeypatch.setattr(
        app_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: (str(source), "JSON"),
    )
    window = MainWindow(profiles_path=profiles_path, xray_config_store=store)

    window._import_xray_config()

    assert store.has_config("office")
    assert store.load("OFFICE") == valid_config_bytes()
    assert b"secret-value" not in store.path.read_bytes()
    assert "imported and encrypted" in window.profile_details.text()
    assert "Connect remains disabled" in window.status_label.text()
    assert not window.connect_button.isEnabled()
    window.close()


def test_import_xray_config_rejects_invalid_tun_policy_without_overwrite(
    tmp_path, qapp, monkeypatch
):
    profile = ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)
    profiles_path = tmp_path / "profiles.json"
    save_profiles(profiles_path, [profile])
    source = tmp_path / "config.json"
    source.write_text('{"inbounds": [], "outbounds": []}', encoding="utf-8")
    store = make_store(tmp_path / "xray-configs.json")
    warnings = []
    monkeypatch.setattr(
        app_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: (str(source), "JSON"),
    )
    monkeypatch.setattr(
        app_module.QMessageBox,
        "warning",
        lambda *_args, **_kwargs: warnings.append(True),
    )
    window = MainWindow(profiles_path=profiles_path, xray_config_store=store)

    window._import_xray_config()

    assert not store.has_config("Office")
    assert warnings
    window.close()


def test_renaming_profile_moves_its_encrypted_xray_config(
    tmp_path, qapp, monkeypatch
):
    original = ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)
    renamed = ConnectionProfile("Branch", Transport.XRAY, "vpn.example.test", 443)
    profiles_path = tmp_path / "profiles.json"
    save_profiles(profiles_path, [original])
    store = make_store(tmp_path / "xray-configs.json")
    store.save("Office", valid_config_bytes())

    class AcceptedDialog:
        def __init__(self, _parent=None, _profile=None):
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

        def to_profile(self):
            return renamed

    monkeypatch.setattr(app_module, "ProfileDialog", AcceptedDialog)
    window = MainWindow(profiles_path=profiles_path, xray_config_store=store)
    window._edit_profile()

    assert store.has_config("Branch")
    assert not store.has_config("Office")
    assert store.load("Branch") == valid_config_bytes()
    window.close()


def test_removing_profile_removes_its_encrypted_xray_config(
    tmp_path, qapp, monkeypatch
):
    profile = ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)
    profiles_path = tmp_path / "profiles.json"
    save_profiles(profiles_path, [profile])
    store = make_store(tmp_path / "xray-configs.json")
    store.save("Office", valid_config_bytes())
    monkeypatch.setattr(
        app_module.QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    window = MainWindow(profiles_path=profiles_path, xray_config_store=store)

    window._remove_profile()

    assert not store.has_config("Office")
    window.close()


def test_config_import_dialog_cancellation_is_noop(tmp_path, qapp, monkeypatch):
    profile = ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)
    profiles_path = tmp_path / "profiles.json"
    save_profiles(profiles_path, [profile])
    store = make_store(tmp_path / "xray-configs.json")
    monkeypatch.setattr(
        app_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: ("", ""),
    )
    window = MainWindow(profiles_path=profiles_path, xray_config_store=store)

    window._import_xray_config()

    assert not store.has_config("Office")
    window.close()
