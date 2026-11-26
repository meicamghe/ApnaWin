import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

import apnawin.app as app_module
from apnawin.app import MainWindow
from apnawin.storage.xray_config_store import XrayConfigStore


def make_store(path):
    def protect(data):
        return b"encrypted:" + data[::-1]

    def unprotect(data):
        if not data.startswith(b"encrypted:"):
            raise ValueError("bad ciphertext")
        return data[len(b"encrypted:"):][::-1]

    return XrayConfigStore(path, protect=protect, unprotect=unprotect)


def test_share_link_import_creates_profile_and_encrypted_config(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    assert app is not None
    share_link = (
        "vless://00000000-0000-4000-8000-000000000001@edge.example.test:443"
        "?encryption=none&type=ws&security=tls&sni=cdn.example.test"
        "&host=cdn.example.test&path=%2Fgateway#Branch%20VLESS"
    )
    monkeypatch.setattr(
        app_module.QInputDialog,
        "getMultiLineText",
        lambda *_args, **_kwargs: (share_link, True),
    )
    store = make_store(tmp_path / "xray-configs.json")
    window = MainWindow(
        profiles_path=tmp_path / "profiles.json",
        xray_config_store=store,
    )

    window._import_xray_share_link()

    assert len(window.profiles) == 1
    profile = window.profiles[0]
    assert profile.name == "Branch VLESS"
    assert profile.endpoint_host == "edge.example.test"
    assert store.has_config(profile.name)
    config = store.load(profile.name)
    assert b"00000000-0000-4000-8000-000000000001" in config
    assert b"00000000-0000-4000-8000-000000000001" not in store.path.read_bytes()
    window.close()


def test_share_link_import_cancel_is_noop(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(
        app_module.QInputDialog,
        "getMultiLineText",
        lambda *_args, **_kwargs: ("", False),
    )
    store = make_store(tmp_path / "xray-configs.json")
    window = MainWindow(
        profiles_path=tmp_path / "profiles.json",
        xray_config_store=store,
    )

    window._import_xray_share_link()

    assert window.profiles == []
    assert not store.path.exists()
    window.close()
