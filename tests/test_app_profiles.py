import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from apnawin.app import MainWindow
from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.storage.profile_store import load_profiles, save_profiles


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_loads_saved_profiles(tmp_path, qapp):
    path = tmp_path / "profiles.json"
    profiles = [
        ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443),
        ConnectionProfile("Lab", Transport.OPENVPN, "192.0.2.10", 1194),
    ]
    save_profiles(path, profiles)

    window = MainWindow(profiles_path=path)

    assert window.profile_list.count() == 2
    assert window.profile_list.item(0).text() == "Office"
    assert window.profile_list.item(1).text() == "Lab"
    assert window.profile_details.text() == "XRAY  •  vpn.example.test:443"
    assert window.connect_button.isEnabled() is False
    window.close()


def test_main_window_refreshes_after_profile_save(tmp_path, qapp):
    path = tmp_path / "profiles.json"
    window = MainWindow(profiles_path=path)
    profile = ConnectionProfile("Personal", Transport.SOCKS, "localhost", 1080)

    assert window._save_profiles([profile]) is True
    window._refresh_profiles(0)

    assert window.profile_list.count() == 1
    assert window.profile_list.currentItem().text() == "Personal"
    assert load_profiles(path) == [profile]
    window.close()


def test_main_window_updates_details_when_selection_changes(tmp_path, qapp):
    path = tmp_path / "profiles.json"
    profiles = [
        ConnectionProfile("One", Transport.XRAY, "one.example.test", 443),
        ConnectionProfile("Two", Transport.SOCKS, "two.example.test", 1080),
    ]
    save_profiles(path, profiles)
    window = MainWindow(profiles_path=path)

    window.profile_list.setCurrentRow(1)

    assert window.profile_details.text() == "SOCKS  •  two.example.test:1080"
    assert window.edit_button.isEnabled()
    assert window.remove_button.isEnabled()
    window.close()
