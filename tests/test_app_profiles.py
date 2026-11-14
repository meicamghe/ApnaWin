import json
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


def test_add_profile_flow_persists_and_selects_new_profile(tmp_path, qapp, monkeypatch):
    from PySide6.QtWidgets import QDialog
    import apnawin.app as app_module

    profile = ConnectionProfile("New", Transport.SOCKS, "127.0.0.1", 1080)

    class AcceptedDialog:
        def __init__(self, _parent=None, _profile=None):
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

        def to_profile(self):
            return profile

    monkeypatch.setattr(app_module, "ProfileDialog", AcceptedDialog)
    window = MainWindow(profiles_path=tmp_path / "profiles.json")

    window._add_profile()

    assert window.profiles == [profile]
    assert window.profile_list.currentRow() == 0
    assert load_profiles(tmp_path / "profiles.json") == [profile]
    window.close()


def test_edit_profile_flow_updates_existing_profile(tmp_path, qapp, monkeypatch):
    from PySide6.QtWidgets import QDialog
    import apnawin.app as app_module

    original = ConnectionProfile("Office", Transport.XRAY, "old.example.test", 443)
    edited = ConnectionProfile("Office", Transport.XRAY, "new.example.test", 8443)
    path = tmp_path / "profiles.json"
    save_profiles(path, [original])

    class AcceptedDialog:
        def __init__(self, _parent=None, profile=None):
            assert profile == original

        def exec(self):
            return QDialog.DialogCode.Accepted

        def to_profile(self):
            return edited

    monkeypatch.setattr(app_module, "ProfileDialog", AcceptedDialog)
    window = MainWindow(profiles_path=path)
    window.profile_list.setCurrentRow(0)

    window._edit_profile()

    assert window.profiles == [edited]
    assert load_profiles(path) == [edited]
    assert window.profile_details.text() == "XRAY  •  new.example.test:8443"
    window.close()


def test_remove_profile_flow_requires_confirmation_and_persists(tmp_path, qapp, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    import apnawin.app as app_module

    profile = ConnectionProfile("Office", Transport.SOCKS, "localhost", 1080)
    path = tmp_path / "profiles.json"
    save_profiles(path, [profile])
    monkeypatch.setattr(
        app_module.QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    window = MainWindow(profiles_path=path)
    window.profile_list.setCurrentRow(0)

    window._remove_profile()

    assert window.profiles == []
    assert load_profiles(path) == []
    assert window.profile_list.count() == 0
    window.close()


def test_save_failure_does_not_replace_in_memory_profiles(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    existing = ConnectionProfile("Existing", Transport.SOCKS, "localhost", 1080)
    proposed = ConnectionProfile("Proposed", Transport.SOCKS, "localhost", 1081)
    monkeypatch.setattr(
        app_module,
        "save_profiles",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk unavailable")),
    )
    monkeypatch.setattr(app_module.QMessageBox, "critical", lambda *_args, **_kwargs: None)
    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    window.profiles = [existing]

    assert window._save_profiles([proposed]) is False
    assert window.profiles == [existing]
    window.close()


def test_profile_json_contains_metadata_only(tmp_path):
    path = tmp_path / "profiles.json"
    save_profiles(
        path,
        [ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)],
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert set(payload) == {"format_version", "profiles"}
    assert set(payload["profiles"][0]) == {
        "name", "transport", "endpoint_host", "endpoint_port"
    }
    assert not {"password", "token", "private_key", "credential"} & set(
        payload["profiles"][0]
    )



def test_add_profile_rejects_duplicate_name_case_insensitively(tmp_path, qapp, monkeypatch):
    from PySide6.QtWidgets import QDialog
    import apnawin.app as app_module

    existing = ConnectionProfile("Office", Transport.SOCKS, "localhost", 1080)
    duplicate = ConnectionProfile("office", Transport.XRAY, "vpn.example.test", 443)
    path = tmp_path / "profiles.json"
    save_profiles(path, [existing])

    class AcceptedDialog:
        def __init__(self, _parent=None, _profile=None):
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

        def to_profile(self):
            return duplicate

    warnings = []
    monkeypatch.setattr(app_module, "ProfileDialog", AcceptedDialog)
    monkeypatch.setattr(
        app_module.QMessageBox,
        "warning",
        lambda *_args, **_kwargs: warnings.append(True),
    )
    window = MainWindow(profiles_path=path)

    window._add_profile()

    assert window.profiles == [existing]
    assert load_profiles(path) == [existing]
    assert warnings
    window.close()


def test_remove_profile_cancel_keeps_profile(tmp_path, qapp, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    import apnawin.app as app_module

    profile = ConnectionProfile("Office", Transport.SOCKS, "localhost", 1080)
    path = tmp_path / "profiles.json"
    save_profiles(path, [profile])
    monkeypatch.setattr(
        app_module.QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.No,
    )
    window = MainWindow(profiles_path=path)
    window.profile_list.setCurrentRow(0)

    window._remove_profile()

    assert window.profiles == [profile]
    assert load_profiles(path) == [profile]
    window.close()
