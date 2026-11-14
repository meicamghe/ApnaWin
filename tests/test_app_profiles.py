import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
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


def test_profile_details_render_as_plain_text_and_rejects_markup_host(tmp_path, qapp):
    hostile_host = "<b>untrusted</b>"
    with pytest.raises(ValueError, match="valid DNS hostname"):
        ConnectionProfile("Imported", Transport.SOCKS, hostile_host, 1080)

    profile = ConnectionProfile("Imported", Transport.SOCKS, "vpn.example.test", 1080)
    path = tmp_path / "profiles.json"
    save_profiles(path, [profile])

    window = MainWindow(profiles_path=path)

    assert window.profile_details.textFormat() == Qt.TextFormat.PlainText
    assert "vpn.example.test" in window.profile_details.text()
    window.close()


def test_remove_confirmation_escapes_profile_name_html(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    hostile_name = '<img src="file:///private/test.png">'
    profile = ConnectionProfile(hostile_name, Transport.SOCKS, "localhost", 1080)
    save_profiles(tmp_path / "profiles.json", [profile])
    captured = []

    def capture_question(*args, **kwargs):
        captured.append(args[2])
        return app_module.QMessageBox.StandardButton.No

    monkeypatch.setattr(app_module.QMessageBox, "question", capture_question)
    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    window._remove_profile()

    assert captured
    assert "&lt;img" in captured[0]
    assert hostile_name not in captured[0]
    window.close()


def test_corrupt_profile_file_disables_editing_and_preserves_original(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    path = tmp_path / "profiles.json"
    original_bytes = b'{"format_version": 1, "profiles": ['
    path.write_bytes(original_bytes)
    monkeypatch.setattr(app_module.QMessageBox, "warning", lambda *_args, **_kwargs: None)
    window = MainWindow(profiles_path=path)

    assert window.profile_storage_writable is False
    assert window.add_button.isEnabled() is False
    assert window.edit_button.isEnabled() is False
    assert window.remove_button.isEnabled() is False
    assert "storage is unavailable" in window.status_label.text().lower()
    assert window._save_profiles([]) is False
    assert path.read_bytes() == original_bytes
    window.close()


def test_unreadable_profile_file_disables_editing(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    path = tmp_path / "profiles.json"
    path.write_text('{"format_version": 1, "profiles": []}', encoding="utf-8")
    monkeypatch.setattr(
        app_module,
        "load_profiles",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("access denied")),
    )
    monkeypatch.setattr(app_module.QMessageBox, "warning", lambda *_args, **_kwargs: None)
    window = MainWindow(profiles_path=path)

    assert window.profile_storage_writable is False
    assert window.add_button.isEnabled() is False
    assert window._save_profiles([]) is False
    window.close()



def test_import_profiles_merges_valid_profiles_and_persists(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    existing = ConnectionProfile("Existing", Transport.SOCKS, "localhost", 1080)
    incoming = ConnectionProfile("Imported", Transport.XRAY, "vpn.example.test", 443)
    source = tmp_path / "incoming.json"
    destination = tmp_path / "profiles.json"
    save_profiles(source, [incoming])
    save_profiles(destination, [existing])
    monkeypatch.setattr(
        app_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: (str(source), "JSON"),
    )
    window = MainWindow(profiles_path=destination)

    window._import_profiles()

    assert window.profiles == [existing, incoming]
    assert load_profiles(destination) == [existing, incoming]
    assert window.profile_list.count() == 2
    assert window.profile_list.currentRow() == 1
    window.close()


def test_import_profiles_rejects_name_collision_without_overwrite(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    existing = ConnectionProfile("Office", Transport.SOCKS, "localhost", 1080)
    conflicting = ConnectionProfile("office", Transport.XRAY, "vpn.example.test", 443)
    source = tmp_path / "incoming.json"
    destination = tmp_path / "profiles.json"
    save_profiles(source, [conflicting])
    save_profiles(destination, [existing])
    original = destination.read_bytes()
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
    window = MainWindow(profiles_path=destination)

    window._import_profiles()

    assert window.profiles == [existing]
    assert destination.read_bytes() == original
    assert warnings
    window.close()


def test_export_profiles_writes_non_secret_profile_file(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    profile = ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)
    destination = tmp_path / "exported.json"
    monkeypatch.setattr(
        app_module.QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(destination), "JSON"),
    )
    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    window.profiles = [profile]
    window._refresh_profiles(0)

    window._export_profiles()

    assert load_profiles(destination) == [profile]
    assert window.export_button.isEnabled()
    window.close()



def test_import_profiles_malformed_file_keeps_existing_profiles(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    existing = ConnectionProfile("Existing", Transport.SOCKS, "localhost", 1080)
    source = tmp_path / "malformed.json"
    destination = tmp_path / "profiles.json"
    source.write_text('{"format_version": 1, "profiles": [', encoding="utf-8")
    save_profiles(destination, [existing])
    original = destination.read_bytes()
    warnings = []
    monkeypatch.setattr(
        app_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: (str(source), "JSON"),
    )
    monkeypatch.setattr(
        app_module.QMessageBox,
        "warning",
        lambda *_args, **kwargs: warnings.append(kwargs.get("text", _args[2] if len(_args) > 2 else "")),
    )
    window = MainWindow(profiles_path=destination)

    window._import_profiles()

    assert window.profiles == [existing]
    assert destination.read_bytes() == original
    assert warnings
    assert "\\n\\n" not in warnings[0]
    assert "\n\n" in warnings[0]
    window.close()


def test_import_profiles_dialog_cancellation_is_noop(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    existing = ConnectionProfile("Existing", Transport.SOCKS, "localhost", 1080)
    destination = tmp_path / "profiles.json"
    save_profiles(destination, [existing])
    original = destination.read_bytes()
    monkeypatch.setattr(
        app_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: ("", ""),
    )
    window = MainWindow(profiles_path=destination)

    window._import_profiles()

    assert window.profiles == [existing]
    assert destination.read_bytes() == original
    window.close()
