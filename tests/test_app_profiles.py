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
    with pytest.raises(ValueError, match="Endpoint host must be"):
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

def test_connect_button_requires_live_controller_and_imported_xray_config(tmp_path, qapp):
    from apnawin.domain.state import ConnectionState
    from apnawin.domain.profile import ConnectionProfile, Transport
    from apnawin.storage.profile_store import save_profiles

    class ConfigStore:
        path = tmp_path / "xray-configs.json"
        def has_config(self, _name):
            return True

    class Controller:
        state = ConnectionState.DISCONNECTED

    profile = ConnectionProfile("Office", Transport.XRAY, "vpn.example.test", 443)
    profiles_path = tmp_path / "profiles.json"
    save_profiles(profiles_path, [profile])
    window = MainWindow(
        profiles_path=profiles_path,
        xray_config_store=ConfigStore(),
        connection_controller=Controller(),
    )
    assert window.connect_button.isEnabled() is True
    assert window.disconnect_button.isEnabled() is False
    window.close()



def test_close_requested_during_connect_disconnects_after_worker_finishes(
    tmp_path, qapp
):
    from apnawin.domain.state import ConnectionState

    class Controller:
        state = ConnectionState.CONNECTED

    window = MainWindow(
        profiles_path=tmp_path / "profiles.json",
        connection_controller=Controller(),
    )
    requested = []
    window._close_after_disconnect = True
    window._disconnect_tunnel = lambda: requested.append("disconnect")

    window._connection_worker_finished()

    assert requested == ["disconnect"]
    assert window._close_after_disconnect is True
    window._connection_timer.stop()



def test_failed_disconnect_does_not_retry_forever_on_window_close(
    tmp_path, qapp
):
    from apnawin.domain.state import ConnectionState

    class Controller:
        state = ConnectionState.ERROR

    class FinishedWorker:
        action = "disconnect"

        def deleteLater(self):
            pass

    window = MainWindow(
        profiles_path=tmp_path / "profiles.json",
        connection_controller=Controller(),
    )
    attempts = []
    window._connection_worker = FinishedWorker()
    window._close_after_disconnect = True
    window._disconnect_tunnel = lambda: attempts.append("disconnect")

    window._connection_worker_finished()

    assert attempts == []
    assert window._close_after_disconnect is False
    assert window._connection_worker is None
    window._connection_timer.stop()


def test_live_apna_catalog_button_is_present_and_windows_gated(tmp_path, qapp):
    window = MainWindow(profiles_path=tmp_path / "profiles.json")

    assert window.import_apna_live_button.isEnabled() is (os.name == "nt")
    window.close()


def test_live_catalog_worker_returns_catalog_without_writing_plaintext(monkeypatch, qapp):
    import apnawin.app as app_module

    class FakeSource:
        def __init__(self, **kwargs):
            assert kwargs["timeout_seconds"] == 3.0
            assert kwargs["retry_attempts"] == 2
            assert callable(kwargs["progress_callback"])
            assert kwargs["cancel_event"].is_set() is False
            self.progress_callback = kwargs["progress_callback"]

        def fetch_document(self):
            self.progress_callback(128, 512)
            return {"Version": "synthetic", "Free_servers": [], "Payloads": []}

    monkeypatch.setattr(app_module, "ApnaLiteCatalogSource", FakeSource)
    worker = app_module._ApnaCatalogFetchWorker()
    worker.run()

    assert worker.catalog["Version"] == "synthetic"
    assert worker.error is None


def test_apna_catalog_file_worker_decodes_raw_catalog_off_ui_thread(tmp_path, qapp, monkeypatch):
    import apnawin.app as app_module

    source = tmp_path / "servers.dat"
    source.write_bytes(b"encrypted-fixture")
    expected = {"Version": "synthetic", "Free_servers": [], "Payloads": []}
    monkeypatch.setattr(app_module, "decode_apna_lite_catalog", lambda data: expected)
    worker = app_module._ApnaCatalogFileWorker(str(source))
    worker.run()

    assert worker.catalog is expected
    assert worker.error is None
    assert worker.source_label == "downloaded catalog file"


def test_apna_catalog_file_worker_reports_decode_error_without_changing_source(
    tmp_path, qapp, monkeypatch
):
    import apnawin.app as app_module

    source = tmp_path / "servers.dat"
    original = b"invalid-encrypted-catalog"
    source.write_bytes(original)

    def fail_decode(_data):
        raise ValueError("Invalid Base64 catalog")

    monkeypatch.setattr(app_module, "decode_apna_lite_catalog", fail_decode)
    worker = app_module._ApnaCatalogFileWorker(str(source))
    worker.run()

    assert worker.catalog is None
    assert worker.error == "ValueError: Invalid Base64 catalog"
    assert source.read_bytes() == original


def test_live_catalog_worker_reports_only_exception_type_and_message(monkeypatch, qapp):
    import apnawin.app as app_module

    class FakeSource:
        def __init__(self, **kwargs):
            pass

        def fetch_document(self):
            raise OSError("temporary network failure")

    monkeypatch.setattr(app_module, "ApnaLiteCatalogSource", FakeSource)
    worker = app_module._ApnaCatalogFetchWorker()
    worker.run()

    assert worker.catalog is None
    assert worker.error == "OSError: temporary network failure"


def test_window_has_larger_server_list_and_host_key_verification_action(tmp_path, qapp):
    window = MainWindow(profiles_path=tmp_path / "profiles.json")

    assert window.width() >= 900
    assert window.height() >= 650
    assert window.profile_list.minimumHeight() >= 280
    assert window.verify_apna_host_key_button.isEnabled() is False
    window.close()



def test_clear_all_profiles_requires_confirmation_and_persists_empty_list(tmp_path, qapp, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    import apnawin.app as app_module

    profiles = [
        ConnectionProfile("One", Transport.SOCKS, "localhost", 1080),
        ConnectionProfile("Two", Transport.XRAY, "vpn.example.test", 443),
    ]
    path = tmp_path / "profiles.json"
    save_profiles(path, profiles)
    monkeypatch.setattr(
        app_module.QMessageBox, "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    window = MainWindow(profiles_path=path)
    window._clear_all_profiles()
    assert window.profiles == []
    assert window.profile_list.count() == 0
    assert load_profiles(path) == []
    assert window.clear_all_button.isEnabled() is False
    window.close()


def test_clear_all_profiles_cancel_preserves_profiles(tmp_path, qapp, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    import apnawin.app as app_module

    profile = ConnectionProfile("Keep", Transport.SOCKS, "localhost", 1080)
    path = tmp_path / "profiles.json"
    save_profiles(path, [profile])
    monkeypatch.setattr(
        app_module.QMessageBox, "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.No,
    )
    window = MainWindow(profiles_path=path)
    window._clear_all_profiles()
    assert window.profiles == [profile]
    assert load_profiles(path) == [profile]
    window.close()


def test_status_error_text_is_selectable(tmp_path, qapp):
    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    flags = window.status_label.textInteractionFlags()
    assert flags & Qt.TextInteractionFlag.TextSelectableByMouse
    assert flags & Qt.TextInteractionFlag.TextSelectableByKeyboard
    window.close()



def test_apna_import_report_shows_all_tiers_even_when_no_ssh_profiles_exist(
    tmp_path, qapp, monkeypatch
):
    import apnawin.app as app_module

    captured = {}
    monkeypatch.setattr(
        app_module,
        "show_copyable_error",
        lambda _parent, title, message: captured.update(title=title, message=message),
    )
    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    catalog = {
        "Free_servers": [
            {"category": "ocsudp", "server_name": "UDP edge", "server_host": "udp.example.test"},
            {"category": "ocsws", "server_name": "SSH edge", "server_host": "ssh.example.test"},
        ],
        "Premium_servers": [{"category": "trojan", "server_name": "Trojan edge"}],
        "Vip_servers": [{"category": "vmess", "server_name": "VMess one"}, {"category": "vmess", "server_name": "VMess two"}],
        "Private_servers": [{"category": "unknown", "server_name": "Private edge"}],
        "Payloads": [],
    }

    window._import_apna_catalog(catalog, source_label="test catalog")

    assert captured["title"] == "APNA catalog import report"
    assert "Catalog total: 6 server records" in captured["message"]
    assert "Free: 2 server records; 1 SSH-compatible" in captured["message"]
    assert "Premium: 1 server records; 0 SSH-compatible" in captured["message"]
    assert "VIP: 2 server records; 0 SSH-compatible" in captured["message"]
    assert "Private: 1 server records; 0 SSH-compatible" in captured["message"]
    assert "ocsudp=1, ocsws=1" in captured["message"]
    assert "Complete server inventory" in captured["message"]
    assert "UDP edge | udp.example.test" in captured["message"]
    assert "Trojan edge" in captured["message"]
    assert "Only SSH-compatible categories are currently importable" in captured["message"]
    assert window.profiles == []
    window.close()



def test_vpn_operation_failure_is_selectable_and_opens_copyable_diagnostics(
    tmp_path, qapp, monkeypatch
):
    import apnawin.app as app_module

    captured = {}
    monkeypatch.setattr(
        app_module,
        "show_copyable_error",
        lambda _parent, title, message: captured.update(title=title, message=message),
    )
    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    window._connection_operation_finished(
        False,
        "ApnaHostKeyProbeError: SSH host-key exchange failed: HTTP 301",
    )
    assert captured["title"] == "VPN operation failed"
    assert "HTTP 301" in captured["message"]
    assert "HTTP 301" in window.status_label.text()
    flags = window.status_label.textInteractionFlags()
    assert flags & Qt.TextInteractionFlag.TextSelectableByMouse
    window.close()

def test_all_import_paths_are_exposed_from_one_import_menu(tmp_path, qapp):
    window = MainWindow(profiles_path=tmp_path / "profiles.json")

    menu = window.import_button.menu()
    assert menu is window.import_menu
    action_texts = [action.text() for action in menu.actions()]
    assert action_texts == [
        "ApnaWin profiles (JSON)…",
        "APNA encrypted catalog / APK…",
        "Fetch live APNA catalog…",
        "Open manual APNA catalog download…",
        "Xray JSON (VLESS / VMess / Trojan / UDP-capable)…",
    ]
    assert window.import_xray_config_button.isHidden()
    assert window.import_apna_apk_button.isHidden()
    assert window.import_apna_live_button.isHidden()
    assert window.import_xray_action.isEnabled() is False
    assert window.import_apna_file_action.isEnabled() is (os.name == "nt")
    assert window.import_apna_live_action.isEnabled() is (os.name == "nt")
    assert window.download_apna_manual_action.isEnabled() is (os.name == "nt")
    window.close()

def test_cancel_live_fetch_requests_worker_cancellation(tmp_path, qapp):
    class Worker:
        def __init__(self):
            self.cancelled = False
        def isRunning(self):
            return True
        def cancel(self):
            self.cancelled = True

    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    worker = Worker()
    window._catalog_worker = worker
    window._cancel_live_apna_catalog()
    assert worker.cancelled is True
    assert window.cancel_catalog_button.isEnabled() is False
    window._catalog_worker = None
    window._connection_timer.stop()
    window.close()


def test_close_requested_during_apna_file_decode_closes_after_worker_finishes(
    tmp_path, qapp, monkeypatch
):
    import apnawin.app as app_module

    window = MainWindow(profiles_path=tmp_path / "profiles.json")
    worker = app_module._ApnaCatalogFileWorker(str(tmp_path / "unused.dat"))
    worker.catalog = {"Version": "synthetic"}
    window._file_worker = worker
    window._close_after_catalog_fetch = True
    closed = []
    monkeypatch.setattr(window, "close", lambda: closed.append(True))

    window._apna_file_import_finished()

    assert closed == [True]
    assert window._close_after_catalog_fetch is False
    assert window._file_worker is None
    window._connection_timer.stop()

