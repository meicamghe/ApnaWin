"""Native desktop shell with supervised Windows Xray TUN connection support."""

import os
import secrets
import sys
from html import escape
from pathlib import Path

from PySide6.QtCore import QStandardPaths, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from apnawin.domain.profile import ConnectionProfile, Transport
from apnawin.domain.state import ConnectionState
from apnawin.engines.xray_process import (
    MAX_XRAY_CONFIG_BYTES,
    inspect_tun_inbound,
    parse_xray_config_bytes,
)
from apnawin.storage.profile_store import load_profiles, save_profiles
from apnawin.storage.xray_config_store import XrayConfigStore
from apnawin.engines.xray_tunnel import XrayTunnelEngine
from apnawin.engines.apna_host_key import scan_apna_ssh_host_key
from apnawin.engines.apna_tunnel_engine import ApnaTunnelEngine
from apnawin.engines.multi_transport import MultiTransportTunnelEngine
from apnawin.services.apna_lite_catalog import decode_apna_lite_apk_catalog
from apnawin.services.apna_lite_profile_mapper import (
    build_apna_lite_ssh_profile,
    list_apna_lite_ssh_payloads,
    list_apna_lite_ssh_servers,
)
from apnawin.storage.apna_profile_store import ApnaProfileStore
from apnawin.services.connection_controller import ConnectionController
from apnawin.services.xray_tunnel_supervisor import XrayTunnelSupervisor


def profile_file_path() -> Path:
    """Return the per-user, application-specific profile file path."""
    app_data = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
    if not app_data:
        raise RuntimeError("Windows did not provide an application data directory")
    return Path(app_data) / "profiles.json"


class ProfileDialog(QDialog):
    """Small editor for non-secret connection endpoint metadata."""

    def __init__(self, parent=None, profile: ConnectionProfile | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit profile" if profile else "Add profile")
        self.setMinimumWidth(360)

        self.name_edit = QLineEdit(profile.name if profile else "")
        self.host_edit = QLineEdit(profile.endpoint_host if profile else "")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(profile.endpoint_port if profile else 443)
        self.transport_combo = QComboBox()
        for transport in Transport:
            self.transport_combo.addItem(transport.value.upper(), transport.value)
        if profile:
            self.transport_combo.setCurrentIndex(
                self.transport_combo.findData(profile.transport.value)
            )

        form = QFormLayout()
        form.addRow("Profile name", self.name_edit)
        form.addRow("Transport", self.transport_combo)
        form.addRow("Server / host", self.host_edit)
        form.addRow("Port", self.port_spin)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_if_valid)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _accept_if_valid(self) -> None:
        try:
            self.to_profile()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid profile", str(exc))
            return
        self.accept()

    def to_profile(self) -> ConnectionProfile:
        return ConnectionProfile(
            name=self.name_edit.text().strip(),
            transport=Transport(self.transport_combo.currentData()),
            endpoint_host=self.host_edit.text().strip(),
            endpoint_port=self.port_spin.value(),
        )





class ApnaCatalogImportDialog(QDialog):
    """Select an SSH-compatible server/payload pair from an APNA Lite APK."""

    def __init__(self, catalog: dict, servers: list[dict], parent=None) -> None:
        super().__init__(parent)
        self.catalog = catalog
        self.servers = servers
        self.payloads: list[dict] = []
        self._host_selections: dict[tuple[str, ...], str] = {}
        self.setWindowTitle("Import APNA Lite server profile")
        self.setMinimumWidth(520)

        self.server_combo = QComboBox()
        for index, server in enumerate(servers):
            name = str(server.get("server_name") or "APNA server")
            category = str(server.get("category") or "")
            self.server_combo.addItem(f"{name} — {category}", index)

        self.payload_combo = QComboBox()
        self.host_key_edit = QLineEdit()
        self.host_key_edit.setPlaceholderText("SHA256:… (optional; recommended)")
        self.brand_edit = QLineEdit()
        self.brand_edit.setPlaceholderText("Only required by payloads containing [brand]")
        self.user_agent_edit = QLineEdit()
        self.user_agent_edit.setPlaceholderText("Optional override")
        self.transparent_dns_check = QCheckBox("Use APNA UDP gateway for transparent DNS")
        self.probe_button = QPushButton("Probe SSH host key (no authentication)")
        self.probe_button.clicked.connect(self._probe_host_key)

        form = QFormLayout()
        form.addRow("Server", self.server_combo)
        form.addRow("Payload", self.payload_combo)
        form.addRow("SSH host-key SHA-256", self.host_key_edit)
        form.addRow("Payload brand", self.brand_edit)
        form.addRow("User-Agent", self.user_agent_edit)
        form.addRow("", self.transparent_dns_check)

        note = QLabel(
            f"Embedded catalog version: {catalog.get('Version', 'unknown')}. "
            "Credentials are extracted in memory and stored encrypted for this Windows user. "
            "Profile exports do not include them."
        )
        note.setWordWrap(True)
        warning = QLabel(
            "A scanned host-key fingerprint is not independently authenticated. "
            "Compare it with a provider-published fingerprint before trusting it."
        )
        warning.setWordWrap(True)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_if_valid)
        buttons.rejected.connect(self.reject)
        self._save_button = buttons.button(QDialogButtonBox.StandardButton.Save)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.probe_button)
        layout.addWidget(note)
        layout.addWidget(warning)
        layout.addWidget(buttons)

        self.server_combo.currentIndexChanged.connect(self._update_payloads)
        self.payload_combo.currentIndexChanged.connect(self._invalidate_mapping)
        self._update_payloads()

    def _invalidate_mapping(self, *_args) -> None:
        self._host_selections.clear()

    def _choose_host(self, pool: list[str]) -> str:
        key = tuple(pool)
        if key not in self._host_selections:
            self._host_selections[key] = secrets.choice(pool)
        return self._host_selections[key]

    def _update_payloads(self, *_args) -> None:
        self._host_selections.clear()
        self.payload_combo.blockSignals(True)
        self.payload_combo.clear()
        server_index = self.server_combo.currentData()
        if server_index is not None:
            server = self.servers[int(server_index)]
            self.payloads = list_apna_lite_ssh_payloads(
                self.catalog, str(server.get("category", ""))
            )
            for index, payload in enumerate(self.payloads):
                name = str(payload.get("friendly_name") or "APNA payload")
                method = str(payload.get("method") or "")
                secure = "TLS" if payload.get("sslws") in (True, "true") else "TCP"
                self.payload_combo.addItem(f"{name} — {method.upper()} / {secure}", index)
        else:
            self.payloads = []
        self.payload_combo.blockSignals(False)
        self._save_button.setEnabled(bool(self.payloads))

    def _build_profile(self):
        server_index = self.server_combo.currentData()
        payload_index = self.payload_combo.currentData()
        if server_index is None or payload_index is None:
            raise ValueError("Select an APNA server and a compatible payload")
        return build_apna_lite_ssh_profile(
            self.catalog,
            self.servers[int(server_index)],
            self.payloads[int(payload_index)],
            host_selector=self._choose_host,
            host_key_sha256=self.host_key_edit.text().strip() or None,
            brand=self.brand_edit.text().strip() or None,
            user_agent=self.user_agent_edit.text().strip() or None,
            transparent_dns=self.transparent_dns_check.isChecked(),
        )

    def _probe_host_key(self) -> None:
        try:
            mapped = self._build_profile()
            fingerprint = scan_apna_ssh_host_key(mapped.session_config)
        except Exception as exc:
            QMessageBox.warning(
                self,
                "SSH host-key probe failed",
                f"The selected APNA endpoint did not complete an SSH key exchange.\n\n{exc}",
            )
            return
        answer = QMessageBox.question(
            self,
            "Verify SSH host key",
            "Fingerprint received from the selected APNA endpoint:\n\n"
            f"{fingerprint}\n\n"
            "Only trust it if it matches a fingerprint obtained independently from the provider. "
            "Store this fingerprint for this profile?",
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.host_key_edit.setText(fingerprint)

    def _accept_if_valid(self) -> None:
        try:
            self._build_profile()
        except (TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Invalid APNA selection", str(exc))
            return
        self.accept()

    def selected_profile(self):
        return self._build_profile()
\n\nclass _ConnectionWorker(QThread):
    operation_finished = Signal(bool, str)

    def __init__(self, controller, action, profile=None):
        super().__init__()
        self.controller = controller
        self.action = action
        self.profile = profile

    def run(self):
        try:
            if self.action == "connect":
                self.controller.connect(self.profile)
            elif self.action == "disconnect":
                self.controller.disconnect()
            else:
                raise ValueError("Unsupported connection operation")
        except Exception as exc:
            self.operation_finished.emit(False, f"{type(exc).__name__}: {exc}")
        else:
            self.operation_finished.emit(True, self.action)

class MainWindow(QMainWindow):
    def __init__(
        self,
        profiles_path: Path | None = None,
        xray_config_store: XrayConfigStore | None = None,
        apna_profile_store: ApnaProfileStore | None = None,
        connection_controller: ConnectionController | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("ApnaWin")
        self.resize(760, 520)
        self.profiles_path = profiles_path or profile_file_path()
        self.xray_config_store = xray_config_store or XrayConfigStore(
            self.profiles_path.with_name("xray-configs.json")
        )
        self.apna_profile_store = apna_profile_store or ApnaProfileStore(
            self.profiles_path.with_name("apna-profiles.json")
        )
        self.connection_controller = connection_controller or self._create_live_connection_controller()
        self._connection_worker = None
        self._close_after_disconnect = False
        self.profiles: list[ConnectionProfile] = []
        self.profile_storage_writable = True

        heading = QLabel("ApnaWin")
        heading.setObjectName("heading")
        self.status_label = QLabel(
            "Disconnected — no verified VPN connection."
        )
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)

        self.profile_list = QListWidget()
        self.profile_list.currentRowChanged.connect(self._show_selected_profile)

        self.profile_details = QLabel("No profile selected.")
        self.profile_details.setTextFormat(Qt.TextFormat.PlainText)
        self.profile_details.setWordWrap(True)

        self.add_button = QPushButton("Add")
        self.add_button.clicked.connect(self._add_profile)
        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self._edit_profile)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove_profile)
        self.import_button = QPushButton("Import…")
        self.import_button.clicked.connect(self._import_profiles)
        self.export_button = QPushButton("Export…")
        self.export_button.clicked.connect(self._export_profiles)
        self.import_xray_config_button = QPushButton("Import Xray config…")
        self.import_xray_config_button.clicked.connect(self._import_xray_config)
        self.import_xray_config_button.setEnabled(False)
        self.import_apna_apk_button = QPushButton("Import APNA APK…")
        self.import_apna_apk_button.clicked.connect(self._import_apna_apk)
        self.import_apna_apk_button.setEnabled(os.name == "nt")
        self.edit_button.setEnabled(False)
        self.remove_button.setEnabled(False)

        profile_actions = QHBoxLayout()
        profile_actions.addWidget(self.add_button)
        profile_actions.addWidget(self.edit_button)
        profile_actions.addWidget(self.remove_button)
        profile_actions.addWidget(self.import_button)
        profile_actions.addWidget(self.export_button)
        profile_actions.addWidget(self.import_xray_config_button)
        profile_actions.addWidget(self.import_apna_apk_button)
        profile_actions.addStretch(1)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self._connect_selected_profile)
        self.connect_button.setEnabled(False)
        self.connect_button.setToolTip("Waits for verified TUN routes, DNS and external TLS egress.")
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self._disconnect_tunnel)
        self.disconnect_button.setEnabled(False)

        layout = QVBoxLayout()
        layout.addWidget(heading)
        layout.addWidget(self.status_label)
        layout.addWidget(QLabel("Connection profiles"))
        layout.addWidget(self.profile_list)
        layout.addLayout(profile_actions)
        layout.addWidget(self.profile_details)
        layout.addWidget(self.connect_button)
        layout.addWidget(self.disconnect_button)
        layout.addStretch(1)

        root = QWidget()
        root.setLayout(layout)
        self.setCentralWidget(root)
        self._load_profiles()
        self._connection_timer = QTimer(self)
        self._connection_timer.setInterval(1500)
        self._connection_timer.timeout.connect(self._poll_connection)
        if self.connection_controller is not None:
            self._connection_timer.start()
        self._update_connection_controls()

    def _create_live_connection_controller(self):
        """Build the real engine only from the protected Program Files installation."""
        if os.name != "nt":
            return None
        program_files = os.environ.get("ProgramFiles")
        if not program_files:
            return None
        helper = Path(program_files) / "ApnaWin" / "ApnaWinElevator.exe"
        if helper.is_symlink() or not helper.is_file():
            return None
        xray_supervisor = XrayTunnelSupervisor(helper, self.xray_config_store)
        xray_engine = XrayTunnelEngine(
            xray_supervisor, helper, self.xray_config_store
        )
        apna_supervisor = XrayTunnelSupervisor(helper, self.xray_config_store)
        apna_engine = ApnaTunnelEngine(
            self.apna_profile_store.load,
            self.xray_config_store,
            apna_supervisor,
        )
        engine = MultiTransportTunnelEngine({
            Transport.XRAY: xray_engine,
            Transport.APNA_SSH: apna_engine,
        })
        return ConnectionController(engine)

    def _update_connection_controls(self):
        controller = self.connection_controller
        busy = self._connection_worker is not None and self._connection_worker.isRunning()
        row = self.profile_list.currentRow()
        profile = self.profiles[row] if 0 <= row < len(self.profiles) else None
        has_config = False
        if profile is not None and profile.transport is Transport.XRAY:
            try:
                has_config = self.xray_config_store.has_config(profile.name)
            except (OSError, ValueError):
                has_config = False
        state = controller.state if controller is not None else ConnectionState.DISCONNECTED
        self.connect_button.setEnabled(
            not busy and controller is not None and profile is not None
            and profile.transport is Transport.XRAY and has_config
            and state is ConnectionState.DISCONNECTED
        )
        self.disconnect_button.setEnabled(
            not busy and controller is not None
            and state in {ConnectionState.CONNECTED, ConnectionState.ERROR}
        )

    def _connect_selected_profile(self):
        if self.connection_controller is None or self._connection_worker is not None:
            return
        row = self.profile_list.currentRow()
        if 0 <= row < len(self.profiles) and self.profiles[row].transport is Transport.XRAY:
            self._start_connection_worker("connect", self.profiles[row])

    def _disconnect_tunnel(self):
        if self.connection_controller is None or self._connection_worker is not None:
            return
        self._start_connection_worker("disconnect")

    def _start_connection_worker(self, action, profile=None):
        self.status_label.setText(
            "Connecting — verifying TUN, IPv4/IPv6 routes, DNS and external egress..."
            if action == "connect" else "Disconnecting — stopping VPN helper..."
        )
        worker = _ConnectionWorker(self.connection_controller, action, profile)
        self._connection_worker = worker
        worker.operation_finished.connect(self._connection_operation_finished)
        worker.finished.connect(self._connection_worker_finished)
        self._update_connection_controls()
        worker.start()

    def _connection_operation_finished(self, success, detail):
        if success and detail == "connect":
            self.status_label.setText("Connected — TUN, dual-stack routes, DNS and external TLS egress verified.")
        elif success:
            self.status_label.setText("Disconnected — VPN helper stopped.")
        else:
            self.status_label.setText("VPN operation failed: " + detail)
        self._update_connection_controls()

    def _connection_worker_finished(self):
        worker = self._connection_worker
        self._connection_worker = None
        if worker is not None:
            worker.deleteLater()
        self._update_connection_controls()
        if self._close_after_disconnect:
            state = (
                self.connection_controller.state
                if self.connection_controller is not None
                else ConnectionState.DISCONNECTED
            )
            if state is ConnectionState.DISCONNECTED:
                self._close_after_disconnect = False
                self.close()
            elif getattr(worker, "action", None) == "disconnect":
                # Do not spin in an automatic retry loop if cleanup itself
                # failed. Keep the window open and let the user retry manually.
                self._close_after_disconnect = False
            else:
                # A close request may arrive while Connect is still running.
                # Once that worker completes, stop the newly-started tunnel.
                self._disconnect_tunnel()

    def _poll_connection(self):
        if self.connection_controller is None:
            return
        if self._connection_worker is not None and self._connection_worker.isRunning():
            return
        try:
            state = self.connection_controller.refresh()
        except Exception as exc:
            state = self.connection_controller.state
            self.status_label.setText("VPN health check failed: " + type(exc).__name__ + ": " + str(exc))
        if state is ConnectionState.ERROR:
            engine = getattr(self.connection_controller, "_engine", None)
            detail = getattr(engine, "last_error", None)
            self.status_label.setText("VPN connection lost or unhealthy. " + (detail or "Disconnect and retry."))
        self._update_connection_controls()

    def closeEvent(self, event):
        worker = self._connection_worker
        if worker is not None and worker.isRunning():
            self._close_after_disconnect = True
            event.ignore()
            return
        if self.connection_controller is not None and self.connection_controller.state is not ConnectionState.DISCONNECTED:
            self._close_after_disconnect = True
            event.ignore()
            self._disconnect_tunnel()
            return
        super().closeEvent(event)

    def _load_profiles(self) -> None:
        try:
            self.profiles = load_profiles(self.profiles_path)
        except FileNotFoundError:
            # A first launch has no profile file yet; creating it is safe.
            self.profiles = []
        except (OSError, ValueError) as exc:
            self.profile_storage_writable = False
            self.add_button.setEnabled(False)
            self.import_button.setEnabled(False)
            self.import_xray_config_button.setEnabled(False)
            self.status_label.setText(
                "Profile storage is unavailable — editing is disabled to protect existing data."
            )
            QMessageBox.warning(
                self,
                "Could not load profiles",
                "Profiles were not loaded. The file was left unchanged. "
                "Profile editing is disabled until the file is recovered.\n\n"
                f"{exc}",
            )
        self._refresh_profiles()

    def _save_profiles(self, updated: list[ConnectionProfile]) -> bool:
        if not self.profile_storage_writable:
            return False
        try:
            save_profiles(self.profiles_path, updated)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Could not save profiles", str(exc))
            return False
        self.profiles = updated
        return True

    def _refresh_profiles(self, selected_row: int = -1) -> None:
        self.profile_list.blockSignals(True)
        self.profile_list.clear()
        for profile in self.profiles:
            self.profile_list.addItem(profile.name)
        if self.profiles:
            row = selected_row if 0 <= selected_row < len(self.profiles) else 0
            self.profile_list.setCurrentRow(row)
        self.profile_list.blockSignals(False)
        self._show_selected_profile(self.profile_list.currentRow())
        self.export_button.setEnabled(bool(self.profiles))
        self._update_connection_controls()

    def _show_selected_profile(self, row: int) -> None:
        selected = 0 <= row < len(self.profiles)
        editable = selected and self.profile_storage_writable
        self.edit_button.setEnabled(editable)
        self.remove_button.setEnabled(editable)
        if not selected:
            self.import_xray_config_button.setEnabled(False)
            self.profile_details.setText("No profile selected.")
            self._update_connection_controls()
            return
        profile = self.profiles[row]
        has_xray_config = False
        config_store_ok = True
        try:
            has_xray_config = self.xray_config_store.has_config(profile.name)
        except (OSError, ValueError) as exc:
            config_store_ok = False
            self.status_label.setText(
                "Encrypted Xray config storage is unavailable; config import is disabled. "
                f"({type(exc).__name__})"
            )
        self.import_xray_config_button.setEnabled(
            self.profile_storage_writable
            and config_store_ok
            and profile.transport == Transport.XRAY
        )
        details = (
            f"{profile.transport.value.upper()}  •  "
            f"{profile.endpoint_host}:{profile.endpoint_port}"
        )
        if has_xray_config:
            details += "\nXray TUN config: imported and encrypted for this Windows user"
        self.profile_details.setText(details)
        self._update_connection_controls()

    def _add_profile(self) -> None:
        if not self.profile_storage_writable:
            return
        dialog = ProfileDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        profile = dialog.to_profile()
        if any(item.name.casefold() == profile.name.casefold() for item in self.profiles):
            QMessageBox.warning(self, "Duplicate profile", "A profile with this name already exists.")
            return
        updated = [*self.profiles, profile]
        if self._save_profiles(updated):
            self._refresh_profiles(len(updated) - 1)

    def _edit_profile(self) -> None:
        if not self.profile_storage_writable:
            return
        row = self.profile_list.currentRow()
        if not 0 <= row < len(self.profiles):
            return
        dialog = ProfileDialog(self, self.profiles[row])
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        profile = dialog.to_profile()
        if any(
            index != row and item.name.casefold() == profile.name.casefold()
            for index, item in enumerate(self.profiles)
        ):
            QMessageBox.warning(self, "Duplicate profile", "A profile with this name already exists.")
            return
        original = self.profiles[row]
        updated = list(self.profiles)
        updated[row] = profile
        renamed_config = original.name.casefold() != profile.name.casefold()
        if renamed_config:
            try:
                self.xray_config_store.rename(original.name, profile.name)
            except (OSError, ValueError) as exc:
                QMessageBox.warning(
                    self,
                    "Could not rename encrypted config",
                    "The profile was not changed because its encrypted Xray config "
                    f"could not be moved. ({type(exc).__name__})",
                )
                return
        if self._save_profiles(updated):
            if profile.transport != Transport.XRAY:
                try:
                    self.xray_config_store.remove(profile.name)
                except (OSError, ValueError) as exc:
                    QMessageBox.warning(
                        self,
                        "Encrypted config cleanup",
                        f"The profile was saved, but its unused Xray config remains stored. ({type(exc).__name__})",
                    )
            self._refresh_profiles(row)
        elif renamed_config:
            try:
                self.xray_config_store.rename(profile.name, original.name)
            except (OSError, ValueError):
                self.status_label.setText(
                    "Profile save failed and encrypted config rename-back also failed; "
                    "check the encrypted config store."
                )

    def _import_profiles(self) -> None:
        """Import validated metadata profiles, rejecting name collisions as a batch."""
        if not self.profile_storage_writable:
            return
        filename, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import profiles",
            "",
            "ApnaWin profile files (*.json);;JSON files (*.json);;All files (*)",
        )
        if not filename:
            return
        try:
            imported = load_profiles(filename)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Import failed", f"Profiles were not imported.\n\n{exc}")
            return

        existing_names = {profile.name.casefold() for profile in self.profiles}
        collisions = [
            profile.name for profile in imported if profile.name.casefold() in existing_names
        ]
        if collisions:
            preview = ", ".join(collisions[:5])
            if len(collisions) > 5:
                preview += f", and {len(collisions) - 5} more"
            QMessageBox.warning(
                self,
                "Import conflict",
                "Import was cancelled because these profile names already exist: " + preview,
            )
            return

        if not imported:
            QMessageBox.information(self, "Import profiles", "The selected file contains no profiles.")
            return
        updated = [*self.profiles, *imported]
        if self._save_profiles(updated):
            self._refresh_profiles(len(updated) - 1)
            self.status_label.setText(f"Imported {len(imported)} profile(s).")

    def _import_xray_config(self) -> None:
        """Import a full-tunnel Xray JSON config and encrypt it with current-user DPAPI."""
        if not self.profile_storage_writable:
            return
        row = self.profile_list.currentRow()
        if not 0 <= row < len(self.profiles):
            return
        profile = self.profiles[row]
        if profile.transport != Transport.XRAY:
            QMessageBox.warning(
                self,
                "Xray config",
                "Select an Xray profile before importing a TUN configuration.",
            )
            return
        filename, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import Xray TUN configuration",
            "",
            "Xray JSON configuration (*.json);;JSON files (*.json);;All files (*)",
        )
        if not filename:
            return
        try:
            with Path(filename).open("rb") as stream:
                config_bytes = stream.read(MAX_XRAY_CONFIG_BYTES + 1)
            if len(config_bytes) > MAX_XRAY_CONFIG_BYTES:
                raise ValueError("Xray config exceeds the configured size limit")
            config = parse_xray_config_bytes(config_bytes)
            inspect_tun_inbound(config)
            self.xray_config_store.save(profile.name, config_bytes)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.warning(
                self,
                "Xray config import failed",
                "The configuration was not stored. No plaintext copy was created by ApnaWin. "
                f"({type(exc).__name__})",
            )
            return
        self.status_label.setText(
            f"Xray TUN config imported and encrypted for {profile.name}. "
            "The installed helper verifies TUN routes, DNS, WFP leak protection and external egress."
        )
        self._show_selected_profile(row)
        self._update_connection_controls()

    def _export_profiles(self) -> None:
        """Export all currently loaded non-secret profile metadata."""
        if not self.profiles:
            return
        filename, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export profiles",
            "apnawin-profiles.json",
            "ApnaWin profile files (*.json);;JSON files (*.json)",
        )
        if not filename:
            return
        try:
            save_profiles(filename, self.profiles)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self.status_label.setText(
            f"Exported {len(self.profiles)} profile(s). Xray credentials/configs are not included."
        )

    def _remove_profile(self) -> None:
        if not self.profile_storage_writable:
            return
        row = self.profile_list.currentRow()
        if not 0 <= row < len(self.profiles):
            return
        profile = self.profiles[row]
        answer = QMessageBox.question(
            self,
            "Remove profile",
            f"Remove the profile “{escape(profile.name, quote=True)}”?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        updated = list(self.profiles)
        updated.pop(row)
        if self._save_profiles(updated):
            try:
                self.xray_config_store.remove(profile.name)
            except (OSError, ValueError) as exc:
                QMessageBox.warning(
                    self,
                    "Encrypted config cleanup",
                    f"The profile was removed, but its encrypted Xray config remains stored. ({type(exc).__name__})",
                )
            self._refresh_profiles(min(row, len(updated) - 1))


def main() -> int:
    """Start the GUI; --smoke-test initializes and closes it for CI packaging checks."""
    smoke_test = "--smoke-test" in sys.argv
    qt_args = [argument for argument in sys.argv if argument != "--smoke-test"]
    app = QApplication(qt_args)
    app.setOrganizationName("ApnaWin")
    app.setApplicationName("ApnaWin")
    window = MainWindow()
    window.show()
    if smoke_test:
        app.processEvents()
        window.close()
        return 0
    return app.exec()
