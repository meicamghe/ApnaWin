"""Native desktop shell with local connection-profile management.

Tunnel connection remains disabled until the privileged lifecycle, route/DNS
rollback, leak protection and end-to-end Windows acceptance tests pass.
"""

import os
import sys
from html import escape
from pathlib import Path

from PySide6.QtCore import QStandardPaths, Qt
from PySide6.QtWidgets import (
    QApplication,
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
from apnawin.engines.xray_process import MAX_XRAY_CONFIG_BYTES
from apnawin.storage.profile_store import load_profiles, save_profiles
from apnawin.services.proxy_profile_import import (
    ProxyProfileImportError,
    import_proxy_profiles,
)
from apnawin.storage.xray_config_store import XrayConfigStore
from apnawin.services.xray_connection_worker import XrayConnectionWorker


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


class MainWindow(QMainWindow):
    def __init__(
        self,
        profiles_path: Path | None = None,
        xray_config_store: XrayConfigStore | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("ApnaWin")
        self.resize(760, 520)
        self.profiles_path = profiles_path or profile_file_path()
        self.xray_config_store = xray_config_store or XrayConfigStore(
            self.profiles_path.with_name("xray-configs.json")
        )
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
        self.import_share_links_button = QPushButton("Import server links…")
        self.import_share_links_button.clicked.connect(self._import_share_links)
        self.export_button = QPushButton("Export…")
        self.export_button.clicked.connect(self._export_profiles)
        self.import_xray_config_button = QPushButton("Import Xray config…")
        self.import_xray_config_button.clicked.connect(self._import_xray_config)
        self.import_xray_config_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.remove_button.setEnabled(False)

        profile_actions = QHBoxLayout()
        profile_actions.addWidget(self.add_button)
        profile_actions.addWidget(self.edit_button)
        profile_actions.addWidget(self.remove_button)
        profile_actions.addWidget(self.import_button)
        profile_actions.addWidget(self.import_share_links_button)
        profile_actions.addWidget(self.export_button)
        profile_actions.addWidget(self.import_xray_config_button)
        profile_actions.addStretch(1)

        self._connection_worker: XrayConnectionWorker | None = None
        self._connection_state = "disconnected"
        self.connect_button = QPushButton("Connect")
        self.connect_button.setEnabled(False)
        self.connect_button.setToolTip(
            "Select an Xray profile with an encrypted TUN config and install ApnaWin under Program Files first."
        )
        self.connect_button.clicked.connect(self._toggle_connection)

        layout = QVBoxLayout()
        layout.addWidget(heading)
        layout.addWidget(self.status_label)
        layout.addWidget(QLabel("Connection profiles"))
        layout.addWidget(self.profile_list)
        layout.addLayout(profile_actions)
        layout.addWidget(self.profile_details)
        layout.addWidget(self.connect_button)
        layout.addStretch(1)

        root = QWidget()
        root.setLayout(layout)
        self.setCentralWidget(root)
        self._load_profiles()

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
            self.import_share_links_button.setEnabled(False)
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

    def _show_selected_profile(self, row: int) -> None:
        selected = 0 <= row < len(self.profiles)
        editable = selected and self.profile_storage_writable
        self.edit_button.setEnabled(editable)
        self.remove_button.setEnabled(editable)
        if not selected:
            self.import_xray_config_button.setEnabled(False)
            self.profile_details.setText("No profile selected.")
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
        self.connect_button.setEnabled(
            self._connection_worker is None
            and config_store_ok
            and profile.transport == Transport.XRAY
            and has_xray_config
            and self._installed_helper_path() is not None
        )
        details = (
            f"{profile.transport.value.upper()}  •  "
            f"{profile.endpoint_host}:{profile.endpoint_port}"
        )
        if has_xray_config:
            details += "\nXray TUN config: imported and encrypted for this Windows user"
        self.profile_details.setText(details)

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

    def _import_share_links(self) -> None:
        """Import standard Xray share links and persist their TUN configs with DPAPI."""
        if not self.profile_storage_writable:
            return
        filename, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import server links",
            "",
            "Server link lists (*.txt *.conf *.links);;Text files (*.txt);;All files (*)",
        )
        if not filename:
            return
        try:
            with Path(filename).open("rb") as stream:
                document = stream.read(1024 * 1024 + 1)
            if len(document) > 1024 * 1024:
                raise ValueError("Server-link document exceeds the 1 MiB limit")
            imported = import_proxy_profiles(
                document,
                self.profiles,
                self.xray_config_store,
                lambda profiles: save_profiles(self.profiles_path, profiles),
            )
        except ProxyProfileImportError as exc:
            if exc.cleanup_errors:
                self.status_label.setText(
                    "Share-link import failed; encrypted-config cleanup is incomplete. "
                    "Do not retry until the local config store is inspected."
                )
                QMessageBox.critical(
                    self,
                    "Import cleanup incomplete",
                    "The import failed and one or more encrypted records could not be removed. "
                    "The affected records are retained; no credentials are shown.",
                )
            else:
                QMessageBox.warning(
                    self,
                    "Server-link import failed",
                    "No profile batch was committed. Check the file and available disk space.",
                )
            return
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.warning(
                self,
                "Server-link import failed",
                f"No profiles were imported. ({type(exc).__name__})",
            )
            return

        self.profiles = [*self.profiles, *imported]
        self._refresh_profiles(len(self.profiles) - 1)
        self.status_label.setText(
            f"Imported {len(imported)} server profile(s); Xray configs are encrypted for this Windows user. "
            "Server compatibility has not yet been tested."
        )

    @staticmethod
    def _installed_helper_path() -> Path | None:
        """Return only the protected Program Files helper installation path."""
        program_files = os.environ.get("ProgramFiles")
        if not program_files:
            return None
        helper = Path(program_files) / "ApnaWin" / "ApnaWinElevator.exe"
        return helper if helper.is_file() and not helper.is_symlink() else None

    def _set_connection_controls(self, active: bool) -> None:
        self.profile_list.setEnabled(not active)
        buttons = (
            self.add_button, self.edit_button, self.remove_button,
            self.import_button, self.import_share_links_button,
            self.export_button, self.import_xray_config_button,
        )
        if active:
            for button in buttons:
                button.setEnabled(False)
            return
        self.add_button.setEnabled(self.profile_storage_writable)
        self.import_button.setEnabled(self.profile_storage_writable)
        self.import_share_links_button.setEnabled(self.profile_storage_writable)
        self.export_button.setEnabled(bool(self.profiles))
        self._show_selected_profile(self.profile_list.currentRow())

    def _toggle_connection(self) -> None:
        worker = self._connection_worker
        if worker is not None and worker.isRunning():
            worker.request_stop()
            self._connection_state = "stopping"
            self.connect_button.setText("Stopping…")
            self.connect_button.setEnabled(False)
            self.status_label.setText("Disconnect requested — restoring network state…")
            return

        row = self.profile_list.currentRow()
        if not 0 <= row < len(self.profiles):
            return
        profile = self.profiles[row]
        if profile.transport != Transport.XRAY:
            QMessageBox.warning(self, "Connect", "Only Xray profiles can use the Windows TUN engine.")
            return
        helper = self._installed_helper_path()
        if helper is None:
            QMessageBox.warning(
                self, "ApnaWin helper not installed",
                "Install ApnaWin from its extracted application folder using Install-ApnaWin.ps1 "
                "as Administrator, then launch the installed ApnaWin.exe.",
            )
            return
        if not self.xray_config_store.has_config(profile.name):
            QMessageBox.warning(self, "Missing Xray config", "Import server links or an Xray TUN config first.")
            return

        worker = XrayConnectionWorker(
            profile,
            helper,
            self.xray_config_store,
            parent=self,
        )
        worker.connected.connect(self._on_connection_connected)
        worker.failed.connect(self._on_connection_failed)
        worker.disconnected.connect(self._on_connection_disconnected)
        worker.lost.connect(self._on_connection_lost)
        worker.finished.connect(self._on_connection_worker_finished)
        self._connection_worker = worker
        self._connection_state = "starting"
        self._set_connection_controls(True)
        self.connect_button.setText("Cancel")
        self.connect_button.setEnabled(True)
        self.status_label.setText("Starting elevated Xray helper and waiting for tunnel traffic verification…")
        worker.start()

    def _on_connection_connected(self, pid: int) -> None:
        self._connection_state = "connected"
        self.connect_button.setText("Disconnect")
        self.connect_button.setEnabled(True)
        self.status_label.setText(
            f"Connected — HTTPS traffic verified through the ApnaWin tunnel (helper PID {pid})."
        )

    def _on_connection_failed(self, message: str) -> None:
        self._connection_state = "failed"
        self.connect_button.setText("Connect")
        self.connect_button.setEnabled(False)
        self.status_label.setText(f"Connection failed — {message}")

    def _on_connection_disconnected(self) -> None:
        self._connection_state = "disconnected"
        self.status_label.setText("Disconnected — helper confirmed tunnel shutdown.")

    def _on_connection_lost(self, exit_code: int) -> None:
        self._connection_state = "lost"
        self.status_label.setText(
            f"Connection lost — elevated helper exited unexpectedly (code {exit_code})."
        )

    def _on_connection_worker_finished(self) -> None:
        worker = self._connection_worker
        if worker is not None and worker.cleanup_failed:
            self._connection_state = "cleanup-error"
            self.connect_button.setText("Cleanup required")
            self.connect_button.setEnabled(False)
            self.status_label.setText(
                "Tunnel cleanup could not be confirmed. Do not reconnect. "
                "Close ApnaWin so the elevated helper can detect parent exit and unwind."
            )
            return
        self._connection_worker = None
        if worker is not None:
            worker.deleteLater()
        self._set_connection_controls(False)
        self.connect_button.setText("Connect")
        self.connect_button.setEnabled(False)
        self._refresh_profiles(self.profile_list.currentRow())

    def closeEvent(self, event) -> None:
        worker = self._connection_worker
        if worker is not None and worker.isRunning():
            worker.request_stop()
            if not worker.wait(20000):
                self.status_label.setText(
                    "The tunnel helper is still stopping. Keep ApnaWin open until cleanup completes."
                )
                event.ignore()
                return
        # If cleanup failed, closing the desktop is the final recovery signal:
        # the elevated helper owns a wait handle on this process and unwinds
        # its Xray Job Object when the parent exits.
        event.accept()

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
            "Connect remains disabled until route/DNS rollback, leak-protection and end-to-end VPN acceptance tests pass."
        )
        self._show_selected_profile(row)

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
