"""Native desktop shell with supervised Windows Xray TUN connection support."""

import os
import secrets
import sys
from dataclasses import replace
from html import escape
from pathlib import Path

from PySide6.QtCore import QStandardPaths, Qt, QThread, QTimer, Signal, QUrl
from PySide6.QtGui import QDesktopServices
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
    QMenu,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
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
from apnawin.services.apna_lite_catalog import (
    MAX_INPUT_BYTES,
    decode_apna_lite_apk_catalog,
    decode_apna_lite_catalog,
)
from apnawin.services.apna_lite_source import APNA_LITE_CATALOG_URL, ApnaLiteCatalogSource
from apnawin.services.apna_lite_profile_mapper import (
    build_apna_lite_ssh_profile,
    list_apna_lite_ssh_payloads,
    list_apna_lite_ssh_servers,
)
from apnawin.storage.apna_profile_store import ApnaProfileStore
from apnawin.services.connection_controller import ConnectionController
from apnawin.services.xray_tunnel_supervisor import XrayTunnelSupervisor



def show_copyable_error(parent, title: str, message: str) -> None:
    """Show diagnostic text in a selectable, copyable error window."""
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setMinimumSize(720, 380)
    text = QPlainTextEdit(dialog)
    text.setObjectName("errorDetails")
    text.setPlainText(str(message))
    text.setReadOnly(True)
    text.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
    text.setTextInteractionFlags(
        Qt.TextInteractionFlag.TextSelectableByMouse
        | Qt.TextInteractionFlag.TextSelectableByKeyboard
    )
    copy_button = QPushButton("Copy error")
    copy_button.clicked.connect(
        lambda: QApplication.clipboard().setText(text.toPlainText())
    )
    close_button = QPushButton("Close")
    close_button.clicked.connect(dialog.accept)
    buttons = QHBoxLayout()
    buttons.addWidget(copy_button)
    buttons.addStretch(1)
    buttons.addWidget(close_button)
    layout = QVBoxLayout(dialog)
    layout.addWidget(QLabel("Select the text below or use Copy error:"))
    layout.addWidget(text)
    layout.addLayout(buttons)
    dialog.exec()


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


class _ApnaCatalogFetchWorker(QThread):
    """Fetch the live catalog off the UI thread and support cancellation."""

    progress = Signal(int, object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        from threading import Event
        self.cancel_event = Event()
        self.catalog = None
        self.error = None

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        try:
            self.catalog = ApnaLiteCatalogSource(
                timeout_seconds=3.0, retry_attempts=2,
                progress_callback=self.progress.emit,
                cancel_event=self.cancel_event,
            ).fetch_document()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"


class _ApnaCatalogFileWorker(QThread):
    """Read and decode a downloaded APNA catalog without blocking the UI."""

    def __init__(self, filename: str, parent=None) -> None:
        super().__init__(parent)
        self.filename = filename
        self.catalog = None
        self.source_label = "downloaded catalog file"
        self.error = None

    def run(self) -> None:
        try:
            path = Path(self.filename)
            with path.open("rb") as stream:
                signature = stream.read(4)
            if signature.startswith(b"PK"):
                self.catalog = decode_apna_lite_apk_catalog(path)
                self.source_label = "APK"
            else:
                size = path.stat().st_size
                if size <= 0 or size > MAX_INPUT_BYTES:
                    raise ValueError("APNA catalog file size is invalid")
                self.catalog = decode_apna_lite_catalog(path.read_bytes())
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"


class _ConnectionWorker(QThread):
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
        self.resize(1120, 780)
        self.setMinimumSize(900, 650)
        self.profiles_path = profiles_path or profile_file_path()
        self.xray_config_store = xray_config_store or XrayConfigStore(
            self.profiles_path.with_name("xray-configs.json")
        )
        self.apna_profile_store = apna_profile_store or ApnaProfileStore(
            self.profiles_path.with_name("apna-profiles.json")
        )
        self.connection_controller = connection_controller or self._create_live_connection_controller()
        self._connection_worker = None
        self._catalog_worker = None
        self._file_worker = None
        self._close_after_disconnect = False
        self._close_after_catalog_fetch = False
        self.profiles: list[ConnectionProfile] = []
        self.profile_storage_writable = True

        heading = QLabel("ApnaWin")
        heading.setObjectName("heading")
        self.status_label = QLabel(
            "Disconnected — no verified VPN connection."
        )
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self.catalog_progress_label = QLabel("")
        self.catalog_progress_label.setTextFormat(Qt.TextFormat.PlainText)
        self.catalog_progress_label.setWordWrap(True)
        self.catalog_progress_label.hide()
        self.catalog_progress_bar = QProgressBar()
        self.catalog_progress_bar.setRange(0, 100)
        self.catalog_progress_bar.setValue(0)
        self.catalog_progress_bar.setTextVisible(True)
        self.catalog_progress_bar.hide()
        self.cancel_catalog_button = QPushButton("Cancel catalog download")
        self.cancel_catalog_button.clicked.connect(self._cancel_live_apna_catalog)
        self.cancel_catalog_button.hide()

        self.profile_list = QListWidget()
        self.profile_list.setMinimumHeight(280)
        self.profile_list.setUniformItemSizes(True)
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
        self.clear_all_button = QPushButton("Clear all servers")
        self.clear_all_button.setToolTip("Remove every saved profile and its encrypted settings.")
        self.clear_all_button.clicked.connect(self._clear_all_profiles)
        self.import_button = QPushButton("Import…")
        self.import_menu = QMenu(self)
        self.import_profiles_action = self.import_menu.addAction("ApnaWin profiles (JSON)…")
        self.import_profiles_action.triggered.connect(self._import_profiles)
        self.import_apna_file_action = self.import_menu.addAction("APNA encrypted catalog / APK…")
        self.import_apna_file_action.triggered.connect(self._import_apna_apk)
        self.import_apna_live_action = self.import_menu.addAction("Fetch live APNA catalog…")
        self.import_apna_live_action.triggered.connect(self._fetch_live_apna_catalog)
        self.download_apna_manual_action = self.import_menu.addAction("Open manual APNA catalog download…")
        self.download_apna_manual_action.triggered.connect(self._open_manual_apna_download)
        self.import_xray_action = self.import_menu.addAction("Xray JSON (VLESS / VMess / Trojan / UDP-capable)…")
        self.import_xray_action.triggered.connect(self._import_xray_config)
        self.import_button.setMenu(self.import_menu)
        self.export_button = QPushButton("Export…")
        self.export_button.clicked.connect(self._export_profiles)
        self.import_xray_config_button = QPushButton("Import Xray config…")
        self.import_xray_config_button.clicked.connect(self._import_xray_config)
        self.import_xray_config_button.setEnabled(False)
        self.import_apna_apk_button = QPushButton("Import APNA file…")
        self.import_apna_apk_button.setToolTip(
            "Import an APK or a downloaded raw APNA catalog file."
        )
        self.import_apna_apk_button.clicked.connect(self._import_apna_apk)
        self.import_apna_apk_button.setEnabled(os.name == "nt")
        self.import_apna_live_button = QPushButton("Fetch live APNA catalog…")
        self.import_apna_live_button.clicked.connect(self._fetch_live_apna_catalog)
        self.import_apna_live_button.setEnabled(os.name == "nt")
        self.verify_apna_host_key_button = QPushButton("Verify SSH host key…")
        self.verify_apna_host_key_button.setToolTip(
            "Probe the selected APNA server and explicitly pin its SSH fingerprint."
        )
        self.verify_apna_host_key_button.clicked.connect(self._verify_selected_apna_host_key)
        self.verify_apna_host_key_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.remove_button.setEnabled(False)

        # Keep action buttons in compact rows so the window remains usable
        # on ordinary laptop displays and at non-maximized sizes.
        profile_actions = QVBoxLayout()
        profile_actions.setSpacing(6)
        profile_actions_primary = QHBoxLayout()
        for button in (
            self.add_button, self.edit_button, self.remove_button,
            self.import_button, self.export_button, self.clear_all_button,
        ):
            profile_actions_primary.addWidget(button)
        profile_actions_primary.addStretch(1)
        profile_actions_secondary = QHBoxLayout()
        # Legacy action buttons remain as internal compatibility handles, but
        # all import paths are exposed through the single Import… menu.
        self.import_xray_config_button.hide()
        self.import_apna_apk_button.hide()
        self.import_apna_live_button.hide()
        profile_actions_secondary.addWidget(self.verify_apna_host_key_button)
        profile_actions_secondary.addStretch(1)
        profile_actions.addLayout(profile_actions_primary)
        profile_actions.addLayout(profile_actions_secondary)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self._connect_selected_profile)
        self.connect_button.setEnabled(False)
        self.connect_button.setToolTip(
            "Waits for verified TUN routes, DNS and external TLS egress."
            if self.connection_controller is not None
            else "Connection engine unavailable. Run Install-ApnaWin.ps1 as administrator from the extracted folder; "
                 "the portable ZIP does not provision the protected elevated VPN helper."
        )
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self._disconnect_tunnel)
        self.disconnect_button.setEnabled(False)

        layout = QVBoxLayout()
        layout.addWidget(heading)
        layout.addWidget(self.status_label)
        layout.addWidget(self.catalog_progress_label)
        layout.addWidget(self.catalog_progress_bar)
        layout.addWidget(self.cancel_catalog_button)
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
        if profile is not None:
            try:
                if profile.transport is Transport.XRAY:
                    has_config = self.xray_config_store.has_config(profile.name)
                elif profile.transport is Transport.APNA_SSH:
                    has_config = self.apna_profile_store.has_config(profile.name)
            except (OSError, ValueError):
                has_config = False
        state = controller.state if controller is not None else ConnectionState.DISCONNECTED
        self.connect_button.setEnabled(
            not busy and controller is not None and profile is not None
            and profile.transport in {Transport.XRAY, Transport.APNA_SSH}
            and has_config and state is ConnectionState.DISCONNECTED
        )
        self.disconnect_button.setEnabled(
            not busy and controller is not None
            and state in {ConnectionState.CONNECTED, ConnectionState.ERROR}
        )
        if hasattr(self, "import_xray_action"):
            self.import_xray_action.setEnabled(
                self.profile_storage_writable
                and profile is not None
                and profile.transport is Transport.XRAY
            )
        self._update_catalog_import_actions()

    def _connect_selected_profile(self):
        if self.connection_controller is None or self._connection_worker is not None:
            return
        row = self.profile_list.currentRow()
        if (
            0 <= row < len(self.profiles)
            and self.profiles[row].transport in {Transport.XRAY, Transport.APNA_SSH}
        ):
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
            self.status_label.setText("Connected — selected tunnel, TUN, dual-stack routes, DNS and external egress verified.")
        elif success:
            self.status_label.setText("Disconnected — VPN helper stopped.")
        else:
            diagnostic = "VPN operation failed:\n" + str(detail)
            self.status_label.setText(diagnostic)
            show_copyable_error(self, "VPN operation failed", diagnostic)
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
        workers = (self._catalog_worker, self._file_worker)
        if any(worker is not None and worker.isRunning() for worker in workers):
            self._close_after_catalog_fetch = True
            if self._catalog_worker is not None and self._catalog_worker.isRunning():
                self._catalog_worker.cancel()
            event.ignore()
            return
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
            self.import_apna_apk_button.setEnabled(False)
            self.import_apna_live_button.setEnabled(False)
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
        self.clear_all_button.setEnabled(bool(self.profiles) and self.profile_storage_writable)
        self._update_connection_controls()

    def _show_selected_profile(self, row: int) -> None:
        selected = 0 <= row < len(self.profiles)
        editable = selected and self.profile_storage_writable
        self.edit_button.setEnabled(editable)
        self.remove_button.setEnabled(editable)
        self.clear_all_button.setEnabled(bool(self.profiles) and self.profile_storage_writable)
        self.import_apna_apk_button.setEnabled(
            self.profile_storage_writable and os.name == "nt"
        )
        self.import_apna_live_button.setEnabled(
            self.profile_storage_writable
            and os.name == "nt"
            and self._catalog_worker is None
        )
        self.verify_apna_host_key_button.setEnabled(
            self.profile_storage_writable and selected
            and self.profiles[row].transport is Transport.APNA_SSH
        )
        if not selected:
            self.import_xray_config_button.setEnabled(False)
            self.profile_details.setText("No profile selected.")
            self._update_connection_controls()
            return
        profile = self.profiles[row]
        has_xray_config = False
        has_apna_config = False
        try:
            has_xray_config = self.xray_config_store.has_config(profile.name)
        except (OSError, ValueError) as exc:
            self.status_label.setText(
                "Encrypted Xray config storage is unavailable. "
                f"({type(exc).__name__})"
            )
        try:
            has_apna_config = self.apna_profile_store.has_config(profile.name)
        except (OSError, ValueError) as exc:
            self.status_label.setText(
                "Encrypted APNA profile storage is unavailable. "
                f"({type(exc).__name__})"
            )
        self.import_xray_config_button.setEnabled(
            self.profile_storage_writable and profile.transport == Transport.XRAY
        )
        details = (
            f"{profile.transport.value.upper()}  •  "
            f"{profile.endpoint_host}:{profile.endpoint_port}"
        )
        if has_xray_config and profile.transport is Transport.XRAY:
            details += "\nXray TUN config: imported and encrypted for this Windows user"
        if has_apna_config and profile.transport is Transport.APNA_SSH:
            try:
                config = self.apna_profile_store.load(profile)
                details += (
                    "\nAPNA SSH settings: encrypted for this Windows user"
                    f"\nPayload transport: {config.payload.mode.value}"
                    f"\nPayload endpoint: {config.payload.connect_host}:{config.payload.connect_port}"
                )
                if config.udpgw_host and config.udpgw_port:
                    details += f"\nUDP gateway: {config.udpgw_host}:{config.udpgw_port}"
                if config.ssh.host_key_sha256:
                    details += f"\nSSH host key: pinned ({config.ssh.host_key_sha256})"
                else:
                    details += "\nSSH host key: system known_hosts verification"
            except (OSError, ValueError, TypeError) as exc:
                details += f"\nAPNA encrypted settings unavailable ({type(exc).__name__})"
        self.profile_details.setText(details)
        self._update_connection_controls()

    def _verify_selected_apna_host_key(self) -> None:
        """Probe and explicitly pin the selected APNA SSH host key."""
        row = self.profile_list.currentRow()
        if not self.profile_storage_writable or not 0 <= row < len(self.profiles):
            return
        profile = self.profiles[row]
        if profile.transport is not Transport.APNA_SSH:
            return
        try:
            config = self.apna_profile_store.load(profile)
            fingerprint = scan_apna_ssh_host_key(config)
        except Exception as exc:
            show_copyable_error(
                self,
                "SSH host-key verification failed",
                "The selected server did not complete an SSH key exchange.\n\n"
                f"{type(exc).__name__}: {exc}",
            )
            return
        answer = QMessageBox.question(
            self,
            "Trust SSH host key?",
            "Fingerprint observed from this server:\\n\\n"
            f"{fingerprint}\\n\\n"
            "This is a first-use fingerprint, not an independently authenticated identity. "
            "Only continue if it matches a fingerprint published by your provider through "
            "a separate trusted channel. Accepting an unverified fingerprint can trust a "
            "man-in-the-middle server. Pin this fingerprint for this profile?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            trusted_ssh = replace(config.ssh, host_key_sha256=fingerprint)
            self.apna_profile_store.save(profile, replace(config, ssh=trusted_ssh))
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.warning(
                self,
                "Could not save SSH host key",
                f"The fingerprint was not stored. ({type(exc).__name__}: {exc})",
            )
            return
        self.status_label.setText(
            f"SSH host key pinned for {profile.name}. You can now retry the VPN connection."
        )
        self._show_selected_profile(row)

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
        original = self.profiles[row]
        dialog = ProfileDialog(self, original)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        profile = dialog.to_profile()
        if any(
            index != row and item.name.casefold() == profile.name.casefold()
            for index, item in enumerate(self.profiles)
        ):
            QMessageBox.warning(self, "Duplicate profile", "A profile with this name already exists.")
            return
        if (
            original.transport is Transport.APNA_SSH
            and profile.transport is Transport.APNA_SSH
            and (
                original.endpoint_host != profile.endpoint_host
                or original.endpoint_port != profile.endpoint_port
            )
        ):
            QMessageBox.warning(
                self,
                "APNA profile is bound to encrypted settings",
                "Changing an APNA server endpoint invalidates its encrypted SSH/payload settings. "
                "Import the APNA APK again to create a profile for a different endpoint.",
            )
            return

        updated = list(self.profiles)
        updated[row] = profile
        renamed_config = original.name.casefold() != profile.name.casefold()
        renamed_xray = renamed_config and original.transport is Transport.XRAY
        renamed_apna = (
            renamed_config
            and original.transport is Transport.APNA_SSH
            and profile.transport is Transport.APNA_SSH
        )
        if renamed_xray:
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
        if renamed_apna:
            try:
                self.apna_profile_store.rename(original, profile)
            except (OSError, TypeError, ValueError) as exc:
                QMessageBox.warning(
                    self,
                    "Could not rename encrypted APNA settings",
                    "The profile was not changed because its encrypted APNA settings "
                    f"could not be moved. ({type(exc).__name__})",
                )
                return

        if self._save_profiles(updated):
            if original.transport is Transport.XRAY and profile.transport is not Transport.XRAY:
                try:
                    self.xray_config_store.remove(profile.name if renamed_xray else original.name)
                except (OSError, ValueError) as exc:
                    QMessageBox.warning(
                        self,
                        "Encrypted config cleanup",
                        f"The profile was saved, but its unused Xray config remains stored. ({type(exc).__name__})",
                    )
            if original.transport is Transport.APNA_SSH and profile.transport is not Transport.APNA_SSH:
                try:
                    self.apna_profile_store.remove(original.name)
                except (OSError, ValueError) as exc:
                    QMessageBox.warning(
                        self,
                        "Encrypted config cleanup",
                        f"The profile was saved, but its unused APNA settings remain stored. ({type(exc).__name__})",
                    )
            self._refresh_profiles(row)
        elif renamed_xray:
            try:
                self.xray_config_store.rename(profile.name, original.name)
            except (OSError, ValueError):
                self.status_label.setText(
                    "Profile save failed and encrypted Xray config rename-back also failed; "
                    "check the encrypted config store."
                )
        elif renamed_apna:
            try:
                self.apna_profile_store.rename(profile, original)
            except (OSError, TypeError, ValueError):
                self.status_label.setText(
                    "Profile save failed and encrypted APNA settings rename-back also failed; "
                    "check the encrypted APNA profile store."
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

    def _update_catalog_import_actions(self) -> None:
        fetching = self._catalog_worker is not None and self._catalog_worker.isRunning()
        decoding = self._file_worker is not None and self._file_worker.isRunning()
        available = self.profile_storage_writable and os.name == "nt"
        self.import_apna_file_action.setEnabled(available and not decoding)
        self.import_apna_live_action.setEnabled(available and not fetching)
        self.download_apna_manual_action.setEnabled(available)
        self.import_apna_apk_button.setEnabled(available and not decoding)
        self.import_apna_live_button.setEnabled(available and not fetching)
        self.cancel_catalog_button.setVisible(fetching)
        self.cancel_catalog_button.setEnabled(fetching)

    def _fetch_live_apna_catalog(self) -> None:
        """Fetch the latest APNA catalog asynchronously, keeping the UI responsive."""
        if not self.profile_storage_writable or os.name != "nt":
            return
        if self._catalog_worker is not None and self._catalog_worker.isRunning():
            return
        worker = _ApnaCatalogFetchWorker(self)
        self._catalog_worker = worker
        self._update_catalog_import_actions()
        worker.progress.connect(self._live_apna_catalog_progress)
        worker.finished.connect(self._live_apna_catalog_finished)
        self.import_apna_live_button.setEnabled(False)
        self.cancel_catalog_button.show()
        self.cancel_catalog_button.setEnabled(True)
        self.catalog_progress_label.setText("در حال اتصال و دریافت کاتالوگ سرورها…")
        self.catalog_progress_label.show()
        self.catalog_progress_bar.setRange(0, 100)
        self.catalog_progress_bar.setValue(0)
        self.catalog_progress_bar.setFormat("0%")
        self.catalog_progress_bar.show()
        self.status_label.setText(
            "Fetching the live APNA catalog with bounded retries and range resume…"
        )
        worker.start()

    def _open_manual_apna_download(self) -> None:
        if self.profile_storage_writable and not QDesktopServices.openUrl(QUrl(APNA_LITE_CATALOG_URL)):
            show_copyable_error(self, "Open manual download",
                "Open this URL in your browser:\n" + APNA_LITE_CATALOG_URL)

    def _cancel_live_apna_catalog(self) -> None:
        worker = self._catalog_worker
        if worker is not None and worker.isRunning():
            worker.cancel()
            self.cancel_catalog_button.setEnabled(False)
            self.catalog_progress_label.setText("درخواست لغو ارسال شد؛ منتظر توقف شبکه…")

    @staticmethod
    def _format_catalog_bytes(value: int) -> str:
        if value < 1024:
            return f"{value} B"
        if value < 1024 * 1024:
            return f"{value / 1024:.1f} KB"
        return f"{value / (1024 * 1024):.2f} MB"

    def _live_apna_catalog_progress(self, received: int, total) -> None:
        received_text = self._format_catalog_bytes(received)
        if isinstance(total, int) and total > 0:
            total_text = self._format_catalog_bytes(total)
            percent = min(100, int(received * 100 / total))
            self.catalog_progress_bar.setRange(0, 100)
            self.catalog_progress_bar.setValue(percent)
            self.catalog_progress_bar.setFormat(f"{percent}%")
            self.catalog_progress_label.setText(
                f"دریافت کاتالوگ سرورها: {received_text} از {total_text}"
            )
        else:
            self.catalog_progress_bar.setRange(0, 0)
            self.catalog_progress_label.setText(
                f"دریافت کاتالوگ سرورها: {received_text} (حجم کل نامشخص)"
            )

    def _live_apna_catalog_finished(self) -> None:
        worker = self._catalog_worker
        if worker is None:
            return
        catalog, error = worker.catalog, worker.error
        self._catalog_worker = None
        worker.deleteLater()
        self._update_catalog_import_actions()
        if self._close_after_catalog_fetch:
            self._close_after_catalog_fetch = False
            self.close()
            return
        if error is not None or not isinstance(catalog, dict):
            detail = error or "The catalog response was empty or invalid."
            if "cancel" in detail.lower():
                self.catalog_progress_label.setText("دریافت لغو شد؛ ورود دستی فعال است.")
                self.catalog_progress_bar.hide()
                self.status_label.setText("APNA catalog download cancelled.")
                return
            self.catalog_progress_label.setText("دریافت کاتالوگ ناموفق بود؛ می‌توانید دوباره تلاش کنید.")
            self.catalog_progress_bar.setFormat("ناموفق")
            self.status_label.setText(
                "Live APNA catalog unavailable. You can still import an APK catalog."
            )
            show_copyable_error(
                self,
                "Live APNA catalog failed",
                "The latest APNA server catalog could not be downloaded or decoded. "
                "No plaintext catalog was saved.\n\n" + detail,
            )
            return
        self.catalog_progress_bar.setRange(0, 100)
        self.catalog_progress_bar.setValue(100)
        self.catalog_progress_bar.setFormat("100%")
        self.catalog_progress_label.setText("دریافت کاتالوگ کامل شد.")
        self._import_apna_catalog(catalog, source_label="live catalog")

    def _import_apna_apk(self) -> None:
        """Import an APNA APK/raw catalog asynchronously; keep the UI responsive."""
        if not self.profile_storage_writable or os.name != "nt":
            return
        if self._file_worker is not None and self._file_worker.isRunning():
            return
        filename, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import APNA catalog or APNA Tunnel Lite APK",
            "",
            "APNA catalog or APK (*.bin *.dat *.json *.apk);;All files (*)",
        )
        if not filename:
            return
        worker = _ApnaCatalogFileWorker(filename, self)
        self._file_worker = worker
        self._update_catalog_import_actions()
        worker.finished.connect(self._apna_file_import_finished)
        self.import_apna_apk_button.setEnabled(False)
        self.catalog_progress_label.setText("در حال خواندن و رمزگشایی فایل سرورها…")
        self.catalog_progress_label.show()
        self.catalog_progress_bar.setRange(0, 0)
        self.catalog_progress_bar.setFormat("در حال پردازش…")
        self.catalog_progress_bar.show()
        self.status_label.setText("Decoding APNA catalog in the background…")
        worker.start()

    def _apna_file_import_finished(self) -> None:
        worker = self._file_worker
        if not isinstance(worker, _ApnaCatalogFileWorker):
            return
        catalog, error = worker.catalog, worker.error
        source_label = worker.source_label
        self._file_worker = None
        worker.deleteLater()
        self._update_catalog_import_actions()
        if self._close_after_catalog_fetch:
            self._close_after_catalog_fetch = False
            self.close()
            return
        if error is not None or not isinstance(catalog, dict):
            detail = error or "The selected file was empty or invalid."
            self.catalog_progress_label.setText("رمزگشایی فایل ناموفق بود؛ فایل اصلی تغییر نکرد.")
            self.catalog_progress_bar.setFormat("ناموفق")
            show_copyable_error(
                self,
                "APNA file import failed",
                "The selected APNA file could not be decoded. The source file was not modified.\n\n"
                + detail,
            )
            return
        self.catalog_progress_bar.setRange(0, 100)
        self.catalog_progress_bar.setValue(100)
        self.catalog_progress_bar.setFormat("100%")
        self.catalog_progress_label.setText("رمزگشایی فایل کامل شد؛ در حال آماده‌سازی فهرست…")
        self._import_apna_catalog(catalog, source_label=source_label)

    def _import_apna_catalog(self, catalog: dict, *, source_label: str) -> None:
        """Import supported SSH servers and report the complete tier/category inventory."""
        sections = (
            ("Free_servers", "Free"),
            ("Premium_servers", "Premium"),
            ("Vip_servers", "VIP"),
            ("Private_servers", "Private"),
        )
        supported_categories = {"ocsws", "ocscf", "ocsnormal", "ocshttp"}
        inventory_lines = []
        record_inventory_lines = []
        all_total = 0
        supported_total = 0
        for section, label in sections:
            records = catalog.get(section, [])
            if not isinstance(records, list):
                records = []
            all_total += len(records)
            category_counts = {}
            for index, record in enumerate(records, start=1):
                if isinstance(record, dict):
                    category = str(record.get("category", "unknown"))
                    category_counts[category] = category_counts.get(category, 0) + 1
                    name = str(record.get("server_name") or f"Server {index}")[:128]
                    host = str(record.get("server_host") or "host unavailable")[:253]
                    record_inventory_lines.append(
                        f"{label} | {category} | {name} | {host}"
                    )
                else:
                    record_inventory_lines.append(
                        f"{label} | invalid record {index} | not importable"
                    )
            ssh_count = sum(
                count for category, count in category_counts.items()
                if category in supported_categories
            )
            supported_total += ssh_count
            category_text = ", ".join(
                f"{category}={count}" for category, count in sorted(category_counts.items())
            ) or "no records"
            inventory_lines.append(
                f"{label}: {len(records)} server records; "
                f"{ssh_count} SSH-compatible; categories: {category_text}"
            )

        try:
            servers = list_apna_lite_ssh_servers(catalog)
        except (TypeError, ValueError) as exc:
            show_copyable_error(
                self,
                "APNA catalog import failed",
                f"Catalog structure is unsupported: {type(exc).__name__}: {exc}",
            )
            return

        existing = {item.name.casefold() for item in self.profiles}
        imported = []
        skipped_duplicate = 0
        skipped_unmappable = 0
        skipped_storage = 0
        for server in servers:
            category = str(server.get("category", ""))
            payloads = list_apna_lite_ssh_payloads(catalog, category)
            mapped_any = False
            # A server can expose several valid payload variants. Import every
            # distinct server/payload combination instead of stopping at the
            # first one; the previous break silently hid the remaining choices.
            for payload in payloads:
                try:
                    candidate = build_apna_lite_ssh_profile(catalog, server, payload)
                except (TypeError, ValueError):
                    continue
                mapped_any = True
                key = candidate.profile.name.casefold()
                if key in existing:
                    skipped_duplicate += 1
                    continue
                try:
                    self.apna_profile_store.save(candidate.profile, candidate.session_config)
                except (OSError, TypeError, ValueError):
                    skipped_storage += 1
                    continue
                imported.append(candidate.profile)
                existing.add(key)
            if not mapped_any:
                skipped_unmappable += 1

        report_lines = [
            f"Source: {source_label}",
            f"Catalog total: {all_total} server records across all tiers",
            f"SSH-compatible records: {supported_total}",
            f"New profiles imported: {len(imported)}",
            f"Existing/duplicate profiles skipped: {skipped_duplicate}",
            f"Incomplete or unmappable SSH records skipped: {skipped_unmappable}",
            f"Encrypted-store failures: {skipped_storage}",
            "",
            *inventory_lines,
            "",
            "Complete server inventory (tier | category | name | host):",
            *record_inventory_lines,
            "",
            "Only SSH-compatible categories are currently importable. Other categories are "
            "listed for visibility but are not presented as connectable profiles.",
        ]
        report = "\n".join(report_lines)
        if imported:
            updated = [*self.profiles, *imported]
            if self._save_profiles(updated):
                self._refresh_profiles(len(updated) - 1)
                self.status_label.setText(
                    f"Imported {len(imported)} APNA SSH profiles. "
                    f"Catalog contains {all_total} server records; "
                    f"{supported_total} are SSH-compatible. "
                    "Open the import report for tier/category counts."
                )
            else:
                for profile in imported:
                    try:
                        self.apna_profile_store.remove(profile.name)
                    except (OSError, ValueError):
                        pass
                report += "\n\nProfile metadata could not be saved; newly written encrypted records were rolled back."
        else:
            self.status_label.setText(
                f"No new APNA profiles imported. Catalog contains {all_total} server records; "
                f"{supported_total} are SSH-compatible."
            )
        show_copyable_error(self, "APNA catalog import report", report)

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
            f"Exported {len(self.profiles)} profile(s). Xray and APNA secrets/configs are not included."
        )

    def _clear_all_profiles(self) -> None:
        """Remove all profile metadata and matching encrypted settings after confirmation."""
        if not self.profile_storage_writable or not self.profiles:
            return
        answer = QMessageBox.question(
            self,
            "Clear all servers",
            f"Remove all {len(self.profiles)} saved profiles and their encrypted settings?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        previous = list(self.profiles)
        if not self._save_profiles([]):
            return
        cleanup_errors = []
        for profile in previous:
            for label, store in (
                ("Xray", self.xray_config_store),
                ("APNA", self.apna_profile_store),
            ):
                try:
                    store.remove(profile.name)
                except (OSError, TypeError, ValueError) as exc:
                    cleanup_errors.append(f"{profile.name} / {label}: {type(exc).__name__}")
        self._refresh_profiles()
        if cleanup_errors:
            show_copyable_error(
                self,
                "Some encrypted settings could not be cleared",
                "The profile list was cleared, but these encrypted records may remain:\n"
                + "\n".join(cleanup_errors),
            )
        else:
            self.status_label.setText(f"Cleared all {len(previous)} saved profiles and their encrypted settings.")

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
            cleanup_errors = []
            try:
                self.xray_config_store.remove(profile.name)
            except (OSError, ValueError) as exc:
                cleanup_errors.append(f"Xray ({type(exc).__name__})")
            try:
                self.apna_profile_store.remove(profile.name)
            except (OSError, ValueError) as exc:
                cleanup_errors.append(f"APNA ({type(exc).__name__})")
            if cleanup_errors:
                QMessageBox.warning(
                    self,
                    "Encrypted config cleanup",
                    "The profile was removed, but encrypted settings remain stored: "
                    + ", ".join(cleanup_errors),
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
