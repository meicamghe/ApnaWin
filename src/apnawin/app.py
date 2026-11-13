"""Native desktop shell with local connection-profile management.

Tunnel connection remains disabled until a real Windows tunnel engine is integrated.
"""

import sys
from pathlib import Path

from PySide6.QtCore import QStandardPaths
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
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
from apnawin.storage.profile_store import load_profiles, save_profiles


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
    def __init__(self, profiles_path: Path | None = None) -> None:
        super().__init__()
        self.setWindowTitle("ApnaWin")
        self.resize(760, 520)
        self.profiles_path = profiles_path or profile_file_path()
        self.profiles: list[ConnectionProfile] = []

        heading = QLabel("ApnaWin")
        heading.setObjectName("heading")
        self.status_label = QLabel(
            "Disconnected — tunnel engine is not configured yet."
        )

        self.profile_list = QListWidget()
        self.profile_list.currentRowChanged.connect(self._show_selected_profile)

        self.profile_details = QLabel("No profile selected.")
        self.profile_details.setWordWrap(True)

        add_button = QPushButton("Add")
        add_button.clicked.connect(self._add_profile)
        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self._edit_profile)
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self._remove_profile)
        self.edit_button.setEnabled(False)
        self.remove_button.setEnabled(False)

        profile_actions = QHBoxLayout()
        profile_actions.addWidget(add_button)
        profile_actions.addWidget(self.edit_button)
        profile_actions.addWidget(self.remove_button)
        profile_actions.addStretch(1)

        self.connect_button = QPushButton("Connect")
        self.connect_button.setEnabled(False)
        self.connect_button.setToolTip(
            "Connection will be enabled after a real Windows tunnel engine is integrated."
        )

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
            self.profiles = []
        except (OSError, ValueError) as exc:
            QMessageBox.warning(
                self,
                "Could not load profiles",
                f"Profiles were not loaded. The file was left unchanged.\\n\\n{exc}",
            )
            self.profiles = []
        self._refresh_profiles()

    def _save_profiles(self, updated: list[ConnectionProfile]) -> bool:
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

    def _show_selected_profile(self, row: int) -> None:
        selected = 0 <= row < len(self.profiles)
        self.edit_button.setEnabled(selected)
        self.remove_button.setEnabled(selected)
        if not selected:
            self.profile_details.setText("No profile selected.")
            return
        profile = self.profiles[row]
        self.profile_details.setText(
            f"{profile.transport.value.upper()}  •  "
            f"{profile.endpoint_host}:{profile.endpoint_port}"
        )

    def _add_profile(self) -> None:
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
        updated = list(self.profiles)
        updated[row] = profile
        if self._save_profiles(updated):
            self._refresh_profiles(row)

    def _remove_profile(self) -> None:
        row = self.profile_list.currentRow()
        if not 0 <= row < len(self.profiles):
            return
        profile = self.profiles[row]
        answer = QMessageBox.question(
            self,
            "Remove profile",
            f"Remove the profile “{profile.name}”?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        updated = list(self.profiles)
        updated.pop(row)
        if self._save_profiles(updated):
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
