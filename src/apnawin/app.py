"""Minimal native desktop shell; tunnel functionality is intentionally not stubbed as real."""

import sys

from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QWidget


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ApnaWin")
        self.resize(760, 480)

        heading = QLabel("ApnaWin")
        heading.setObjectName("heading")
        status = QLabel("Disconnected — tunnel engine is not configured yet.")
        self.status_label = status

        connect_button = QPushButton("Connect")
        connect_button.setEnabled(False)
        connect_button.setToolTip("Connection will be enabled after a Windows engine is integrated.")

        layout = QVBoxLayout()
        layout.addWidget(heading)
        layout.addWidget(status)
        layout.addWidget(connect_button)
        layout.addStretch(1)

        root = QWidget()
        root.setLayout(layout)
        self.setCentralWidget(root)


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()
