"""
EnvStego - main.py
Entry point. Run this file to launch the application.

    python main.py

ICT3215 Digital Forensics — SIT
"""

import sys
import os

# Ensure the project root is on the path when running as a bundled exe
if getattr(sys, "frozen", False):
    os.chdir(os.path.dirname(sys.executable))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt

from ui_main import MainWindow, STYLE


def main():
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("EnvStego")
    app.setOrganizationName("SIT-ICT3215")
    app.setStyle("Fusion")          # Fusion base makes dark theme consistent
    app.setStyleSheet(STYLE)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()