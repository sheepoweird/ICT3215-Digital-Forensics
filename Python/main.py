"""
EnvStego - main.py
Entry point. Run this file to launch the application.

    python main.py

ICT3215 Digital Forensics — SIT
"""

import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

# Ensure the project root is on the path when running as a bundled exe
if getattr(sys, "frozen", False):
    os.chdir(os.path.dirname(sys.executable))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt

from ui_main import MainWindow, STYLE


def _install_crash_guard():
    """
    By default PyQt aborts the whole app when any slot raises an exception — a
    single unexpected error (an odd serial state, a theme redraw) then looks like
    a crash. This logs the error and keeps the app running instead, and records a
    traceback so the cause can be found.
    """
    log_path = Path(__file__).resolve().parent / "envstego_error.log"
    state = {"showing": False, "last": None}

    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"\n===== {datetime.now().isoformat(timespec='seconds')} =====\n{text}")
        except OSError:
            pass
        print(text, file=sys.stderr)
        # Show one dialog at a time, and not again for the same repeating error, so a
        # fault that fires on every repaint cannot bury the screen in message boxes.
        signature = f"{exc_type.__name__}: {exc}"
        if QApplication.instance() is not None and not state["showing"] and signature != state["last"]:
            state["showing"] = True
            state["last"] = signature
            try:
                QMessageBox.warning(
                    None, "EnvStego — unexpected error",
                    "Something went wrong, but the app is still running.\n\n"
                    f"{signature}\n\nDetails were saved to:\n{log_path}")
            finally:
                state["showing"] = False

    sys.excepthook = hook


def main():
    _install_crash_guard()

    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    # The vault viewer decodes via Pillow and downscales, but lift Qt's default 256 MB
    # image-allocation guard so the fallback loader never rejects a large local image.
    try:
        from PyQt6.QtGui import QImageReader
        QImageReader.setAllocationLimit(0)
    except Exception:
        pass
    app.setApplicationName("EnvStego")
    app.setOrganizationName("SIT-ICT3215")
    app.setStyle("Fusion")          # Fusion base makes dark theme consistent
    app.setStyleSheet(STYLE)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()