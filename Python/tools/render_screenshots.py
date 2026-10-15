"""
EnvStego — offscreen UI screenshot renderer

Launches the real PyQt6 app with QT_QPA_PLATFORM=offscreen and a throwaway
QSettings .ini (so the developer's saved state is never touched), then captures
every tab to evidence/ui/ and runs a basic layout sanity check on each frame.

Usage (from the Python/ directory):
    QT_QPA_PLATFORM=offscreen python tools/render_screenshots.py [out_dir]

The environment variable is also set defensively inside the script.
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# The offscreen plugin on Windows does not auto-load the system font database;
# point it at the Windows fonts so captured text is legible instead of tofu boxes.
if os.name == "nt":
    os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

APP_DIR = Path(__file__).resolve().parent.parent          # .../Python
sys.path.insert(0, str(APP_DIR))

from PyQt6.QtCore import Qt, QSettings, QEventLoop, QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication                    # noqa: E402

import ui_main                                             # noqa: E402
from ui_main import MainWindow, STYLE                       # noqa: E402

TABS = ["signals", "encrypt", "decrypt", "token", "inspector"]


def pump(ms: int):
    """Run the Qt event loop for ms milliseconds (lets worker threads post back)."""
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def layout_check(img) -> dict:
    """Cheap sanity checks on a captured QImage: right size, not a blank frame."""
    w, h = img.width(), img.height()
    # Sample a grid of pixels; a healthy UI has many distinct colours.
    step_x = max(1, w // 40)
    step_y = max(1, h // 40)
    seen = set()
    for y in range(0, h, step_y):
        for x in range(0, w, step_x):
            seen.add(img.pixel(x, y))
            if len(seen) > 20:
                break
        if len(seen) > 20:
            break
    return {"w": w, "h": h, "distinct_colours": len(seen),
            "blank": len(seen) <= 2, "min_size_ok": w >= 900 and h >= 650}


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (APP_DIR.parent / "evidence" / "ui")
    out.mkdir(parents=True, exist_ok=True)

    # Throwaway settings store. QSettings("SIT-ICT3215", "EnvStego") always uses the
    # Windows registry, so the app's QSettings is swapped for one backed by a temp .ini.
    ini = Path(tempfile.mkdtemp(prefix="envstego_qsettings_")) / "EnvStego.ini"

    class IsolatedSettings(QSettings):
        def __init__(self, *_args):
            super().__init__(str(ini), QSettings.Format.IniFormat)

    ui_main.QSettings = IsolatedSettings
    print(f"[i] Throwaway QSettings file: {ini}")

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("EnvStego")
    app.setOrganizationName("SIT-ICT3215")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)

    win = MainWindow()
    win.resize(1200, 800)
    win.show()

    # Let the launch-time signal collection fully finish so every tab (Signals,
    # Encrypt, Inspector) shows real data rather than a "Collecting…" placeholder.
    waited = 0
    pump(800)
    while getattr(win, "_collecting", False) and waited < 25000:
        pump(300)
        waited += 300
    pump(600)

    all_ok = True
    print(f"[i] Signal collection settled after ~{waited} ms\n")
    for i, name in enumerate(TABS):
        win._tabs.setCurrentIndex(i)
        pump(450)
        pixmap = win.grab()
        path = out / f"tab{i + 1}_{name}.png"
        saved = pixmap.save(str(path), "PNG")
        chk = layout_check(pixmap.toImage())
        ok = saved and not chk["blank"] and chk["min_size_ok"]
        all_ok = all_ok and ok
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] tab{i + 1}_{name:<10} {chk['w']}x{chk['h']}  "
              f"colours={chk['distinct_colours']:<3} "
              f"blank={chk['blank']} min_size_ok={chk['min_size_ok']} saved={saved}")

    win.close()
    pump(200)
    print(f"\n[i] Screenshots written to: {out}")
    print(f"[{'PASS' if all_ok else 'FAIL'}] Overall layout check")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
