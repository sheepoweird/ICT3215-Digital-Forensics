"""
EnvStego - ui_main.py
PyQt6 application window.

Pages (left sidebar, grouped by workflow):
  Setup       Token     — pair, test and manage the 3T hardware token
              Signals   — select environment variables (or a preset) to build the key
  Protect     Encrypt   — hide payload inside a PNG carrier image
              Decrypt   — extract and recover payload from a stego image
  Diagnostics Inspector — view raw collected signal values

The page stack keeps the original index order (Signals, Encrypt, Decrypt, Token,
Inspector) so saved settings and TAB_* constants are unchanged.

Selections, presets, file paths and the active page are remembered between
refreshes and app restarts (QSettings).

Team member: Application Interface & Data Extraction Logic
ICT3215 Digital Forensics — SIT
"""

import html
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget, QLabel,
    QPushButton, QCheckBox, QProgressBar, QFileDialog, QTextEdit, QButtonGroup,
    QScrollArea, QFrame, QTableWidget, QTableWidgetItem, QLineEdit, QStatusBar,
    QGridLayout, QHeaderView, QMessageBox, QComboBox, QInputDialog, QToolButton,
    QApplication, QListWidget, QListWidgetItem, QSizePolicy, QDialog,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QUrl, QPointF, QTimer
from PyQt6.QtGui import (QColor, QDesktopServices, QPainter, QPainterPath, QPen, QPixmap, QImage,
                         QShortcut, QKeySequence)

from signals import EnvSignal, collect_all_signals
from crypto_engine import (
    derive_env_key, encrypt_payload, decrypt_payload, estimate_entropy_bits,
    assess_selection, recommended_ids, pack_payload, unpack_payload, packed_size,
    request_index_key, pack_header, unpack_header, OUTER_SIZE, PAYLOAD_AAD,
    SHARD_OUTER_SIZE, unpack_shard_tag, KIND_FILE, KIND_FOLDER, payload_kind,
)
import multi_image as mi
import media
import vault as V
from archive import zip_folder, safe_extract_zip
from stego_engine import extract, MAGIC, LEGACY_MAGIC
from media import embed_blob, lsb_capacity_bytes, read_lsb_all
from winutils import pictures_dir, downloads_dir
from winutils import protect_str, unprotect_str
from cryptography.exceptions import InvalidTag
from token_comms import (
    pair_token_usb, ping_token, load_config, forget_pairing, list_serial_ports,
    token_fingerprint, TokenError, UNREACHABLE_MSG as TOKEN_UNREACHABLE_HINT,
)


# ─── STYLESHEET ──────────────────────────────────────────────────────────────

STYLE = """
* { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; }

QMainWindow, QWidget#root, QWidget#main, QWidget#page, QStackedWidget {
    background-color: #0d1117;
    color: #c9d1d9;
}
QLabel { color: #c9d1d9; background: transparent; }

/* ── Sidebar ─────────────────────────────────────────────── */
QWidget#sidebar { background: #010409; border-right: 1px solid #21262d; }
QLabel#brand { color: #e6edf3; font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }
QLabel#brand_sub { color: #6e7681; font-size: 11px; }
QLabel#nav_group {
    color: #6e7681; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
    padding: 0 12px;
}
QPushButton#nav {
    background: transparent; border: none; border-radius: 8px;
    text-align: left; padding: 0; margin: 0;
}
QPushButton#nav:hover { background: #161b22; }
QPushButton#nav:checked { background: #1a2233; }
QLabel#nav_title { color: #adbac7; font-size: 13px; font-weight: 600; }
QLabel#nav_title[active="true"] { color: #ffffff; }
QLabel#nav_sub { color: #6e7681; font-size: 11px; }
QLabel#nav_sub[tone="ok"]   { color: #3fb950; }
QLabel#nav_sub[tone="warn"] { color: #d29922; }
QLabel#nav_sub[tone="bad"]  { color: #f85149; }
QFrame#nav_marker { background: transparent; border-radius: 2px; }
QFrame#nav_marker[active="true"] { background: #2f81f7; }
QLabel#sidebar_foot { color: #484f58; font-size: 10px; }

/* ── Top bar ─────────────────────────────────────────────── */
QWidget#topbar { background: #0d1117; border-bottom: 1px solid #21262d; }
QLabel#page_title { color: #e6edf3; font-size: 20px; font-weight: 600; }
QLabel#page_sub { color: #8b949e; font-size: 12px; }

/* ── Cards and text ──────────────────────────────────────── */
QFrame#card {
    background: #161b22;
    border: 1px solid #262c36;
    border-radius: 10px;
}
QLabel#section {
    color: #8b949e; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
}
QLabel#field_label { color: #adbac7; font-size: 12px; font-weight: 600; }
QLabel#muted { color: #8b949e; font-size: 12px; }
QLabel#subtle { color: #6e7681; font-size: 11px; }
QLabel#hint  { color: #d29922; font-size: 12px; }
QLabel#mono  { font-family: Consolas, monospace; color: #d29922; font-size: 12px; }
QLabel#step_num {
    background: #21262d; color: #adbac7; border-radius: 10px;
    font-size: 11px; font-weight: 700; min-width: 20px; max-width: 20px;
    min-height: 20px; max-height: 20px;
}
QLabel#callout_warn {
    background: #272115; color: #e3b341; border: 1px solid #5c4813;
    border-radius: 8px; padding: 10px 12px; font-size: 12px;
}
QLabel#callout_danger {
    background: #25171a; color: #f0b6b3; border: 1px solid #5d2a2e;
    border-radius: 8px; padding: 10px 12px; font-size: 12px;
}
QFrame#divider { background: #21262d; max-height: 1px; min-height: 1px; border: none; }

/* ── Buttons ─────────────────────────────────────────────── */
QPushButton {
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 7px 14px;
}
QPushButton:hover { background-color: #292e36; color: #e6edf3; border-color: #8b949e; }
QPushButton:pressed { background-color: #1c2128; }
QPushButton:disabled { color: #484f58; border-color: #21262d; background-color: #161b22; }
QPushButton#btn_primary {
    background-color: #1f6feb;
    color: #ffffff;
    border: 1px solid #388bfd;
    font-weight: 600;
    font-size: 14px;
    padding: 10px 26px;
}
QPushButton#btn_primary:hover { background-color: #388bfd; }
QPushButton#btn_primary:disabled { background-color: #172437; color: #545d68; border-color: #21262d; }
QPushButton#btn_decrypt {
    background-color: #6e40c9;
    color: #ffffff;
    border: 1px solid #8957e5;
    font-weight: 600;
    font-size: 14px;
    padding: 10px 26px;
}
QPushButton#btn_decrypt:hover { background-color: #8957e5; }
QPushButton#btn_decrypt:disabled { background-color: #1d1730; color: #545d68; border-color: #21262d; }
QPushButton#btn_danger { color: #f85149; }
QPushButton#btn_danger:hover { border-color: #f85149; background-color: #2d1a1a; }
QPushButton#btn_danger:disabled { color: #484f58; border-color: #21262d; background-color: #161b22; }
QPushButton#btn_small {
    background: #21262d; color: #8b949e; border: 1px solid #30363d;
    border-radius: 6px; padding: 0 9px; font-size: 11px;
}
QPushButton#btn_small:hover { color: #58a6ff; border-color: #58a6ff; }
QPushButton#btn_small:disabled { color: #3d444d; border-color: #21262d; background: #161b22; }
QPushButton#btn_link {
    background: transparent; border: none; color: #58a6ff; padding: 0 4px;
}
QPushButton#btn_link:hover { text-decoration: underline; }
QPushButton#chip_ok {
    background: #12261e; color: #3fb950; border: 1px solid #238636; border-radius: 15px; padding: 4px 14px;
}
QPushButton#chip_ok:hover { border-color: #3fb950; }
QPushButton#chip_off {
    background: #2d1a1a; color: #f85149; border: 1px solid #da3633; border-radius: 15px; padding: 4px 14px;
}
QPushButton#chip_off:hover { border-color: #f85149; }
QPushButton#chip_idle {
    background: #161b22; color: #adbac7; border: 1px solid #30363d; border-radius: 15px; padding: 4px 14px;
}
QPushButton#chip_idle:hover { border-color: #58a6ff; }
QPushButton#chip_warn {
    background: #272115; color: #d29922; border: 1px solid #9e6a03; border-radius: 15px; padding: 4px 14px;
}
QPushButton#chip_warn:hover { border-color: #d29922; }

QToolButton {
    background: transparent; color: #6e7681; border: none; padding: 0 6px; font-size: 13px;
}
QToolButton:hover { color: #f85149; }

/* ── Inputs ──────────────────────────────────────────────── */
QLineEdit, QComboBox {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 8px 10px;
    color: #c9d1d9;
    selection-background-color: #1f6feb;
}
QLineEdit:focus, QComboBox:focus { border-color: #2f81f7; }
QLineEdit:read-only { color: #c9d1d9; }
QLineEdit#drop { border: 1px dashed #3d444d; }
QLineEdit#drop[filled="true"] { border: 1px solid #30363d; }
QLineEdit#drop[dragging="true"] { border: 1px dashed #2f81f7; background-color: #0f1d33; }
QListWidget#carrier_list {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 4px;
    color: #c9d1d9;
    outline: none;
}
QListWidget#carrier_list::item { padding: 4px 6px; border-radius: 4px; }
QListWidget#carrier_list::item:selected { background: #1f6feb; color: #ffffff; }
QComboBox:hover { border-color: #484f58; }
QComboBox:disabled { color: #484f58; }
QComboBox::drop-down { border: none; width: 26px; }
QComboBox QAbstractItemView {
    background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
    selection-background-color: #1f6feb; outline: none; padding: 4px;
}

QTextEdit {
    background-color: #0d1117;
    border: 1px solid #262c36;
    border-radius: 8px;
    padding: 8px;
    color: #c9d1d9;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}

/* ── Scrolling ───────────────────────────────────────────── */
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget#page { background: #0d1117; }
QScrollBar:vertical { background: transparent; width: 8px; margin: 2px; }
QScrollBar::handle:vertical { background: #30363d; border-radius: 3px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #484f58; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }

/* ── Meters ──────────────────────────────────────────────── */
QProgressBar {
    border: none;
    border-radius: 3px;
    background-color: #21262d;
    height: 6px;
    text-align: center;
}
QProgressBar::chunk { border-radius: 3px; }
QProgressBar#stab_high::chunk  { background-color: #3fb950; }
QProgressBar#stab_med::chunk   { background-color: #d29922; }
QProgressBar#stab_low::chunk   { background-color: #da3633; }
QProgressBar#capacity_bar::chunk { background-color: #2f81f7; }
QProgressBar#capacity_over::chunk { background-color: #da3633; }
QProgressBar#entropy_bar::chunk  { background-color: #3fb950; }

/* ── Check boxes (the tick image is added at runtime) ────── */
QCheckBox { spacing: 8px; color: #c9d1d9; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #484f58;
    border-radius: 4px;
    background-color: #0d1117;
}
QCheckBox::indicator:hover { border-color: #2f81f7; }
QCheckBox::indicator:checked { background-color: #1f6feb; border-color: #388bfd; }
QCheckBox::indicator:disabled { background-color: #161b22; border-color: #262c36; }
QCheckBox::indicator:checked:disabled { background-color: #9e6a03; border-color: #d29922; }

/* ── Signal rows ─────────────────────────────────────────── */
QWidget#signal_row { border-radius: 8px; border: 1px solid transparent; }
QWidget#signal_row:hover { background: #1c2128; }
QWidget#signal_row[checked="true"] {
    background: rgba(56, 139, 253, 22);
    border: 1px solid rgba(56, 139, 253, 70);
}
QLabel#sig_name { color: #e6edf3; font-weight: 600; }
QLabel#sig_name[readable="false"] { color: #6e7681; }
QWidget#signal_row[blocked="true"] QLabel#sig_name { color: #545d68; }
QWidget#signal_row[blocked="true"] QLabel#sig_desc { color: #3d444d; }
QLabel#sig_desc { color: #6e7681; font-size: 11px; }
QLabel#badge_ok {
    background: #12261e; color: #3fb950; border: 1px solid #238636;
    border-radius: 10px; padding: 2px 10px; font-size: 10px; font-weight: 700;
}
QLabel#badge_na {
    background: #161b22; color: #6e7681; border: 1px solid #30363d;
    border-radius: 10px; padding: 2px 10px; font-size: 10px;
}
QLabel#badge_warn {
    background: #272115; color: #d29922; border: 1px solid #9e6a03;
    border-radius: 10px; padding: 2px 10px; font-size: 10px; font-weight: 700;
}

/* ── Table ───────────────────────────────────────────────── */
QTableWidget {
    background-color: #161b22;
    alternate-background-color: #1a1f27;
    border: 1px solid #262c36;
    border-radius: 10px;
    gridline-color: transparent;
    selection-background-color: #1a3a5c;
    selection-color: #e6edf3;
    color: #c9d1d9;
    outline: none;
}
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 9px 10px;
    border: none;
    border-bottom: 1px solid #30363d;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
QTableWidget::item { padding: 6px 10px; border: none; }

/* ── Chrome ──────────────────────────────────────────────── */
QStatusBar {
    background-color: #010409;
    color: #8b949e;
    border-top: 1px solid #21262d;
    font-size: 11px;
}
QStatusBar::item { border: none; }
QToolTip {
    background-color: #1c2128; color: #e6edf3; border: 1px solid #30363d;
    padding: 6px 8px; border-radius: 6px;
}
QMessageBox, QInputDialog { background-color: #161b22; }
"""


def _app_dir() -> Path:
    """Folder the app runs from: next to the executable when frozen, else this file's
    directory. Settings are kept here as an .ini so the app writes nothing to the
    Windows registry, which forensic tools parse comprehensively and which lingers in
    hives and shadow copies even after the app is deleted."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def _runtime_style() -> str:
    """
    Stylesheet rules that need images: the check-box tick and the combo-box arrow.
    Styling those controls removes Qt's built-in glyphs, so small PNGs are drawn
    here (needs a running QApplication) and referenced by file path.
    """
    folder = Path(tempfile.gettempdir()) / "envstego_ui"
    folder.mkdir(exist_ok=True)

    def draw(name: str, w: int, h: int, color: str, points: list[tuple[float, float]],
             width: float, fill: bool = False):
        for scale, suffix in ((1, ""), (2, "@2x")):
            pm = QPixmap(w * scale, h * scale)
            pm.fill(Qt.GlobalColor.transparent)
            p = QPainter(pm)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            path = QPainterPath(QPointF(points[0][0] * scale, points[0][1] * scale))
            for x, y in points[1:]:
                path.lineTo(QPointF(x * scale, y * scale))
            if fill:
                path.closeSubpath()
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(color))
                p.drawPath(path)
            else:
                pen = QPen(QColor(color), width * scale)
                pen.setCapStyle(Qt.PenCapStyle.RoundCap)
                pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
                p.setPen(pen)
                p.drawPath(path)
            p.end()
            pm.save(str(folder / f"{name}{suffix}.png"))
        return (folder / f"{name}.png").as_posix()

    tick = draw("tick", 16, 16, "#ffffff", [(4, 8.5), (7, 11.5), (12.5, 5)], 2.0)
    # A solid, brighter down-triangle so the dropdown control is obvious.
    arrow = draw("arrow", 12, 8, "#c9d1d9", [(1.5, 2.5), (10.5, 2.5), (6, 7)], 0, fill=True)
    return (
        f"QCheckBox::indicator:checked {{ image: url({tick}); }}\n"
        f"QComboBox::down-arrow {{ image: url({arrow}); width: 12px; height: 8px; }}\n"
    )


# ─── PRESETS ─────────────────────────────────────────────────────────────────

def _stable_identity(s: EnvSignal) -> bool:
    return s.category in ("Hardware", "OS") and s.stability >= 8


# The raw 1–10 stability rating is not meaningful to a user, so each row shows a plain
# word and colour instead: green = a permanent identifier that will not change, amber =
# usually steady but can change if hardware/network changes, red = changes in everyday use.
def _stability_display(stability: int) -> tuple[str, str, str]:
    """Return (word, colour, tooltip) for a stability rating."""
    if stability >= 8:
        return ("Stable", "#3fb950",
                "Permanent: a hardware or firmware identifier that does not change in normal use.")
    if stability >= 5:
        return ("May change", "#d29922",
                "Usually steady, but changes if you swap the hardware or change network.")
    return ("Volatile", "#f85149",
            "Changes during everyday use; not safe to rely on by itself.")


BUILTIN_PRESETS = [
    ("Recommended",
     "A strong, steady default. The best choice if you are unsure.",
     None),            # special: selected via recommended_ids(), not a predicate
    ("Device-bound",
     "Stable hardware and OS identifiers. Opens on this PC on any network.",
     _stable_identity),
    ("Location-bound",
     "Device-bound plus the local network. Only opens on this PC at this location.",
     lambda s: _stable_identity(s) or (s.category == "Network" and s.stability >= 8)),
    ("Hardware only",
     "Physical components only. Survives an OS reinstall.",
     lambda s: s.category == "Hardware" and s.stability >= 8),
    ("Everything available",
     "Every readable signal. Strongest binding, but breaks most easily.",
     lambda s: True),
]

CATEGORY_ORDER = ["Hardware", "Network", "OS", "Unknown"]


# ─── WORKER THREADS ──────────────────────────────────────────────────────────

def _resolve_selection(signal_ids: set) -> tuple[list[EnvSignal], list[EnvSignal]]:
    """Collects signals live. Returns (readable selected signals, selected but unreadable)."""
    fresh = [s for s in collect_all_signals() if s.id in signal_ids]
    readable = [s for s in fresh if s.available and s.value]
    missing = [s for s in fresh if not (s.available and s.value)]
    return readable, missing


class CollectWorker(QThread):
    done = pyqtSignal(list)

    def run(self):
        self.done.emit(collect_all_signals())


class PairWorker(QThread):
    done = pyqtSignal(bool, str)
    progress = pyqtSignal(str)

    def __init__(self, port: str):
        super().__init__()
        self._port = port

    def run(self):
        self.done.emit(*pair_token_usb(self._port, progress=self.progress.emit))


class PingWorker(QThread):
    done = pyqtSignal(bool, str)

    def run(self):
        try:
            ping_token()
            self.done.emit(True, "Token answered and proved its identity.")
        except TokenError as e:
            self.done.emit(False, str(e))


class TestKeyWorker(QThread):
    done  = pyqtSignal(str, dict)   # fingerprint, {signal id: (name, live value)}
    error = pyqtSignal(str)

    def __init__(self, selected_ids):
        super().__init__()
        self._ids = set(selected_ids)

    def run(self):
        try:
            selected, missing = _resolve_selection(self._ids)
            if missing:
                self.error.emit("Unreadable: " + ", ".join(s.name for s in missing))
                return
            _, fp = derive_env_key(selected)
            snapshot = {s.id: (s.name, s.value) for s in selected}
            self.done.emit(fp, snapshot)
        except Exception as e:
            self.error.emit(str(e))


class EncryptWorker(QThread):
    done  = pyqtSignal(str, str, str)
    error = pyqtSignal(str)

    def __init__(self, selected_ids, carriers, payload_path, outputs, match_timestamps=False):
        super().__init__()
        self._selected_ids = set(selected_ids)
        self._carriers     = list(carriers)   # one carrier = single image; several = split
        self._payload      = payload_path
        self._outputs      = list(outputs)
        self._match_timestamps = match_timestamps

    def run(self):
        try:
            selected, missing = _resolve_selection(self._selected_ids)
            if missing:
                self.error.emit(
                    "These selected signals cannot be read right now:\n  "
                    + "\n  ".join(s.name for s in missing)
                    + "\n\nDeselect them on the Signals page, or refresh if they should be available."
                )
                return

            # A folder is zipped into one payload; a single file is used as-is.
            if os.path.isdir(self._payload):
                raw = zip_folder(self._payload)
                plaintext_blob = pack_payload(self._payload, raw, kind=KIND_FOLDER)
                src_desc = f"{Path(self._payload).name}{os.sep}  (folder, zipped to {len(raw):,} bytes)"
            else:
                with open(self._payload, "rb") as f:
                    raw = f.read()
                plaintext_blob = pack_payload(self._payload, raw, kind=KIND_FILE)
                src_desc = f"{Path(self._payload).name}  ({len(raw):,} bytes)"

            env_key, fp = derive_env_key(selected)
            index_key = request_index_key()
            salt, nonce, ct = encrypt_payload(plaintext_blob, env_key, PAYLOAD_AAD)
            # The header stores the signal IDs, encrypted under the token-only index key
            header = pack_header(index_key, salt, nonce, len(ct), sorted(s.id for s in selected))
            blob = header + ct

            if len(self._carriers) > 1:
                written = mi.split_embed(index_key, blob, self._carriers, self._outputs,
                                         match_timestamps=self._match_timestamps)
                carrier_desc = f"{len(written)} images (split)"
                out_desc = "\n                 ".join(written)
                first_out = written[0]
            else:
                first_out = embed_blob(self._carriers[0], blob, self._outputs[0],
                                       match_timestamps=self._match_timestamps)
                written = [first_out]
                carrier_desc = Path(self._carriers[0]).name
                out_desc = first_out

            self.done.emit(
                f"Payload embedded successfully\n"
                f"  Signals used:  {len(selected)} (stored encrypted in the image header)\n"
                f"  Payload:       {src_desc}\n"
                f"  Encrypted to:  {len(ct):,} bytes  (AES-256-GCM, per-file HKDF salt)\n"
                f"  Carrier:       {carrier_desc}\n"
                f"  Output:        {out_desc}",
                fp,
                first_out
            )
        except Exception as e:
            self.error.emit(str(e))


def _folder_size(folder: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(folder):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _unique_path(folder: str, name: str) -> Path:
    p = Path(folder) / name
    i = 1
    while p.exists():
        p = Path(folder) / f"{Path(name).stem} ({i}){Path(name).suffix}"
        i += 1
    return p


ENV_MISMATCH_MSG = (
    "Decryption failed — Authentication tag mismatch\n\n"
    "The key rebuilt here does not match the one used during encryption:\n"
    "  • Different signal selection  →  check the Signals page / preset\n"
    "  • Different network   →  BSSID/gateway signals changed\n"
    "  • Different machine   →  hardware serials changed\n"
    "  • Different token     →  token reset or another token paired\n"
    "  • Forensic lab/clone  →  no live environment signals\n\n"
    "The payload is mathematically unrecoverable in this environment."
)


class DecryptWorker(QThread):
    done         = pyqtSignal(str, str, str, bytes)
    error        = pyqtSignal(str)
    signals_used = pyqtSignal(list)   # IDs read from a v3 header, so the UI can show them

    def __init__(self, selected_ids, stego_paths, output_dir):
        super().__init__()
        self._selected_ids = set(selected_ids)
        self._stego_paths  = [stego_paths] if isinstance(stego_paths, str) else list(stego_paths)
        self._stego        = self._stego_paths[0] if self._stego_paths else ""
        self._output_dir   = output_dir

    def run(self):
        try:
            if len(self._stego_paths) > 1:
                self._decrypt_multi()        # a payload split across several images
                return

            stream = read_lsb_all(self._stego)   # decode the carrier once, then slice
            if len(stream) < 4:
                self.error.emit("This image is too small to contain an EnvStego payload.")
                return
            marker = stream[:4]

            if marker == LEGACY_MAGIC:
                self.error.emit(
                    "This image was made by an older EnvStego build that used a hardcoded "
                    "token secret. It is not supported by the secure token protocol.")
                return
            if marker == MAGIC:
                self._decrypt_v2()           # legacy ENV2 image, uses the page's selection
            else:
                self._decrypt_v3(stream)     # current format, signals read from the header
        except InvalidTag:
            self.error.emit(ENV_MISMATCH_MSG)
        except Exception as e:
            self.error.emit(str(e))

    # -- current format: token-encrypted header, signals auto-detected -------------
    def _decrypt_v3(self, stream: bytes):
        cap = len(stream)
        if cap < OUTER_SIZE:
            self.error.emit("No EnvStego payload detected in this image.")
            return
        index_key = request_index_key()          # token round-trip 1
        try:
            salt, nonce, ct_len, ids = unpack_header(index_key, stream[:OUTER_SIZE])
        except InvalidTag:
            # The header did not decrypt. Before blaming the token, check whether this
            # image is actually one piece of a split set — a common mistake is to pick a
            # single shard without enabling split mode. Reuse the decoded stream.
            total = None
            if cap >= SHARD_OUTER_SIZE:
                try:
                    _mid, _idx, total, _slen = unpack_shard_tag(index_key, stream[:SHARD_OUTER_SIZE])
                except InvalidTag:
                    total = None
            if total:
                self.error.emit(
                    f"This carrier is one piece of a set split across {total} carriers.\n\n"
                    "Tick “This file was split across several images” and add the whole "
                    "set (all its stego files) to recover the payload.")
                return
            self.error.emit(
                "No EnvStego payload here, or this is not the token that made it.\n\n"
                "The image header could not be decrypted. Check you selected a stego image "
                "from this tool and that the paired token is the one used to create it.")
            return
        if ct_len <= 0 or ct_len > cap - OUTER_SIZE:
            self.error.emit("The image header is corrupted or the image was recompressed.")
            return
        ct = stream[OUTER_SIZE:OUTER_SIZE + ct_len]
        self._finish_v3(salt, nonce, ids, ct, "read from the image header")

    # -- current format, split across several images -------------------------------
    def _decrypt_multi(self):
        index_key = request_index_key()          # token round-trip 1
        try:
            blob = mi.join_extract(index_key, self._stego_paths)   # regroup + order the shards
        except InvalidTag:
            self.error.emit(
                "These are not EnvStego split images, or this is not the token that made them.\n\n"
                "Check you selected stego images from this tool and that the paired token is the "
                "one used to create them.")
            return
        try:
            salt, nonce, ct_len, ids = unpack_header(index_key, blob[:OUTER_SIZE])
        except InvalidTag:
            self.error.emit("The reassembled header could not be decrypted — a shard may be corrupted.")
            return
        if ct_len <= 0 or OUTER_SIZE + ct_len > len(blob):
            self.error.emit("The reassembled payload is incomplete or corrupted.")
            return
        ct = blob[OUTER_SIZE:OUTER_SIZE + ct_len]
        self._finish_v3(salt, nonce, ids, ct,
                        f"read from the header of {len(self._stego_paths)} split images")

    def _finish_v3(self, salt, nonce, ids, ct, how):
        """Shared tail for both v3 paths: collect the named signals, derive the key, decrypt."""
        fresh = {s.id: s for s in collect_all_signals()}
        selected, missing = [], []
        for sid in ids:
            s = fresh.get(sid)
            if s is not None and s.available and s.value:
                selected.append(s)
            else:
                missing.append(s.name if s is not None else sid)
        if missing:
            self.error.emit(
                "Environment mismatch — the image needs these signals, which cannot be read here:\n  "
                + "\n  ".join(missing)
                + "\n\nThe key cannot be rebuilt without them (forensic defense active).")
            return
        self.signals_used.emit([s.id for s in selected])

        env_key, fp = derive_env_key(selected)   # token round-trip 2
        blob = decrypt_payload(salt, nonce, ct, env_key, PAYLOAD_AAD)
        name, data = unpack_payload(blob)
        self._save_and_report(name, data, payload_kind(blob), fp, len(selected), how)

    # -- legacy ENV2 format: signals come from the page's selection ----------------
    def _decrypt_v2(self):
        salt, nonce, ct = extract(self._stego)
        selected, missing = _resolve_selection(self._selected_ids)
        if not selected:
            self.error.emit("This older image needs you to select, on the Signals page, the "
                            "same signals used to encrypt it.")
            return
        if missing:
            self.error.emit(
                "Environment mismatch — these selected signals cannot be read here:\n  "
                + "\n  ".join(s.name for s in missing)
                + "\n\nThe key cannot be rebuilt without them (forensic defense active).")
            return
        env_key, fp = derive_env_key(selected)
        blob = decrypt_payload(salt, nonce, ct, env_key, MAGIC)
        name, data = unpack_payload(blob)
        self._save_and_report(name, data, payload_kind(blob), fp, len(selected), "collected live at decrypt time")

    def _save_and_report(self, name, data, kind, fp, n_signals, how):
        out_dir = self._output_dir or str(Path(self._stego).parent)
        if kind == KIND_FOLDER:
            folder = _unique_path(out_dir, name)
            written = safe_extract_zip(data, str(folder))   # zip-slip protected
            recovered = f"folder {name}{os.sep}  ({len(written)} file{'s' if len(written) != 1 else ''})"
            saved = str(folder)
        else:
            out_path = _unique_path(out_dir, name)
            with open(out_path, "wb") as f:
                f.write(data)
            recovered = f"{name}  ({len(data):,} bytes)"
            saved = str(out_path)
        self.done.emit(
            f"Payload extracted and decrypted\n"
            f"  Signals used: {n_signals} ({how})\n"
            f"  Recovered:    {recovered}\n"
            f"  Saved to:     {saved}",
            fp, saved, data)


# ─── VAULT WORKERS (token-bound; run off the GUI thread) ─────────────────────

class VaultCreateWorker(QThread):
    done  = pyqtSignal(object, str)   # (Vault, recovery_code)
    error = pyqtSignal(str)

    def __init__(self, path, selected_ids):
        super().__init__()
        self._path = path
        self._ids = set(selected_ids)

    def run(self):
        try:
            selected, missing = _resolve_selection(self._ids)
            if not selected:
                self.error.emit("Select at least one readable signal on the Signals page first.")
                return
            if missing:
                self.error.emit("Some selected signals are unreadable: "
                                + ", ".join(s.name for s in missing))
                return
            index_key = request_index_key()
            env_key, _fp = derive_env_key(selected)
            v, code = V.create_vault(self._path, index_key, env_key, [s.id for s in selected])
            self.done.emit(v, code)
        except Exception as e:
            self.error.emit(str(e))


class VaultUnlockWorker(QThread):
    done  = pyqtSignal(object, list, str)   # (Vault, signal_ids, fingerprint)
    error = pyqtSignal(str)

    def __init__(self, path):
        super().__init__()
        self._path = path

    def run(self):
        try:
            index_key = request_index_key()
            try:
                sig_ids = V.read_signal_ids(self._path, index_key)
            except InvalidTag:
                self.error.emit("This vault was made with a different token — it cannot be opened here.")
                return
            selected, missing = _resolve_selection(set(sig_ids))
            if missing:
                self.error.emit(
                    "The vault needs these signals, which cannot be read here:\n  "
                    + "\n  ".join(s.name for s in missing)
                    + "\n\nMove back to the original environment, or unlock with the recovery code.")
                return
            env_key, fp = derive_env_key(selected)
            try:
                v = V.unlock_env(self._path, env_key)
            except InvalidTag:
                self.error.emit(
                    "The environment does not match — the vault key could not be rebuilt.\n\n"
                    "A signal changed (network/location?), or this is a different machine. "
                    "Use the recovery code, then re-bind the vault to this environment.")
                return
            self.done.emit(v, sig_ids, fp)
        except Exception as e:
            self.error.emit(str(e))


class VaultHeartbeatWorker(QThread):
    """A lightweight reachability check for auto-lock (the dead-man's switch)."""
    result = pyqtSignal(bool, str)

    def run(self):
        try:
            ping_token()
            self.result.emit(True, "")
        except TokenError as e:
            self.result.emit(False, str(e))
        except Exception as e:
            self.result.emit(False, str(e))


class VaultTaskWorker(QThread):
    """Runs a local vault operation (add/read/export) off the GUI thread so a big
    file does not freeze the window. No token/BLE involved — the vault is unlocked."""
    done  = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            self.done.emit(self._fn())
        except Exception as e:
            self.error.emit(str(e))


# ─── REUSABLE WIDGETS ────────────────────────────────────────────────────────

class _DropLineEdit(QLineEdit):
    """Read-only path field that also accepts a file dragged from Explorer."""
    dropped = pyqtSignal(str)

    def __init__(self, want_dir: bool):
        super().__init__()
        self._want_dir = want_dir
        self.setObjectName("drop")
        self.setReadOnly(True)
        self.setAcceptDrops(True)

    def _set_flag(self, name: str, value: bool):
        self.setProperty(name, value)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._set_flag("dragging", True)

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dragLeaveEvent(self, e):
        self._set_flag("dragging", False)
        super().dragLeaveEvent(e)

    def dropEvent(self, e):
        self._set_flag("dragging", False)
        urls = e.mimeData().urls()
        if urls and urls[0].isLocalFile():
            path = urls[0].toLocalFile()
            if self._want_dir and os.path.isfile(path):
                path = os.path.dirname(path)
            self.dropped.emit(path)


class FilePicker(QWidget):
    """Step number + label above a path field (drag-and-drop) + clear + Browse."""
    changed = pyqtSignal(str)
    last_dir = ""   # shared across pickers so Browse opens where the user last was

    def __init__(self, label: str, mode: str = "open", filter_: str = "All Files (*.*)",
                 placeholder: str = "Select or drop a file…", parent=None, step: int | None = None,
                 allow_dir: bool = False):
        super().__init__(parent)
        self._mode   = mode
        self._filter = filter_
        self._allow_dir = allow_dir   # also offer a "Folder…" button (payload can be a folder)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(8)
        if step is not None:
            num = QLabel(str(step))
            num.setObjectName("step_num")
            num.setAlignment(Qt.AlignmentFlag.AlignCenter)
            head.addWidget(num)
        lbl = QLabel(label)
        lbl.setObjectName("field_label")
        head.addWidget(lbl)
        head.addStretch()
        outer.addLayout(head)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.path_edit = _DropLineEdit(want_dir=(mode == "dir"))
        self.path_edit.setPlaceholderText(placeholder)
        self.path_edit.setMinimumHeight(36)
        self.path_edit.dropped.connect(self.set_path)
        self.path_edit.textChanged.connect(self._on_text)
        row.addWidget(self.path_edit, stretch=1)

        self._clear_btn = QToolButton()
        self._clear_btn.setText("✕")
        self._clear_btn.setToolTip("Clear")
        self._clear_btn.setVisible(False)
        self._clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_btn.clicked.connect(lambda: self.set_path(""))
        row.addWidget(self._clear_btn)

        btn = QPushButton("Choose folder…" if mode == "dir" else "Browse…")
        btn.setMinimumWidth(96)
        btn.setMinimumHeight(36)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(self._browse)
        row.addWidget(btn)
        if allow_dir:
            folder_btn = QPushButton("Folder…")
            folder_btn.setMinimumWidth(80)
            folder_btn.setMinimumHeight(36)
            folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            folder_btn.setToolTip("Hide a whole folder (it is zipped into the image)")
            folder_btn.clicked.connect(self._browse_folder)
            row.addWidget(folder_btn)
        outer.addLayout(row)

    def _browse_folder(self):
        start = self.path() or FilePicker.last_dir
        path = QFileDialog.getExistingDirectory(self, "Choose Folder to hide", start)
        if path:
            self.set_path(path)

    def _on_text(self, text: str):
        self._clear_btn.setVisible(bool(text))
        self.path_edit.setToolTip(text)
        self.path_edit._set_flag("filled", bool(text))
        self.changed.emit(text)

    def _browse(self):
        start = os.path.dirname(self.path()) if self.path() else FilePicker.last_dir
        if self._mode == "save":
            path, _ = QFileDialog.getSaveFileName(self, "Save File", self.path() or start, self._filter)
        elif self._mode == "dir":
            path = QFileDialog.getExistingDirectory(self, "Choose Folder", self.path() or start)
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Open File", start, self._filter)
        if path:
            self.set_path(path)

    def path(self) -> str:
        return self.path_edit.text().strip()

    def set_path(self, p: str):
        p = os.path.normpath(p) if p else ""
        if p:
            FilePicker.last_dir = p if self._mode == "dir" else os.path.dirname(p)
        self.path_edit.setText(p)


class _DropListWidget(QListWidget):
    """A list that also accepts files dragged in from Explorer."""
    dropped = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragEnterEvent(e)

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragMoveEvent(e)

    def dropEvent(self, e):
        if e.mimeData().hasUrls():
            paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
            if paths:
                self.dropped.emit(paths)
                e.acceptProposedAction()
                return
        super().dropEvent(e)


class _VaultDropTable(QTableWidget):
    """The vault's file table, which also accepts files dragged in from Explorer."""
    filesDropped = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragEnterEvent(e)

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragMoveEvent(e)

    def dropEvent(self, e):
        if e.mimeData().hasUrls():
            paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
            if paths:
                self.filesDropped.emit(paths)
                e.acceptProposedAction()
                return
        super().dropEvent(e)


class MultiFilePicker(QWidget):
    """A labelled list of image paths with Add / Remove / Clear, for multi-image split."""
    changed = pyqtSignal()

    def __init__(self, label: str, filter_: str = "PNG Images (*.png)", step: int | None = None,
                 parent=None):
        super().__init__(parent)
        self._filter = filter_
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(8)
        if step is not None:
            num = QLabel(str(step))
            num.setObjectName("step_num")
            num.setAlignment(Qt.AlignmentFlag.AlignCenter)
            head.addWidget(num)
        lbl = QLabel(label)
        lbl.setObjectName("field_label")
        head.addWidget(lbl)
        head.addStretch()
        self._count_lbl = QLabel("none")
        self._count_lbl.setObjectName("subtle")
        head.addWidget(self._count_lbl)
        outer.addLayout(head)

        self._list = _DropListWidget()
        self._list.setObjectName("carrier_list")
        self._list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self._list.setMinimumHeight(96)
        self._list.setMaximumHeight(150)
        self._list.setToolTip("Drop PNG/WAV files here, or use Add images…")
        self._list.dropped.connect(self._on_dropped)
        outer.addWidget(self._list)

        row = QHBoxLayout()
        row.setSpacing(6)
        add = QPushButton("Add images…")
        add.setMinimumHeight(32)
        add.setCursor(Qt.CursorShape.PointingHandCursor)
        add.clicked.connect(self._add)
        rm = QPushButton("Remove")
        rm.setMinimumHeight(32)
        rm.setCursor(Qt.CursorShape.PointingHandCursor)
        rm.clicked.connect(self._remove_selected)
        clr = QPushButton("Clear")
        clr.setMinimumHeight(32)
        clr.setCursor(Qt.CursorShape.PointingHandCursor)
        clr.clicked.connect(self.clear)
        row.addWidget(add)
        row.addWidget(rm)
        row.addWidget(clr)
        row.addStretch()
        outer.addLayout(row)

    def _add(self):
        start = FilePicker.last_dir
        paths, _ = QFileDialog.getOpenFileNames(self, "Add carrier images", start, self._filter)
        if paths:
            FilePicker.last_dir = os.path.dirname(paths[-1])
            self._add_paths(*paths)

    def _on_dropped(self, paths):
        # Only accept carrier files (PNG/WAV); ignore folders and other junk drops.
        good = [p for p in paths if os.path.isfile(p) and media.is_carrier(p)]
        if good:
            self._add_paths(*good)

    def _add_paths(self, *paths):
        """Add paths to the list, skipping duplicates. Also used by tests (no dialog)."""
        existing = set(self.paths())
        added = False
        for p in paths:
            p = os.path.normpath(p)
            if p not in existing:
                item = QListWidgetItem(os.path.basename(p))
                item.setToolTip(p)
                item.setData(Qt.ItemDataRole.UserRole, p)
                self._list.addItem(item)
                existing.add(p)
                added = True
        if added:
            self._update()

    def _remove_selected(self):
        for item in self._list.selectedItems():
            self._list.takeItem(self._list.row(item))
        self._update()

    def clear(self):
        self._list.clear()
        self._update()

    def _update(self):
        n = self._list.count()
        self._count_lbl.setText("none" if n == 0 else f"{n} image{'s' if n != 1 else ''}")
        self.changed.emit()

    def paths(self) -> list[str]:
        return [self._list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self._list.count())]

    def count(self) -> int:
        return self._list.count()


def _looks_textual(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return False
    try:
        data[:8192].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


class VaultViewer(QDialog):
    """Shows a decrypted file from RAM only — nothing is written to disk."""
    _IMG = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}

    MAX_DIM = 4096      # cap the displayed image so a huge photo can't exhaust memory

    @staticmethod
    def _pixmap_from(data: bytes):
        """
        Decode an image with Pillow (handles JPEG/PNG/etc. without Qt's image plugins)
        and downscale very large images. A small JPEG can decode to hundreds of MB of
        pixels, which Qt refuses to allocate and which there is no point rendering at
        full size, so cap it to screen size here.
        """
        try:
            import io
            from PIL import Image
            im = Image.open(io.BytesIO(data))
            # JPEG can decode directly at a reduced scale — much faster and lighter.
            im.draft("RGB", (VaultViewer.MAX_DIM, VaultViewer.MAX_DIM))
            im.load()
            if max(im.size) > VaultViewer.MAX_DIM:
                im.thumbnail((VaultViewer.MAX_DIM, VaultViewer.MAX_DIM), Image.LANCZOS)
            im = im.convert("RGBA")
            qimg = QImage(im.tobytes("raw", "RGBA"), im.width, im.height,
                          QImage.Format.Format_RGBA8888)
            return QPixmap.fromImage(qimg.copy())      # copy so the pixmap owns the pixels
        except Exception:
            pm = QPixmap()                             # last resort: Qt's own loader
            return pm if pm.loadFromData(data) else None

    def __init__(self, name: str, data: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Vault · {name}")
        self.resize(780, 640)
        lay = QVBoxLayout(self)
        head = QLabel(f"{name}  ·  {len(data):,} bytes  ·  shown from memory (no copy on disk)")
        head.setObjectName("subtle")
        lay.addWidget(head)

        shown = False
        if Path(name).suffix.lower() in self._IMG:
            pm = self._pixmap_from(data)
            if pm is not None:
                lbl = QLabel()
                lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                lbl.setPixmap(pm)
                area = QScrollArea()
                area.setWidgetResizable(True)
                area.setWidget(lbl)
                lay.addWidget(area, stretch=1)
                shown = True
        if not shown and _looks_textual(data):
            te = QTextEdit()
            te.setReadOnly(True)
            te.setStyleSheet("font-family:Consolas,monospace;")
            text = data.decode("utf-8", errors="replace")
            te.setPlainText(text[:200_000] + ("\n…(truncated)…" if len(text) > 200_000 else ""))
            lay.addWidget(te, stretch=1)
            shown = True
        if not shown:
            info = QLabel("This file type can't be previewed in memory.\n\nUse <b>Export</b> to open it "
                          "in its own program — that writes a decrypted copy to disk, which you should "
                          "delete when done.")
            info.setWordWrap(True)
            info.setObjectName("muted")
            lay.addWidget(info, stretch=1)

        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(close)
        lay.addLayout(row)


class StatusPanel(QLabel):
    """Result/status panel below action buttons."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWordWrap(True)
        self.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setTextFormat(Qt.TextFormat.RichText)
        self.setVisible(False)

    def _show(self, icon, msg, bg, fg, border, body_fg):
        # First line is the headline; any further lines are aligned details
        head, _, body = msg.partition("\n")
        text = (f"<div style='font-size:13px; font-weight:600; color:{fg};'>"
                f"{icon}&nbsp;&nbsp;{html.escape(head)}</div>")
        lines = [ln for ln in body.splitlines() if ln.strip()]
        if lines and all(ln.startswith("  ") for ln in lines):
            # Indented "Label:  value" details (encrypt/decrypt results) stay aligned
            text += (f"<pre style='font-family:Consolas,monospace; font-size:12px; "
                     f"color:{body_fg}; margin:6px 0 0 0;'>{html.escape(body)}</pre>")
        elif lines:
            text += (f"<div style='font-size:12px; color:{body_fg}; margin-top:6px;'>"
                     f"{html.escape(body.strip()).replace(chr(10), '<br>')}</div>")
        self.setStyleSheet(
            f"background:{bg}; border:1px solid {border}; border-radius:8px; padding:12px 14px;"
        )
        self.setText(text)
        self.setVisible(True)

    def show_success(self, msg: str):
        self._show("✓", msg, "#12261e", "#3fb950", "#238636", "#a5d6a7")

    def show_error(self, msg: str):
        self._show("✕", msg, "#25171a", "#f85149", "#8e2b2b", "#f0b6b3")

    def show_info(self, msg: str):
        self._show("…", msg, "#161b22", "#adbac7", "#30363d", "#8b949e")

    def clear(self):
        self.setVisible(False)


def _travel_safe(signal: EnvSignal) -> bool:
    """A signal that does not change when the user moves location or network."""
    return signal.category != "Network"


class SignalRow(QWidget):
    toggled = pyqtSignal(str, bool)

    def __init__(self, signal: EnvSignal, selected: bool, parent=None, blocked: bool = False):
        super().__init__(parent)
        self._signal = signal
        self._blocked = blocked      # disabled by portable mode (volatile signal)
        self.setObjectName("signal_row")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._build()
        self.set_checked(selected)

    def _build(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 7, 12, 7)
        layout.setSpacing(12)

        self._cb = QCheckBox()
        self._cb.toggled.connect(lambda c: self.toggled.emit(self._signal.id, c))
        self._cb.toggled.connect(self._sync_style)
        layout.addWidget(self._cb)

        info = QVBoxLayout()
        info.setSpacing(2)
        name_lbl = QLabel(self._signal.name)
        name_lbl.setObjectName("sig_name")
        name_lbl.setProperty("readable", self.readable)
        desc_lbl = QLabel(self._signal.description)
        desc_lbl.setObjectName("sig_desc")
        # Wrap and allow shrinking, so a long description never pushes the stability
        # column and badge past the right edge (the list has no horizontal scrollbar).
        for lbl in (name_lbl, desc_lbl):
            lbl.setWordWrap(True)
            lbl.setMinimumWidth(0)
            lbl.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        info.addWidget(name_lbl)
        info.addWidget(desc_lbl)
        layout.addLayout(info, stretch=1)

        word, colour, tip = _stability_display(self._signal.stability)
        stab_lbl = QLabel(word)
        stab_lbl.setObjectName("stab_word")
        stab_lbl.setFixedWidth(96)
        stab_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stab_lbl.setStyleSheet(f"color:{colour}; font-size:12px; font-weight:600;")
        stab_lbl.setToolTip(tip)
        layout.addWidget(stab_lbl)

        self._badge = QLabel()
        self._badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._badge.setFixedWidth(88)
        layout.addWidget(self._badge)

        sig = self._signal
        self._cb.setEnabled(self.readable and not self._blocked)
        if self._blocked:
            self._badge.setText("Off · portable")
            self._badge.setObjectName("badge_na")
            self.setToolTip("Disabled in portable mode — this signal changes when you move "
                            "location or network.")
            self.setProperty("blocked", True)
        elif self.readable:
            self._badge.setText("Available")
            self._badge.setObjectName("badge_ok")
            self.setToolTip(f"Current value:\n{sig.value}")
            self.setCursor(Qt.CursorShape.PointingHandCursor)
        else:
            self._badge.setText("Not available")
            self._badge.setObjectName("badge_na")
            self.setToolTip(sig.error or "Not available on this machine")

    def _sync_style(self, *_):
        self.setProperty("checked", self._cb.isChecked())
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, e):
        # The whole row is a click target, not just the tiny checkbox
        if self.readable and not self._blocked and e.button() == Qt.MouseButton.LeftButton:
            self._cb.toggle()
        super().mousePressEvent(e)

    def set_checked(self, checked: bool):
        self._cb.blockSignals(True)
        self._cb.setChecked(checked)
        self._cb.blockSignals(False)
        self._sync_style()
        if not self.readable:
            self._badge.setText("Unreadable ⚠" if checked else "Not available")
            self._badge.setObjectName("badge_warn" if checked else "badge_na")
            self._badge.style().unpolish(self._badge)
            self._badge.style().polish(self._badge)
            self._badge.setToolTip(
                "Selected but not readable right now — the key cannot be built" if checked
                else (self._signal.error or "Not available on this machine"))

    @property
    def readable(self) -> bool:
        return bool(self._signal.available and self._signal.value)

    @property
    def signal(self) -> EnvSignal:
        return self._signal


def _card(spacing: int = 10) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(spacing)
    return frame, lay


def _section(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("section")
    return lbl


def _divider() -> QFrame:
    line = QFrame()
    line.setObjectName("divider")
    return line


def _label(text: str, name: str = "muted", wrap: bool = True) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(name)
    lbl.setWordWrap(wrap)
    return lbl


def _page(scroll: bool = True, max_width: int = 960) -> tuple[QWidget, QVBoxLayout]:
    """
    A page whose content column is centred and capped in width, so lines stay
    readable on wide windows. Scrolling pages never squash their content.
    Returns (widget to add to the page stack, content layout).
    """
    inner = QWidget()
    inner.setObjectName("page")
    inner.setMaximumWidth(max_width)
    lay = QVBoxLayout(inner)
    lay.setContentsMargins(28, 22, 28, 22)
    lay.setSpacing(14)

    holder = QWidget()
    holder.setObjectName("page")
    h = QHBoxLayout(holder)
    h.setContentsMargins(0, 0, 0, 0)
    h.addStretch(1)
    h.addWidget(inner, 100)
    h.addStretch(1)

    if not scroll:
        return holder, lay
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidget(holder)
    return area, lay


class NavButton(QPushButton):
    """Sidebar entry: title, live status line, and an accent marker when active."""

    def __init__(self, title: str):
        super().__init__()
        self.setObjectName("nav")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(52)

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 10, 0)
        row.setSpacing(10)
        self._marker = QFrame()
        self._marker.setObjectName("nav_marker")
        self._marker.setFixedSize(3, 26)
        row.addWidget(self._marker)

        self._title = QLabel(title)
        self._title.setObjectName("nav_title")
        self._sub = QLabel("")
        self._sub.setObjectName("nav_sub")
        col = QVBoxLayout()
        col.setSpacing(1)
        col.setContentsMargins(0, 0, 0, 0)
        col.addStretch()                 # centre the title/status block vertically
        col.addWidget(self._title)
        col.addWidget(self._sub)
        col.addStretch()
        row.addLayout(col, 1)

        for w in (self._marker, self._title, self._sub):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.toggled.connect(self._sync)

    @staticmethod
    def _repolish(w: QWidget):
        w.style().unpolish(w)
        w.style().polish(w)

    def _sync(self, active: bool):
        for w in (self._marker, self._title):
            w.setProperty("active", active)
            self._repolish(w)

    def set_status(self, text: str, tone: str = "muted"):
        self._sub.setText(text)
        has = bool(text)
        self._sub.setVisible(has)
        self.setFixedHeight(52 if has else 38)   # title-only entries are shorter
        if self._sub.property("tone") != tone:
            self._sub.setProperty("tone", tone)
            self._repolish(self._sub)


# ─── MAIN WINDOW ─────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    TAB_SIGNALS, TAB_ENCRYPT, TAB_DECRYPT, TAB_TOKEN, TAB_INSPECTOR, TAB_VAULT = range(6)

    # Page titles shown in the top bar, keyed by page index
    PAGE_INFO = {
        TAB_SIGNALS:   ("Environment signals",
                        "Choose what the key is bound to. The same signals must be readable when you decrypt."),
        TAB_ENCRYPT:   ("Encrypt & hide",
                        "Encrypt a file with your environment key and hide it inside a PNG image or WAV audio file."),
        TAB_DECRYPT:   ("Decrypt & extract",
                        "Recover a hidden file. Needs the same signals and the same token used to encrypt."),
        TAB_TOKEN:     ("Hardware token",
                        "Pair, test and manage the 3T token that holds the master secret."),
        TAB_INSPECTOR: ("Signal inspector",
                        "Raw values read from this machine, and which ones feed the key."),
        TAB_VAULT:     ("Env Vault",
                        "An encrypted store bound to this PC and the token. Locks itself when the token leaves."),
    }
    # Sidebar layout: (group, [(page index, label)]) in workflow order
    NAV_LAYOUT = [
        ("SETUP",       [(TAB_TOKEN, "Token"), (TAB_SIGNALS, "Signals")]),
        ("PROTECT",     [(TAB_ENCRYPT, "Encrypt"), (TAB_DECRYPT, "Decrypt"), (TAB_VAULT, "Vault")]),
        ("DIAGNOSTICS", [(TAB_INSPECTOR, "Inspector")]),
    ]

    ENC_LABEL, ENC_BUSY = "Encrypt && Embed", "Encrypting…"
    DEC_LABEL, DEC_BUSY = "Decrypt && Extract", "Decrypting…"

    def __init__(self):
        super().__init__()
        self.setWindowTitle("EnvStego  —  Environment-Keyed Steganography")
        self.setMinimumSize(1000, 680)
        self.resize(1200, 800)
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(app.styleSheet() + _runtime_style())

        # Keep settings in an .ini beside the app, not in the Windows registry.
        self._settings = QSettings(str(_app_dir() / "envstego_settings.ini"),
                                   QSettings.Format.IniFormat)
        self._all_signals: list[EnvSignal] = []
        self._signal_rows: list[SignalRow] = []
        self._selected_ids: set[str] = set(self._load_json("signals/selected", []))
        self._user_presets: dict[str, list[str]] = self._load_json("signals/presets", {})
        self._active_preset: str | None = unprotect_str(
            self._settings.value("signals/active_preset", "")) or None
        self._token_cfg = load_config()
        self._workers: set[QThread] = set()
        self._busy = False
        self._collecting = False
        # First launch with nothing chosen falls back to the Recommended preset once.
        self._did_default_preset = bool(self._selected_ids) or bool(self._active_preset)
        # Which signal categories are collapsed on the Signals page (remembered).
        self._collapsed_cats: set[str] = set(self._load_json("signals/collapsed_cats", []))
        self._last_test: tuple[frozenset, str, dict] | None = None
        self._token_reachable: bool | None = None   # None = not contacted this session
        self._vault: V.Vault | None = None           # unlocked vault instance, else None
        self._vault_sig_ids: list[str] = []          # signals the open vault is bound to
        self._enc_output_auto = False
        self._enc_capacity_ok = False
        self._pending_pair_msg: str | None = None
        self._privacy = self._settings.value("privacy/mode", True, type=bool)
        self._portable = self._settings.value("portable/mode", False, type=bool)

        self._ui_ready = False
        self._build_ui()
        self._ui_ready = True
        # Panic lock: instantly lock the vault from anywhere in the app.
        self._panic_sc = QShortcut(QKeySequence("Ctrl+Shift+L"), self)
        self._panic_sc.activated.connect(self._panic_lock)
        self._restore_state()
        self._refresh_token_ui()
        self._refresh_ports()
        self._refresh_actions()
        self._start_collection()

        # Notice the token being plugged in or out without the rescan button
        self._port_timer = QTimer(self)
        self._port_timer.timeout.connect(self._poll_ports)
        self._port_timer.start(2000)

    # ── State persistence ────────────────────────────────────────────────────

    # Settings that name the environment a payload is bound to are sealed (DPAPI on
    # Windows) so a raw registry/ini dump does not reveal the signal selection.
    _SENSITIVE_KEYS = {"signals/selected", "signals/presets", "signals/active_preset"}

    def _load_json(self, key, default):
        try:
            raw = self._settings.value(key, "")
            if key in self._SENSITIVE_KEYS and raw:
                raw = unprotect_str(raw)
            return json.loads(raw)
        except (TypeError, ValueError):
            return default

    def _save_json(self, key, value):
        raw = json.dumps(value)
        if key in self._SENSITIVE_KEYS:
            raw = protect_str(raw)
        self._settings.setValue(key, raw)

    def _restore_state(self):
        geo = self._settings.value("window/geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        # Save recovered files to Downloads by default (overridden below if a path is
        # remembered and privacy mode is off).
        self._dec_output.set_path(downloads_dir())
        self._enc_output_auto = self._settings.value("enc/output_auto", False, type=bool)
        # Privacy mode: never reload remembered file paths, and purge any that an
        # earlier (possibly crashed) session left behind, so cleanup does not depend
        # on a clean exit.
        if self._privacy:
            self._purge_file_paths()
        else:
            for picker, key in self._persisted_pickers():
                path = self._settings.value(key, "")
                if path and (os.path.exists(path) or picker._mode == "save"):
                    picker.set_path(path)
            FilePicker.last_dir = self._settings.value("files/last_dir", "")
        # Ending on the Token page after pairing is common, but starting there is not useful
        tab = self._settings.value("window/tab", 0, type=int)
        self._tabs.setCurrentIndex(tab if tab != self.TAB_TOKEN else 0)

    def _persisted_pickers(self):
        return [
            (self._enc_payload, "enc/payload"),
            (self._enc_carrier, "enc/carrier"),
            (self._enc_output,  "enc/output"),
            (self._dec_stego,   "dec/stego"),
            (self._dec_output,  "dec/output_dir"),
        ]

    def _purge_file_paths(self):
        """Remove every remembered file path from settings right now (privacy mode)."""
        for _picker, key in self._persisted_pickers():
            self._settings.remove(key)
        self._settings.remove("files/last_dir")
        self._settings.sync()

    def closeEvent(self, event):
        # Lock the vault on exit so its key never outlives the window.
        if self._vault is not None:
            self._vault_timer.stop()
            self._vault.lock()
            self._vault = None
        self._settings.setValue("window/geometry", self.saveGeometry())
        self._settings.setValue("window/tab", self._tabs.currentIndex())
        self._settings.setValue("enc/output_auto", self._enc_output_auto)
        self._settings.setValue("privacy/mode", self._privacy)
        if self._privacy:
            self._purge_file_paths()      # leave no trace of which files were used
        else:
            for picker, key in self._persisted_pickers():
                self._settings.setValue(key, picker.path())
            self._settings.setValue("files/last_dir", FilePicker.last_dir)
        for w in list(self._workers):
            w.wait(5000)
        # Remove the throwaway UI glyphs from %TEMP% so the app leaves nothing behind
        # there. They are only tick/arrow images, but a clean exit leaves no trace.
        try:
            import shutil
            shutil.rmtree(Path(tempfile.gettempdir()) / "envstego_ui", ignore_errors=True)
        except Exception:
            pass
        super().closeEvent(event)

    def _start_worker(self, worker: QThread):
        self._workers.add(worker)
        worker.finished.connect(lambda: self._workers.discard(worker))
        worker.start()

    # ── UI Construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        hbox = QHBoxLayout(root)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(0)

        hbox.addWidget(self._build_sidebar())

        main = QWidget()
        main.setObjectName("main")
        vbox = QVBoxLayout(main)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(self._build_topbar())

        # ── Page stack (index order matches TAB_* and the saved page) ──
        self._tabs = QStackedWidget()
        self._tabs.addWidget(self._build_signals_tab())
        self._tabs.addWidget(self._build_encrypt_tab())
        self._tabs.addWidget(self._build_decrypt_tab())
        self._tabs.addWidget(self._build_token_tab())
        self._tabs.addWidget(self._build_inspector_tab())
        self._tabs.addWidget(self._build_vault_tab())
        self._tabs.currentChanged.connect(self._on_page_changed)
        vbox.addWidget(self._tabs, stretch=1)
        hbox.addWidget(main, stretch=1)
        self._show_page_meta(self._tabs.currentIndex())

        # ── Status bar ────────────────────────────────────────────
        self._status = QStatusBar()
        self._status.setSizeGripEnabled(False)
        self.setStatusBar(self._status)
        self._status.showMessage("Initialising…")

    def _build_sidebar(self) -> QWidget:
        side = QWidget()
        side.setObjectName("sidebar")
        side.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        side.setFixedWidth(224)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(12, 20, 12, 14)
        lay.setSpacing(2)

        brand = QLabel("EnvStego")
        brand.setObjectName("brand")
        brand.setContentsMargins(12, 0, 0, 0)
        lay.addWidget(brand)
        tag = QLabel("Environment-keyed steganography")
        tag.setObjectName("brand_sub")
        tag.setContentsMargins(12, 0, 0, 0)
        lay.addWidget(tag)
        lay.addSpacing(22)

        self._nav: dict[int, NavButton] = {}
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        for group, items in self.NAV_LAYOUT:
            lay.addWidget(_label(group, "nav_group", wrap=False))
            lay.addSpacing(4)
            for index, title in items:
                btn = NavButton(title)
                if index in self.PAGE_INFO:
                    btn.setToolTip(self.PAGE_INFO[index][1])   # hover shows what the page does
                btn.clicked.connect(lambda _=False, i=index: self._tabs.setCurrentIndex(i))
                self._nav_group.addButton(btn)
                self._nav[index] = btn
                lay.addWidget(btn)
            lay.addSpacing(16)

        lay.addStretch()

        # Both persistent security modes live together at the foot of the sidebar,
        # with a "?" badge on the right that explains them on hover.
        modes_row = QHBoxLayout()
        # No left margin: the "nav_group" style already pads 12px, matching the other
        # section headers and the checkboxes below. Right margin keeps the "?" in place.
        modes_row.setContentsMargins(0, 0, 10, 0)
        modes_row.setSpacing(6)
        modes_row.addWidget(_label("MODES", "nav_group", wrap=False),
                            0, Qt.AlignmentFlag.AlignVCenter)
        modes_row.addStretch()
        modes_help = QLabel("?")
        modes_help.setAlignment(Qt.AlignmentFlag.AlignCenter)
        modes_help.setCursor(Qt.CursorShape.WhatsThisCursor)
        modes_help.setFixedSize(16, 16)
        modes_help.setStyleSheet(
            "QLabel{color:#8b949e; font-weight:700; font-size:11px; border:1px solid #30363d;"
            " border-radius:8px;} QLabel:hover{color:#e6edf3; border-color:#8b949e;}")
        modes_help.setToolTip(
            "Privacy mode\n"
            "File paths are not remembered, the stego image copies the carrier's date, and\n"
            "outputs default to Pictures/Downloads. Leaves less for a forensic examiner to find.\n\n"
            "Portable mode\n"
            "Only signals that travel with this PC (hardware, OS) can be selected, so you can\n"
            "encrypt and decrypt anywhere on this machine. Network and location signals are\n"
            "disabled, so the data is bound to this PC and the token, not to a place.")
        modes_row.addWidget(modes_help, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addLayout(modes_row)
        lay.addSpacing(6)

        self._privacy_cb = QCheckBox("Privacy mode")
        self._privacy_cb.setChecked(self._privacy)
        self._privacy_cb.setCursor(Qt.CursorShape.PointingHandCursor)
        self._privacy_cb.setContentsMargins(12, 0, 0, 0)
        self._privacy_cb.toggled.connect(self._on_privacy_toggled)
        lay.addWidget(self._privacy_cb)
        lay.addSpacing(6)

        self._portable_cb = QCheckBox("Portable mode")
        self._portable_cb.setChecked(self._portable)
        self._portable_cb.setCursor(Qt.CursorShape.PointingHandCursor)
        self._portable_cb.setContentsMargins(12, 0, 0, 0)
        self._portable_cb.toggled.connect(self._on_portable_toggled)
        lay.addWidget(self._portable_cb)
        lay.addSpacing(12)

        foot = QLabel("ICT3215 Digital Forensics · SIT")
        foot.setObjectName("sidebar_foot")
        foot.setContentsMargins(12, 0, 0, 0)
        lay.addWidget(foot)
        return side

    def _on_privacy_toggled(self, on: bool):
        self._privacy = on
        self._settings.setValue("privacy/mode", on)
        if on:
            self._purge_file_paths()      # don't wait for a clean exit to clear them

    def _build_topbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("topbar")
        bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        bar.setFixedHeight(76)
        row = QHBoxLayout(bar)
        row.setContentsMargins(28, 0, 20, 0)
        row.setSpacing(10)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        self._page_title = QLabel()
        self._page_title.setObjectName("page_title")
        self._page_sub = QLabel()
        self._page_sub.setObjectName("page_sub")
        titles.addStretch()
        titles.addWidget(self._page_title)
        titles.addWidget(self._page_sub)
        titles.addStretch()
        row.addLayout(titles, stretch=1)

        self._token_chip = QPushButton()
        self._token_chip.setFixedHeight(32)
        self._token_chip.setCursor(Qt.CursorShape.PointingHandCursor)
        self._token_chip.setToolTip("Open the Token page")
        self._token_chip.clicked.connect(lambda: self._tabs.setCurrentIndex(self.TAB_TOKEN))
        row.addWidget(self._token_chip)

        self._refresh_btn = QPushButton("↻  Refresh signals")
        self._refresh_btn.setFixedHeight(32)
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.setToolTip("Re-read every environment signal. Your selection is kept.")
        self._refresh_btn.clicked.connect(self._start_collection)
        row.addWidget(self._refresh_btn)
        return bar

    def _on_page_changed(self, index: int):
        self._settings.setValue("window/tab", index)
        self._show_page_meta(index)

    def _show_page_meta(self, index: int):
        title, sub = self.PAGE_INFO.get(index, ("", ""))
        self._page_title.setText(title)
        self._page_sub.setText(sub)
        btn = self._nav.get(index)
        if btn and not btn.isChecked():
            btn.setChecked(True)

    def _key_card(self) -> tuple[QFrame, QLabel]:
        """Compact summary of the current key inputs, shown on Encrypt and Decrypt."""
        frame, lay = _card()
        lay.setContentsMargins(18, 12, 14, 12)
        row = QHBoxLayout()
        row.setSpacing(12)
        lay.addLayout(row)
        row.addWidget(_section("Key inputs"))
        lbl = QLabel()
        lbl.setTextFormat(Qt.TextFormat.RichText)
        row.addWidget(lbl, stretch=1)
        change = QPushButton("Change signals →")
        change.setObjectName("btn_link")
        change.setCursor(Qt.CursorShape.PointingHandCursor)
        change.clicked.connect(lambda: self._tabs.setCurrentIndex(self.TAB_SIGNALS))
        row.addWidget(change)
        return frame, lbl

    def _action_bar(self, button: QPushButton, hint: QLabel) -> QHBoxLayout:
        """Primary action on the right, with what is still missing explained beside it."""
        row = QHBoxLayout()
        row.setSpacing(16)
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(hint, stretch=1)
        button.setMinimumWidth(210)
        button.setMinimumHeight(46)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        row.addWidget(button)
        return row

    # ─────────────────────────────────────────────────────────────
    #  PAGE — SIGNAL SELECTION
    # ─────────────────────────────────────────────────────────────

    def _build_signals_tab(self) -> QWidget:
        page, outer = _page(scroll=False, max_width=1120)
        outer.setSpacing(12)

        # ── Preset card ───────────────────────────────────────────
        preset_card, pc = _card(spacing=8)
        pc.addWidget(_section("Start from a preset"))
        preset_bar = QHBoxLayout()
        preset_bar.setSpacing(8)

        self._preset_combo = QComboBox()
        self._preset_combo.setMinimumWidth(280)
        self._preset_combo.setMinimumHeight(36)
        self._preset_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self._preset_combo.activated.connect(self._on_preset_chosen)
        preset_bar.addWidget(self._preset_combo)

        self._preset_save_btn = QPushButton("Save as preset…")
        self._preset_save_btn.clicked.connect(self._save_preset)
        preset_bar.addWidget(self._preset_save_btn)

        self._preset_del_btn = QPushButton("Delete preset")
        self._preset_del_btn.setObjectName("btn_danger")
        self._preset_del_btn.clicked.connect(self._delete_preset)
        preset_bar.addWidget(self._preset_del_btn)

        preset_bar.addStretch()

        self._clear_sel_btn = QPushButton("Clear selection")
        self._clear_sel_btn.clicked.connect(lambda: self._apply_selection(set(), None))
        preset_bar.addWidget(self._clear_sel_btn)
        pc.addLayout(preset_bar)

        self._preset_desc = _label("", "muted")
        pc.addWidget(self._preset_desc)
        outer.addWidget(preset_card)
        self._rebuild_preset_combo()

        # Shown only while portable mode (toggled in the sidebar) is on
        self._portable_note = _label(
            "⬡  Portable mode is on — network / location signals are disabled below. Files are "
            "bound to this PC and the token, not to a place, so they open on this laptop anywhere.",
            "hint")
        self._portable_note.setVisible(self._portable)
        outer.addWidget(self._portable_note)

        tip = _label("Click anywhere on a row to toggle it. Hover a row to see the value read "
                     "from this machine.", "subtle")
        outer.addWidget(tip)

        # ── Signal list ───────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll_content = QWidget()
        self._scroll_content.setObjectName("page")
        self._scroll_layout = QVBoxLayout(self._scroll_content)
        self._scroll_layout.setSpacing(6)
        self._scroll_layout.setContentsMargins(0, 0, 6, 0)
        self._loading_lbl = QLabel("Profiling environment — reading hardware, network and OS signals…")
        self._loading_lbl.setObjectName("muted")
        self._loading_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._loading_lbl.setMinimumHeight(160)
        self._scroll_layout.addWidget(self._loading_lbl)
        self._scroll_layout.addStretch()
        scroll.setWidget(self._scroll_content)
        outer.addWidget(scroll, stretch=1)

        # ── Summary bar ───────────────────────────────────────────
        summary_frame, sf = _card()
        sf.setContentsMargins(18, 12, 14, 12)
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(14)
        sf.addLayout(summary_layout)

        self._sel_count_lbl = QLabel("0 signals selected")
        self._sel_count_lbl.setObjectName("muted")

        self._entropy_lbl = QLabel("Estimated entropy: — bits")
        self._entropy_lbl.setStyleSheet("color:#58a6ff; font-size:13px; font-weight:600;")

        self._entropy_bar = QProgressBar()
        self._entropy_bar.setObjectName("entropy_bar")
        self._entropy_bar.setFixedWidth(140)
        self._entropy_bar.setFixedHeight(6)
        self._entropy_bar.setTextVisible(False)
        self._entropy_bar.setMaximum(256)

        self._fp_lbl = QLabel("Key fingerprint:  —")
        self._fp_lbl.setObjectName("mono")
        self._fp_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self._test_btn = QPushButton("Test Key")
        self._test_btn.setFixedHeight(34)
        self._test_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._test_btn.clicked.connect(self._test_key)

        summary_layout.addWidget(self._sel_count_lbl, stretch=1)
        summary_layout.addWidget(self._entropy_lbl)
        summary_layout.addWidget(self._entropy_bar)
        summary_layout.addSpacing(10)
        summary_layout.addWidget(self._fp_lbl)
        summary_layout.addWidget(self._test_btn)

        outer.addWidget(summary_frame)
        return page

    # ── Presets ──────────────────────────────────────────────────

    def _rebuild_preset_combo(self):
        c = self._preset_combo
        c.blockSignals(True)
        c.clear()
        c.addItem("Custom selection", "")
        for name, desc, _ in BUILTIN_PRESETS:
            c.addItem(name, f"builtin:{name}")
            c.setItemData(c.count() - 1, desc, Qt.ItemDataRole.ToolTipRole)
        if self._user_presets:
            c.insertSeparator(c.count())
            for name in sorted(self._user_presets, key=str.lower):
                c.addItem(f"★  {name}", f"user:{name}")
        idx = c.findData(self._active_preset) if self._active_preset else 0
        c.setCurrentIndex(max(idx, 0))
        c.blockSignals(False)
        self._update_preset_controls()

    def _current_preset(self) -> tuple[str, str] | None:
        data = self._preset_combo.currentData()
        if not data:
            return None
        kind, _, name = data.partition(":")
        return kind, name

    def _update_preset_controls(self):
        data = self._current_preset()
        self._preset_del_btn.setEnabled(bool(data) and data[0] == "user")
        desc = ""
        if data and data[0] == "builtin":
            desc = next(d for n, d, _ in BUILTIN_PRESETS if n == data[1])
        elif data and data[0] == "user":
            desc = f"Your saved preset · {len(self._user_presets.get(data[1], []))} signals"
        self._preset_desc.setText(desc)
        self._preset_desc.setVisible(bool(desc))

    def _on_preset_chosen(self, index: int):
        data = self._preset_combo.itemData(index)
        if not data:
            self._set_active_preset(None)
            self._update_preset_controls()
            return
        kind, _, name = data.partition(":")
        if kind == "builtin":
            rule = next(r for n, _, r in BUILTIN_PRESETS if n == name)
            if rule is None:                      # "Recommended" — top strong, steady signals
                ids = set(recommended_ids(self._all_signals))
            else:
                ids = {s.id for s in self._all_signals if s.available and s.value and rule(s)}
        else:
            ids = set(self._user_presets.get(name, []))
        self._apply_selection(ids, f"{kind}:{name}")

    def _save_preset(self):
        if not self._selected_ids:
            QMessageBox.information(self, "Nothing selected", "Select at least one signal before saving a preset.")
            return
        data = self._current_preset()
        suggested = data[1] if data and data[0] == "user" else ""
        name, ok = QInputDialog.getText(self, "Save preset", "Preset name:", text=suggested)
        name = name.strip()
        if not ok or not name:
            return
        if name in self._user_presets and name != suggested:
            if QMessageBox.question(self, "Overwrite preset", f"Replace the existing preset '{name}'?") \
                    != QMessageBox.StandardButton.Yes:
                return
        self._user_presets[name] = sorted(self._selected_ids)
        self._save_json("signals/presets", self._user_presets)
        self._set_active_preset(f"user:{name}")
        self._rebuild_preset_combo()
        self._status.showMessage(f"Preset '{name}' saved ({len(self._selected_ids)} signals)")

    def _delete_preset(self):
        data = self._current_preset()
        if not data or data[0] != "user":
            return
        if QMessageBox.question(self, "Delete preset", f"Delete the preset '{data[1]}'?") \
                != QMessageBox.StandardButton.Yes:
            return
        self._user_presets.pop(data[1], None)
        self._save_json("signals/presets", self._user_presets)
        self._set_active_preset(None)
        self._rebuild_preset_combo()

    def _set_active_preset(self, key: str | None):
        self._active_preset = key
        self._settings.setValue("signals/active_preset", protect_str(key or ""))

    # ── Selection ────────────────────────────────────────────────

    def _volatile_ids(self) -> set:
        """IDs of signals disabled by portable mode (change when you move)."""
        return {s.id for s in self._all_signals if not _travel_safe(s)}

    def _apply_selection(self, ids: set, preset_key: str | None):
        ids = set(ids)
        if self._portable:
            ids -= self._volatile_ids()          # portable mode never selects volatile signals
        self._selected_ids = ids
        for row in self._signal_rows:
            row.set_checked(row.signal.id in self._selected_ids)
        self._set_active_preset(preset_key)
        self._rebuild_preset_combo()
        self._on_selection_changed()

    def _on_portable_toggled(self, on: bool):
        self._portable = on
        self._settings.setValue("portable/mode", on)
        self._portable_note.setVisible(on)
        if self._all_signals:
            self._populate_signal_rows(self._all_signals)    # re-block/unblock rows
            if on and self._selected_ids & self._volatile_ids():
                # drop any now-disabled signals from the current selection
                self._apply_selection(self._selected_ids - self._volatile_ids(), None)

    def _on_row_toggled(self, signal_id: str, checked: bool):
        if checked:
            self._selected_ids.add(signal_id)
        else:
            self._selected_ids.discard(signal_id)
        if self._active_preset:
            self._set_active_preset(None)
            self._rebuild_preset_combo()
        self._on_selection_changed()

    def _on_selection_changed(self):
        self._save_json("signals/selected", sorted(self._selected_ids))
        self._update_summary()
        self._refresh_actions()

    def _populate_signal_rows(self, signals: list[EnvSignal]):
        while self._scroll_layout.count() > 1:
            item = self._scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._signal_rows.clear()
        categories = {}
        for s in signals:
            categories.setdefault(s.category, []).append(s)

        for cat_name in CATEGORY_ORDER:
            cat_signals = categories.get(cat_name, [])
            if not cat_signals:
                continue

            collapsed = cat_name in self._collapsed_cats

            header_widget = QWidget()
            header_layout = QHBoxLayout(header_widget)
            header_layout.setContentsMargins(2, 10, 0, 2)
            header_layout.setSpacing(8)

            readable = sum(1 for s in cat_signals if s.available and s.value)

            # A chevron button collapses/expands the whole category.
            chevron = QToolButton()
            chevron.setObjectName("chevron")
            chevron.setText("▸" if collapsed else "▾")
            chevron.setCursor(Qt.CursorShape.PointingHandCursor)
            chevron.setToolTip("Collapse or expand this category")
            chevron.setStyleSheet("QToolButton{border:none;background:transparent;color:#8b949e;"
                                  "font-size:13px;padding:0 2px;} QToolButton:hover{color:#e6edf3;}")
            cat_label = _section(f"{cat_name}  ·  {readable}/{len(cat_signals)} available")

            sel_btn = QPushButton("Select all")
            sel_btn.setObjectName("btn_small")
            sel_btn.setFixedHeight(24)
            sel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            sel_btn.setToolTip(f"Select every readable {cat_name} signal")
            desel_btn = QPushButton("Deselect all")
            desel_btn.setObjectName("btn_small")
            desel_btn.setFixedHeight(24)
            desel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            desel_btn.setToolTip(f"Unselect every {cat_name} signal")

            # Chevron, then the bulk actions above the checkbox column they control,
            # then the section label and a divider rule filling the row to the right.
            header_layout.addWidget(chevron)
            header_layout.addWidget(sel_btn)
            header_layout.addWidget(desel_btn)
            header_layout.addSpacing(8)
            header_layout.addWidget(cat_label)
            header_layout.addWidget(_divider(), stretch=1)

            group = QFrame()
            group.setObjectName("card")
            g_layout = QVBoxLayout(group)
            g_layout.setContentsMargins(6, 6, 6, 6)
            g_layout.setSpacing(2)
            group.setVisible(not collapsed)

            def _toggle_cat(_=False, cat=cat_name, grp=group, chev=chevron):
                now_collapsed = grp.isVisible()
                grp.setVisible(not now_collapsed)
                chev.setText("▸" if now_collapsed else "▾")
                if now_collapsed:
                    self._collapsed_cats.add(cat)
                else:
                    self._collapsed_cats.discard(cat)
                self._save_json("signals/collapsed_cats", sorted(self._collapsed_cats))
            chevron.clicked.connect(_toggle_cat)

            cat_ids = []
            # Show the steadiest signals first within each category.
            for sig in sorted(cat_signals, key=lambda s: s.stability, reverse=True):
                blocked = self._portable and not _travel_safe(sig)
                row = SignalRow(sig, sig.id in self._selected_ids, blocked=blocked)
                row.toggled.connect(self._on_row_toggled)
                g_layout.addWidget(row)
                self._signal_rows.append(row)
                if row.readable:
                    cat_ids.append(sig.id)

            sel_btn.setEnabled(len(cat_ids) > 0)   # nothing readable -> nothing to select
            sel_btn.clicked.connect(
                lambda _=False, ids=cat_ids: self._apply_selection(self._selected_ids | set(ids), None))
            desel_btn.clicked.connect(
                lambda _=False, ids=[s.id for s in cat_signals]:
                self._apply_selection(self._selected_ids - set(ids), None))

            self._scroll_layout.insertWidget(self._scroll_layout.count() - 1, header_widget)
            self._scroll_layout.insertWidget(self._scroll_layout.count() - 1, group)

        self._update_summary()

    def _selection_breakdown(self) -> tuple[list[EnvSignal], list[EnvSignal]]:
        """(readable selected, selected but unreadable) based on the last collection."""
        by_id = {s.id: s for s in self._all_signals}
        chosen = [by_id[i] for i in self._selected_ids if i in by_id]
        active = [s for s in chosen if s.available and s.value]
        return active, [s for s in chosen if s not in active]

    def _update_summary(self):
        active, ignored = self._selection_breakdown()
        count   = len(active)
        entropy = estimate_entropy_bits(active)

        # Rate the selection for strength + lock-out risk, and reflect it on the
        # entropy label's colour and tooltip (blue = ok, amber = caution, red = weak).
        level, advice = assess_selection(active)
        colour = {"ok": "#58a6ff", "caution": "#d29922", "weak": "#f85149"}[level]
        prefix = {"ok": "", "caution": "⚠ ", "weak": "⚠ "}[level]
        self._entropy_lbl.setText(f"{prefix}Estimated entropy:  {entropy} bits")
        self._entropy_lbl.setStyleSheet(f"color:{colour}; font-size:13px; font-weight:600;")
        self._entropy_lbl.setToolTip(advice or "Solid environment binding.")
        self._entropy_bar.setValue(min(entropy, 256))
        self._fp_lbl.setText("Key fingerprint:  —")

        if ignored:
            names = ", ".join(s.name for s in ignored)
            self._sel_count_lbl.setText(f"{count} selected  |  ⚠ {len(ignored)} unreadable: {names}")
            self._sel_count_lbl.setStyleSheet("color:#d29922; font-size:11px;")
        else:
            self._sel_count_lbl.setText(f"{count} signal{'s' if count != 1 else ''} selected")
            self._sel_count_lbl.setStyleSheet("color:#8b949e; font-size:12px;")

        self._update_key_cards()

    def _test_key(self):
        ids = frozenset(self._selected_ids)
        self._set_busy(True)
        self._test_btn.setText("Testing…")
        self._fp_lbl.setText("Key fingerprint:  asking token…")
        w = TestKeyWorker(ids)
        w.done.connect(lambda fp, snap: self._on_test_done(ids, fp, snap))
        w.error.connect(self._on_test_error)
        self._start_worker(w)

    def _on_test_done(self, ids: frozenset, fp: str, snapshot: dict):
        self._set_busy(False)
        self._note_token_result(True)
        self._test_btn.setText("Test Key")
        changed = []
        note = ""
        self._fp_lbl.setToolTip("")
        if self._last_test and self._last_test[0] == ids:
            if self._last_test[1] == fp:
                note = "  ✓ stable"
            else:
                # Name exactly which selected signals moved, so the cause is obvious.
                prev = self._last_test[2] if len(self._last_test) > 2 else {}
                for sid, (name, value) in snapshot.items():
                    old = prev.get(sid, (None, None))[1]
                    if old is not None and old != value:
                        changed.append((name, old, value))
                if changed:
                    names = ", ".join(n for n, _o, _v in changed)
                    note = f"  ⚠ changed — {names} differ(s) from last test"
                    self._fp_lbl.setToolTip(
                        "These selected signals changed value since the last Test Key:\n\n"
                        + "\n".join(f"• {n}\n     was: {o}\n     now: {v}" for n, o, v in changed)
                        + "\n\nAny file encrypted under the earlier fingerprint will not decrypt "
                          "while these differ. Deselect the unstable signal(s), or use Portable "
                          "mode / a Hardware-only preset to avoid network signals.")
                else:
                    note = "  ⚠ changed since last test"
        self._last_test = (ids, fp, snapshot)
        self._fp_lbl.setText(f"Key fingerprint:  {fp}{note}")
        if changed:
            self._status.showMessage(
                f"Key changed — {', '.join(n for n, _o, _v in changed)} moved since last test "
                f"(hover the fingerprint for details)")
        else:
            self._status.showMessage(
                f"Key fingerprint {fp} — "
                + ("environment is stable" if note.strip().startswith("✓")
                   else "run Test Key again to confirm the environment is stable"))

    def _on_test_error(self, msg: str):
        self._set_busy(False)
        self._note_token_result(False, msg)
        self._test_btn.setText("Test Key")
        self._fp_lbl.setText("Key fingerprint:  error")
        QMessageBox.warning(self, "Test Key failed", msg)

    # ─────────────────────────────────────────────────────────────
    #  TAB 2 — ENCRYPT
    # ─────────────────────────────────────────────────────────────

    def _build_encrypt_tab(self) -> QWidget:
        page, layout = _page()

        key_frame, self._enc_key_lbl = self._key_card()
        layout.addWidget(key_frame)

        files, il = _card(spacing=14)
        il.addWidget(_section("Files"))

        self._enc_payload = FilePicker("File or folder to hide", filter_="All Files (*.*)", step=1,
                                       allow_dir=True,
                                       placeholder="Any file, or a whole folder — browse, or drop it here")
        self._enc_carrier = FilePicker(
            "Carrier — PNG image or WAV audio", step=2,
            filter_="Carriers (*.png *.wav);;PNG Images (*.png);;WAV Audio (*.wav);;All (*.*)",
            placeholder="The PNG or WAV to hide it in — browse, or drop it here")
        self._enc_output  = FilePicker("Save stego carrier as", mode="save", step=3,
                                       filter_="Carrier (*.png *.wav)",
                                       placeholder="Suggested automatically next to the carrier")

        # Multi-image split: the same payload spread across several carriers.
        self._enc_carriers = MultiFilePicker(
            "Carrier images/audio (PNG or WAV) — filled in order", step=2,
            filter_="Carriers (*.png *.wav);;PNG Images (*.png);;WAV Audio (*.wav)")
        self._enc_out_dir  = FilePicker("Save stego images to folder", mode="dir", step=3,
                                        placeholder="The split images are written here")

        self._enc_carrier.changed.connect(self._on_carrier_changed)
        self._enc_payload.changed.connect(self._update_capacity)
        self._enc_output.changed.connect(self._on_output_edited)
        self._enc_carriers.changed.connect(self._update_capacity)
        self._enc_out_dir.changed.connect(self._refresh_actions)

        self._enc_split = QCheckBox("Split across several carrier images (for payloads too big for one)")
        self._enc_split.setObjectName("mode_check")
        self._enc_split.toggled.connect(self._on_split_toggled)

        il.addWidget(self._enc_payload)
        il.addWidget(self._enc_split)
        il.addWidget(self._enc_carrier)
        il.addWidget(self._enc_output)
        il.addWidget(self._enc_carriers)
        il.addWidget(self._enc_out_dir)
        self._enc_carriers.setVisible(False)
        self._enc_out_dir.setVisible(False)
        il.addWidget(_divider())

        cap_top = QHBoxLayout()
        self._cap_label = QLabel("Select a carrier (PNG image or WAV audio) to see capacity")
        self._cap_label.setObjectName("muted")
        cap_top.addWidget(self._cap_label)
        cap_top.addStretch()
        self._img_info_lbl = QLabel("")
        self._img_info_lbl.setObjectName("subtle")
        cap_top.addWidget(self._img_info_lbl)
        il.addLayout(cap_top)

        self._cap_bar = QProgressBar()
        self._cap_bar.setObjectName("capacity_bar")
        self._cap_bar.setFixedHeight(6)
        self._cap_bar.setTextVisible(False)
        il.addWidget(self._cap_bar)
        layout.addWidget(files)

        self._enc_btn = QPushButton(self.ENC_LABEL)
        self._enc_btn.setObjectName("btn_primary")
        self._enc_btn.clicked.connect(self._do_encrypt)
        self._enc_hint = QLabel("")
        self._enc_hint.setObjectName("hint")
        layout.addLayout(self._action_bar(self._enc_btn, self._enc_hint))

        self._enc_result = StatusPanel()
        layout.addWidget(self._enc_result)

        result_row = QHBoxLayout()
        self._enc_fp_lbl = QLabel("")
        self._enc_fp_lbl.setObjectName("mono")
        self._enc_fp_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        result_row.addWidget(self._enc_fp_lbl)
        result_row.addStretch()
        self._enc_shred_btn = QPushButton("Shred original")
        self._enc_shred_btn.setObjectName("btn_danger")
        self._enc_shred_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._enc_shred_btn.setToolTip("Overwrite and delete the original payload file so the "
                                       "plaintext does not linger on disk")
        self._enc_shred_btn.setVisible(False)
        self._enc_shred_btn.clicked.connect(self._shred_original)
        result_row.addWidget(self._enc_shred_btn)
        self._enc_open_btn = QPushButton("Show in folder")
        self._enc_open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._enc_open_btn.setVisible(False)
        self._enc_open_btn.clicked.connect(lambda: self._open_folder(self._enc_last_output))
        result_row.addWidget(self._enc_open_btn)
        layout.addLayout(result_row)
        self._enc_last_payload = ""
        self._enc_last_output = ""

        layout.addStretch()
        return page

    def _on_split_toggled(self, on: bool):
        # Swap the single carrier/output pickers for the multi-image ones (or back).
        self._enc_carrier.setVisible(not on)
        self._enc_output.setVisible(not on)
        self._enc_carriers.setVisible(on)
        self._enc_out_dir.setVisible(on)
        if on and not self._enc_out_dir.path():
            self._enc_out_dir.set_path(pictures_dir() if self._privacy else "")
        self._update_capacity()

    def _on_carrier_changed(self, carrier: str):
        # Suggest an output path unless the user chose one themselves. Privacy mode
        # puts it in Pictures; otherwise next to the carrier.
        if carrier and (self._enc_output_auto or not self._enc_output.path()):
            p = Path(carrier)
            folder = pictures_dir() if self._privacy else str(p.parent)
            suggestion = str(Path(folder) / f"{p.stem}_stego{media.output_suffix(carrier)}")
            self._enc_output.set_path(suggestion)
            self._enc_output_auto = True
        elif not carrier and self._enc_output_auto:
            self._enc_output.set_path("")
            self._enc_output_auto = True
        self._update_capacity()

    def _on_output_edited(self, _text: str):
        carrier = self._enc_carrier.path()
        if carrier:
            p = Path(carrier)
            auto = str(p.with_name(f"{p.stem}_stego{media.output_suffix(carrier)}"))
            self._enc_output_auto = self._enc_output.path() == auto
        else:
            self._enc_output_auto = False
        self._refresh_actions()

    def _update_capacity(self, *_):
        if self._enc_split.isChecked():
            self._update_capacity_split()
            return
        carrier = self._enc_carrier.path()
        payload = self._enc_payload.path()
        self._enc_capacity_ok = False
        self._cap_bar.setObjectName("capacity_bar")

        if not carrier or not os.path.isfile(carrier):
            self._cap_label.setText("Select a carrier (PNG image or WAV audio) to see capacity")
            self._img_info_lbl.setText("")
            self._cap_bar.setValue(0)
        else:
            try:
                info = media.carrier_info(carrier)
                # Usable payload capacity = total LSB bytes minus the v3 header overhead
                cap = max(0, lsb_capacity_bytes(carrier) - OUTER_SIZE)
                self._img_info_lbl.setText(
                    f"{info['summary']}  |  capacity {cap:,} B  ({cap/1024:.1f} KB)"
                )
                if payload and os.path.isdir(payload):
                    # A folder is zipped at encrypt time, so the exact size is not known
                    # yet. Show the uncompressed total as a rough upper bound and let the
                    # encrypt step do the strict capacity check once zipped.
                    total = _folder_size(payload)
                    self._enc_capacity_ok = cap > 0
                    if cap <= 0:
                        self._cap_label.setText("Folder too large for this carrier — use a bigger image")
                        self._cap_bar.setObjectName("capacity_over")
                    elif total <= cap:
                        self._cap_label.setText(f"Folder — up to {total:,} / {cap:,} bytes before zip (fits)")
                    else:
                        self._cap_label.setText(
                            f"Folder — {total:,} B before zip; may fit in {cap:,} B after compression")
                    self._cap_bar.setValue(min(100, int(total / cap * 100)) if cap > 0 else 100)
                elif payload and os.path.isfile(payload):
                    needed = packed_size(payload, os.path.getsize(payload))
                    pct = min(100, int(needed / cap * 100)) if cap > 0 else 100
                    if needed > cap:
                        self._cap_label.setText(
                            f"⚠  Payload too large: needs {needed:,} B, carrier holds {cap:,} B"
                        )
                        self._cap_bar.setObjectName("capacity_over")
                    else:
                        self._cap_label.setText(f"Using {needed:,} / {cap:,} bytes  ({pct}%)")
                        self._enc_capacity_ok = True
                    self._cap_bar.setValue(max(pct, 1))
                else:
                    self._cap_label.setText(f"Capacity: {cap:,} bytes  ({cap/1024:.1f} KB)")
                    self._cap_bar.setValue(0)
            except Exception as e:
                self._cap_label.setText(f"Cannot read image: {e}")
                self._img_info_lbl.setText("")
                self._cap_bar.setValue(0)

        self._cap_bar.style().unpolish(self._cap_bar)
        self._cap_bar.style().polish(self._cap_bar)
        self._refresh_actions()

    def _update_capacity_split(self):
        carriers = [c for c in self._enc_carriers.paths() if os.path.isfile(c)]
        payload = self._enc_payload.path()
        self._enc_capacity_ok = False
        self._cap_bar.setObjectName("capacity_bar")
        try:
            if len(carriers) < 2:
                self._cap_label.setText("Add at least two carrier images to split across")
                self._img_info_lbl.setText("")
                self._cap_bar.setValue(0)
            else:
                cap = mi.total_capacity(carriers)       # combined usable bytes (tags deducted)
                self._img_info_lbl.setText(
                    f"{len(carriers)} images  |  combined capacity {cap:,} B  ({cap/1024:.1f} KB)")
                if payload and os.path.isdir(payload):
                    total = _folder_size(payload)
                    self._enc_capacity_ok = cap > OUTER_SIZE
                    self._cap_label.setText(
                        f"Folder — {total:,} B before zip; header+payload must fit in {cap:,} B")
                    self._cap_bar.setValue(min(100, int(total / cap * 100)) if cap > 0 else 100)
                elif payload and os.path.isfile(payload):
                    needed = OUTER_SIZE + packed_size(payload, os.path.getsize(payload))
                    pct = min(100, int(needed / cap * 100)) if cap > 0 else 100
                    if needed > cap:
                        self._cap_label.setText(
                            f"⚠  Payload too large: needs {needed:,} B, images hold {cap:,} B")
                        self._cap_bar.setObjectName("capacity_over")
                    else:
                        self._cap_label.setText(f"Using {needed:,} / {cap:,} bytes  ({pct}%)")
                        self._enc_capacity_ok = True
                    self._cap_bar.setValue(max(pct, 1))
                else:
                    self._cap_label.setText(f"Combined capacity: {cap:,} bytes  ({cap/1024:.1f} KB)")
                    self._cap_bar.setValue(0)
        except Exception as e:
            self._cap_label.setText(f"Cannot read an image: {e}")
            self._img_info_lbl.setText("")
            self._cap_bar.setValue(0)
        self._cap_bar.style().unpolish(self._cap_bar)
        self._cap_bar.style().polish(self._cap_bar)
        self._refresh_actions()

    def _encrypt_blockers(self) -> list[str]:
        active, missing = self._selection_breakdown()
        payload = self._enc_payload.path()
        out = []
        if not self._token_cfg:
            out.append("pair a hardware token")
        if not active:
            out.append("select signals")
        elif missing:
            out.append("deselect unreadable signals")
        if not payload or not os.path.exists(payload):
            out.append("choose a file or folder")

        if self._enc_split.isChecked():
            if self._enc_carriers.count() < 2:
                out.append("add at least two carrier images")
            elif payload and os.path.exists(payload) and not self._enc_capacity_ok:
                out.append("add more or larger carriers")
            if not self._enc_out_dir.path():
                out.append("choose an output folder")
        else:
            carrier, output = self._enc_carrier.path(), self._enc_output.path()
            if not carrier or not os.path.isfile(carrier):
                out.append("choose a carrier (PNG or WAV)")
            elif payload and os.path.exists(payload) and not self._enc_capacity_ok:
                out.append("use a bigger carrier image")
            if not output:
                out.append("choose an output path")
            elif carrier and os.path.normcase(os.path.abspath(output)) == os.path.normcase(os.path.abspath(carrier)):
                out.append("pick an output different from the carrier")
        return out

    def _do_encrypt(self):
        if self._encrypt_blockers():
            return

        if self._enc_split.isChecked():
            carriers = [c for c in self._enc_carriers.paths() if os.path.isfile(c)]
            outputs = mi.suggest_outputs(carriers, self._enc_out_dir.path())
            existing = [o for o in outputs if os.path.exists(o)]
            if existing:
                if QMessageBox.question(
                        self, "Overwrite files",
                        f"{len(existing)} output image(s) already exist in that folder. Overwrite them?") \
                        != QMessageBox.StandardButton.Yes:
                    return
        else:
            carriers = [self._enc_carrier.path()]
            outputs = [self._enc_output.path()]
            out_final = str(Path(outputs[0]).with_suffix(media.output_suffix(carriers[0])))
            if os.path.exists(out_final):
                if QMessageBox.question(self, "Overwrite file",
                                        f"{Path(out_final).name} already exists. Overwrite it?") \
                        != QMessageBox.StandardButton.Yes:
                    return

        self._set_busy(True)
        self._enc_btn.setText(self.ENC_BUSY)
        self._enc_result.show_info("Collecting live signals and requesting the key from the token over BLE…")
        self._enc_fp_lbl.setText("")
        self._enc_open_btn.setVisible(False)

        w = EncryptWorker(self._selected_ids, carriers, self._enc_payload.path(), outputs,
                          match_timestamps=self._privacy)
        w.done.connect(self._on_encrypt_done)
        w.error.connect(self._on_encrypt_error)
        self._start_worker(w)

    def _on_encrypt_done(self, msg: str, fp: str, out_path: str):
        self._set_busy(False)
        self._note_token_result(True)
        self._enc_btn.setText(self.ENC_LABEL)
        self._enc_result.show_success(msg)
        self._enc_fp_lbl.setText(f"Key fingerprint:  {fp}")
        self._enc_last_output = out_path
        if not self._enc_split.isChecked():
            self._enc_output.set_path(out_path)
        self._enc_open_btn.setVisible(True)
        # Offer to wipe the original now that a stego copy exists
        self._enc_last_payload = self._enc_payload.path()
        self._enc_shred_btn.setVisible(bool(self._enc_last_payload)
                                       and os.path.isfile(self._enc_last_payload))
        # Convenience: the image just made is the one most likely to be decrypted next
        if not self._dec_stego.path():
            self._dec_stego.set_path(out_path)
        self._status.showMessage(f"Encrypt complete — key fingerprint: {fp}")

    def _shred_original(self):
        path = self._enc_last_payload
        if not path or not os.path.isfile(path):
            self._enc_shred_btn.setVisible(False)
            return
        if QMessageBox.warning(
                self, "Shred the original?",
                f"This overwrites and deletes:\n{path}\n\n"
                "The encrypted copy is already saved, so you will still be able to decrypt it.\n\n"
                "Note: on SSDs and USB flash drives, overwriting cannot guarantee the data is "
                "unrecoverable (wear-levelling writes elsewhere). The surest protection is to keep "
                "originals only on media you can fully control.\n\nDelete the original now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        try:
            from winutils import shred_file
            shred_file(path)
        except OSError as e:
            self._enc_result.show_error(f"Could not shred the original:\n{e}")
            return
        self._enc_last_payload = ""
        self._enc_shred_btn.setVisible(False)
        if self._enc_payload.path() == path:
            self._enc_payload.set_path("")
        self._status.showMessage("Original payload securely overwritten and deleted")

    def _on_encrypt_error(self, msg: str):
        self._set_busy(False)
        self._note_token_result(False, msg)
        self._enc_btn.setText(self.ENC_LABEL)
        self._enc_result.show_error(msg)
        self._status.showMessage("Encryption failed")

    # ─────────────────────────────────────────────────────────────
    #  TAB 3 — DECRYPT
    # ─────────────────────────────────────────────────────────────

    def _build_decrypt_tab(self) -> QWidget:
        page, layout = _page()

        note = _label(
            "⚠  Decryption rebuilds the key from live signals and the paired token. A different machine, "
            "network, token or a cloned disk gives a different key, and the file cannot be recovered.",
            "callout_warn")
        layout.addWidget(note)

        key_frame, self._dec_key_lbl = self._key_card()
        layout.addWidget(key_frame)

        files, il = _card(spacing=14)
        il.addWidget(_section("Files"))
        self._dec_stego  = FilePicker(
            "Stego carrier (PNG or WAV)", step=1,
            filter_="Carriers (*.png *.wav);;PNG Images (*.png);;WAV Audio (*.wav)",
            placeholder="A PNG or WAV made by Encrypt — browse, or drop it here")
        self._dec_stegos = MultiFilePicker(
            "Stego carriers (the full split set)", step=1,
            filter_="Carriers (*.png *.wav);;PNG Images (*.png);;WAV Audio (*.wav)")
        self._dec_output = FilePicker("Save recovered file to", mode="dir", step=2,
                                      placeholder="Same folder as the stego image")
        self._dec_split = QCheckBox("This file was split across several images")
        self._dec_split.setObjectName("mode_check")
        self._dec_split.toggled.connect(self._on_dec_split_toggled)
        self._dec_stego.changed.connect(self._refresh_actions)
        self._dec_stegos.changed.connect(self._refresh_actions)
        il.addWidget(self._dec_split)
        il.addWidget(self._dec_stego)
        il.addWidget(self._dec_stegos)
        il.addWidget(self._dec_output)
        self._dec_stegos.setVisible(False)
        il.addWidget(_label("The file is restored under its original name. Existing files are "
                            "never overwritten.", "subtle"))
        layout.addWidget(files)

        self._dec_btn = QPushButton(self.DEC_LABEL)
        self._dec_btn.setObjectName("btn_decrypt")
        self._dec_btn.clicked.connect(self._do_decrypt)
        self._dec_hint = QLabel("")
        self._dec_hint.setObjectName("hint")
        layout.addLayout(self._action_bar(self._dec_btn, self._dec_hint))

        self._dec_result = StatusPanel()
        layout.addWidget(self._dec_result)

        result_row = QHBoxLayout()
        self._dec_fp_lbl = QLabel("")
        self._dec_fp_lbl.setObjectName("mono")
        self._dec_fp_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        result_row.addWidget(self._dec_fp_lbl)
        result_row.addStretch()
        self._dec_open_btn = QPushButton("Show recovered file")
        self._dec_open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._dec_open_btn.setVisible(False)
        self._dec_open_btn.clicked.connect(lambda: self._open_folder(self._dec_last_path))
        result_row.addWidget(self._dec_open_btn)
        layout.addLayout(result_row)
        self._dec_last_path = ""

        self._dec_preview_lbl = _section("Preview (text files only)")
        self._dec_preview_lbl.setVisible(False)
        layout.addWidget(self._dec_preview_lbl)

        self._dec_preview = QTextEdit()
        self._dec_preview.setReadOnly(True)
        self._dec_preview.setMaximumHeight(160)
        self._dec_preview.setVisible(False)
        layout.addWidget(self._dec_preview)

        layout.addStretch()
        return page

    def _on_dec_split_toggled(self, on: bool):
        self._dec_stego.setVisible(not on)
        self._dec_stegos.setVisible(on)
        self._refresh_actions()

    def _decrypt_blockers(self) -> list[str]:
        # v3 images carry their own (encrypted) signal list, so no manual selection is
        # needed to decrypt. Only the token and a stego image are required.
        out = []
        if not self._token_cfg:
            out.append("pair a hardware token")
        if self._dec_split.isChecked():
            if self._dec_stegos.count() < 2:
                out.append("add the split images")
        else:
            stego = self._dec_stego.path()
            if not stego or not os.path.isfile(stego):
                out.append("choose a stego carrier (PNG or WAV)")
        return out

    def _do_decrypt(self):
        if self._decrypt_blockers():
            return
        self._set_busy(True)
        self._dec_btn.setText(self.DEC_BUSY)
        self._dec_result.show_info("Collecting live signals and requesting the key from the token over BLE…")
        self._dec_fp_lbl.setText("")
        self._dec_open_btn.setVisible(False)
        self._dec_preview.setVisible(False)
        self._dec_preview_lbl.setVisible(False)

        stego_arg = self._dec_stegos.paths() if self._dec_split.isChecked() else self._dec_stego.path()
        w = DecryptWorker(self._selected_ids, stego_arg, self._dec_output.path())
        w.done.connect(self._on_decrypt_done)
        w.error.connect(self._on_decrypt_error)
        w.signals_used.connect(self._on_decrypt_signals_used)
        self._start_worker(w)

    def _on_decrypt_signals_used(self, ids: list):
        # Reflect the signals the image actually used (read from its header) on the
        # Signals page, so the user can see what environment it is bound to.
        if ids and self._all_signals:
            self._apply_selection(set(ids), None)

    def _on_decrypt_done(self, msg: str, fp: str, out_path: str, plaintext: bytes):
        self._set_busy(False)
        self._note_token_result(True)
        self._dec_btn.setText(self.DEC_LABEL)
        self._dec_result.show_success(msg)
        self._dec_fp_lbl.setText(f"Key fingerprint:  {fp}")
        self._dec_last_path = out_path
        self._dec_open_btn.setVisible(True)
        self._status.showMessage("Decryption successful")

        if b"\x00" not in plaintext[:4096]:
            try:
                text = plaintext.decode("utf-8")
                self._dec_preview.setPlainText(text[:2000] + ("…" if len(text) > 2000 else ""))
                self._dec_preview.setVisible(True)
                self._dec_preview_lbl.setVisible(True)
            except UnicodeDecodeError:
                pass

    def _on_decrypt_error(self, msg: str):
        self._set_busy(False)
        self._note_token_result(False, msg)
        self._dec_btn.setText(self.DEC_LABEL)
        self._dec_result.show_error(msg)
        self._status.showMessage("Decryption failed")

    def _open_folder(self, path: str):
        if not path:
            return
        if os.path.isfile(path) and os.name == "nt":
            # Opens Explorer with the file highlighted
            import subprocess
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        else:
            folder = path if os.path.isdir(path) else os.path.dirname(path)
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    # ─────────────────────────────────────────────────────────────
    #  TAB 4 — HARDWARE TOKEN
    # ─────────────────────────────────────────────────────────────

    def _build_token_tab(self) -> QWidget:
        page, layout = _page()

        # ── Status card ───────────────────────────────────────────
        status_card, sl = _card(spacing=12)
        sl.addWidget(_section("Token status"))
        self._tok_title = QLabel()
        self._tok_title.setStyleSheet("font-size:20px; font-weight:600;")
        sl.addWidget(self._tok_title)

        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(6)
        self._tok_fields = {}
        for r, (key, label) in enumerate([
            ("token_id", "Token ID"), ("ble_mac", "BLE address"), ("paired_at", "Paired on"),
            ("firmware", "Firmware"), ("protection", "Credential storage"),
        ]):
            k = QLabel(label)
            k.setObjectName("muted")
            v = QLabel("—")
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            v.setStyleSheet("font-family:Consolas,monospace; color:#c9d1d9;")
            grid.addWidget(k, r, 0)
            grid.addWidget(v, r, 1)
            self._tok_fields[key] = v
        grid.setColumnStretch(1, 1)
        sl.addLayout(grid)
        sl.addWidget(_divider())

        btns = QHBoxLayout()
        btns.setSpacing(8)
        self._ping_btn = QPushButton("Test connection")
        self._ping_btn.setToolTip("Runs the full authenticated BLE handshake without deriving a key")
        self._ping_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._ping_btn.clicked.connect(self._start_ping)
        self._forget_btn = QPushButton("Forget pairing on this PC")
        self._forget_btn.setObjectName("btn_danger")
        self._forget_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._forget_btn.clicked.connect(self._forget_token)
        btns.addWidget(self._ping_btn)
        btns.addStretch()
        btns.addWidget(self._forget_btn)
        sl.addLayout(btns)
        self._ping_result = StatusPanel()
        sl.addWidget(self._ping_result)
        layout.addWidget(status_card)

        # ── Pairing card ──────────────────────────────────────────
        pair_card, pl = _card(spacing=12)
        pl.addWidget(_section("Pair over USB"))
        steps = QGridLayout()
        steps.setHorizontalSpacing(10)
        steps.setVerticalSpacing(8)
        for r, text in enumerate([
            "Plug the token in with a USB cable. Close any serial monitor (PlatformIO, Arduino IDE) "
            "that is using its port.",
            "Wait for its light: a few blinks, then 2 short flashes means it is ready. "
            "The port below is detected automatically.",
            "Click Pair Token. No buttons on the token need pressing; it takes up to 15 seconds "
            "and the Bluetooth link is checked straight after.",
        ]):
            num = QLabel(str(r + 1))
            num.setObjectName("step_num")
            num.setAlignment(Qt.AlignmentFlag.AlignCenter)
            steps.addWidget(num, r, 0, Qt.AlignmentFlag.AlignTop)
            steps.addWidget(_label(text, "muted"), r, 1)
        steps.setColumnStretch(1, 1)
        pl.addLayout(steps)

        port_row = QHBoxLayout()
        port_row.setSpacing(8)
        self._port_combo = QComboBox()
        self._port_combo.setMinimumWidth(320)
        self._port_combo.setMinimumHeight(38)
        self._port_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self._port_combo.currentIndexChanged.connect(self._on_port_changed)
        port_row.addWidget(self._port_combo, stretch=1)
        rescan = QPushButton("↻")
        rescan.setToolTip("Rescan serial ports")
        rescan.setFixedSize(40, 38)
        rescan.setCursor(Qt.CursorShape.PointingHandCursor)
        rescan.clicked.connect(self._refresh_ports)
        port_row.addWidget(rescan)
        port_row.addSpacing(8)
        self._pair_btn = QPushButton("Pair Token")
        self._pair_btn.setObjectName("btn_primary")
        self._pair_btn.setMinimumWidth(170)
        self._pair_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pair_btn.clicked.connect(self._start_pairing)
        port_row.addWidget(self._pair_btn)
        pl.addLayout(port_row)

        pl.addWidget(_label(
            "Pairing is the only time secrets cross a wire. The token creates its master secret with its "
            "hardware RNG and it never leaves the device. This PC receives an authentication key, stored "
            "encrypted with Windows DPAPI. Key requests then travel over an encrypted, mutually "
            "authenticated BLE channel, so the cable is not needed afterwards.", "subtle"))
        layout.addWidget(pair_card)

        layout.addWidget(self._build_troubleshooting())
        layout.addStretch()
        return page

    def _build_troubleshooting(self) -> QFrame:
        """Collapsed by default: LED meanings, power problems and the factory reset."""
        card, cl = _card(spacing=12)
        toggle = QPushButton("▸  Troubleshooting and the token's light")
        toggle.setObjectName("btn_link")
        toggle.setCheckable(True)
        toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        toggle.setStyleSheet("text-align:left; font-weight:600; color:#adbac7; padding:0;")
        cl.addWidget(toggle)

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 4, 0, 0)
        bl.setSpacing(12)

        bl.addWidget(_section("What the light means"))
        legend = QGridLayout()
        legend.setHorizontalSpacing(24)
        legend.setVerticalSpacing(6)
        for r, (pattern, meaning) in enumerate([
            ("A few blinks, then 2 short flashes", "Ready, waiting to pair"),
            ("A few blinks, then 1 short flash", "Ready, already paired"),
            ("The blinks repeat over and over", "Restarting — not enough power (see below)"),
            ("3 short flashes", "Pairing succeeded"),
            ("2 very fast flashes", "Key request served"),
            ("1 long flash  /  3 long flashes", "Request rejected  /  locked for 30 s"),
            ("10 rapid flashes", "Factory reset — all secrets erased"),
        ]):
            legend.addWidget(_label(pattern, "muted", wrap=False), r, 0)
            legend.addWidget(_label(meaning, "muted"), r, 1)
        legend.setColumnStretch(1, 1)
        bl.addLayout(legend)

        bl.addWidget(_section("If pairing fails"))
        bl.addWidget(_label(
            "• Light keeps repeating its start-up blinks: the USB port is too weak. Use a port on the back "
            "of the PC, a short cable or a powered hub.\n"
            "• \"Port is being used\": close the PlatformIO or Arduino serial monitor, then try again.\n"
            "• Port missing from the list: re-plug the cable; the list updates by itself.", "muted"))

        reset = QLabel(
            "<b>Factory reset:</b> only if the token is bound to another PC or you want to destroy it. Hold "
            "the IO0 button while the token starts up; 10 fast flashes confirm the reset. This destroys the "
            "master secret — <b>every file encrypted with that token becomes permanently unrecoverable.</b> "
            "Do not press IO0 to pair."
        )
        reset.setObjectName("callout_danger")
        reset.setWordWrap(True)
        reset.setTextFormat(Qt.TextFormat.RichText)
        bl.addWidget(reset)

        body.setVisible(False)
        cl.addWidget(body)

        def on_toggle(open_: bool):
            body.setVisible(open_)
            toggle.setText(("▾" if open_ else "▸") + "  Troubleshooting and the token's light")
        toggle.toggled.connect(on_toggle)
        self._trouble_toggle = toggle
        return card

    def _refresh_token_chip(self):
        """Header chip: paired? and, if known, did the token last answer over Bluetooth?"""
        cfg = self._token_cfg
        chip = self._token_chip
        if not cfg:
            chip.setObjectName("chip_off")
            chip.setText("○  No token paired")
            chip.setToolTip("Pair the hardware token on the Token page")
        else:
            fp = token_fingerprint(cfg["token_id"])
            if self._token_reachable is True:
                chip.setObjectName("chip_ok")
                chip.setText(f"●  Connected · {fp}")
                chip.setToolTip("The token answered over Bluetooth this session")
            elif self._token_reachable is False:
                chip.setObjectName("chip_warn")
                chip.setText(f"●  Not in range · {fp}")
                chip.setToolTip("The last attempt could not reach the token over Bluetooth.\n"
                                "Is it powered on and nearby? Click to open the Token page.")
            else:
                chip.setObjectName("chip_idle")
                chip.setText(f"●  Paired · {fp}")
                chip.setToolTip("Paired, not contacted yet this session.\n"
                                "Use Test connection on the Token page to check it is in range.")
        chip.style().unpolish(chip)
        chip.style().polish(chip)

    def _note_token_result(self, ok: bool, msg: str = ""):
        """Record a real token operation's outcome for the header chip."""
        if not ok and TOKEN_UNREACHABLE_HINT not in msg:
            return   # failed for another reason (e.g. wrong environment) — token did answer
        self._token_reachable = ok
        self._refresh_token_chip()

    def _refresh_token_ui(self):
        cfg = self._token_cfg
        self._refresh_token_chip()
        if cfg:
            fp = token_fingerprint(cfg["token_id"])
            self._tok_title.setText(f"✓  Paired with token {fp}")
            self._tok_title.setStyleSheet("font-size:20px; font-weight:600; color:#3fb950;")
            prot = {"dpapi": "Windows DPAPI (bound to your Windows account)",
                    "none": "⚠ Unprotected (non-Windows)"}.get(cfg.get("auth_key_protection"), "?")
            values = {
                "token_id": cfg["token_id"].upper(),
                "ble_mac": cfg.get("ble_mac", "—"),
                "paired_at": cfg.get("paired_at", "—").replace("T", "  ").replace("+00:00", " UTC"),
                "firmware": f"v{cfg.get('firmware', '?')}",
                "protection": prot,
            }
            self._pair_btn.setText("Re-pair Token")
        else:
            self._tok_title.setText("No hardware token paired")
            self._tok_title.setStyleSheet("font-size:20px; font-weight:600; color:#f85149;")
            values = {}
            self._pair_btn.setText("Pair Token")
        for key, lbl in self._tok_fields.items():
            lbl.setText(values.get(key, "—"))
        self._token_chip.style().unpolish(self._token_chip)
        self._token_chip.style().polish(self._token_chip)
        self._update_key_cards()

    def _refresh_ports(self):
        saved = self._settings.value("token/port", "")
        try:
            ports = list_serial_ports()
        except Exception:
            ports = []      # a device mid-reset can make enumeration throw
        self._port_combo.blockSignals(True)
        self._port_combo.clear()
        for dev, desc in ports:
            self._port_combo.addItem(f"{dev}  —  {desc}" if desc != dev else dev, dev)
        if not ports:
            self._port_combo.addItem("No serial ports found — plug in the token", None)
        idx = self._port_combo.findData(saved)
        self._port_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._port_combo.blockSignals(False)
        self._refresh_actions()

    def _poll_ports(self):
        if self._busy or self._tabs.currentIndex() != self.TAB_TOKEN:
            return
        try:
            found = [dev for dev, _ in list_serial_ports()]
        except Exception:
            return      # serial enumeration can throw if a device is mid-reset; just skip
        listed = [self._port_combo.itemData(i) for i in range(self._port_combo.count())]
        if found != [d for d in listed if d]:
            self._refresh_ports()

    def _on_port_changed(self, _i):
        port = self._port_combo.currentData()
        if port:
            self._settings.setValue("token/port", port)
        self._refresh_actions()

    def _start_pairing(self):
        port = self._port_combo.currentData()
        if not port:
            return
        if self._token_cfg and QMessageBox.question(
                self, "Re-pair token",
                "Re-pairing issues a new authentication key. Files you already encrypted with this token "
                "stay decryptable, but the old pairing stops working.\n\nContinue?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self._set_busy(True)
        self._pair_btn.setText("Pairing…")
        self._ping_result.show_info(f"Pairing over {port}…\nThis takes up to 15 seconds.")
        self._status.showMessage(f"Pairing with hardware token via USB ({port})…")
        w = PairWorker(port)
        w.progress.connect(lambda step: self._ping_result.show_info(f"Pairing over {port}…\n{step}"))
        w.done.connect(self._on_pairing_done)
        self._start_worker(w)

    def _on_pairing_done(self, success: bool, msg: str):
        self._set_busy(False)
        self._token_cfg = load_config()
        self._refresh_token_ui()
        if success:
            self._status.showMessage(f"Hardware token paired: {msg}")
            # Confirm the Bluetooth link straight away, so problems show up now and not mid-encrypt
            self._pending_pair_msg = msg
            self._start_ping()
        else:
            self._ping_result.show_error(msg)
            self._status.showMessage("Token pairing failed")
            self._trouble_toggle.setChecked(True)
        self._refresh_actions()

    def _start_ping(self):
        self._set_busy(True)
        self._ping_btn.setText("Testing…")
        if self._pending_pair_msg:
            self._ping_result.show_info(f"{self._pending_pair_msg}\nChecking the Bluetooth link…")
        else:
            self._ping_result.show_info("Connecting over BLE and running the challenge-response handshake…")
        w = PingWorker()
        w.done.connect(self._on_ping_done)
        self._start_worker(w)

    def _on_ping_done(self, ok: bool, msg: str):
        self._set_busy(False)
        self._note_token_result(ok, msg)
        self._ping_btn.setText("Test connection")
        paired_msg, self._pending_pair_msg = self._pending_pair_msg, None
        if paired_msg and ok:
            self._ping_result.show_success(
                f"{paired_msg}\nBluetooth link verified. You can now encrypt and decrypt;\n"
                "the USB cable is no longer needed.")
            self._status.showMessage("Token paired and reachable over Bluetooth")
        elif paired_msg:
            self._ping_result.show_error(
                f"Paired over USB, but the Bluetooth check failed\n{msg}\n\n"
                "Make sure Bluetooth is on and the token is close by, then click Test connection.")
            self._status.showMessage("Token paired, Bluetooth check failed")
        elif ok:
            self._ping_result.show_success(msg)
            self._status.showMessage("Token reachable and authenticated")
        else:
            self._ping_result.show_error(msg)
            self._status.showMessage("Token test failed")

    def _forget_token(self):
        if QMessageBox.question(
                self, "Forget pairing",
                "Delete this PC's token credentials?\n\nThe token keeps its master secret, so you can pair "
                "again later from this PC and your files stay decryptable."
        ) != QMessageBox.StandardButton.Yes:
            return
        forget_pairing()
        self._token_cfg = None
        self._ping_result.clear()
        self._refresh_token_ui()
        self._refresh_actions()
        self._status.showMessage("Token pairing removed from this PC")

    # ─────────────────────────────────────────────────────────────
    #  TAB 5 — INSPECTOR
    # ─────────────────────────────────────────────────────────────

    def _build_inspector_tab(self) -> QWidget:
        page, layout = _page(scroll=False, max_width=1400)

        layout.addWidget(_label(
            "Selected signals are hashed together on this PC and only the hash is sent to the token, "
            "which mixes in its master secret (HMAC-SHA256). Raw values never leave this machine.", "muted"))

        bar = QHBoxLayout()
        self._inspector_redact = QCheckBox("Hide sensitive values (safe for screenshots)")
        self._inspector_redact.setObjectName("mode_check")
        self._inspector_redact.setToolTip(
            "Mask the raw signal values (disk serial, machine GUID, SID, …) so this page can be "
            "screenshotted for a report without exposing this machine's real identifiers.")
        self._inspector_redact.toggled.connect(lambda _on: self._populate_inspector())
        bar.addWidget(self._inspector_redact)
        bar.addStretch()
        layout.addLayout(bar)

        self._inspector_table = QTableWidget()
        self._inspector_table.setColumnCount(6)
        self._inspector_table.setHorizontalHeaderLabels(
            ["In key", "ID", "Signal", "Category", "Stability", "Value / error"]
        )
        self._inspector_table.verticalHeader().setVisible(False)
        self._inspector_table.verticalHeader().setDefaultSectionSize(34)
        self._inspector_table.setShowGrid(False)
        self._inspector_table.setAlternatingRowColors(True)
        self._inspector_table.setWordWrap(False)
        self._inspector_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._inspector_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        hdr = self._inspector_table.horizontalHeader()
        hdr.setHighlightSections(False)
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        for col in range(5):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self._inspector_table, stretch=1)
        return page

    @staticmethod
    def _redact_value(value: str) -> str:
        """Mask an identifier for safe screenshots: keep a hint of shape, hide the rest."""
        v = value or ""
        if len(v) <= 6:
            return "•" * max(4, len(v))
        return f"{v[:2]}{'•' * 6}{v[-2:]}"

    def _populate_inspector(self):
        redact = getattr(self, "_inspector_redact", None) and self._inspector_redact.isChecked()
        self._inspector_table.setRowCount(0)
        for sig in self._all_signals:
            row = self._inspector_table.rowCount()
            self._inspector_table.insertRow(row)
            if not sig.available:
                shown_value = f"[N/A]  {sig.error or ''}"
            elif redact:
                shown_value = self._redact_value(sig.value)
            else:
                shown_value = sig.value
            items = [
                "✓" if sig.id in self._selected_ids else "",
                sig.id,
                sig.name,
                sig.category,
                f"{sig.stability}/10",
                shown_value,
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(str(text))
                if col == 0:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    item.setForeground(QColor("#58a6ff"))
                elif not sig.available:
                    item.setForeground(QColor("#484f58"))
                elif col == 5:
                    item.setForeground(QColor("#3fb950"))
                self._inspector_table.setItem(row, col, item)

    # ─────────────────────────────────────────────────────────────
    #  TAB 6 — ENV VAULT
    # ─────────────────────────────────────────────────────────────

    def _vault_default_path(self) -> str:
        saved = self._settings.value("vault/path", "")
        if saved:
            return saved
        return os.path.join(os.path.expanduser("~"), "EnvVault")

    def _build_vault_tab(self) -> QWidget:
        page, layout = _page()

        layout.addWidget(_label(
            "An encrypted store bound to the token + this PC — it locks itself when the token "
            "goes out of range.", "muted"))

        # — status / location card —
        card, cl = _card(spacing=10)
        cl.addWidget(_section("Vault"))
        self._vault_status = QLabel()
        self._vault_status.setStyleSheet("font-size:16px; font-weight:600;")
        cl.addWidget(self._vault_status)
        loc = QHBoxLayout()
        loc.addWidget(_label("Location:", "subtle"))
        self._vault_loc = QLabel(self._vault_default_path())
        self._vault_loc.setObjectName("mono")
        self._vault_loc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        loc.addWidget(self._vault_loc)
        loc.addStretch()
        self._vault_change_loc = QPushButton("Change…")
        self._vault_change_loc.setCursor(Qt.CursorShape.PointingHandCursor)
        self._vault_change_loc.clicked.connect(self._vault_choose_location)
        loc.addWidget(self._vault_change_loc)
        cl.addLayout(loc)
        layout.addWidget(card)

        # — "how it works" panel (shown only before a vault exists, so the empty
        #    page is not a bare button and a new user understands the feature) —
        self._vault_howto, hl = _card(spacing=8)
        hl.addWidget(_section("How the vault works"))
        for icon, text in [
            ("📥", "Add any file — it is encrypted into the vault and the original is securely shredded."),
            ("🔑", "The key is bound to this token + this PC. A copied disk, or the wrong "
                   "environment, cannot open it."),
            ("👁", "Open files right here while unlocked — the plaintext stays in memory only. "
                   "The vault auto-locks when the token goes out of range."),
        ]:
            row = QHBoxLayout()
            row.setSpacing(10)
            ic = QLabel(icon)
            ic.setStyleSheet("font-size:16px;")
            ic.setFixedWidth(24)
            ic.setAlignment(Qt.AlignmentFlag.AlignTop)
            row.addWidget(ic)
            row.addWidget(_label(text, "muted"), stretch=1)
            hl.addLayout(row)
        hl.addWidget(_label("Use the vault for files you keep and reopen on this PC. Use Encrypt & "
                            "hide instead to tuck a single file inside a PNG or WAV to share.", "subtle"))
        layout.addWidget(self._vault_howto)

        # — action bar (changes with state) —
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self._vault_create_btn = QPushButton("Create Env Vault")
        self._vault_create_btn.setObjectName("btn_primary")
        self._vault_create_btn.clicked.connect(self._vault_create)
        self._vault_unlock_btn = QPushButton("Unlock")
        self._vault_unlock_btn.setObjectName("btn_primary")
        self._vault_unlock_btn.clicked.connect(self._vault_unlock)
        self._vault_recovery_btn = QPushButton("Unlock with recovery code")
        self._vault_recovery_btn.clicked.connect(self._vault_unlock_recovery)
        self._vault_lock_btn = QPushButton("Lock now")
        self._vault_lock_btn.setObjectName("btn_danger")
        self._vault_lock_btn.setToolTip("Lock the vault now  (Ctrl+Shift+L from anywhere)")
        self._vault_lock_btn.clicked.connect(lambda: self._vault_do_lock("Locked."))
        for b in (self._vault_create_btn, self._vault_unlock_btn,
                  self._vault_recovery_btn, self._vault_lock_btn):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            actions.addWidget(b)
        actions.addStretch()
        self._vault_add_btn = QPushButton("Add files…")
        self._vault_add_btn.clicked.connect(self._vault_add_files)
        self._vault_open_btn = QPushButton("Open")
        self._vault_open_btn.clicked.connect(self._vault_open_selected)
        self._vault_export_btn = QPushButton("Export…")
        self._vault_export_btn.clicked.connect(self._vault_export_selected)
        self._vault_remove_btn = QPushButton("Remove")
        self._vault_remove_btn.setObjectName("btn_danger")
        self._vault_remove_btn.clicked.connect(self._vault_remove_selected)
        for b in (self._vault_add_btn, self._vault_open_btn,
                  self._vault_export_btn, self._vault_remove_btn):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            actions.addWidget(b)
        layout.addLayout(actions)

        self._vault_result = StatusPanel()
        layout.addWidget(self._vault_result)

        # — file table (visible only when unlocked) —
        self._vault_table = _VaultDropTable()
        self._vault_table.filesDropped.connect(self._vault_add_files)
        self._vault_table.setColumnCount(3)
        self._vault_table.setHorizontalHeaderLabels(["Name", "Size", "Added"])
        self._vault_table.verticalHeader().setVisible(False)
        self._vault_table.setShowGrid(False)
        self._vault_table.setAlternatingRowColors(True)
        self._vault_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._vault_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._vault_table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self._vault_table.doubleClicked.connect(lambda *_: self._vault_open_selected())
        hdr = self._vault_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._vault_table, stretch=1)
        layout.addStretch()

        # heartbeat timer for auto-lock (started only while unlocked)
        self._vault_timer = QTimer(self)
        self._vault_timer.setInterval(25_000)
        self._vault_timer.timeout.connect(self._vault_heartbeat_tick)
        return page

    # -- state / rendering ----------------------------------------------------
    def _refresh_vault_ui(self):
        if not getattr(self, "_ui_ready", False):
            return
        path = self._vault_loc.text()
        unlocked = self._vault is not None
        exists = V.is_vault(path)
        idle = not self._busy and not self._collecting

        self._vault_create_btn.setVisible(not exists and not unlocked)
        self._vault_create_btn.setEnabled(idle and bool(self._token_cfg) and bool(self._selected_ids))
        self._vault_unlock_btn.setVisible(exists and not unlocked)
        self._vault_unlock_btn.setEnabled(idle and bool(self._token_cfg))
        self._vault_recovery_btn.setVisible(exists and not unlocked)
        self._vault_lock_btn.setVisible(unlocked)
        self._vault_howto.setVisible(not exists and not unlocked)
        self._vault_change_loc.setEnabled(not unlocked and idle)
        for b in (self._vault_add_btn, self._vault_open_btn,
                  self._vault_export_btn, self._vault_remove_btn):
            b.setVisible(unlocked)
            b.setEnabled(unlocked and idle)
        self._vault_table.setVisible(unlocked)

        if unlocked:
            reach = {True: "token in range", False: "⚠ token not answering",
                     None: "token not checked yet"}[self._token_reachable]
            self._vault_status.setText(
                f"🔓 Unlocked · {self._vault.count()} item(s) · "
                f"{self._vault.total_bytes():,} bytes · auto-lock on ({reach})")
            self._vault_status.setStyleSheet("font-size:16px; font-weight:600; color:#3fb950;")
        elif exists:
            self._vault_status.setText("🔒 Locked")
            self._vault_status.setStyleSheet("font-size:16px; font-weight:600; color:#adbac7;")
        else:
            self._vault_status.setText("No vault here yet")
            self._vault_status.setStyleSheet("font-size:16px; font-weight:600; color:#8b949e;")
            # Explain exactly what is still needed before "Create" becomes available.
            if not self._token_cfg:
                self._vault_result.show_info("Pair a token on the Token page, then pick signals on the "
                                             "Signals page, before creating a vault.")
            elif not self._selected_ids:
                self._vault_result.show_info("Pick the environment signals to bind this vault to on the "
                                             "Signals page (or click ✨ Recommended), then create it.")
            else:
                self._vault_result.clear()

    def _populate_vault_table(self):
        self._vault_table.setRowCount(0)
        if self._vault is None:
            return
        for e in self._vault.list_entries():
            r = self._vault_table.rowCount()
            self._vault_table.insertRow(r)
            name_item = QTableWidgetItem(e["name"])
            name_item.setData(Qt.ItemDataRole.UserRole, e["blob"])
            size = e["size"]
            size_txt = f"{size:,} B" if size < 1024 else (f"{size/1024:.1f} KB" if size < 2**20
                                                           else f"{size/2**20:.1f} MB")
            added = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("added", 0)))
            for c, item in enumerate((name_item, QTableWidgetItem(size_txt), QTableWidgetItem(added))):
                self._vault_table.setItem(r, c, item)

    def _selected_vault_blobs(self) -> list[str]:
        rows = {ix.row() for ix in self._vault_table.selectedIndexes()}
        return [self._vault_table.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in sorted(rows)]

    # -- location -------------------------------------------------------------
    def _vault_choose_location(self):
        start = self._vault_loc.text() or os.path.expanduser("~")
        path = QFileDialog.getExistingDirectory(self, "Choose or create a vault folder", start)
        if path:
            self._vault_loc.setText(os.path.normpath(path))
            self._settings.setValue("vault/path", self._vault_loc.text())
            self._vault_result.clear()
            self._refresh_vault_ui()

    # -- create ---------------------------------------------------------------
    def _vault_create(self):
        path = self._vault_loc.text()
        if os.path.isdir(path) and os.listdir(path):
            self._vault_result.show_error("Pick an empty folder (or a new one) for the vault.")
            return
        self._set_busy(True)
        self._vault_result.show_info("Creating vault and sealing its key with the token…")
        w = VaultCreateWorker(path, self._selected_ids)
        w.done.connect(self._on_vault_created)
        w.error.connect(self._on_vault_error)
        self._start_worker(w)

    def _on_vault_error(self, msg: str):
        self._set_busy(False)
        self._note_token_result(False, msg)
        self._vault_result.show_error(msg)
        self._refresh_vault_ui()

    def _on_vault_created(self, v, code: str):
        self._set_busy(False)
        self._vault = v
        self._note_token_result(True)
        self._settings.setValue("vault/path", self._vault_loc.text())
        self._show_recovery_code(code)
        self._populate_vault_table()
        self._start_vault_heartbeat()
        self._vault_result.show_success("Vault created and unlocked. Keep the recovery code safe.")
        self._refresh_vault_ui()

    def _show_recovery_code(self, code: str):
        box = QMessageBox(self)
        box.setWindowTitle("Recovery code — write this down now")
        box.setIcon(QMessageBox.Icon.Warning)
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(
            "This is the <b>only</b> way to open the vault if the token is lost or the "
            "environment changes permanently.<br><br>"
            f"<div style='font-family:Consolas,monospace; font-size:16px; color:#3fb950;'>{code}</div>"
            "<br>It is <b>not stored anywhere</b> in readable form. Save it somewhere safe and offline.")
        copy = box.addButton("Copy", QMessageBox.ButtonRole.ActionRole)
        box.addButton("I've saved it", QMessageBox.ButtonRole.AcceptRole)
        box.exec()
        if box.clickedButton() is copy:
            QApplication.clipboard().setText(code)

    # -- unlock ---------------------------------------------------------------
    def _vault_unlock(self):
        self._set_busy(True)
        self._vault_result.show_info("Reading the vault's signal list, collecting them and asking the token…")
        w = VaultUnlockWorker(self._vault_loc.text())
        w.done.connect(self._on_vault_unlocked)
        w.error.connect(self._on_vault_unlock_error)
        self._start_worker(w)

    def _on_vault_unlocked(self, v, sig_ids: list, fp: str):
        self._set_busy(False)
        self._vault = v
        self._vault_sig_ids = sig_ids
        self._note_token_result(True)
        self._populate_vault_table()
        self._start_vault_heartbeat()
        self._vault_result.show_success(
            f"Vault unlocked · key fingerprint {fp} · {v.count()} item(s).")
        self._refresh_vault_ui()

    def _on_vault_unlock_error(self, msg: str):
        self._set_busy(False)
        self._note_token_result(False, msg)
        self._vault_result.show_error(msg)
        self._refresh_vault_ui()

    def _vault_unlock_recovery(self):
        code, ok = QInputDialog.getText(self, "Unlock with recovery code",
                                        "Enter the recovery code shown when the vault was created:")
        if not ok or not code.strip():
            return
        try:
            self._vault = V.unlock_recovery(self._vault_loc.text(), code)
        except Exception:
            self._vault_result.show_error("That recovery code did not open the vault.")
            return
        self._vault_sig_ids = []
        self._populate_vault_table()
        self._start_vault_heartbeat()
        self._vault_result.show_success(
            "Vault unlocked with the recovery code. Tip: re-bind it to this environment "
            "below so the token can open it normally again.")
        self._refresh_vault_ui()

    # -- lock / auto-lock -----------------------------------------------------
    def _panic_lock(self):
        """Lock the vault immediately (Ctrl+Shift+L), from any page."""
        if self._vault is not None:
            self._vault_do_lock("Locked (panic).")
            self._status.showMessage("Vault locked.")

    def _vault_do_lock(self, reason: str):
        if self._vault is None:
            return
        self._vault_timer.stop()
        self._vault.lock()
        self._vault = None
        self._vault_table.setRowCount(0)
        self._vault_result.show_info(reason)
        self._refresh_vault_ui()

    def _start_vault_heartbeat(self):
        self._vault_timer.start()

    def _vault_heartbeat_tick(self):
        if self._vault is None or self._busy:
            return
        w = VaultHeartbeatWorker()
        w.result.connect(self._on_vault_heartbeat)
        self._start_worker(w)

    def _on_vault_heartbeat(self, ok: bool, msg: str):
        self._note_token_result(ok, msg)
        if not ok and self._vault is not None:
            self._vault_do_lock("Auto-locked — the token went out of range. "
                                "Unlock again when it is back.")

    # -- file operations ------------------------------------------------------
    def _vault_add_files(self, paths=None):
        if self._vault is None:
            return
        # A list comes from a drag-and-drop onto the table; the button passes a bool.
        if not isinstance(paths, list):
            paths, _ = QFileDialog.getOpenFileNames(self, "Add files to the vault", FilePicker.last_dir)
        paths = [p for p in paths if os.path.isfile(p)]      # ignore dropped folders
        if not paths:
            return
        shred = QMessageBox.question(
            self, "Shred originals?",
            f"Add {len(paths)} file(s) to the vault and securely delete the originals?\n\n"
            "Choose No to keep the originals in place.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes

        big = sum(os.path.getsize(p) for p in paths if os.path.isfile(p)) > 256 * 2**20
        self._set_busy(True)
        self._vault_result.show_info(
            "Encrypting into the vault…" + ("  (large file — this can take a moment)" if big else ""))
        vault, keep = self._vault, not shred

        def work():
            n = 0
            for p in paths:
                vault.add_file(p, shred_original=not keep)
                n += 1
            return n

        w = VaultTaskWorker(work)
        w.done.connect(lambda n: self._on_vault_added(n, shred))
        w.error.connect(self._on_vault_task_error)
        self._start_worker(w)

    def _on_vault_added(self, n, shred):
        self._set_busy(False)
        self._populate_vault_table()
        self._vault_result.show_success(
            f"Added {n} file(s)." + (" Originals shredded." if shred else ""))
        self._refresh_vault_ui()

    def _on_vault_task_error(self, msg):
        self._set_busy(False)
        self._populate_vault_table()
        self._vault_result.show_error(msg)
        self._refresh_vault_ui()

    def _vault_open_selected(self):
        if self._vault is None:
            return
        blobs = self._selected_vault_blobs()
        if not blobs:
            self._vault_result.show_info("Select an item to open.")
            return
        vault, blob = self._vault, blobs[0]
        self._set_busy(True)
        self._vault_result.show_info("Decrypting in memory…")
        w = VaultTaskWorker(lambda: vault.read_bytes(blob))
        w.done.connect(self._on_vault_opened)
        w.error.connect(self._on_vault_task_error)
        self._start_worker(w)

    def _on_vault_opened(self, result):
        self._set_busy(False)
        self._vault_result.clear()
        name, data = result
        VaultViewer(name, data, self).exec()

    def _vault_export_selected(self):
        if self._vault is None:
            return
        blobs = self._selected_vault_blobs()
        if not blobs:
            self._vault_result.show_info("Select item(s) to export.")
            return
        if QMessageBox.warning(
                self, "Export decrypted copy",
                f"Write {len(blobs)} decrypted file(s) to a folder?\n\n"
                "These are plaintext copies on disk, outside the vault's protection.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        dest = QFileDialog.getExistingDirectory(self, "Export to folder", downloads_dir())
        if not dest:
            return
        vault = self._vault
        self._set_busy(True)
        self._vault_result.show_info("Exporting decrypted copies…")

        def work():
            for b in blobs:
                vault.export(b, dest)
            return len(blobs), dest

        w = VaultTaskWorker(work)
        w.done.connect(lambda r: self._on_vault_exported(*r))
        w.error.connect(self._on_vault_task_error)
        self._start_worker(w)

    def _on_vault_exported(self, n, dest):
        self._set_busy(False)
        self._vault_result.show_success(f"Exported {n} file(s) to {dest}")

    def _vault_remove_selected(self):
        if self._vault is None:
            return
        blobs = self._selected_vault_blobs()
        if not blobs:
            return
        if QMessageBox.warning(
                self, "Remove from vault",
                f"Permanently shred and remove {len(blobs)} item(s) from the vault?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        for b in blobs:
            try:
                self._vault.remove(b)
            except Exception as e:
                self._vault_result.show_error(f"Could not remove item: {e}")
                break
        self._populate_vault_table()
        self._vault_result.show_success("Removed.")
        self._refresh_vault_ui()

    # ─────────────────────────────────────────────────────────────
    #  SIGNAL COLLECTION
    # ─────────────────────────────────────────────────────────────

    def _start_collection(self):
        self._collecting = True
        self._refresh_btn.setText("↻  Scanning…")
        self._status.showMessage("Profiling environment — please wait…")
        self._refresh_actions()

        w = CollectWorker()
        w.done.connect(self._on_signals_collected)
        self._start_worker(w)

    def _on_signals_collected(self, signals: list[EnvSignal]):
        self._collecting = False
        self._all_signals = signals
        self._loading_lbl.hide()
        self._populate_signal_rows(signals)
        self._populate_inspector()
        self._refresh_btn.setText("↻  Refresh signals")

        # On a first run with no saved selection, start from the Recommended preset.
        if not self._did_default_preset:
            self._did_default_preset = True
            idx = self._preset_combo.findData("builtin:Recommended")
            if idx >= 0:
                self._preset_combo.setCurrentIndex(idx)
                self._on_preset_chosen(idx)

        available_count = sum(1 for s in signals if s.available)
        self._status.showMessage(
            f"Environment profiled — {available_count}/{len(signals)} signals available"
        )
        self._refresh_actions()

    # ─────────────────────────────────────────────────────────────
    #  BUTTON STATE
    # ─────────────────────────────────────────────────────────────

    def _set_busy(self, busy: bool):
        """Only one token operation runs at a time, so every token action is locked while busy."""
        self._busy = busy
        self._refresh_actions()

    def _refresh_actions(self, *_):
        if not self._ui_ready:
            return
        idle = not self._busy and not self._collecting
        paired = self._token_cfg is not None
        active, missing = self._selection_breakdown()

        enc_block = self._encrypt_blockers()
        dec_block = self._decrypt_blockers()
        self._enc_btn.setEnabled(idle and not enc_block)
        self._dec_btn.setEnabled(idle and not dec_block)
        if self._collecting:
            self._enc_hint.setText("Reading environment signals…")
            self._dec_hint.setText("Reading environment signals…")
        else:
            self._enc_hint.setText("To encrypt: " + " · ".join(enc_block) if enc_block else "")
            self._dec_hint.setText("To decrypt: " + " · ".join(dec_block) if dec_block else "")

        self._test_btn.setEnabled(idle and paired and bool(active) and not missing)
        self._test_btn.setToolTip(
            "Ask the token for the key from the selected signals and show its fingerprint.\n"
            "Run it twice to confirm the environment is stable."
            if paired else "Pair a hardware token first (Token page)"
        )
        # Presets resolve against the collected signals, so wait for the scan
        self._preset_combo.setEnabled(not self._collecting)
        self._clear_sel_btn.setEnabled(bool(self._selected_ids))
        self._preset_save_btn.setEnabled(bool(self._selected_ids))
        self._refresh_btn.setEnabled(idle)
        # Token management does not depend on the signal scan
        self._pair_btn.setEnabled(not self._busy and self._port_combo.currentData() is not None)
        self._ping_btn.setEnabled(not self._busy and paired)
        self._forget_btn.setEnabled(not self._busy and paired)
        self._populate_inspector_marks()
        self._refresh_vault_ui()
        self._refresh_nav(enc_block, dec_block)

    def _populate_inspector_marks(self):
        for row in range(self._inspector_table.rowCount()):
            id_item = self._inspector_table.item(row, 1)
            mark = self._inspector_table.item(row, 0)
            if id_item and mark:
                mark.setText("✓" if id_item.text() in self._selected_ids else "")

    def _refresh_nav(self, enc_block: list[str], dec_block: list[str]):
        """Live one-line status under each sidebar entry, so prerequisites are visible everywhere."""
        cfg = self._token_cfg
        self._nav[self.TAB_TOKEN].set_status(
            f"Paired · {token_fingerprint(cfg['token_id'])}" if cfg else "Not paired",
            "ok" if cfg else "bad")

        active, missing = self._selection_breakdown()
        if self._collecting and not self._all_signals:
            sig = ("Scanning…", "muted")
        elif missing:
            sig = (f"{len(active)} selected · {len(missing)} unreadable", "warn")
        elif active:
            sig = (f"{len(active)} selected · {estimate_entropy_bits(active)} bits", "ok")
        else:
            sig = ("None selected", "warn")
        self._nav[self.TAB_SIGNALS].set_status(*sig)

        # Encrypt / Decrypt / Vault show the title only (no status line).
        for index in (self.TAB_ENCRYPT, self.TAB_DECRYPT, self.TAB_VAULT):
            self._nav[index].set_status("")

        if self._all_signals:
            readable = sum(1 for s in self._all_signals if s.available)
            self._nav[self.TAB_INSPECTOR].set_status(f"{readable}/{len(self._all_signals)} readable")
        else:
            self._nav[self.TAB_INSPECTOR].set_status("Scanning…")

    def _update_key_cards(self):
        if not self._ui_ready:
            return
        active, missing = self._selection_breakdown()
        if not self._all_signals and self._selected_ids:
            sig_txt = f"<b>{len(self._selected_ids)}</b> signals selected"
        elif active:
            sig_txt = f"<b>{len(active)}</b> signal{'s' if len(active) != 1 else ''}"
            if self._active_preset:
                sig_txt += f" · preset <b>{self._active_preset.partition(':')[2]}</b>"
            if missing:
                sig_txt += f" <span style='color:#d29922'>· ⚠ {len(missing)} unreadable</span>"
        else:
            sig_txt = "<span style='color:#d29922'>No signals selected</span>"
        if self._token_cfg:
            tok_txt = f"token <b>{token_fingerprint(self._token_cfg['token_id'])}</b>"
        else:
            tok_txt = "<span style='color:#f85149'>no token paired</span>"
        plus = "&nbsp;<span style='color:#6e7681'>+</span>&nbsp;"
        self._enc_key_lbl.setText(f"{sig_txt} {plus} {tok_txt}")
        # Decrypt does not use the page selection: current images carry their own
        # (encrypted) signal list, read from the header with the token's help.
        self._dec_key_lbl.setText(
            f"signals <b>read from the image</b> {plus} {tok_txt} {plus} "
            f"<span style='color:#8b949e'>this PC's live values</span>")
