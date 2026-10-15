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
import tempfile
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget, QLabel,
    QPushButton, QCheckBox, QProgressBar, QFileDialog, QTextEdit, QButtonGroup,
    QScrollArea, QFrame, QTableWidget, QTableWidgetItem, QLineEdit, QStatusBar,
    QGridLayout, QHeaderView, QMessageBox, QComboBox, QInputDialog, QToolButton,
    QApplication,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QUrl, QPointF, QTimer
from PyQt6.QtGui import QColor, QDesktopServices, QPainter, QPainterPath, QPen, QPixmap

from signals import EnvSignal, collect_all_signals
from crypto_engine import (
    derive_env_key, encrypt_payload, decrypt_payload, estimate_entropy_bits,
    pack_payload, unpack_payload, packed_size,
)
from stego_engine import embed, extract, get_image_info, MAGIC
from cryptography.exceptions import InvalidTag
from token_comms import (
    pair_token_usb, ping_token, load_config, forget_pairing, list_serial_ports,
    token_fingerprint, TokenError,
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


def _runtime_style() -> str:
    """
    Stylesheet rules that need images: the check-box tick and the combo-box arrow.
    Styling those controls removes Qt's built-in glyphs, so small PNGs are drawn
    here (needs a running QApplication) and referenced by file path.
    """
    folder = Path(tempfile.gettempdir()) / "envstego_ui"
    folder.mkdir(exist_ok=True)

    def draw(name: str, w: int, h: int, color: str, points: list[tuple[float, float]], width: float):
        for scale, suffix in ((1, ""), (2, "@2x")):
            pm = QPixmap(w * scale, h * scale)
            pm.fill(Qt.GlobalColor.transparent)
            p = QPainter(pm)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            pen = QPen(QColor(color), width * scale)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            p.setPen(pen)
            path = QPainterPath(QPointF(points[0][0] * scale, points[0][1] * scale))
            for x, y in points[1:]:
                path.lineTo(QPointF(x * scale, y * scale))
            p.drawPath(path)
            p.end()
            pm.save(str(folder / f"{name}{suffix}.png"))
        return (folder / f"{name}.png").as_posix()

    tick = draw("tick", 16, 16, "#ffffff", [(4, 8.5), (7, 11.5), (12.5, 5)], 2.0)
    arrow = draw("arrow", 12, 8, "#8b949e", [(2, 2), (6, 6), (10, 2)], 1.6)
    return (
        f"QCheckBox::indicator:checked {{ image: url({tick}); }}\n"
        f"QComboBox::down-arrow {{ image: url({arrow}); width: 12px; height: 8px; }}\n"
    )


# ─── PRESETS ─────────────────────────────────────────────────────────────────

def _stable_identity(s: EnvSignal) -> bool:
    return s.category in ("Hardware", "OS") and s.stability >= 8


BUILTIN_PRESETS = [
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
    done  = pyqtSignal(str)
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
            self.done.emit(fp)
        except Exception as e:
            self.error.emit(str(e))


class EncryptWorker(QThread):
    done  = pyqtSignal(str, str, str)
    error = pyqtSignal(str)

    def __init__(self, selected_ids, carrier, payload_path, output_path):
        super().__init__()
        self._selected_ids = set(selected_ids)
        self._carrier      = carrier
        self._payload      = payload_path
        self._output       = output_path

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

            with open(self._payload, "rb") as f:
                plaintext = f.read()

            env_key, fp = derive_env_key(selected)
            salt, nonce, ct = encrypt_payload(pack_payload(self._payload, plaintext), env_key, MAGIC)
            out_path = embed(self._carrier, salt, nonce, ct, self._output)

            self.done.emit(
                f"Payload embedded successfully\n"
                f"  Signals used:  {len(selected)} (collected live at encrypt time)\n"
                f"  Payload:       {Path(self._payload).name}  ({len(plaintext):,} bytes)\n"
                f"  Encrypted to:  {len(ct):,} bytes  (AES-256-GCM, per-file HKDF salt)\n"
                f"  Carrier:       {Path(self._carrier).name}\n"
                f"  Output:        {out_path}",
                fp,
                out_path
            )
        except Exception as e:
            self.error.emit(str(e))


def _unique_path(folder: str, name: str) -> Path:
    p = Path(folder) / name
    i = 1
    while p.exists():
        p = Path(folder) / f"{Path(name).stem} ({i}){Path(name).suffix}"
        i += 1
    return p


class DecryptWorker(QThread):
    done  = pyqtSignal(str, str, str, bytes)
    error = pyqtSignal(str)

    def __init__(self, selected_ids, stego_path, output_dir):
        super().__init__()
        self._selected_ids = set(selected_ids)
        self._stego        = stego_path
        self._output_dir   = output_dir

    def run(self):
        try:
            # Parse the image first so a wrong file fails before contacting the token
            salt, nonce, ct = extract(self._stego)

            selected, missing = _resolve_selection(self._selected_ids)
            if missing:
                self.error.emit(
                    "Environment mismatch — these selected signals cannot be read here:\n  "
                    + "\n  ".join(s.name for s in missing)
                    + "\n\nThe key cannot be rebuilt without them (forensic defense active)."
                )
                return

            env_key, fp = derive_env_key(selected)
            name, data = unpack_payload(decrypt_payload(salt, nonce, ct, env_key, MAGIC))

            out_dir = self._output_dir or str(Path(self._stego).parent)
            out_path = _unique_path(out_dir, name)
            with open(out_path, "wb") as f:
                f.write(data)

            self.done.emit(
                f"Payload extracted and decrypted\n"
                f"  Signals used: {len(selected)} (collected live at decrypt time)\n"
                f"  Recovered:    {name}  ({len(data):,} bytes)\n"
                f"  Saved to:     {out_path}",
                fp,
                str(out_path),
                data
            )
        except InvalidTag:
            self.error.emit(
                "Decryption failed — Authentication tag mismatch\n\n"
                "The key rebuilt here does not match the one used during encryption:\n"
                "  • Different signal selection  →  check the Signals page / preset\n"
                "  • Different network   →  BSSID/gateway signals changed\n"
                "  • Different machine   →  hardware serials changed\n"
                "  • Different token     →  token reset or another token paired\n"
                "  • Forensic lab/clone  →  no live environment signals\n\n"
                "The payload is mathematically unrecoverable in this environment."
            )
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
                 placeholder: str = "Select or drop a file…", parent=None, step: int | None = None):
        super().__init__(parent)
        self._mode   = mode
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
        outer.addLayout(row)

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


class SignalRow(QWidget):
    toggled = pyqtSignal(str, bool)

    def __init__(self, signal: EnvSignal, selected: bool, parent=None):
        super().__init__(parent)
        self._signal = signal
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
        info.addWidget(name_lbl)
        info.addWidget(desc_lbl)
        layout.addLayout(info, stretch=4)

        stab_col = QVBoxLayout()
        stab_col.setSpacing(4)
        s = self._signal.stability
        stab_lbl = QLabel(f"Stability {s}/10")
        stab_lbl.setObjectName("subtle")
        stab_bar = QProgressBar()
        stab_bar.setFixedWidth(96)
        stab_bar.setFixedHeight(6)
        stab_bar.setTextVisible(False)
        stab_bar.setValue(s * 10)
        stab_bar.setObjectName("stab_high" if s >= 8 else ("stab_med" if s >= 6 else "stab_low"))
        stab_col.addWidget(stab_lbl)
        stab_col.addWidget(stab_bar)
        layout.addLayout(stab_col)

        self._badge = QLabel()
        self._badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._badge.setFixedWidth(88)
        layout.addWidget(self._badge)

        sig = self._signal
        self._cb.setEnabled(self.readable)
        if self.readable:
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
        if self.readable and e.button() == Qt.MouseButton.LeftButton:
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

        col = QVBoxLayout()
        col.setSpacing(1)
        col.setContentsMargins(0, 0, 0, 0)
        self._title = QLabel(title)
        self._title.setObjectName("nav_title")
        self._sub = QLabel("")
        self._sub.setObjectName("nav_sub")
        col.addWidget(self._title)
        col.addWidget(self._sub)
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
        if self._sub.property("tone") != tone:
            self._sub.setProperty("tone", tone)
            self._repolish(self._sub)


# ─── MAIN WINDOW ─────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    TAB_SIGNALS, TAB_ENCRYPT, TAB_DECRYPT, TAB_TOKEN, TAB_INSPECTOR = range(5)

    # Page titles shown in the top bar, keyed by page index
    PAGE_INFO = {
        TAB_SIGNALS:   ("Environment signals",
                        "Choose what the key is bound to. The same signals must be readable when you decrypt."),
        TAB_ENCRYPT:   ("Encrypt & hide",
                        "Encrypt a file with your environment key and hide it inside a PNG image."),
        TAB_DECRYPT:   ("Decrypt & extract",
                        "Recover a hidden file. Needs the same signals and the same token used to encrypt."),
        TAB_TOKEN:     ("Hardware token",
                        "Pair, test and manage the 3T token that holds the master secret."),
        TAB_INSPECTOR: ("Signal inspector",
                        "Raw values read from this machine, and which ones feed the key."),
    }
    # Sidebar layout: (group, [(page index, label)]) in workflow order
    NAV_LAYOUT = [
        ("SETUP",       [(TAB_TOKEN, "Token"), (TAB_SIGNALS, "Signals")]),
        ("PROTECT",     [(TAB_ENCRYPT, "Encrypt"), (TAB_DECRYPT, "Decrypt")]),
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

        self._settings = QSettings("SIT-ICT3215", "EnvStego")
        self._all_signals: list[EnvSignal] = []
        self._signal_rows: list[SignalRow] = []
        self._selected_ids: set[str] = set(self._load_json("signals/selected", []))
        self._user_presets: dict[str, list[str]] = self._load_json("signals/presets", {})
        self._active_preset: str | None = self._settings.value("signals/active_preset", "") or None
        self._token_cfg = load_config()
        self._workers: set[QThread] = set()
        self._busy = False
        self._collecting = False
        self._last_test: tuple[frozenset, str] | None = None
        self._enc_output_auto = False
        self._enc_capacity_ok = False
        self._pending_pair_msg: str | None = None

        self._ui_ready = False
        self._build_ui()
        self._ui_ready = True
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

    def _load_json(self, key, default):
        try:
            return json.loads(self._settings.value(key, ""))
        except (TypeError, ValueError):
            return default

    def _save_json(self, key, value):
        self._settings.setValue(key, json.dumps(value))

    def _restore_state(self):
        geo = self._settings.value("window/geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        for picker, key in self._persisted_pickers():
            path = self._settings.value(key, "")
            if path and (os.path.exists(path) or picker._mode == "save"):
                picker.set_path(path)
        self._enc_output_auto = self._settings.value("enc/output_auto", False, type=bool)
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

    def closeEvent(self, event):
        self._settings.setValue("window/geometry", self.saveGeometry())
        self._settings.setValue("window/tab", self._tabs.currentIndex())
        for picker, key in self._persisted_pickers():
            self._settings.setValue(key, picker.path())
        self._settings.setValue("enc/output_auto", self._enc_output_auto)
        self._settings.setValue("files/last_dir", FilePicker.last_dir)
        for w in list(self._workers):
            w.wait(5000)
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
                btn.clicked.connect(lambda _=False, i=index: self._tabs.setCurrentIndex(i))
                self._nav_group.addButton(btn)
                self._nav[index] = btn
                lay.addWidget(btn)
            lay.addSpacing(16)

        lay.addStretch()
        foot = QLabel("ICT3215 Digital Forensics · SIT")
        foot.setObjectName("sidebar_foot")
        foot.setContentsMargins(12, 0, 0, 0)
        lay.addWidget(foot)
        return side

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
        self._settings.setValue("signals/active_preset", key or "")

    # ── Selection ────────────────────────────────────────────────

    def _apply_selection(self, ids: set, preset_key: str | None):
        self._selected_ids = set(ids)
        for row in self._signal_rows:
            row.set_checked(row.signal.id in self._selected_ids)
        self._set_active_preset(preset_key)
        self._rebuild_preset_combo()
        self._on_selection_changed()

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

            header_widget = QWidget()
            header_layout = QHBoxLayout(header_widget)
            header_layout.setContentsMargins(2, 10, 0, 2)
            header_layout.setSpacing(8)

            readable = sum(1 for s in cat_signals if s.available and s.value)
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

            # Bulk actions sit on the left, directly above the checkbox column they
            # control; the section label and a divider rule fill the row to the right.
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

            cat_ids = []
            for sig in cat_signals:
                row = SignalRow(sig, sig.id in self._selected_ids)
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

        self._entropy_lbl.setText(f"Estimated entropy:  {entropy} bits")
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
        w.done.connect(lambda fp: self._on_test_done(ids, fp))
        w.error.connect(self._on_test_error)
        self._start_worker(w)

    def _on_test_done(self, ids: frozenset, fp: str):
        self._set_busy(False)
        self._test_btn.setText("Test Key")
        if self._last_test and self._last_test[0] == ids:
            stable = self._last_test[1] == fp
            note = "  ✓ stable" if stable else "  ⚠ changed since last test"
        else:
            note = ""
        self._last_test = (ids, fp)
        self._fp_lbl.setText(f"Key fingerprint:  {fp}{note}")
        self._status.showMessage(
            f"Key fingerprint {fp} — "
            + ("environment is stable" if note.strip().startswith("✓")
               else "run Test Key again to confirm the environment is stable")
        )

    def _on_test_error(self, msg: str):
        self._set_busy(False)
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

        self._enc_payload = FilePicker("File to hide", filter_="All Files (*.*)", step=1,
                                       placeholder="Any file type — browse, or drop it here")
        self._enc_carrier = FilePicker("Carrier image (PNG)", filter_="PNG Images (*.png);;All (*.*)", step=2,
                                       placeholder="The PNG to hide it in — browse, or drop it here")
        self._enc_output  = FilePicker("Save stego image as", mode="save", filter_="PNG Images (*.png)", step=3,
                                       placeholder="Suggested automatically next to the carrier")

        self._enc_carrier.changed.connect(self._on_carrier_changed)
        self._enc_payload.changed.connect(self._update_capacity)
        self._enc_output.changed.connect(self._on_output_edited)

        il.addWidget(self._enc_payload)
        il.addWidget(self._enc_carrier)
        il.addWidget(self._enc_output)
        il.addWidget(_divider())

        cap_top = QHBoxLayout()
        self._cap_label = QLabel("Select a carrier image to see capacity")
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
        self._enc_open_btn = QPushButton("Show in folder")
        self._enc_open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._enc_open_btn.setVisible(False)
        self._enc_open_btn.clicked.connect(lambda: self._open_folder(self._enc_output.path()))
        result_row.addWidget(self._enc_open_btn)
        layout.addLayout(result_row)

        layout.addStretch()
        return page

    def _on_carrier_changed(self, carrier: str):
        # Suggest an output path next to the carrier unless the user chose one themselves
        if carrier and (self._enc_output_auto or not self._enc_output.path()):
            p = Path(carrier)
            suggestion = str(p.with_name(f"{p.stem}_stego.png"))
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
            self._enc_output_auto = self._enc_output.path() == str(p.with_name(f"{p.stem}_stego.png"))
        else:
            self._enc_output_auto = False
        self._refresh_actions()

    def _update_capacity(self, *_):
        carrier = self._enc_carrier.path()
        payload = self._enc_payload.path()
        self._enc_capacity_ok = False
        self._cap_bar.setObjectName("capacity_bar")

        if not carrier or not os.path.isfile(carrier):
            self._cap_label.setText("Select a carrier image to see capacity")
            self._img_info_lbl.setText("")
            self._cap_bar.setValue(0)
        else:
            try:
                info = get_image_info(carrier)
                cap  = info["capacity_bytes"]
                self._img_info_lbl.setText(
                    f"{info['width']} × {info['height']} px  |  capacity {cap:,} B  ({cap/1024:.1f} KB)"
                )
                if payload and os.path.isfile(payload):
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

    def _encrypt_blockers(self) -> list[str]:
        active, missing = self._selection_breakdown()
        carrier, payload, output = self._enc_carrier.path(), self._enc_payload.path(), self._enc_output.path()
        out = []
        if not self._token_cfg:
            out.append("pair a hardware token")
        if not active:
            out.append("select signals")
        elif missing:
            out.append("deselect unreadable signals")
        if not payload or not os.path.isfile(payload):
            out.append("choose a payload file")
        if not carrier or not os.path.isfile(carrier):
            out.append("choose a carrier PNG")
        elif payload and os.path.isfile(payload) and not self._enc_capacity_ok:
            out.append("use a bigger carrier image")
        if not output:
            out.append("choose an output path")
        elif carrier and os.path.normcase(os.path.abspath(output)) == os.path.normcase(os.path.abspath(carrier)):
            out.append("pick an output different from the carrier")
        return out

    def _do_encrypt(self):
        if self._encrypt_blockers():
            return
        output = self._enc_output.path()
        out_png = str(Path(output).with_suffix(".png"))
        if os.path.exists(out_png):
            if QMessageBox.question(self, "Overwrite file", f"{Path(out_png).name} already exists. Overwrite it?") \
                    != QMessageBox.StandardButton.Yes:
                return

        self._set_busy(True)
        self._enc_btn.setText(self.ENC_BUSY)
        self._enc_result.show_info("Collecting live signals and requesting the key from the token over BLE…")
        self._enc_fp_lbl.setText("")
        self._enc_open_btn.setVisible(False)

        w = EncryptWorker(self._selected_ids, self._enc_carrier.path(), self._enc_payload.path(), output)
        w.done.connect(self._on_encrypt_done)
        w.error.connect(self._on_encrypt_error)
        self._start_worker(w)

    def _on_encrypt_done(self, msg: str, fp: str, out_path: str):
        self._set_busy(False)
        self._enc_btn.setText(self.ENC_LABEL)
        self._enc_result.show_success(msg)
        self._enc_fp_lbl.setText(f"Key fingerprint:  {fp}")
        self._enc_output.set_path(out_path)
        self._enc_open_btn.setVisible(True)
        # Convenience: the image just made is the one most likely to be decrypted next
        if not self._dec_stego.path():
            self._dec_stego.set_path(out_path)
        self._status.showMessage(f"Encrypt complete — key fingerprint: {fp}")

    def _on_encrypt_error(self, msg: str):
        self._set_busy(False)
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
        self._dec_stego  = FilePicker("Stego image", filter_="PNG Images (*.png)", step=1,
                                      placeholder="A PNG made by Encrypt — browse, or drop it here")
        self._dec_output = FilePicker("Save recovered file to", mode="dir", step=2,
                                      placeholder="Same folder as the stego image")
        self._dec_stego.changed.connect(self._refresh_actions)
        il.addWidget(self._dec_stego)
        il.addWidget(self._dec_output)
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

    def _decrypt_blockers(self) -> list[str]:
        active, _ = self._selection_breakdown()
        stego = self._dec_stego.path()
        out = []
        if not self._token_cfg:
            out.append("pair a hardware token")
        if not active:
            out.append("select the signals used to encrypt")
        if not stego or not os.path.isfile(stego):
            out.append("choose a stego image")
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

        w = DecryptWorker(self._selected_ids, self._dec_stego.path(), self._dec_output.path())
        w.done.connect(self._on_decrypt_done)
        w.error.connect(self._on_decrypt_error)
        self._start_worker(w)

    def _on_decrypt_done(self, msg: str, fp: str, out_path: str, plaintext: bytes):
        self._set_busy(False)
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

    def _refresh_token_ui(self):
        cfg = self._token_cfg
        if cfg:
            fp = token_fingerprint(cfg["token_id"])
            self._token_chip.setObjectName("chip_ok")
            self._token_chip.setText(f"●  Token {fp}")
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
            self._token_chip.setObjectName("chip_off")
            self._token_chip.setText("○  No token paired")
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
        ports = list_serial_ports()
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
        listed = [self._port_combo.itemData(i) for i in range(self._port_combo.count())]
        found = [dev for dev, _ in list_serial_ports()]
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

    def _populate_inspector(self):
        self._inspector_table.setRowCount(0)
        for sig in self._all_signals:
            row = self._inspector_table.rowCount()
            self._inspector_table.insertRow(row)
            items = [
                "✓" if sig.id in self._selected_ids else "",
                sig.id,
                sig.name,
                sig.category,
                f"{sig.stability}/10",
                sig.value if sig.available else f"[N/A]  {sig.error or ''}",
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

        for index, block in ((self.TAB_ENCRYPT, enc_block), (self.TAB_DECRYPT, dec_block)):
            if self._busy:
                state = ("Working…", "muted")
            elif self._collecting:
                state = ("Waiting for signals…", "muted")
            elif not block:
                state = ("Ready", "ok")
            else:
                state = (f"{len(block)} step{'s' if len(block) != 1 else ''} to go", "muted")
            self._nav[index].set_status(*state)

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
        text = f"{sig_txt} &nbsp;<span style='color:#6e7681'>+</span>&nbsp; {tok_txt}"
        self._enc_key_lbl.setText(text)
        self._dec_key_lbl.setText(text)
