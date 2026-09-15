"""
EnvStego - ui_main.py
PyQt6 application window.

Tabs:
  1. Signals   — select environment variables to build the key
  2. Encrypt   — hide payload inside a PNG carrier image
  3. Decrypt   — extract and recover payload from a stego image
  4. Inspector — view raw collected signal values

Team member: Application Interface & Data Extraction Logic
ICT3215 Digital Forensics — SIT
"""

import os
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QCheckBox, QProgressBar,
    QFileDialog, QTextEdit, QGroupBox, QScrollArea, QFrame,
    QTableWidget, QTableWidgetItem, QLineEdit, QSplitter,
    QStatusBar, QGridLayout, QSizePolicy, QHeaderView, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt6.QtGui import QFont, QPixmap, QColor, QPalette, QFontDatabase

from signals import EnvSignal, collect_all_signals
from crypto_engine import derive_key, encrypt_payload, decrypt_payload, estimate_entropy_bits
from stego_engine import embed, extract, get_capacity_bytes, get_image_info
from cryptography.exceptions import InvalidTag


# ─── STYLESHEET ──────────────────────────────────────────────────────────────

STYLE = """
* { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; }

QMainWindow, QWidget#root {
    background-color: #0d1117;
    color: #c9d1d9;
}

QTabWidget::pane {
    border: 1px solid #21262d;
    background-color: #0d1117;
    border-radius: 0px;
    top: -1px;
}
QTabBar { background-color: #0d1117; }
QTabBar::tab {
    background-color: #0d1117;
    color: #6e7681;
    padding: 10px 22px;
    border: 1px solid #21262d;
    border-bottom: none;
    min-width: 110px;
}
QTabBar::tab:selected {
    color: #e6edf3;
    border-top: 2px solid #58a6ff;
    background-color: #0d1117;
}
QTabBar::tab:hover:!selected { color: #c9d1d9; }

QGroupBox {
    border: 1px solid #21262d;
    border-radius: 6px;
    margin-top: 14px;
    padding: 14px 10px 10px 10px;
    color: #6e7681;
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 1px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    text-transform: uppercase;
}

QPushButton {
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton:hover { background-color: #30363d; color: #e6edf3; border-color: #58a6ff; }
QPushButton:pressed { background-color: #1c2128; }
QPushButton:disabled { color: #484f58; border-color: #21262d; }
QPushButton#btn_primary {
    background-color: #1f6feb;
    color: #ffffff;
    border: 1px solid #388bfd;
    font-weight: bold;
    font-size: 14px;
    padding: 11px 28px;
    border-radius: 6px;
}
QPushButton#btn_primary:hover { background-color: #388bfd; }
QPushButton#btn_primary:disabled { background-color: #1c2d43; color: #484f58; border-color: #21262d; }
QPushButton#btn_decrypt {
    background-color: #2d1b69;
    color: #d2a8ff;
    border: 1px solid #8957e5;
    font-weight: bold;
    font-size: 14px;
    padding: 11px 28px;
    border-radius: 6px;
}
QPushButton#btn_decrypt:hover { background-color: #3d2a7a; }
QPushButton#btn_decrypt:disabled { background-color: #1a1433; color: #484f58; border-color: #21262d; }

QLineEdit {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 7px 10px;
    color: #c9d1d9;
}
QLineEdit:focus { border-color: #58a6ff; }
QLineEdit:read-only { color: #8b949e; }

QTextEdit {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 8px;
    color: #c9d1d9;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}

QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: #161b22; width: 6px; }
QScrollBar::handle:vertical { background: #30363d; border-radius: 3px; min-height: 20px; }
QScrollBar::handle:vertical:hover { background: #58a6ff; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

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
QProgressBar#capacity_bar::chunk { background-color: #58a6ff; }
QProgressBar#entropy_bar::chunk  { background-color: #3fb950; }

QCheckBox { spacing: 8px; color: #c9d1d9; }
QCheckBox::indicator {
    width: 15px; height: 15px;
    border: 1px solid #30363d;
    border-radius: 3px;
    background-color: #161b22;
}
QCheckBox::indicator:checked { background-color: #1f6feb; border-color: #388bfd; }
QCheckBox::indicator:disabled { background-color: #21262d; border-color: #21262d; }

QTableWidget {
    background-color: #161b22;
    alternate-background-color: #1c2128;
    border: 1px solid #21262d;
    border-radius: 6px;
    gridline-color: #21262d;
    selection-background-color: #1a3a5c;
    color: #c9d1d9;
}
QHeaderView::section {
    background-color: #21262d;
    color: #6e7681;
    padding: 7px 10px;
    border: none;
    border-right: 1px solid #30363d;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
}
QTableWidget::item { padding: 5px 8px; border: none; }

QStatusBar {
    background-color: #161b22;
    color: #6e7681;
    border-top: 1px solid #21262d;
    font-size: 11px;
}
QLabel { color: #c9d1d9; }
"""


# ─── WORKER THREADS ──────────────────────────────────────────────────────────

class CollectWorker(QThread):
    done    = pyqtSignal(list)
    status  = pyqtSignal(str)

    def run(self):
        self.status.emit("Profiling environment…")
        signals = collect_all_signals()
        self.done.emit(signals)


class EncryptWorker(QThread):
    done  = pyqtSignal(str, str, str)
    error = pyqtSignal(str)

    def __init__(self, selected_ids, carrier, payload_path, output_path):
        super().__init__()
        self._selected_ids = set(selected_ids)  # signal IDs chosen by user
        self._carrier      = carrier
        self._payload      = payload_path
        self._output       = output_path

    def run(self):
        try:
            # Re-collect signals LIVE at encrypt time — not cached startup values
            fresh    = collect_all_signals()
            selected = [s for s in fresh
                        if s.id in self._selected_ids and s.available and s.value]
            if not selected:
                self.error.emit(
                    "None of the selected signals are readable right now.\n"
                    "Go to the Signals tab, click Refresh, and re-select your signals."
                )
                return

            with open(self._payload, "rb") as f:
                plaintext = f.read()

            key, fp   = derive_key(selected)
            nonce, ct = encrypt_payload(plaintext, key)
            out_path  = embed(self._carrier, nonce, ct, self._output)

            self.done.emit(
                f"Payload embedded successfully\n"
                f"  Signals used:  {len(selected)} (collected live at encrypt time)\n"
                f"  Payload:       {len(plaintext):,} bytes\n"
                f"  Encrypted to:  {len(ct):,} bytes  (AES-256-GCM + 16 B tag)\n"
                f"  Carrier:       {Path(self._carrier).name}\n"
                f"  Output:        {Path(out_path).name}",
                fp,
                out_path
            )
        except Exception as e:
            self.error.emit(str(e))


class DecryptWorker(QThread):
    done  = pyqtSignal(str, bytes)
    error = pyqtSignal(str)

    def __init__(self, selected_ids, stego_path, output_path):
        super().__init__()
        self._selected_ids = set(selected_ids)  # signal IDs chosen by user
        self._stego        = stego_path
        self._output       = output_path

    def run(self):
        try:
            # Re-collect signals LIVE at decrypt time — this is what makes the
            # forensic defense work: if environment changed, key derivation
            # produces a different key and AES-GCM authentication fails.
            fresh    = collect_all_signals()
            selected = [s for s in fresh
                        if s.id in self._selected_ids and s.available and s.value]
            if not selected:
                self.error.emit(
                    "None of the selected signals are readable in the current environment.\n"
                    "This may mean the environment has changed (forensic defense active)."
                )
                return

            key, _    = derive_key(selected)
            nonce, ct = extract(self._stego)
            plaintext = decrypt_payload(nonce, ct, key)

            if self._output:
                with open(self._output, "wb") as f:
                    f.write(plaintext)

            self.done.emit(
                f"Payload extracted and decrypted\n"
                f"  Signals used: {len(selected)} (collected live at decrypt time)\n"
                f"  Recovered:    {len(plaintext):,} bytes\n"
                f"  Saved to:     {Path(self._output).name if self._output else '(not saved)'}",
                plaintext
            )
        except InvalidTag:
            self.error.emit(
                "Decryption failed — Authentication tag mismatch\n\n"
                "The current environment does not match the one used during encryption.\n"
                "Dead-disk forensic defense confirmed working:\n"
                "  • Different network   →  BSSID/gateway signals changed\n"
                "  • Different machine   →  hardware serials changed\n"
                "  • Forensic lab/clone  →  no live environment signals\n\n"
                "The payload is mathematically unrecoverable in this environment."
            )
        except Exception as e:
            self.error.emit(str(e))


# ─── REUSABLE WIDGETS ────────────────────────────────────────────────────────

class FilePicker(QWidget):
    """Label + LineEdit + Browse button row."""

    def __init__(self, label: str, mode: str = "open",
                 filter_: str = "All Files (*.*)", parent=None):
        super().__init__(parent)
        self._mode   = mode
        self._filter = filter_
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        lbl = QLabel(label)
        lbl.setMinimumWidth(130)
        lbl.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(lbl)

        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Select a file…")
        self.path_edit.setReadOnly(True)
        layout.addWidget(self.path_edit, stretch=1)

        btn = QPushButton("Browse")
        btn.setMinimumWidth(80)
        btn.clicked.connect(self._browse)
        layout.addWidget(btn)

    def _browse(self):
        if self._mode == "save":
            path, _ = QFileDialog.getSaveFileName(
                self, "Save File", "", self._filter
            )
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open File", "", self._filter
            )
        if path:
            self.path_edit.setText(path)

    def path(self) -> str:
        return self.path_edit.text().strip()

    def set_path(self, p: str):
        self.path_edit.setText(p)


class StatusPanel(QLabel):
    """Collapsible result/status panel below action buttons."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWordWrap(True)
        self.setMinimumHeight(60)
        self.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.setVisible(False)
        self.setContentsMargins(12, 10, 12, 10)

    def show_success(self, msg: str):
        self.setStyleSheet(
            "background:#1a4731; color:#3fb950; border:1px solid #2ea043;"
            "border-radius:6px; padding:10px; font-family:Consolas,monospace; font-size:12px;"
        )
        self.setText(f"✓  {msg}")
        self.setVisible(True)

    def show_error(self, msg: str):
        self.setStyleSheet(
            "background:#2d1a1a; color:#f85149; border:1px solid #da3633;"
            "border-radius:6px; padding:10px; font-family:Consolas,monospace; font-size:12px;"
        )
        self.setText(f"✗  {msg}")
        self.setVisible(True)

    def clear(self):
        self.setVisible(False)


class SignalRow(QWidget):
    """
    One row in the signal selection list.
    Contains: checkbox | name + description | stability bar | status badge
    """

    toggled = pyqtSignal()

    def __init__(self, signal: EnvSignal, parent=None):
        super().__init__(parent)
        self._signal = signal
        self._build()

    def _build(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 3, 6, 3)
        layout.setSpacing(10)

        self._cb = QCheckBox()
        self._cb.setEnabled(False)
        self._cb.toggled.connect(self.toggled.emit)
        layout.addWidget(self._cb)

        # Name + description
        info = QVBoxLayout()
        info.setSpacing(1)
        self._name_lbl = QLabel(self._signal.name)
        self._name_lbl.setStyleSheet("font-weight:600; color:#c9d1d9;")
        self._desc_lbl = QLabel(self._signal.description)
        self._desc_lbl.setStyleSheet("font-size:11px; color:#6e7681;")
        info.addWidget(self._name_lbl)
        info.addWidget(self._desc_lbl)
        layout.addLayout(info, stretch=4)

        # Stability bar
        stab_col = QVBoxLayout()
        stab_col.setSpacing(2)
        stab_lbl = QLabel("Stability")
        stab_lbl.setStyleSheet("font-size:10px; color:#6e7681;")
        self._stab_bar = QProgressBar()
        self._stab_bar.setMaximumWidth(90)
        self._stab_bar.setFixedHeight(6)
        self._stab_bar.setTextVisible(False)
        self._stab_bar.setValue(self._signal.stability * 10)
        s = self._signal.stability
        bar_id = "stab_high" if s >= 8 else ("stab_med" if s >= 6 else "stab_low")
        self._stab_bar.setObjectName(bar_id)
        stab_col.addWidget(stab_lbl)
        stab_col.addWidget(self._stab_bar)
        layout.addLayout(stab_col)

        # Status badge
        self._badge = QLabel("Loading")
        self._badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._badge.setMinimumWidth(80)
        self._badge.setStyleSheet(
            "background:#2d2a17; color:#d29922; border:1px solid #9e6a03;"
            "border-radius:10px; padding:2px 8px; font-size:10px; font-weight:bold;"
        )
        layout.addWidget(self._badge)

    def update_signal(self, signal: EnvSignal):
        self._signal = signal
        if signal.available:
            self._cb.setEnabled(True)
            self._cb.setChecked(False)   # user must deliberately choose signals
            # Force Qt style engine to repaint the checkbox (needed on Windows)
            self._cb.style().unpolish(self._cb)
            self._cb.style().polish(self._cb)
            self._cb.update()
            self._badge.setText("Available")
            self._badge.setStyleSheet(
                "background:#1a4731; color:#3fb950; border:1px solid #2ea043;"
                "border-radius:10px; padding:2px 8px; font-size:10px; font-weight:bold;"
            )
        else:
            self._cb.setEnabled(False)
            self._cb.setChecked(False)
            self._cb.style().unpolish(self._cb)
            self._cb.style().polish(self._cb)
            self._cb.update()
            tooltip = signal.error or "Not available on this machine"
            self._badge.setText("N/A")
            self._badge.setToolTip(tooltip)
            self._badge.setStyleSheet(
                "background:#1c1c1c; color:#484f58; border:1px solid #30363d;"
                "border-radius:10px; padding:2px 8px; font-size:10px;"
            )

    @property
    def is_selected(self) -> bool:
        return self._cb.isEnabled() and self._cb.isChecked()

    @property
    def signal(self) -> EnvSignal:
        return self._signal


# ─── MAIN WINDOW ─────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("EnvStego  —  Environment-Keyed Steganography")
        self.setMinimumSize(900, 680)
        self.resize(1020, 740)

        self._all_signals: list[EnvSignal] = []
        self._signal_rows: list[SignalRow] = []
        self._collect_worker = None
        self._op_worker      = None

        self._build_ui()
        self._start_collection()

    # ── UI Construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)

        # ── Header bar ────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet("background:#161b22; border-bottom:1px solid #21262d;")
        header.setFixedHeight(62)
        hbox = QHBoxLayout(header)
        hbox.setContentsMargins(20, 0, 20, 0)

        title = QLabel("EnvStego")
        title.setStyleSheet(
            "font-size:22px; font-weight:bold; color:#58a6ff; letter-spacing:2px;"
        )
        sub = QLabel("Environment-Keyed Steganography  ·  ICT3215 Digital Forensics")
        sub.setStyleSheet("font-size:11px; color:#6e7681; margin-left:12px;")
        hbox.addWidget(title)
        hbox.addWidget(sub)
        hbox.addStretch()

        self._refresh_btn = QPushButton("↻  Refresh Signals")
        self._refresh_btn.setFixedHeight(32)
        self._refresh_btn.clicked.connect(self._start_collection)
        hbox.addWidget(self._refresh_btn)

        vbox.addWidget(header)

        # ── Tab widget ────────────────────────────────────────────
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        vbox.addWidget(self._tabs, stretch=1)

        self._tabs.addTab(self._build_signals_tab(),  "  Signals  ")
        self._tabs.addTab(self._build_encrypt_tab(),  "  Encrypt  ")
        self._tabs.addTab(self._build_decrypt_tab(),  "  Decrypt  ")
        self._tabs.addTab(self._build_inspector_tab(),"  Inspector  ")

        # ── Status bar ────────────────────────────────────────────
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Initialising…")

    # ─────────────────────────────────────────────────────────────
    #  TAB 1 — SIGNAL SELECTION
    # ─────────────────────────────────────────────────────────────

    def _build_signals_tab(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:#0d1117;")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(16, 16, 16, 12)
        outer.setSpacing(10)

        info = QLabel(
            "Select which environment variables will form the encryption key.  "
            "The same combination must be present at decryption time.  "
            "Signals marked N/A are not readable in this environment."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#8b949e; font-size:12px; padding:4px 0;")
        outer.addWidget(info)

        # Scroll area for signal rows
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll_content = QWidget()
        self._scroll_content.setStyleSheet("background:#0d1117;")
        self._scroll_layout = QVBoxLayout(self._scroll_content)
        self._scroll_layout.setSpacing(4)
        self._scroll_layout.setContentsMargins(0, 0, 4, 0)
        self._scroll_layout.addStretch()
        scroll.setWidget(self._scroll_content)
        outer.addWidget(scroll, stretch=1)

        # ── Summary bar ──────────────────────────────────────────
        summary_frame = QFrame()
        summary_frame.setStyleSheet(
            "background:#161b22; border:1px solid #21262d; border-radius:6px;"
        )
        summary_layout = QHBoxLayout(summary_frame)
        summary_layout.setContentsMargins(14, 10, 14, 10)

        self._sel_count_lbl = QLabel("0 signals selected")
        self._sel_count_lbl.setStyleSheet("color:#8b949e; font-size:12px;")

        self._entropy_lbl = QLabel("Estimated entropy: — bits")
        self._entropy_lbl.setStyleSheet(
            "color:#58a6ff; font-size:13px; font-weight:bold;"
        )

        self._entropy_bar = QProgressBar()
        self._entropy_bar.setObjectName("entropy_bar")
        self._entropy_bar.setMaximumWidth(180)
        self._entropy_bar.setFixedHeight(8)
        self._entropy_bar.setTextVisible(False)
        self._entropy_bar.setMaximum(256)
        self._entropy_bar.setValue(0)

        self._fp_lbl = QLabel("Key fingerprint:  —")
        self._fp_lbl.setStyleSheet(
            "font-family:Consolas,monospace; font-size:12px; color:#d29922;"
        )

        fp_btn = QPushButton("Test Key")
        fp_btn.setFixedHeight(28)
        fp_btn.setToolTip(
            "Derive the key from selected signals and show its fingerprint.\n"
            "Use this to verify your environment is stable before encrypting."
        )
        fp_btn.clicked.connect(self._test_key)

        summary_layout.addWidget(self._sel_count_lbl)
        summary_layout.addSpacing(20)
        summary_layout.addWidget(self._entropy_lbl)
        summary_layout.addWidget(self._entropy_bar)
        summary_layout.addStretch()
        summary_layout.addWidget(self._fp_lbl)
        summary_layout.addSpacing(12)
        summary_layout.addWidget(fp_btn)

        outer.addWidget(summary_frame)
        return page

    def _populate_signal_rows(self, signals: list[EnvSignal]):
        """Build signal rows grouped by category."""
        # Clear existing
        while self._scroll_layout.count() > 1:
            item = self._scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._signal_rows.clear()
        categories = {}
        for s in signals:
            categories.setdefault(s.category, []).append(s)

        for cat_name in ["Hardware", "Network", "OS"]:
            cat_signals = categories.get(cat_name, [])
            if not cat_signals:
                continue

            group = QGroupBox(cat_name)
            group.setStyleSheet(
                "QGroupBox { margin-top:14px; } "
                "QGroupBox::title { color:#6e7681; font-size:10px; letter-spacing:1.5px; }"
            )
            g_layout = QVBoxLayout(group)
            g_layout.setSpacing(2)

            for sig in cat_signals:
                row = SignalRow(sig)
                row.toggled.connect(self._update_summary)
                g_layout.addWidget(row)
                self._signal_rows.append(row)
                row.update_signal(sig)          # called AFTER parenting so Qt style engine refreshes

            self._scroll_layout.insertWidget(self._scroll_layout.count() - 1, group)

        self._update_summary()

    def _update_summary(self):
        selected = [r.signal for r in self._signal_rows if r.is_selected]
        count    = len(selected)
        entropy  = estimate_entropy_bits(selected)

        self._sel_count_lbl.setText(
            f"{count} signal{'s' if count != 1 else ''} selected"
        )
        self._entropy_lbl.setText(f"Estimated entropy:  {entropy} bits")
        self._entropy_bar.setValue(entropy)
        self._fp_lbl.setText("Key fingerprint:  —")

    def _test_key(self):
        selected = [r.signal for r in self._signal_rows if r.is_selected]
        if not selected:
            self._fp_lbl.setText("Key fingerprint:  (select signals first)")
            return
        try:
            _, fp = derive_key(selected)
            self._fp_lbl.setText(f"Key fingerprint:  {fp}")
            self._status.showMessage(
                f"Key fingerprint derived: {fp}  — "
                "Run again to confirm environment is stable"
            )
        except Exception as e:
            self._fp_lbl.setText(f"Error: {e}")

    # ─────────────────────────────────────────────────────────────
    #  TAB 2 — ENCRYPT
    # ─────────────────────────────────────────────────────────────

    def _build_encrypt_tab(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:#0d1117;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(12)

        # File inputs
        inputs = QGroupBox("Files")
        il = QVBoxLayout(inputs)
        il.setSpacing(10)

        self._enc_payload  = FilePicker("Payload file:", filter_="All Files (*.*)")
        self._enc_carrier  = FilePicker("Carrier image:", filter_="PNG Images (*.png);;All (*.*)")
        self._enc_output   = FilePicker("Output PNG:", mode="save", filter_="PNG Images (*.png)")

        self._enc_carrier.path_edit.textChanged.connect(self._update_capacity)
        self._enc_payload.path_edit.textChanged.connect(self._update_capacity)

        il.addWidget(self._enc_payload)
        il.addWidget(self._enc_carrier)
        il.addWidget(self._enc_output)
        layout.addWidget(inputs)

        # Capacity display
        cap_frame = QFrame()
        cap_frame.setStyleSheet(
            "background:#161b22; border:1px solid #21262d; border-radius:6px;"
        )
        cap_layout = QVBoxLayout(cap_frame)
        cap_layout.setContentsMargins(14, 10, 14, 10)
        cap_layout.setSpacing(6)

        cap_top = QHBoxLayout()
        self._cap_label = QLabel("Select a carrier image to see capacity")
        self._cap_label.setStyleSheet("color:#8b949e; font-size:12px;")
        cap_top.addWidget(self._cap_label)
        cap_top.addStretch()
        self._img_info_lbl = QLabel("")
        self._img_info_lbl.setStyleSheet("color:#6e7681; font-size:11px;")
        cap_top.addWidget(self._img_info_lbl)
        cap_layout.addLayout(cap_top)

        self._cap_bar = QProgressBar()
        self._cap_bar.setObjectName("capacity_bar")
        self._cap_bar.setFixedHeight(8)
        self._cap_bar.setTextVisible(False)
        self._cap_bar.setValue(0)
        cap_layout.addWidget(self._cap_bar)

        layout.addWidget(cap_frame)

        # Encrypt button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._enc_btn = QPushButton("  ⬛  Encrypt & Embed  ")
        self._enc_btn.setObjectName("btn_primary")
        self._enc_btn.setMinimumHeight(46)
        self._enc_btn.clicked.connect(self._do_encrypt)
        btn_row.addWidget(self._enc_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Result
        self._enc_result = StatusPanel()
        layout.addWidget(self._enc_result)

        # Fingerprint display after encrypt
        self._enc_fp_lbl = QLabel("")
        self._enc_fp_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._enc_fp_lbl.setStyleSheet(
            "font-family:Consolas,monospace; color:#d29922; font-size:13px;"
        )
        layout.addWidget(self._enc_fp_lbl)
        layout.addStretch()
        return page

    def _update_capacity(self):
        carrier = self._enc_carrier.path()
        payload = self._enc_payload.path()

        if not carrier or not os.path.isfile(carrier):
            self._cap_label.setText("Select a carrier image to see capacity")
            self._img_info_lbl.setText("")
            self._cap_bar.setValue(0)
            return
        try:
            info = get_image_info(carrier)
            cap  = info["capacity_bytes"]
            self._img_info_lbl.setText(
                f"{info['width']} × {info['height']} px  |  "
                f"capacity: {cap:,} B  ({cap/1024:.1f} KB)"
            )

            if payload and os.path.isfile(payload):
                payload_size = os.path.getsize(payload)
                # encrypted payload = payload_size + 16 (GCM tag) + 20 (header)
                total_needed = payload_size + 16 + 20
                pct = min(100, int(total_needed / cap * 100)) if cap > 0 else 100

                if total_needed > cap:
                    self._cap_label.setText(
                        f"⚠  Payload too large: need {total_needed:,} B, "
                        f"capacity {cap:,} B"
                    )
                    self._cap_bar.setStyleSheet(
                        "QProgressBar::chunk { background:#da3633; border-radius:3px; }"
                    )
                else:
                    self._cap_label.setText(
                        f"Using {total_needed:,} / {cap:,} bytes  ({pct}%)"
                    )
                    self._cap_bar.setStyleSheet("")  # Reset to default
                self._cap_bar.setValue(pct)
            else:
                self._cap_label.setText(
                    f"Capacity: {cap:,} bytes  ({cap/1024:.1f} KB)"
                )
                self._cap_bar.setValue(0)
        except Exception as e:
            self._cap_label.setText(f"Cannot read image: {e}")

    def _do_encrypt(self):
        selected_ids = [r.signal.id for r in self._signal_rows if r.is_selected]
        if not selected_ids:
            self._enc_result.show_error("No signals selected. Go to the Signals tab and tick at least one.")
            return
        carrier = self._enc_carrier.path()
        payload = self._enc_payload.path()
        output  = self._enc_output.path()
        if not carrier or not os.path.isfile(carrier):
            self._enc_result.show_error("Please select a valid carrier PNG image.")
            return
        if not payload or not os.path.isfile(payload):
            self._enc_result.show_error("Please select a payload file to embed.")
            return
        if not output:
            self._enc_result.show_error("Please specify an output file path.")
            return

        self._enc_btn.setEnabled(False)
        self._enc_btn.setText("  ⏳  Encrypting…  ")
        self._enc_result.clear()
        self._enc_fp_lbl.setText("")

        self._op_worker = EncryptWorker(selected_ids, carrier, payload, output)
        self._op_worker.done.connect(self._on_encrypt_done)
        self._op_worker.error.connect(self._on_encrypt_error)
        self._op_worker.start()

    def _on_encrypt_done(self, msg: str, fp: str, out_path: str):
        self._enc_result.show_success(msg)
        self._enc_fp_lbl.setText(f"Key fingerprint:  {fp}")
        self._enc_btn.setEnabled(True)
        self._enc_btn.setText("  ⬛  Encrypt & Embed  ")
        self._status.showMessage(f"Encrypt complete — key fingerprint: {fp}")

    def _on_encrypt_error(self, msg: str):
        self._enc_result.show_error(msg)
        self._enc_btn.setEnabled(True)
        self._enc_btn.setText("  ⬛  Encrypt & Embed  ")
        self._status.showMessage("Encryption failed")

    # ─────────────────────────────────────────────────────────────
    #  TAB 3 — DECRYPT
    # ─────────────────────────────────────────────────────────────

    def _build_decrypt_tab(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:#0d1117;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(12)

        note = QLabel(
            "⚠  Decryption requires the same environment signals that were active during encryption.  "
            "Running in a different physical location or on a cloned disk will cause authentication failure."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            "background:#2d2a17; color:#d29922; border:1px solid #9e6a03;"
            "border-radius:6px; padding:10px; font-size:12px;"
        )
        layout.addWidget(note)

        inputs = QGroupBox("Files")
        il = QVBoxLayout(inputs)
        il.setSpacing(10)
        self._dec_stego  = FilePicker("Stego image:", filter_="PNG Images (*.png)")
        self._dec_output = FilePicker("Output file:", mode="save", filter_="All Files (*.*)")
        il.addWidget(self._dec_stego)
        il.addWidget(self._dec_output)
        layout.addWidget(inputs)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._dec_btn = QPushButton("  🔓  Decrypt & Extract  ")
        self._dec_btn.setObjectName("btn_decrypt")
        self._dec_btn.setMinimumHeight(46)
        self._dec_btn.clicked.connect(self._do_decrypt)
        btn_row.addWidget(self._dec_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._dec_result = StatusPanel()
        layout.addWidget(self._dec_result)

        # Preview (if recovered is text)
        self._dec_preview_lbl = QLabel("Preview (text payloads only):")
        self._dec_preview_lbl.setStyleSheet("color:#6e7681; font-size:11px;")
        self._dec_preview_lbl.setVisible(False)
        layout.addWidget(self._dec_preview_lbl)

        self._dec_preview = QTextEdit()
        self._dec_preview.setReadOnly(True)
        self._dec_preview.setMaximumHeight(120)
        self._dec_preview.setVisible(False)
        layout.addWidget(self._dec_preview)

        layout.addStretch()
        return page

    def _do_decrypt(self):
        selected_ids = [r.signal.id for r in self._signal_rows if r.is_selected]
        if not selected_ids:
            self._dec_result.show_error("No signals selected. Go to the Signals tab and tick at least one.")
            return
        stego  = self._dec_stego.path()
        output = self._dec_output.path()
        if not stego or not os.path.isfile(stego):
            self._dec_result.show_error("Please select a valid stego PNG image.")
            return
        if not output:
            self._dec_result.show_error("Please specify an output file path.")
            return

        self._dec_btn.setEnabled(False)
        self._dec_btn.setText("  ⏳  Decrypting…  ")
        self._dec_result.clear()
        self._dec_preview.setVisible(False)
        self._dec_preview_lbl.setVisible(False)

        self._op_worker = DecryptWorker(selected_ids, stego, output)
        self._op_worker.done.connect(self._on_decrypt_done)
        self._op_worker.error.connect(self._on_decrypt_error)
        self._op_worker.start()

    def _on_decrypt_done(self, msg: str, plaintext: bytes):
        self._dec_result.show_success(msg)
        self._dec_btn.setEnabled(True)
        self._dec_btn.setText("  🔓  Decrypt & Extract  ")
        self._status.showMessage("Decryption successful")

        # Try to show a text preview
        try:
            text = plaintext.decode("utf-8")
            self._dec_preview.setPlainText(text[:2000] + ("…" if len(text) > 2000 else ""))
            self._dec_preview.setVisible(True)
            self._dec_preview_lbl.setVisible(True)
        except UnicodeDecodeError:
            pass  # Binary payload — no preview

    def _on_decrypt_error(self, msg: str):
        self._dec_result.show_error(msg)
        self._dec_btn.setEnabled(True)
        self._dec_btn.setText("  🔓  Decrypt & Extract  ")
        self._status.showMessage("Decryption failed — environment mismatch")

    # ─────────────────────────────────────────────────────────────
    #  TAB 4 — INSPECTOR
    # ─────────────────────────────────────────────────────────────

    def _build_inspector_tab(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:#0d1117;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        info = QLabel(
            "Raw signal values collected from this machine's environment. "
            "These are the inputs to the HKDF key derivation function."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#8b949e; font-size:12px; padding-bottom:4px;")
        layout.addWidget(info)

        self._inspector_table = QTableWidget()
        self._inspector_table.setColumnCount(5)
        self._inspector_table.setHorizontalHeaderLabels(
            ["ID", "Signal Name", "Category", "Stability", "Value / Error"]
        )
        self._inspector_table.setAlternatingRowColors(True)
        self._inspector_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._inspector_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        hdr = self._inspector_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self._inspector_table)
        return page

    def _populate_inspector(self, signals: list[EnvSignal]):
        self._inspector_table.setRowCount(0)
        for sig in signals:
            row = self._inspector_table.rowCount()
            self._inspector_table.insertRow(row)
            items = [
                sig.id,
                sig.name,
                sig.category,
                f"{sig.stability}/10",
                sig.value if sig.available else f"[N/A]  {sig.error or ''}",
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(str(text))
                if not sig.available:
                    item.setForeground(QColor("#484f58"))
                elif col == 4:
                    item.setForeground(QColor("#3fb950"))
                self._inspector_table.setItem(row, col, item)

    # ─────────────────────────────────────────────────────────────
    #  SIGNAL COLLECTION
    # ─────────────────────────────────────────────────────────────

    def _start_collection(self):
        self._refresh_btn.setEnabled(False)
        self._refresh_btn.setText("↻  Collecting…")
        self._status.showMessage("Profiling environment — please wait…")

        self._collect_worker = CollectWorker()
        self._collect_worker.status.connect(self._status.showMessage)
        self._collect_worker.done.connect(self._on_signals_collected)
        self._collect_worker.start()

    def _on_signals_collected(self, signals: list[EnvSignal]):
        self._all_signals = signals
        self._populate_signal_rows(signals)
        self._populate_inspector(signals)

        available_count = sum(1 for s in signals if s.available)
        self._status.showMessage(
            f"Environment profiled — {available_count}/{len(signals)} signals available"
        )
        self._refresh_btn.setEnabled(True)
        self._refresh_btn.setText("↻  Refresh Signals")

    # ─────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────

    def _selected_signals(self) -> list[EnvSignal]:
        return [r.signal for r in self._signal_rows if r.is_selected]