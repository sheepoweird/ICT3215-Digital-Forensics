"""
EnvStego — UI smoke test (no hardware required)

Drives the real MainWindow offscreen through every user flow: pairing, test
connection, presets, Test Key, encrypt, decrypt, a wrong-environment decrypt,
and forgetting the pairing. The token is the software twin from test_offline.py,
signal collection returns a fixed set of signals, and modal dialogs auto-answer
"Yes", so the run is fast and deterministic.

It checks behaviour only (what gets enabled, written and reported), never layout,
so it should pass unchanged before and after any visual redesign.

Run from the Python/ directory:
    python -m pytest tests/test_ui_smoke.py -v
"""

import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if os.name == "nt":
    os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import numpy as np
import pytest
from PIL import Image
from PyQt6.QtCore import QEventLoop, QSettings
from PyQt6.QtWidgets import QApplication, QMessageBox

import crypto_engine
import token_comms as tc
import ui_main
from signals import EnvSignal
from test_offline import SimToken, run_transaction

SIM = SimToken()
FAKE_CFG = {
    "version": 2, "host_id": "TESTHOST", "token_id": SIM.token_id.hex(),
    "ble_mac": "AA:BB:CC:DD:EE:FF", "char_uuid": tc.CHARACTERISTIC_UUID, "firmware": "2",
    "auth_key": "unused", "auth_key_protection": "dpapi", "paired_at": "2026-10-13T12:00:00+00:00",
}
STATE = {"cfg": dict(FAKE_CFG)}

FAKE_SIGNALS = [
    ("hw_cpu", "CPU Processor ID", "Hardware", 9, "178BFBFF00870F10"),
    ("hw_disk", "Primary Disk Serial", "Hardware", 9, "WD-WXQ2E20653H3"),
    ("hw_battery", "Battery Design Capacity", "Hardware", 6, None),
    ("net_gatewaymac", "Default Gateway MAC", "Network", 8, "ec:75:0c:8f:93:f8"),
    ("net_bssid", "Connected AP BSSID", "Network", 8, None),
    ("os_machineguid", "Windows Machine GUID", "OS", 10, "6178c0a8-898b-41ea-aa92"),
]
DEVICE_BOUND = {"hw_cpu", "hw_disk", "os_machineguid"}


def fake_collect():
    return [EnvSignal(id=i, name=n, category=c, description=f"{n} (test)", stability=s,
                      value=v, available=v is not None, error=None if v else "not present")
            for i, n, c, s, v in FAKE_SIGNALS]


PAIR_SHOULD_FAIL = {"value": False}


def fake_pair(_port, progress=None):
    if progress:
        progress("Waiting for the token to answer. No buttons need pressing…")
    if PAIR_SHOULD_FAIL["value"]:
        return False, tc.POWER_MESSAGE
    STATE["cfg"] = dict(FAKE_CFG)
    return True, f"Token {tc.token_fingerprint(SIM.token_id.hex())} bound (BLE AA:BB:CC:DD:EE:FF)"


def wait_until(cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture(scope="module")
def win(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    # QSettings("SIT-ICT3215", "EnvStego") always uses the Windows registry, whatever
    # setDefaultFormat says, so swap in a class that writes to a throwaway .ini instead.
    ini = Path(tempfile.mkdtemp(prefix="envstego_ui_test_")) / "EnvStego.ini"

    class IsolatedSettings(QSettings):
        def __init__(self, *_args):
            super().__init__(str(ini), QSettings.Format.IniFormat)

    mp.setattr(ui_main, "QSettings", IsolatedSettings)
    mp.setattr(ui_main, "collect_all_signals", fake_collect)
    mp.setattr(ui_main, "load_config", lambda: STATE["cfg"])
    mp.setattr(ui_main, "forget_pairing", lambda: STATE.update(cfg=None))
    mp.setattr(ui_main, "pair_token_usb", fake_pair)
    mp.setattr(ui_main, "ping_token", lambda: None)
    mp.setattr(ui_main, "list_serial_ports", lambda: [("COM9", "USB-SERIAL CH340 (COM9)")])
    mp.setattr(crypto_engine, "request_env_key",
               lambda h: run_transaction(SIM, SIM.auth_key, SIM.token_id, tc.OP_DERIVE, h))
    # Modal dialogs would block an offscreen run: answer every question "Yes"
    mp.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    for name in ("warning", "information", "critical"):
        mp.setattr(QMessageBox, name, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))

    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(ui_main.STYLE)
    w = ui_main.MainWindow()
    w.show()
    assert wait_until(lambda: not w._collecting), "signal collection never finished"
    w.files = tmp_path_factory.mktemp("ui_flow")
    yield w
    w.close()
    mp.undo()


def idle(w):
    return wait_until(lambda: not w._busy)


# ── Startup ──────────────────────────────────────────────────────────────────

def test_startup_shows_paired_token_and_all_pages(win):
    assert win._tabs.count() == 5
    assert win._token_cfg is not None
    assert win._ping_btn.isEnabled() and win._forget_btn.isEnabled()
    assert win._pair_btn.isEnabled()                      # a port is available
    assert len(win._signal_rows) == len(FAKE_SIGNALS)
    assert not win._enc_btn.isEnabled()                   # nothing selected yet
    assert win._inspector_table.rowCount() == len(FAKE_SIGNALS)


# ── Token ────────────────────────────────────────────────────────────────────

def test_test_connection(win):
    win._start_ping()
    assert idle(win)
    assert "proved its identity" in win._ping_result.text()


# ── Signals ──────────────────────────────────────────────────────────────────

def test_preset_selects_expected_signals(win):
    idx = win._preset_combo.findData("builtin:Device-bound")
    assert idx >= 0
    win._on_preset_chosen(idx)
    assert win._selected_ids == DEVICE_BOUND
    assert win._active_preset == "builtin:Device-bound"
    assert win._test_btn.isEnabled()


def test_test_key_reports_fingerprint(win):
    win._test_key()
    assert idle(win)
    first = win._fp_lbl.text()
    assert "-" in first and "error" not in first.lower()
    win._test_key()
    assert idle(win)
    assert "stable" in win._fp_lbl.text()


# ── Encrypt / decrypt ────────────────────────────────────────────────────────

def _make_carrier(path):
    x = np.arange(200, dtype=np.uint8)
    arr = np.dstack([np.tile(x, (200, 1)), np.tile(x.reshape(200, 1), (1, 200)),
                     np.full((200, 200), 90, np.uint8)])
    Image.fromarray(arr, "RGB").save(path, format="PNG")


PAYLOAD = "Evidence log line 1\nEvidence log line 2\n"


def test_encrypt(win):
    payload = win.files / "secret.txt"
    payload.write_text(PAYLOAD, encoding="utf-8")
    carrier = win.files / "carrier.png"
    _make_carrier(carrier)

    win._enc_payload.set_path(str(payload))
    win._enc_carrier.set_path(str(carrier))
    expected_out = str(win.files / "carrier_stego.png")
    assert os.path.normcase(win._enc_output.path()) == os.path.normcase(expected_out)
    assert win._enc_btn.isEnabled(), win._enc_hint.text()

    win._do_encrypt()
    assert idle(win)
    assert os.path.isfile(expected_out)
    assert "successfully" in win._enc_result.text()
    assert "-" in win._enc_fp_lbl.text()


def test_decrypt(win):
    stego = str(win.files / "carrier_stego.png")
    assert os.path.normcase(win._dec_stego.path()) == os.path.normcase(stego)  # auto-filled
    out_dir = win.files / "recovered"
    out_dir.mkdir()
    win._dec_output.set_path(str(out_dir))
    assert win._dec_btn.isEnabled(), win._dec_hint.text()

    win._do_decrypt()
    assert idle(win)
    assert "decrypted" in win._dec_result.text()
    recovered = out_dir / "secret.txt"
    assert recovered.read_text(encoding="utf-8") == PAYLOAD
    assert win._dec_preview.toPlainText() == PAYLOAD


def test_decrypt_with_different_signals_fails(win):
    win._apply_selection(DEVICE_BOUND - {"os_machineguid"}, None)
    win._do_decrypt()
    assert idle(win)
    assert "Authentication tag mismatch" in win._dec_result.text()
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")


def test_encrypt_blocked_when_carrier_too_small(win):
    tiny = win.files / "tiny.png"
    Image.new("RGB", (8, 8), (10, 10, 10)).save(tiny)
    good = win._enc_carrier.path()
    win._enc_carrier.set_path(str(tiny))
    assert not win._enc_btn.isEnabled()
    assert "bigger carrier" in win._enc_hint.text()
    win._enc_carrier.set_path(good)
    assert win._enc_btn.isEnabled()


# ── Forget / pair ────────────────────────────────────────────────────────────

def test_forget_pairing_blocks_token_actions(win):
    win._forget_token()
    assert win._token_cfg is None
    assert not win._enc_btn.isEnabled()
    assert not win._dec_btn.isEnabled()
    assert not win._ping_btn.isEnabled()
    assert not win._test_btn.isEnabled()
    assert "pair a hardware token" in win._enc_hint.text()


def test_failed_pairing_explains_and_opens_troubleshooting(win):
    PAIR_SHOULD_FAIL["value"] = True
    try:
        assert not win._trouble_toggle.isChecked()
        win._start_pairing()
        assert idle(win)
        assert win._token_cfg is None
        assert "not giving it enough power" in win._ping_result.text()
        assert win._trouble_toggle.isChecked()
    finally:
        PAIR_SHOULD_FAIL["value"] = False


def test_pairing_restores_everything_and_checks_bluetooth(win):
    win._start_pairing()
    assert idle(win)
    assert win._token_cfg is not None
    text = win._ping_result.text()
    assert "bound" in text and "Bluetooth link verified" in text
    assert win._enc_btn.isEnabled()
    assert win._dec_btn.isEnabled()


def test_pairing_with_bluetooth_failure_says_so(win, monkeypatch):
    def failing_ping():
        raise tc.TokenError("Could not reach the hardware token over Bluetooth.")
    monkeypatch.setattr(ui_main, "ping_token", failing_ping)
    win._start_pairing()
    assert idle(win)
    assert win._token_cfg is not None
    assert "Bluetooth check failed" in win._ping_result.text()


def test_navigation_reaches_every_page(win):
    for i in range(win._tabs.count()):
        win._tabs.setCurrentIndex(i)
        assert win._tabs.currentIndex() == i
