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
    # Default this suite to privacy off, so its path-based assertions see remembered
    # paths and next-to-carrier output. A dedicated test toggles privacy on.
    seed = QSettings(str(ini), QSettings.Format.IniFormat)
    seed.setValue("privacy/mode", False)
    seed.sync()

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
    assert win._tabs.count() == 6
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


def test_recommended_preset_selects_a_strong_readable_set(win):
    win._apply_selection(set(), None)          # start empty
    idx = win._preset_combo.findData("builtin:Recommended")
    assert idx >= 0                            # Recommended is a built-in preset
    win._on_preset_chosen(idx)
    # Only readable signals, more than one, and never the unreadable ones.
    assert len(win._selected_ids) >= 2
    assert "net_bssid" not in win._selected_ids and "hw_battery" not in win._selected_ids
    chosen = [s for s in win._all_signals if s.id in win._selected_ids]
    assert all(s.available and s.value for s in chosen)
    assert crypto_engine.assess_selection(chosen)[0] == "ok"
    assert win._active_preset == "builtin:Recommended"
    assert win._test_btn.isEnabled()


def test_signal_rows_sorted_by_stability_within_category(win):
    # Steadiest signals appear first within each category.
    by_cat = {}
    for row in win._signal_rows:
        by_cat.setdefault(row.signal.category, []).append(row.signal.stability)
    for cat, stabs in by_cat.items():
        assert stabs == sorted(stabs, reverse=True), f"{cat} not sorted: {stabs}"


def test_stability_display_maps_to_words_and_colours():
    assert ui_main._stability_display(10)[0] == "Stable"
    assert ui_main._stability_display(8)[0] == "Stable"
    assert ui_main._stability_display(7)[0] == "May change"
    assert ui_main._stability_display(5)[0] == "May change"
    assert ui_main._stability_display(4)[0] == "Volatile"
    assert ui_main._stability_display(10)[1] == "#3fb950"   # green
    assert ui_main._stability_display(3)[1] == "#f85149"    # red


def test_category_collapse_toggles_and_is_remembered(win):
    # Collapsing a category records it; the state persists for the next rebuild.
    assert "Hardware" not in win._collapsed_cats
    win._collapsed_cats.add("Hardware")
    win._populate_signal_rows(win._all_signals)          # rebuild with Hardware collapsed
    assert "Hardware" in win._collapsed_cats             # still remembered
    win._collapsed_cats.discard("Hardware")


def test_test_key_reports_fingerprint(win):
    win._test_key()
    assert idle(win)
    first = win._fp_lbl.text()
    assert "-" in first and "error" not in first.lower()
    win._test_key()
    assert idle(win)
    assert "stable" in win._fp_lbl.text()


def test_test_key_names_the_signal_that_changed(win, monkeypatch):
    # Baseline with a stable environment
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._test_key()
    assert idle(win)

    # Now one selected signal's live value changes (as a Wi-Fi toggle would do)
    def changed_collect():
        rows = []
        for i, n, c, s, v in FAKE_SIGNALS:
            if i == "hw_disk":
                v = "WD-WXQ2E20653H3-MOVED"
            rows.append(EnvSignal(id=i, name=n, category=c, description=f"{n} (test)",
                                  stability=s, value=v, available=v is not None,
                                  error=None if v else "not present"))
        return rows

    monkeypatch.setattr(ui_main, "collect_all_signals", changed_collect)
    win._test_key()
    assert idle(win)
    label = win._fp_lbl.text()
    assert "changed" in label.lower()
    assert "Primary Disk Serial" in label                 # the exact signal is named
    tip = win._fp_lbl.toolTip()
    assert "WD-WXQ2E20653H3" in tip and "MOVED" in tip     # old -> new shown in the tooltip

    # Restore baseline collection for later tests
    monkeypatch.undo()
    win._test_key()
    assert idle(win)


# ── Encrypt / decrypt ────────────────────────────────────────────────────────

def _make_carrier(path):
    x = np.arange(200, dtype=np.uint8)
    arr = np.dstack([np.tile(x, (200, 1)), np.tile(x.reshape(200, 1), (1, 200)),
                     np.full((200, 200), 90, np.uint8)])
    Image.fromarray(arr, "RGB").save(path, format="PNG")


def _make_wav(path, seconds=1.0, rate=44100, channels=2):
    import wave
    n = int(seconds * rate) * channels
    sig = (np.sin(np.linspace(0, 300 * np.pi, n)) * 8000).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(sig.tobytes())


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
    # v3 images carry their own signal list, so no manual selection is required
    win._apply_selection(set(), None)
    assert win._dec_btn.isEnabled(), win._dec_hint.text()

    win._do_decrypt()
    assert idle(win)
    assert "decrypted" in win._dec_result.text()
    recovered = out_dir / "secret.txt"
    assert recovered.read_text(encoding="utf-8") == PAYLOAD
    assert win._dec_preview.toPlainText() == PAYLOAD
    # The signals the image used are reflected back on the Signals page
    assert win._selected_ids == DEVICE_BOUND


def test_folder_round_trip(win):
    # Build a small folder, hide it, then decrypt and confirm it is restored
    src = win.files / "evidence_set"
    src.mkdir()
    (src / "note.txt").write_text("chain of custody", encoding="utf-8")
    (src / "sub").mkdir()
    (src / "sub" / "pic.bin").write_bytes(bytes(range(64)))

    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._enc_payload.set_path(str(src))
    carrier = win.files / "folder_carrier.png"
    _make_carrier(carrier)
    win._enc_carrier.set_path(str(carrier))
    out_png = win.files / "folder_stego.png"
    win._enc_output.set_path(str(out_png))
    assert win._enc_btn.isEnabled(), win._enc_hint.text()
    win._do_encrypt()
    assert idle(win)
    assert "folder, zipped" in win._enc_result.text()

    # Decrypt into a fresh folder
    rec = win.files / "rec"
    rec.mkdir()
    win._dec_stego.set_path(str(out_png))
    win._dec_output.set_path(str(rec))
    win._apply_selection(set(), None)        # v3 auto-selects from header
    win._do_decrypt()
    assert idle(win)
    assert "folder" in win._dec_result.text()
    assert (rec / "evidence_set" / "note.txt").read_text(encoding="utf-8") == "chain of custody"
    assert (rec / "evidence_set" / "sub" / "pic.bin").read_bytes() == bytes(range(64))
    # Restore the shared state the later tests expect
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._dec_stego.set_path(str(win.files / "carrier_stego.png"))
    win._enc_payload.set_path(str(win.files / "secret.txt"))
    win._enc_carrier.set_path(str(win.files / "carrier.png"))
    win._enc_output.set_path(str(win.files / "carrier_stego.png"))


def test_multi_image_split_round_trip(win):
    # A payload bigger than one small carrier, split across three images and rejoined.
    payload = win.files / "big.bin"
    # ~30 KB: too big for one 200×200 carrier (~15 KB), fits across three.
    payload.write_bytes(bytes((i * 7) % 256 for i in range(30_000)))

    carriers = []
    for i in range(3):
        c = win.files / f"split_carrier_{i}.png"
        _make_carrier(c)                     # 200×200 ≈ 15 KB usable each
        carriers.append(str(c))

    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._enc_payload.set_path(str(payload))
    win._enc_split.setChecked(True)
    for c in carriers:
        win._enc_carriers._add_paths(c)      # test helper: add without a dialog
    out_dir = win.files / "split_out"
    out_dir.mkdir()
    win._enc_out_dir.set_path(str(out_dir))
    assert win._enc_btn.isEnabled(), win._enc_hint.text()

    win._do_encrypt()
    assert idle(win)
    assert "split" in win._enc_result.text()
    written = sorted(str(p) for p in out_dir.glob("*_stego.png"))
    assert len(written) >= 2                  # spilled across multiple carriers

    # Decrypt the whole set
    rec = win.files / "split_rec"
    rec.mkdir()
    win._dec_split.setChecked(True)
    for p in written:
        win._dec_stegos._add_paths(p)
    win._dec_output.set_path(str(rec))
    win._apply_selection(set(), None)         # v3 auto-selects from header
    win._do_decrypt()
    assert idle(win)
    assert "decrypted" in win._dec_result.text()
    assert (rec / "big.bin").read_bytes() == payload.read_bytes()

    # Restore shared state for the tests that follow
    win._enc_split.setChecked(False)
    win._dec_split.setChecked(False)
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._dec_stego.set_path(str(win.files / "carrier_stego.png"))
    win._enc_payload.set_path(str(win.files / "secret.txt"))
    win._enc_carrier.set_path(str(win.files / "carrier.png"))
    win._enc_output.set_path(str(win.files / "carrier_stego.png"))


def test_audio_wav_carrier_round_trip(win):
    # Hide a file inside a WAV carrier and recover it through the real UI flow.
    payload = win.files / "audio_secret.txt"
    msg = "hidden inside audio\n" * 20
    payload.write_text(msg, encoding="utf-8")
    carrier = win.files / "song.wav"
    _make_wav(carrier)

    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._enc_payload.set_path(str(payload))
    win._enc_carrier.set_path(str(carrier))
    # Output should default to a .wav next to the carrier, not .png
    assert win._enc_output.path().lower().endswith(".wav"), win._enc_output.path()
    out_wav = win._enc_output.path()
    assert win._enc_btn.isEnabled(), win._enc_hint.text()

    win._do_encrypt()
    assert idle(win)
    assert "successfully" in win._enc_result.text()
    assert os.path.isfile(out_wav)

    rec = win.files / "audio_rec"
    rec.mkdir()
    win._dec_stego.set_path(out_wav)
    win._dec_output.set_path(str(rec))
    win._apply_selection(set(), None)         # v3 auto-selects from header
    win._do_decrypt()
    assert idle(win)
    assert "decrypted" in win._dec_result.text()
    assert (rec / "audio_secret.txt").read_text(encoding="utf-8") == msg

    # Restore shared state for the tests that follow
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._dec_stego.set_path(str(win.files / "carrier_stego.png"))
    win._enc_payload.set_path(str(win.files / "secret.txt"))
    win._enc_carrier.set_path(str(win.files / "carrier.png"))
    win._enc_output.set_path(str(win.files / "carrier_stego.png"))


def test_single_shard_decrypt_suggests_split_mode(win):
    # Encrypt split across 2 carriers, then try to decrypt just ONE without split mode.
    payload = win.files / "shard_probe.bin"
    payload.write_bytes(bytes((i * 3) % 256 for i in range(25_000)))
    carriers = []
    for i in range(2):
        c = win.files / f"probe_carrier_{i}.png"
        _make_carrier(c)
        carriers.append(str(c))

    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._enc_payload.set_path(str(payload))
    win._enc_split.setChecked(True)
    for c in carriers:
        win._enc_carriers._add_paths(c)
    out_dir = win.files / "probe_out"
    out_dir.mkdir()
    win._enc_out_dir.set_path(str(out_dir))
    win._do_encrypt()
    assert idle(win)
    written = sorted(str(p) for p in out_dir.glob("*_stego.png"))
    assert len(written) == 2

    # Now decrypt only one piece, single-image mode -> should point to split mode
    win._enc_split.setChecked(False)
    win._dec_split.setChecked(False)
    win._dec_stego.set_path(written[0])
    win._apply_selection(set(), None)
    win._do_decrypt()
    assert idle(win)
    assert "split across" in win._dec_result.text().lower()

    # Restore shared state
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._dec_stego.set_path(str(win.files / "carrier_stego.png"))
    win._enc_payload.set_path(str(win.files / "secret.txt"))
    win._enc_carrier.set_path(str(win.files / "carrier.png"))
    win._enc_output.set_path(str(win.files / "carrier_stego.png"))


def test_token_chip_tracks_reachability(win, monkeypatch):
    win._token_reachable = None
    win._refresh_token_chip()
    assert "Paired" in win._token_chip.text()          # paired, not yet contacted

    win._start_ping()
    assert idle(win)
    assert "Connected" in win._token_chip.text()

    def offline():
        raise ui_main.TokenError(f"{ui_main.TOKEN_UNREACHABLE_HINT} Is it powered on and in range?")
    monkeypatch.setattr(ui_main, "ping_token", offline)
    win._start_ping()
    assert idle(win)
    assert "Not in range" in win._token_chip.text()

    # A failure that is not about connectivity (the token answered) leaves it alone
    win._note_token_result(False, "Decryption failed — Authentication tag mismatch")
    assert "Not in range" in win._token_chip.text()

    monkeypatch.undo()
    win._start_ping()
    assert idle(win)
    assert "Connected" in win._token_chip.text()


def test_decrypt_key_card_says_signals_come_from_the_image(win):
    win._apply_selection(set(), None)
    text = win._dec_key_lbl.text()
    assert "read from the image" in text
    assert "No signals selected" not in text           # no misleading warning on Decrypt
    assert "No signals selected" in win._enc_key_lbl.text()   # Encrypt still warns
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")


def test_signal_rows_fit_without_clipping(win):
    win.resize(1200, 800)
    win._tabs.setCurrentIndex(win.TAB_SIGNALS)
    loop = QEventLoop()
    for _ in range(5):
        loop.processEvents()
    rows = [r for r in win._signal_rows if r.isVisible()]
    assert rows
    for row in rows:
        badge = row._badge
        assert badge.geometry().right() <= row.width(), (
            f"{row._signal.id}: badge ends at {badge.geometry().right()} > row width {row.width()}")


def test_panic_lock_locks_the_vault(win):
    class _FakeVault:
        def lock(self): pass
        def count(self): return 0
        def total_bytes(self): return 0
    win._vault = _FakeVault()
    win._panic_lock()                 # Ctrl+Shift+L handler
    assert win._vault is None
    win._panic_lock()                 # no-op when already locked (no error)


def test_vault_empty_state_shows_howto(win, tmp_path):
    # With no vault yet, the "how it works" intro is shown; once a vault is open
    # it gives way to the file table.
    win._vault = None
    win._vault_loc.setText(str(tmp_path / "no_vault_here"))
    win._refresh_vault_ui()
    assert not win._vault_howto.isHidden()

    class _FakeVault:
        def count(self): return 0
        def total_bytes(self): return 0
    win._vault = _FakeVault()
    win._refresh_vault_ui()
    assert win._vault_howto.isHidden()
    win._vault = None
    win._refresh_vault_ui()


def test_vault_create_add_open_lock_unlock(win, monkeypatch, tmp_path):
    vdir = tmp_path / "EnvVault"
    win._vault_loc.setText(str(vdir))
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")

    # Don't let the one-time recovery dialog or shred prompt block the offscreen run
    monkeypatch.setattr(ui_main.MainWindow, "_show_recovery_code", lambda self, code: None)

    win._vault_create()
    assert idle(win)
    assert win._vault is not None and win._vault.count() == 0
    assert ui_main.V.is_vault(str(vdir))

    # Add a file (keep the original: answer "No" to the shred prompt)
    src = tmp_path / "secret_note.txt"
    src.write_text("vault body content", encoding="utf-8")
    monkeypatch.setattr(ui_main.QFileDialog, "getOpenFileNames",
                        staticmethod(lambda *a, **k: ([str(src)], "")))
    monkeypatch.setattr(ui_main.QMessageBox, "question",
                        staticmethod(lambda *a, **k: ui_main.QMessageBox.StandardButton.No))
    win._vault_add_files()
    assert idle(win)
    assert win._vault.count() == 1
    assert win._vault_table.rowCount() == 1
    assert src.exists()                                   # original kept (said No)

    # Drag-and-drop path: a list of files goes straight in (no file dialog).
    drop = tmp_path / "dropped.txt"
    drop.write_text("dropped content", encoding="utf-8")
    win._vault_add_files([str(drop)])
    assert idle(win)
    assert win._vault.count() == 2 and win._vault_table.rowCount() == 2

    # Open in the in-memory viewer (don't actually exec a modal)
    opened = {}
    class FakeViewer:
        def __init__(self, name, data, parent=None): opened["name"], opened["data"] = name, data
        def exec(self): return 0
    monkeypatch.setattr(ui_main, "VaultViewer", FakeViewer)
    win._vault_table.selectRow(0)
    win._vault_open_selected()
    assert idle(win)
    assert opened == {"name": "secret_note.txt", "data": b"vault body content"}

    # Lock, then unlock again with the token+environment
    win._vault_do_lock("locked for test")
    assert win._vault is None
    win._vault_unlock()
    assert idle(win)
    assert win._vault is not None and win._vault.count() == 2   # both files survive re-unlock


def test_vault_viewer_decodes_jpeg(win, tmp_path):
    # Regression: QPixmap.loadFromData can't decode JPEG without Qt's plugin;
    # the viewer must fall back to Pillow and show the image, not "can't preview".
    import io
    arr = (np.random.rand(60, 80, 3) * 255).astype("uint8")
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="JPEG")
    jpeg = buf.getvalue()

    pm = ui_main.VaultViewer._pixmap_from(jpeg)
    assert pm is not None and not pm.isNull()
    assert pm.width() == 80 and pm.height() == 60


def test_vault_viewer_downscales_huge_images(win):
    # Regression: a large image must be capped (Qt's 256 MB allocation limit / memory).
    import io
    arr = (np.random.rand(600, 9000, 3) * 255).astype("uint8")   # 9000 px wide
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    pm = ui_main.VaultViewer._pixmap_from(buf.getvalue())
    assert pm is not None and not pm.isNull()
    assert max(pm.width(), pm.height()) <= ui_main.VaultViewer.MAX_DIM


def test_vault_auto_locks_when_token_unreachable(win, monkeypatch, tmp_path):
    vdir = tmp_path / "EnvVault2"
    win._vault_loc.setText(str(vdir))
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    monkeypatch.setattr(ui_main.MainWindow, "_show_recovery_code", lambda self, code: None)
    win._vault_create()
    assert idle(win)
    assert win._vault is not None

    # Token drops off: the heartbeat should auto-lock the vault
    def gone():
        raise ui_main.TokenError(f"{ui_main.TOKEN_UNREACHABLE_HINT} Is it powered on and in range?")
    monkeypatch.setattr(ui_main, "ping_token", gone)
    win._vault_heartbeat_tick()
    assert wait_until(lambda: win._vault is None)         # heartbeat thread locks it
    assert "Auto-locked" in win._vault_result.text()


def test_multi_picker_drop_filters_non_carriers(win):
    png = win.files / "drop_ok.png"
    _make_carrier(png)
    wav = win.files / "drop_ok.wav"
    _make_wav(wav)
    txt = win.files / "drop_bad.txt"
    txt.write_text("nope", encoding="utf-8")
    folder = win.files / "drop_folder"
    folder.mkdir()

    win._enc_carriers.clear()
    win._enc_carriers._on_dropped([str(png), str(wav), str(txt), str(folder)])
    added = [os.path.basename(p) for p in win._enc_carriers.paths()]
    assert set(added) == {"drop_ok.png", "drop_ok.wav"}    # txt + folder rejected
    win._enc_carriers.clear()


def test_inspector_redaction_masks_values(win):
    win._tabs.setCurrentIndex(win.TAB_INSPECTOR)
    win._inspector_redact.setChecked(False)
    # Find a row with a real value and remember it
    table = win._inspector_table
    plain = None
    for r in range(table.rowCount()):
        val = table.item(r, 5).text()
        if val and not val.startswith("[N/A]"):
            plain = (r, val)
            break
    assert plain is not None, "no available signal value to test"

    win._inspector_redact.setChecked(True)
    masked = table.item(plain[0], 5).text()
    assert "•" in masked
    assert masked != plain[1]
    if len(plain[1]) > 6:
        assert plain[1] not in masked            # the full value is not exposed

    win._inspector_redact.setChecked(False)      # restore
    assert "•" not in table.item(plain[0], 5).text()


def test_decrypt_fails_when_environment_changed(win, monkeypatch):
    # A signal the image needs is no longer readable here -> environment mismatch
    def changed_env():
        out = []
        for sig in fake_collect():
            if sig.id == "os_machineguid":
                sig.value, sig.available = None, False
            out.append(sig)
        return out
    monkeypatch.setattr(ui_main, "collect_all_signals", changed_env)
    win._do_decrypt()
    assert idle(win)
    assert "Environment mismatch" in win._dec_result.text()


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


def test_portable_mode_blocks_network_signals(win):
    win._apply_selection(set(), None)
    # Off: a network signal can be selected
    win._portable_cb.setChecked(False)
    win._apply_selection({"hw_cpu", "net_gatewaymac"}, None)
    assert "net_gatewaymac" in win._selected_ids

    # On: network signals are dropped and can no longer be selected
    win._portable_cb.setChecked(True)
    assert "net_gatewaymac" not in win._selected_ids
    assert "hw_cpu" in win._selected_ids
    win._apply_selection({"hw_cpu", "hw_disk", "net_bssid"}, None)
    assert "net_bssid" not in win._selected_ids
    # The network rows are shown disabled
    net_rows = [r for r in win._signal_rows if r.signal.category == "Network"]
    assert net_rows and all(not r._cb.isEnabled() for r in net_rows)
    # Hardware rows stay enabled (when readable)
    hw_rows = [r for r in win._signal_rows if r.signal.category == "Hardware" and r.readable]
    assert all(r._cb.isEnabled() for r in hw_rows)

    win._portable_cb.setChecked(False)
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")


def test_privacy_mode_purges_remembered_paths_immediately(win):
    # Simulate stale paths left in settings by an earlier (e.g. crashed) session
    win._privacy_cb.setChecked(False)
    win._settings.setValue("enc/payload", r"C:\secret\leak.txt")
    win._settings.setValue("dec/stego", r"C:\secret\hidden.png")
    win._settings.setValue("files/last_dir", r"C:\secret")

    win._privacy_cb.setChecked(True)      # turning privacy on must clear them now
    for key in ("enc/payload", "enc/carrier", "enc/output", "dec/stego",
                "dec/output_dir", "files/last_dir"):
        assert not win._settings.value(key, ""), f"{key} still stored"
    win._privacy_cb.setChecked(False)


def test_privacy_mode_changes_output_defaults_and_timestamp_flag(win, monkeypatch):
    from winutils import pictures_dir
    captured = {}
    real_worker = ui_main.EncryptWorker

    def spy(*args, **kwargs):
        captured["match_timestamps"] = kwargs.get("match_timestamps")
        w = real_worker(*args, **kwargs)
        return w
    monkeypatch.setattr(ui_main, "EncryptWorker", spy)

    win._privacy_cb.setChecked(True)
    assert win._privacy is True

    # New carrier now suggests an output inside the Pictures folder
    carrier = win.files / "beach.png"
    _make_carrier(carrier)
    win._enc_output.set_path("")
    win._enc_output_auto = True
    win._enc_carrier.set_path(str(carrier))
    assert os.path.normcase(os.path.dirname(win._enc_output.path())) == os.path.normcase(pictures_dir())

    # Encrypt passes match_timestamps=True while privacy mode is on
    payload = win.files / "p.txt"
    payload.write_text("hi", encoding="utf-8")
    win._enc_payload.set_path(str(payload))
    win._enc_output.set_path(str(win.files / "out.png"))
    assert win._enc_btn.isEnabled(), win._enc_hint.text()
    win._do_encrypt()
    assert idle(win)
    assert captured["match_timestamps"] is True
    win._privacy_cb.setChecked(False)


def test_shred_button_appears_and_wipes_original(win, monkeypatch):
    # Runs last: it deletes its own payload, so it must not disturb shared state
    payload = win.files / "to_shred.txt"
    payload.write_text("delete me", encoding="utf-8")
    carrier = win.files / "carrier2.png"
    _make_carrier(carrier)
    win._privacy_cb.setChecked(False)
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
    win._enc_payload.set_path(str(payload))
    win._enc_carrier.set_path(str(carrier))
    win._enc_output.set_path(str(win.files / "shred_out.png"))
    win._do_encrypt()
    assert idle(win)

    # The shred button appears after a successful encrypt (isHidden reflects our
    # setVisible intent regardless of which page is current in the stack)
    assert not win._enc_shred_btn.isHidden()
    monkeypatch.setattr(QMessageBox, "warning",
                        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    win._shred_original()
    assert not payload.exists()               # original overwritten + deleted
    assert win._enc_shred_btn.isHidden()
    assert os.path.isfile(str(win.files / "shred_out.png"))   # stego copy kept
