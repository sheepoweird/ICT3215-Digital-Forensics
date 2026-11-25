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
from functools import partial
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
# The module fixture answers this prompt. Keep the real dialog for its own test.
_ASK_DELETE_ORIGINALS = ui_main.MainWindow._ask_delete_originals
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


def fake_pair(_port, progress=None, should_cancel=None):
    if progress:
        progress("When the token's light stays on, press its IO0 button.")
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
    from test_vault import Token
    vault_key = Token()
    mp.setattr(ui_main.V, "create_vault", partial(ui_main.V.create_vault, key_provider=vault_key))
    mp.setattr(ui_main.V, "unlock_env", partial(ui_main.V.unlock_env, key_provider=vault_key))
    # Modal dialogs would block an offscreen run: answer every question "Yes"
    mp.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    mp.setattr(ui_main.MainWindow, "_ask_delete_originals", lambda self, count: True)
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

def test_rescan_after_first_collection_does_not_crash(win):
    # Regression: the loading label is deleted by the first populate, so a second
    # collection (Refresh) must not raise "wrapped C/C++ object ... has been deleted".
    win._on_signals_collected(fake_collect())
    win._on_signals_collected(fake_collect())
    assert len(win._signal_rows) > 0


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


def test_choosing_preset_does_not_rebuild_the_combo(win):
    # Regression: picking a preset must not clear()+rebuild the combo from inside its
    # own activated handler — that corrupted the popup so it would not reopen.
    before = win._preset_combo.count()
    idx = win._preset_combo.findData("builtin:Device-bound")
    win._on_preset_chosen(idx)                        # simulate the activated signal
    assert win._preset_combo.count() == before        # items untouched
    assert win._preset_combo.currentData() == "builtin:Device-bound"
    assert win._preset_combo.isEnabled()


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
    assert not hasattr(win, "_dec_preview")  # Recovered plaintext is not shown in the window
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
    win._enc_carriers.clear()
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
    assert len(written) == 3
    assert win._dec_split.isChecked()
    assert set(win._dec_stegos.paths()) == set(written)

    # Decrypt the whole set
    rec = win.files / "split_rec"
    rec.mkdir()
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


@pytest.mark.parametrize("extension", ["wav", "mp3"])
def test_audio_carrier_round_trip(win, extension):
    # Hide a file inside an audio carrier and recover it through the real UI flow.
    payload = win.files / "audio_secret.txt"
    msg = "hidden inside audio\n" * 20
    payload.write_text(msg, encoding="utf-8")
    carrier = win.files / f"song.{extension}"
    if extension == "mp3":
        import soundfile

        soundfile.write(carrier, np.zeros(16000, dtype=np.int16), 16000)
    else:
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

    rec = win.files / f"audio_rec_{extension}"
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
    win._enc_carriers.clear()
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


@pytest.mark.parametrize("mixed", [False, True])
def test_small_split_outputs_all_carriers_and_hands_complete_set_to_decrypt(win, tmp_path, mixed):
    payload = tmp_path / "small.txt"
    content = b"A small payload must still be split across every chosen carrier."
    payload.write_bytes(content)
    carriers = []
    for index in range(3):
        extension = ("jpg", "webp", "wav")[index] if mixed else "png"
        path = tmp_path / f"carrier_{index}.{extension}"
        if extension == "wav":
            _make_wav(path)
        else:
            pixels = np.random.default_rng(index).integers(0, 256, (200, 200, 3), dtype=np.uint8)
            Image.fromarray(pixels).save(path)
        carriers.append(str(path))
    output, recovered = tmp_path / "outputs", tmp_path / "recovered"
    output.mkdir()
    recovered.mkdir()
    try:
        win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
        win._enc_payload.set_path(str(payload))
        win._enc_split.setChecked(True)
        win._enc_carriers.clear()
        win._enc_carriers._add_paths(*carriers)
        win._enc_out_dir.set_path(str(output))
        win._do_encrypt()
        assert idle(win)
        written = {os.path.normpath(str(path)) for path in output.iterdir()}
        assert len(written) == 3, win._enc_result.text()
        assert win._dec_split.isChecked()
        assert set(win._dec_stegos.paths()) == written  # No manual handoff required.
        win._dec_output.set_path(str(recovered))
        win._apply_selection(set(), None)
        win._do_decrypt()
        assert idle(win)
        assert (recovered / payload.name).read_bytes() == content

        # A lone piece of a real multi-piece set gives an actionable missing-set error.
        win._dec_stegos.clear()
        win._dec_stegos._add_paths(next(iter(written)))
        assert win._dec_btn.isEnabled()
        win._do_decrypt()
        assert idle(win)
        assert "Incomplete set" in win._dec_result.text()
        assert len(list(recovered.iterdir())) == 1

        # A later single encryption replaces the old split selection and mode.
        win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
        win._enc_split.setChecked(False)
        win._enc_carrier.set_path(carriers[0])
        single = tmp_path / ("single.jpg" if mixed else "single.png")
        win._enc_output.set_path(str(single))
        win._do_encrypt()
        assert idle(win)
        assert single.exists()
        assert not win._dec_split.isChecked()
        assert win._dec_stego.path() == str(single)
        assert win._dec_stegos.count() == 0
    finally:
        win._enc_split.setChecked(False)
        win._dec_split.setChecked(False)
        win._enc_carriers.clear()
        win._dec_stegos.clear()
        win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
        win._dec_stego.set_path(str(win.files / "carrier_stego.png"))
        win._enc_payload.set_path(str(win.files / "secret.txt"))
        win._enc_carrier.set_path(str(win.files / "carrier.png"))
        win._enc_output.set_path(str(win.files / "carrier_stego.png"))


@pytest.mark.parametrize("as_split_set", [False, True])
def test_old_one_piece_split_output_is_recoverable(win, tmp_path, as_split_set):
    selected = [signal for signal in fake_collect() if signal.id in DEVICE_BOUND]
    env_key, _ = crypto_engine.derive_env_key(selected)
    index_key = crypto_engine.request_index_key()
    name, content = "previous_split.txt", b"recover the one file generated by the old splitter"
    salt, nonce, ciphertext = crypto_engine.encrypt_payload(
        crypto_engine.pack_payload(name, content), env_key, crypto_engine.PAYLOAD_AAD)
    blob = crypto_engine.pack_header(index_key, salt, nonce, len(ciphertext), sorted(DEVICE_BOUND)) + ciphertext
    tag = crypto_engine.pack_shard_tag(index_key, crypto_engine.new_manifest_id(), 0, 1, len(blob))
    carrier, stego = tmp_path / "carrier.png", tmp_path / "old_single_piece.png"
    _make_carrier(carrier)
    ui_main.embed_blob(str(carrier), tag + blob, str(stego), order_key=index_key)
    output = tmp_path / "recovered"
    output.mkdir()
    try:
        win._dec_split.setChecked(as_split_set)
        win._dec_stegos.clear()
        win._dec_stegos._add_paths(str(stego))
        win._dec_stego.set_path(str(stego))
        win._dec_output.set_path(str(output))
        win._apply_selection(set(), None)
        win._do_decrypt()
        assert idle(win)
        assert (output / name).read_bytes() == content, win._dec_result.text()
    finally:
        win._dec_split.setChecked(False)
        win._dec_stegos.clear()
        win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
        win._dec_stego.set_path(str(win.files / "carrier_stego.png"))


@pytest.mark.parametrize("extension", ["jpg", "webp", "bmp", "tiff"])
def test_native_image_ui_round_trip(win, tmp_path, extension):
    carrier = tmp_path / f"carrier.{extension}"
    pixels = np.random.default_rng(30).integers(0, 256, (240, 320, 3), dtype=np.uint8)
    Image.fromarray(pixels).save(carrier)
    payload = tmp_path / "document.pdf"
    content = b"%PDF-1.7\n" + bytes(range(256))
    payload.write_bytes(content)
    original = carrier.read_bytes()
    output = tmp_path / f"output.{extension}"
    recovered = tmp_path / "recovered"
    recovered.mkdir()
    try:
        win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")
        win._enc_split.setChecked(False)
        win._enc_payload.set_path(str(payload))
        win._enc_carrier.set_path(str(carrier))
        win._enc_output.set_path(str(output))
        assert win._enc_btn.isEnabled(), win._enc_hint.text()
        win._do_encrypt()
        assert idle(win)
        assert output.exists(), win._enc_result.text()
        assert carrier.read_bytes() == original
        assert win._dec_stego.path() == str(output) and not win._dec_split.isChecked()
        win._dec_output.set_path(str(recovered))
        win._apply_selection(set(), None)
        win._do_decrypt()
        assert idle(win)
        assert (recovered / payload.name).read_bytes() == content, win._dec_result.text()
    finally:
        win._enc_split.setChecked(False)
        win._dec_split.setChecked(False)
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


def test_vault_create_add_list_lock_unlock(win, monkeypatch, tmp_path):
    vdir = tmp_path / "EnvVault"
    win._vault_loc.setText(str(vdir))
    win._apply_selection(DEVICE_BOUND, "builtin:Device-bound")

    # Don't let the one-time recovery dialog or shred prompt block the offscreen run
    monkeypatch.setattr(ui_main.MainWindow, "_show_recovery_code", lambda self, code: None)

    win._vault_create()
    assert idle(win)
    assert win._vault is not None and win._vault.count() == 0
    assert ui_main.V.is_vault(str(vdir))

    # Add a file (choose Keep in the originals prompt)
    src = tmp_path / "secret_note.txt"
    src.write_text("vault body content", encoding="utf-8")
    monkeypatch.setattr(ui_main.QFileDialog, "getOpenFileNames",
                        staticmethod(lambda *a, **k: ([str(src)], "")))
    monkeypatch.setattr(ui_main.MainWindow, "_ask_delete_originals", lambda self, count: False)
    win._vault_add_files()
    assert idle(win)
    assert win._vault.count() == 1
    assert win._vault_table.rowCount() == 1
    assert src.exists()                                   # original kept

    # Drag-and-drop path: a list of files goes straight in (no file dialog).
    drop = tmp_path / "dropped.txt"
    drop.write_text("dropped content", encoding="utf-8")
    win._vault_add_files([str(drop)])
    assert idle(win)
    assert win._vault.count() == 2 and win._vault_table.rowCount() == 2

    assert not hasattr(win, "_vault_open_btn")
    assert not hasattr(win._vault, "read_bytes")

    # Lock, then unlock again with the token+environment
    win._vault_do_lock("locked for test")
    assert win._vault is None
    win._vault_unlock()
    assert idle(win)
    assert win._vault is not None and win._vault.count() == 2   # both files survive re-unlock




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


def test_vault_auto_locks_when_idle_even_with_token_in_range(win, tmp_path):
    session, _ = ui_main.V.create_vault(str(tmp_path / "vault"), bytes(32), bytes(32), [])
    win._vault = session
    win._start_vault_heartbeat()
    win._vault_heartbeat_tick()
    assert idle(win) and wait_until(lambda: win._vault_heartbeat_worker is None)
    assert win._vault is session                          # recent activity: stays open

    win._vault_last_used -= ui_main.VAULT_IDLE_LOCK_S
    win._busy = True
    try:
        win._vault_heartbeat_tick()                       # a running action counts as activity
        assert win._vault is session
    finally:
        win._busy = False

    win._vault_last_used -= ui_main.VAULT_IDLE_LOCK_S
    win._vault_heartbeat_tick()
    assert win._vault is None and not session.unlocked
    assert "without vault activity" in win._vault_result.text()


@pytest.mark.parametrize("message,wparam,reason", [
    (ui_main.WM_WTSSESSION_CHANGE, ui_main.WTS_SESSION_LOCK, "Windows was locked"),
    (ui_main.WM_WTSSESSION_CHANGE, ui_main.WTS_SESSION_LOGOFF, "Windows was locked"),
    (ui_main.WM_POWERBROADCAST, ui_main.PBT_APMSUSPEND, "sleep or hibernate"),
    (ui_main.WM_QUERYENDSESSION, 0, "signing out or shutting down"),
])
def test_vault_locks_when_windows_locks_sleeps_or_ends_the_session(win, tmp_path, message, wparam, reason):
    session, _ = ui_main.V.create_vault(str(tmp_path / "vault"), bytes(32), bytes(32), [])
    win._vault = session
    win._on_windows_message(0x0400, 0)                    # an unrelated message changes nothing
    assert win._vault is session
    win._on_windows_message(message, wparam)
    assert win._vault is None and not session.unlocked
    assert reason in win._vault_result.text()


def test_closing_the_originals_prompt_keeps_the_originals(win, monkeypatch):
    shown = []

    def close_without_choosing(box):
        shown.append([button.text() for button in box.buttons()])
        return 0

    monkeypatch.setattr(ui_main.QMessageBox, "exec", close_without_choosing)
    assert _ASK_DELETE_ORIGINALS(win, 2) is False
    assert sorted(shown[0]) == ["Delete", "Keep"]


def test_vault_ui_export_and_recovery_require_explicit_file_action(win, monkeypatch, tmp_path):
    vdir, output = tmp_path / "vault", tmp_path / "output"
    output.mkdir()
    session, code = ui_main.V.create_vault(str(vdir), bytes(32), bytes(32), ["hw_cpu"])
    session.add_bytes("document.pdf", b"selected plaintext")
    win._vault_loc.setText(str(vdir))
    win._vault = session
    win._populate_vault_table()
    win._vault_table.selectRow(0)
    monkeypatch.setattr(ui_main.QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(ui_main.QFileDialog, "getExistingDirectory", lambda *a, **k: str(output))
    win._vault_export_selected()
    assert idle(win)
    assert (output / "document.pdf").read_bytes() == b"selected plaintext"
    win._vault_do_lock("test recovery")
    prompts = []

    def enter_code(*args, **kwargs):
        prompts.append(args)
        assert args[-1] == ui_main.QLineEdit.EchoMode.Password
        return code, True

    monkeypatch.setattr(ui_main.QInputDialog, "getText", enter_code)
    win._vault_unlock_recovery()
    assert win._vault.recovery and code not in win._vault.__dict__.values()
    win._vault_table.selectRow(0)
    win._vault_export_selected()
    assert idle(win)
    assert len(prompts) == 2  # Browsing recovery does not authorize a later export.
    assert (output / "document (1).pdf").read_bytes() == b"selected plaintext"
    win._vault_do_lock("test complete")


def test_ui_submits_one_export_for_multiple_rows(win, monkeypatch, tmp_path):
    session, _ = ui_main.V.create_vault(str(tmp_path / "vault"), bytes(32), bytes(32), ["hw_cpu"])
    blobs = {session.add_bytes(name, name.encode())["blob"] for name in ("one", "two", "three")}
    win._vault = session
    win._populate_vault_table()
    win._vault_table.selectAll()
    calls = []
    export_many = session.export_many
    def export(selection, *args, **kwargs):
        calls.append(set(selection))
        return export_many(selection, *args, **kwargs)
    monkeypatch.setattr(session, "export_many", export)
    monkeypatch.setattr(ui_main.QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(ui_main.QFileDialog, "getExistingDirectory", lambda *a, **k: str(tmp_path))
    win._vault_export_selected()
    assert idle(win)
    assert calls == [blobs]
    assert all((tmp_path / name).read_bytes() == name.encode() for name in ("one", "two", "three"))
    win._vault_do_lock("done")


def test_vault_has_no_migration_action(win):
    assert not hasattr(win, "_vault_upgrade_btn")
    assert not hasattr(win, "_vault_upgrade")


def test_old_heartbeat_result_does_not_cancel_a_file_approval_wait(win):
    session = object()
    win._vault = session
    win._busy = True
    try:
        win._on_vault_heartbeat(session, False, "Another Bluetooth operation is in progress")
        assert win._vault is session
    finally:
        win._vault = None
        win._busy = False



def test_vault_reports_originals_that_could_not_be_shredded(win, monkeypatch, tmp_path):
    import winutils

    v, _ = ui_main.V.create_vault(str(tmp_path / "vault"), bytes(32), bytes(32), [])
    win._vault = v
    source = tmp_path / "still-plaintext.txt"
    source.write_bytes(b"sample")
    monkeypatch.setattr(winutils, "shred_file", lambda _: False)
    win._vault_add_files([str(source)])
    assert idle(win)
    assert source.exists() and v.count() == 1
    assert "still-plaintext.txt" in win._vault_result.text()
    assert "Plaintext may remain" in win._vault_result.text()
    win._vault_do_lock("test complete")




def test_partial_import_updates_reachability_and_lists_outcomes(win, tmp_path):
    session, _ = ui_main.V.create_vault(str(tmp_path / "vault"), bytes(32), bytes(32), [])
    win._vault = session
    win._note_token_result(True)
    win._on_vault_added(session, ["one", "two", "three"],
                        [{"shred_status": "shredded"}, {"shred_status": "kept"},
                         {"error": "Device not found", "unreachable": True}])
    assert win._token_reachable is False
    assert "Added 2 file(s)" in win._vault_result.text()
    assert "Device not found" in win._vault_result.text()
    win._vault_do_lock("test done")


def test_vault_heartbeat_retries_only_transient_errors(monkeypatch):
    failures = iter([tc.TokenTransientError("temporary"), None, tc.TokenAuthError("wrong token")])
    attempts, results = [], []

    def ping():
        attempts.append(True)
        failure = next(failures)
        if failure is not None:
            raise failure

    monkeypatch.setattr(ui_main, "ping_token", ping)
    worker = ui_main.VaultHeartbeatWorker()
    worker.result.connect(lambda ok, msg: results.append((ok, msg)))
    worker.run()
    worker.run()
    assert len(attempts) == 3
    assert results == [(True, ""), (False, "wrong token")]


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


# ── Token firmware install / update ──────────────────────────────

def _firmware_plan(mode, running=8):
    import firmware_flasher as ff
    bundle = ff.Bundle(board="esp32s3", version=9, flash_size_mb=16, segments=[], app_offset=0x10000)
    return ff.FlashPlan("COM9", "ESP32-S3", bundle, 16, mode, running, [],
                        reason="" if mode else "The board's partition table has no NVS key storage.")


def test_firmware_update_keeps_keys_and_reports_new_version(win, monkeypatch):
    calls = []
    monkeypatch.setattr(ui_main, "inspect_token", lambda port, status: _firmware_plan("update"))
    monkeypatch.setattr(ui_main, "flash_token",
                        lambda plan, erase, status, progress: calls.append((plan.mode, erase)) or {"FW": "9"})
    win._start_firmware(erase=False)
    assert idle(win)
    assert calls == [("update", False)]
    text = win._fw_result.text()
    assert "v9 is installed" in text and "keys and pairing were kept" in text
    assert win._fw_btn.isEnabled() and win._fw_progress.isHidden()


def test_firmware_unknown_layout_is_not_flashed(win, monkeypatch):
    calls = []
    monkeypatch.setattr(ui_main, "inspect_token", lambda port, status: _firmware_plan(None))
    monkeypatch.setattr(ui_main, "flash_token", lambda *a, **k: calls.append(a))
    win._start_firmware(erase=False)
    assert idle(win)
    assert calls == []
    assert "no NVS" in win._fw_result.text() and "Erase and start fresh" in win._fw_result.text()


def test_firmware_erase_needs_typed_confirmation(win, monkeypatch):
    calls = []
    monkeypatch.setattr(ui_main, "inspect_token", lambda port, status: _firmware_plan("update"))
    monkeypatch.setattr(ui_main, "flash_token",
                        lambda plan, erase, status, progress: calls.append(erase) or {"FW": "9"})
    monkeypatch.setattr(ui_main.QInputDialog, "getText", staticmethod(lambda *a, **k: ("erase it", True)))
    win._start_firmware(erase=True)
    assert idle(win)
    assert calls == [] and "Nothing was erased" in win._fw_result.text()

    monkeypatch.setattr(ui_main.QInputDialog, "getText", staticmethod(lambda *a, **k: ("ERASE", True)))
    win._start_firmware(erase=True)
    assert idle(win)
    assert calls == [True]
    assert "Forget pairing" in win._fw_result.text()      # this PC's pairing no longer matches


def test_firmware_failure_is_shown(win, monkeypatch):
    import firmware_flasher as ff

    def fail(port, status):
        raise ff.FlashError("The token did not enter download mode.")
    monkeypatch.setattr(ui_main, "inspect_token", fail)
    win._start_firmware(erase=False)
    assert idle(win)
    assert "download mode" in win._fw_result.text()
