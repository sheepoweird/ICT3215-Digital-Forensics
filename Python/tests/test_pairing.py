"""
EnvStego — USB pairing tests (no hardware required)

Runs the real token_comms.pair_token_usb against scripted serial ports that model
the two firmwares:
  * new firmware — answers PAIR_ECDH with an encrypted (ECDH-wrapped) auth key
  * old firmware — ignores PAIR_ECDH, answers the legacy PAIR_DEVICE in plaintext

and the situations users hit: low-power restart loop, a busy port, a missing port,
a mid-pairing drop that recovers, a silent token, and a token bound to another PC.

Run from the Python/ directory:
    python -m pytest tests/test_pairing.py -v
"""

import json
import sys
from pathlib import Path

import pytest
import serial

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import token_comms as tc
from pair_crypto import new_keypair, seal_auth_key

TOKEN_ID = bytes.fromhex("f10553cd5fb8f6e0199acc61fb2f9543")
AUTH_KEY = bytes(range(32))
MAC = "84:1f:e8:67:b6:c2"


def _common(req):
    return (f";REQ={req};TOKEN_ID={TOKEN_ID.hex()};BLE_MAC={MAC};"
            f"CHAR_UUID={tc.CHARACTERISTIC_UUID};FW=3")


class Firmware:
    """Scripted serial port that answers like real firmware, keyed on the command verb."""

    def __init__(self, kind="ecdh"):
        self.kind = kind                 # "ecdh" (new) or "legacy" (old)
        self.verb = None
        self.req = None
        self.pc_pub = None
        self.closed = False
        self._tok_priv, self._tok_pub = new_keypair()

    def write(self, data: bytes):
        parts = data.decode().strip().split(":")
        self.verb = parts[0]
        self.req = parts[2] if len(parts) > 2 else None
        if self.verb == "PAIR_ECDH" and len(parts) > 3:
            self.pc_pub = bytes.fromhex(parts[3])

    def flush(self):
        pass

    def readline(self) -> bytes:
        if self.verb == "PAIR_ECDH":
            if self.kind != "ecdh":
                return b"[HW] Token is UNPAIRED. Waiting for USB handshake...\n"   # old fw: alive, silent
            enc = seal_auth_key(self._tok_priv, self._tok_pub, self.pc_pub, TOKEN_ID, AUTH_KEY)
            return (f"PAIRING_SUCCESS{_common(self.req)};MODE=ECDH;"
                    f"TOK_PUB={self._tok_pub.hex()};ENC={enc.hex()}\n").encode()
        if self.verb == "PAIR_DEVICE":
            return (f"PAIRING_SUCCESS{_common(self.req)};AUTH_KEY={AUTH_KEY.hex()}\n").encode()
        return b"\n"

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(tc, "CONFIG_FILE", tmp_path / "token_config.json")
    monkeypatch.setattr(tc, "_protect_secret", lambda secret: (secret.hex(), "none"))
    monkeypatch.setattr(tc.time, "sleep", lambda _s: None)
    monkeypatch.setattr(tc, "PAIR_WINDOW_S", 2.0)
    monkeypatch.setattr(tc, "ECDH_PROBE_S", 0.0)       # fall back quickly in the old-firmware test


def use_ports(monkeypatch, *results):
    """Each _open_port call returns (or raises) the next result; the last one repeats."""
    queue = list(results)

    def fake_open(_port):
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return item
    monkeypatch.setattr(tc, "_open_port", fake_open)


def saved_config():
    return json.loads(tc.CONFIG_FILE.read_text())


def test_ecdh_pairing_succeeds_and_recovers_auth_key(monkeypatch):
    use_ports(monkeypatch, Firmware("ecdh"))
    steps = []
    ok, msg = tc.pair_token_usb("COM3", progress=steps.append)

    assert ok, msg
    assert "F105-53CD" in msg and "bound" in msg
    cfg = saved_config()
    assert cfg["token_id"] == TOKEN_ID.hex()
    assert cfg["pairing"] == "ecdh"
    # The recovered (sealed-then-opened) auth key matches what the token sent
    assert bytes.fromhex(cfg["auth_key"]) == AUTH_KEY
    assert any("securely" in s.lower() or "encrypted" in s.lower() for s in steps)


def test_ecdh_auth_key_never_appears_in_plaintext_on_the_wire(monkeypatch):
    seen = []
    fw = Firmware("ecdh")
    real_readline = fw.readline
    fw.readline = lambda: seen.append(real_readline()) or seen[-1]
    use_ports(monkeypatch, fw)
    tc.pair_token_usb("COM3")
    wire = b"".join(seen)
    assert AUTH_KEY.hex().encode() not in wire        # the key is only ever sent encrypted
    assert b"MODE=ECDH" in wire


def test_falls_back_to_legacy_for_old_firmware(monkeypatch):
    use_ports(monkeypatch, Firmware("legacy"))
    steps = []
    ok, msg = tc.pair_token_usb("COM3", progress=steps.append)
    assert ok, msg
    assert saved_config()["pairing"] == "legacy"
    assert any("older firmware" in s.lower() or "legacy" in s.lower() for s in steps)


def test_brownout_loop_is_reported_as_a_power_problem(monkeypatch):
    class Brownout(Firmware):
        def readline(self):
            return b"Brownout detector was triggered\n"
    use_ports(monkeypatch, Brownout())
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok and msg == tc.POWER_MESSAGE
    assert not tc.CONFIG_FILE.exists()


def test_port_in_use_gives_a_plain_explanation(monkeypatch):
    busy = serial.SerialException("could not open port 'COM3': PermissionError(13, 'Access is denied.', None, 5)")
    use_ports(monkeypatch, busy)
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok and "being used by another program" in msg
    assert "Access is denied" not in msg


def test_missing_port_gives_a_plain_explanation(monkeypatch):
    gone = serial.SerialException("could not open port 'COM7': FileNotFoundError(2, 'cannot find the file', None, 2)")
    use_ports(monkeypatch, gone)
    ok, msg = tc.pair_token_usb("COM7")
    assert not ok and "not available" in msg and "plugged in" in msg


def test_connection_drop_mid_pairing_recovers(monkeypatch):
    dropped = Firmware("ecdh")
    orig = dropped.readline
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise serial.SerialException("GetOverlappedResult failed (Access is denied)")
        return orig()
    dropped.readline = flaky
    use_ports(monkeypatch, dropped)
    steps = []
    ok, msg = tc.pair_token_usb("COM3", progress=steps.append)
    assert ok, msg
    assert any("Reconnecting" in s for s in steps)


def test_silent_token_gives_next_steps(monkeypatch):
    class Silent(Firmware):
        def readline(self):
            return b"\n"
    use_ports(monkeypatch, Silent())
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok and "did not answer" in msg and "2 short flashes" in msg


def test_firmware_hkdf_formula_matches_reference():
    """The ESP32 builds HKDF from HMAC by hand (no mbedtls_hkdf). Prove that formula
    equals cryptography's HKDF(salt=None), so the two sides derive the same wrap key."""
    import hashlib
    import hmac
    import os
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    ikm, info = os.urandom(32), os.urandom(96)
    reference = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)
    # Firmware: extract with a 32-zero salt, then one expand block
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    firmware = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    assert firmware == reference


def test_token_bound_to_other_pc_is_refused(monkeypatch):
    class Refusing(Firmware):
        def readline(self):
            return f"PAIRING_REFUSED;REQ={self.req};REASON=BOUND_TO_OTHER_HOST\n".encode()
    use_ports(monkeypatch, Refusing())
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok and "different PC" in msg
