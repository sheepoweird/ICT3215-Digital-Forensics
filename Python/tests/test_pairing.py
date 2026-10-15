"""
EnvStego — USB pairing tests (no hardware required)

Runs the real token_comms.pair_token_usb against a scripted serial port, covering
the situations users actually hit: the token answering, a token stuck restarting
from low USB power, a port held by another program, a missing port, a connection
that drops mid-pairing and recovers, and a token that never answers.

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

TOKEN_ID = "f10553cd5fb8f6e0199acc61fb2f9543"
AUTH_KEY = "11" * 32
REPLY = object()          # placeholder: answer with a PAIRING_SUCCESS for the current request


class FakePort:
    """Scripted serial port: each readline() returns (or raises) the next script item."""

    def __init__(self, script):
        self.script = list(script)
        self.request_id = None
        self.closed = False

    def write(self, data: bytes):
        parts = data.decode().strip().split(":")
        self.request_id = parts[2]

    def flush(self):
        pass

    def readline(self) -> bytes:
        item = self.script.pop(0) if self.script else ""
        if isinstance(item, Exception):
            raise item
        if item is REPLY:
            item = (f"PAIRING_SUCCESS;REQ={self.request_id};TOKEN_ID={TOKEN_ID};AUTH_KEY={AUTH_KEY};"
                    f"BLE_MAC=84:1f:e8:67:b6:c2;CHAR_UUID={tc.CHARACTERISTIC_UUID};FW=2")
        return (item + "\n").encode()

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(tc, "CONFIG_FILE", tmp_path / "token_config.json")
    monkeypatch.setattr(tc, "_protect_secret", lambda secret: (secret.hex(), "none"))
    monkeypatch.setattr(tc.time, "sleep", lambda _s: None)
    monkeypatch.setattr(tc, "PAIR_WINDOW_S", 2.0)


def use_ports(monkeypatch, *results):
    """Each call to _open_port returns (or raises) the next result; the last one repeats."""
    queue = list(results)

    def fake_open(_port):
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return item
    monkeypatch.setattr(tc, "_open_port", fake_open)


def test_successful_pairing_saves_config_and_reports_progress(monkeypatch):
    port = FakePort(["--- 3T Token Booting ---", "[HW] Token is UNPAIRED.", REPLY])
    use_ports(monkeypatch, port)
    steps = []
    ok, msg = tc.pair_token_usb("COM3", progress=steps.append)

    assert ok, msg
    assert "F105-53CD" in msg and "bound" in msg
    cfg = json.loads(tc.CONFIG_FILE.read_text())
    assert cfg["token_id"] == TOKEN_ID and cfg["version"] == tc.CONFIG_VERSION
    assert any("Waiting for the token" in s for s in steps)
    assert any("Saving the pairing" in s for s in steps)
    assert port.closed


def test_brownout_loop_is_reported_as_a_power_problem(monkeypatch):
    loop = ["--- 3T Token Booting ---", "Brownout detector was triggered"] * 3
    use_ports(monkeypatch, FakePort(loop))
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok
    assert msg == tc.POWER_MESSAGE
    assert not tc.CONFIG_FILE.exists()


def test_one_restart_then_success_still_pairs(monkeypatch):
    use_ports(monkeypatch, FakePort(["Brownout detector was triggered", "--- 3T Token Booting ---", REPLY]))
    ok, msg = tc.pair_token_usb("COM3")
    assert ok, msg


def test_port_in_use_gives_a_plain_explanation(monkeypatch):
    busy = serial.SerialException("could not open port 'COM3': PermissionError(13, 'Access is denied.', None, 5)")
    use_ports(monkeypatch, busy)
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok
    assert "being used by another program" in msg
    assert "Access is denied" not in msg


def test_missing_port_gives_a_plain_explanation(monkeypatch):
    gone = serial.SerialException("could not open port 'COM7': FileNotFoundError(2, 'The system cannot find "
                                  "the file specified.', None, 2)")
    use_ports(monkeypatch, gone)
    ok, msg = tc.pair_token_usb("COM7")
    assert not ok
    assert "not available" in msg and "plugged in" in msg


def test_connection_drop_mid_pairing_recovers(monkeypatch):
    """The original bug report: GetOverlappedResult / Access is denied while reading."""
    dropped = FakePort([serial.SerialException(
        "GetOverlappedResult failed (PermissionError(13, 'Access is denied.', None, 5))")])
    use_ports(monkeypatch, dropped, FakePort(["--- 3T Token Booting ---", REPLY]))
    steps = []
    ok, msg = tc.pair_token_usb("COM3", progress=steps.append)
    assert ok, msg
    assert dropped.closed
    assert any("Reconnecting" in s for s in steps)


def test_silent_token_gives_next_steps(monkeypatch):
    use_ports(monkeypatch, FakePort([]))
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok
    assert "did not answer" in msg and "2 short flashes" in msg


def test_token_bound_to_other_pc_is_refused(monkeypatch):
    class Refusing(FakePort):
        def readline(self):
            return f"PAIRING_REFUSED;REQ={self.request_id};REASON=BOUND_TO_OTHER_HOST\n".encode()
    use_ports(monkeypatch, Refusing([]))
    ok, msg = tc.pair_token_usb("COM3")
    assert not ok
    assert "different PC" in msg
