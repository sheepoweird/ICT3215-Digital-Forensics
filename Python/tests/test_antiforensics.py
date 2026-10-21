"""
EnvStego — anti-forensics feature tests (no hardware required)

Combines what used to be test_privacy, test_secure_delete and test_secret_store.
Covers:
  * embed(match_timestamps=True) copies the carrier's dates onto the stego image
  * timestamp copying is cosmetic: a failure never breaks embedding
  * pictures_dir / downloads_dir resolve real folders
  * shred_file overwrites then deletes the original plaintext
  * protect_str / unprotect_str seal settings so a registry dump reveals nothing

Run from the Python/ directory:
    python -m pytest tests/test_antiforensics.py -v
"""

import json
import os
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import stego_engine
from winutils import (copy_file_times, shred_file, pictures_dir, downloads_dir,
                      protect_str, unprotect_str)


def _carrier(path, dt_epoch=None):
    x = np.arange(200, dtype=np.uint8)
    arr = np.dstack([np.tile(x, (200, 1)), np.tile(x.reshape(200, 1), (1, 200)),
                     np.full((200, 200), 70, np.uint8)])
    Image.fromarray(arr, "RGB").save(path, format="PNG")
    if dt_epoch is not None:
        os.utime(path, (dt_epoch, dt_epoch))
    return str(path)


# ── Timestamp blending ───────────────────────────────────────────────────────

def test_copy_file_times_matches_mtime(tmp_path):
    old = tmp_path / "old.txt"
    old.write_text("x")
    old_epoch = time.time() - 400 * 24 * 3600          # ~400 days ago
    os.utime(old, (old_epoch, old_epoch))
    new = tmp_path / "new.txt"
    new.write_text("y")

    assert copy_file_times(str(old), str(new)) is True
    assert abs(os.stat(new).st_mtime - old_epoch) < 2


def test_copy_file_times_never_raises_on_bad_source(tmp_path):
    dst = tmp_path / "d.txt"
    dst.write_text("y")
    assert copy_file_times(str(tmp_path / "does_not_exist"), str(dst)) is False


def test_embed_matches_timestamps_when_asked(tmp_path):
    old_epoch = time.time() - 365 * 24 * 3600
    carrier = _carrier(tmp_path / "holiday.png", old_epoch)
    salt, nonce, ct = os.urandom(16), os.urandom(12), os.urandom(200)
    out = stego_engine.embed(carrier, salt, nonce, ct, str(tmp_path / "out.png"),
                             match_timestamps=True)
    # The fresh output inherits the carrier's old modified date
    assert abs(os.stat(out).st_mtime - old_epoch) < 2


def test_embed_keeps_fresh_timestamp_by_default(tmp_path):
    old_epoch = time.time() - 365 * 24 * 3600
    carrier = _carrier(tmp_path / "c.png", old_epoch)
    salt, nonce, ct = os.urandom(16), os.urandom(12), os.urandom(120)
    out = stego_engine.embed(carrier, salt, nonce, ct, str(tmp_path / "out.png"))
    assert os.stat(out).st_mtime - old_epoch > 1000     # clearly a new date


def test_embed_still_round_trips_with_timestamp_copy(tmp_path):
    carrier = _carrier(tmp_path / "c.png", time.time() - 10000)
    salt, nonce, ct = os.urandom(16), os.urandom(12), os.urandom(300)
    out = stego_engine.embed(carrier, salt, nonce, ct, str(tmp_path / "out.png"),
                             match_timestamps=True)
    r_salt, r_nonce, r_ct = stego_engine.extract(out)
    assert (r_salt, r_nonce, r_ct) == (salt, nonce, ct)


def test_user_dirs_return_existing_folders():
    for path in (pictures_dir(), downloads_dir()):
        assert isinstance(path, str) and path
        assert os.path.isdir(path)


# ── Secure delete ─────────────────────────────────────────────────────────────

def test_shred_overwrites_then_deletes(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_bytes(b"TOP SECRET contents that must not survive")
    assert shred_file(str(f)) is True
    assert not f.exists()
    # The original name is gone from the directory, and nothing was left behind
    assert list(tmp_path.iterdir()) == []


def test_shred_missing_file_returns_false(tmp_path):
    assert shred_file(str(tmp_path / "nope.bin")) is False


def test_shred_large_file(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(3 * 1024 * 1024 + 123))   # exercises the 1 MB chunk loop
    assert shred_file(str(f), passes=1) is True
    assert not f.exists()


def test_shred_empty_file(tmp_path):
    f = tmp_path / "empty.bin"
    f.touch()
    assert shred_file(str(f)) is True
    assert not f.exists()


# ── Settings sealing (DPAPI) ──────────────────────────────────────────────────

def test_seal_round_trip():
    original = json.dumps(["hw_cpu", "hw_disk", "os_machineguid"])
    sealed = protect_str(original)
    assert unprotect_str(sealed) == original


def test_sealed_form_hides_the_content_on_windows():
    original = json.dumps(["hw_cpu", "os_machineguid"])
    sealed = protect_str(original)
    if os.name == "nt":
        assert sealed != original
        assert "hw_cpu" not in sealed          # not readable from a registry dump
        assert sealed.startswith("dpapi1:")
    else:
        assert sealed == original              # no DPAPI off Windows


def test_old_plaintext_values_still_read():
    # Values saved before sealing have no prefix and must load unchanged
    assert unprotect_str('["hw_cpu"]') == '["hw_cpu"]'


def test_empty_string_is_passed_through():
    assert protect_str("") == ""
    assert unprotect_str("") == ""
