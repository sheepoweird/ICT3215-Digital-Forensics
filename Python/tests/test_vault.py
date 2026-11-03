"""
EnvStego — Env Vault tests (encrypted store + index + key wrapping)

The index/env keys are fixed stand-ins here, so no token/BLE is involved.
Run from the Python/ directory:
    python -m pytest tests/test_vault.py -v
"""

import json
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import vault as V

INDEX_KEY = bytes(range(32))
ENV_KEY = bytes(range(32, 64))
OTHER_ENV = bytes(range(64, 96))
SIGNALS = ["hw_cpu", "hw_disk", "os_machineguid"]


def _new(tmp_path, sub="vault"):
    p = tmp_path / sub
    return V.create_vault(str(p), INDEX_KEY, ENV_KEY, SIGNALS)


# ── creation ─────────────────────────────────────────────────────────────────

def test_create_returns_recovery_code_and_is_detected(tmp_path):
    v, code = _new(tmp_path)
    assert v.unlocked and v.count() == 0
    assert len(code.replace("-", "")) >= 32           # 160-bit base32
    assert V.is_vault(v.path)


def test_create_refuses_nonempty_folder(tmp_path):
    d = tmp_path / "busy"
    d.mkdir()
    (d / "stray.txt").write_text("x")
    with pytest.raises(V.VaultError, match="empty"):
        V.create_vault(str(d), INDEX_KEY, ENV_KEY, SIGNALS)


def test_on_disk_leaks_no_names_or_plaintext(tmp_path):
    v, _ = _new(tmp_path)
    v.add_bytes("passwords.txt", b"hunter2 is the secret")
    files = {p.name for p in Path(v.path).iterdir()}
    assert V.META_NAME in files and V.INDEX_NAME in files
    # No real filename appears on disk, and the plaintext is nowhere in the folder
    for p in Path(v.path).iterdir():
        blob = p.read_bytes()
        assert b"passwords" not in blob
        assert b"hunter2" not in blob


# ── add / read / remove ──────────────────────────────────────────────────────

def test_add_file_shreds_original_and_round_trips(tmp_path):
    v, _ = _new(tmp_path)
    src = tmp_path / "report.docx"
    src.write_bytes(b"CONFIDENTIAL BODY" * 100)
    entry = v.add_file(str(src))
    assert not src.exists()                            # original shredded
    name, data = v.read_bytes(entry["blob"])
    assert name == "report.docx" and data == b"CONFIDENTIAL BODY" * 100


def test_add_bytes_does_not_need_an_original(tmp_path):
    v, _ = _new(tmp_path)
    e = v.add_bytes("note.txt", b"in-memory content")
    assert v.read_bytes(e["blob"]) == ("note.txt", b"in-memory content")
    assert v.count() == 1 and v.total_bytes() == len(b"in-memory content")


def test_blob_size_is_blurred_to_buckets(tmp_path):
    # Two different small payloads must look the same size on disk (same 4 KiB bucket),
    # yet each still reads back to its exact original bytes.
    v, _ = _new(tmp_path)
    a = v.add_bytes("a.bin", b"A" * 100)
    b = v.add_bytes("b.bin", b"B" * 3000)
    sa = (Path(v.path) / a["blob"]).stat().st_size
    sb = (Path(v.path) / b["blob"]).stat().st_size
    assert sa == sb                                   # on-disk size reveals only the bucket
    assert v.read_bytes(a["blob"])[1] == b"A" * 100   # exact bytes still recovered
    assert v.read_bytes(b["blob"])[1] == b"B" * 3000
    assert a["size"] == 100 and b["size"] == 3000     # true sizes live (sealed) in the index


def test_remove_shreds_blob_and_drops_entry(tmp_path):
    v, _ = _new(tmp_path)
    e = v.add_bytes("a.bin", b"aaaa")
    blob_path = Path(v.path) / e["blob"]
    assert blob_path.exists()
    v.remove(e["blob"])
    assert not blob_path.exists() and v.count() == 0


def test_export_writes_plaintext_to_disk(tmp_path):
    v, _ = _new(tmp_path)
    e = v.add_bytes("photo.jpg", b"\xff\xd8\xff\xe0 jpeg bytes")
    out = tmp_path / "out"
    out.mkdir()
    path = v.export(e["blob"], str(out))
    assert Path(path).read_bytes() == b"\xff\xd8\xff\xe0 jpeg bytes"
    assert Path(path).name == "photo.jpg"


# ── lock / unlock ────────────────────────────────────────────────────────────

def test_lock_then_unlock_with_env(tmp_path):
    v, _ = _new(tmp_path)
    v.add_bytes("x.txt", b"persisted")
    v.lock()
    assert not v.unlocked
    with pytest.raises(V.VaultError, match="locked"):
        v.list_entries()

    v2 = V.unlock_env(v.path, ENV_KEY)
    assert v2.unlocked and v2.count() == 1
    assert v2.read_bytes(v2.list_entries()[0]["blob"])[1] == b"persisted"


def test_wrong_environment_cannot_unlock(tmp_path):
    v, _ = _new(tmp_path)
    v.lock()
    with pytest.raises(InvalidTag):
        V.unlock_env(v.path, OTHER_ENV)


def test_recovery_code_unlocks_when_environment_lost(tmp_path):
    v, code = _new(tmp_path)
    v.add_bytes("k.txt", b"recoverable")
    v.lock()
    # Environment gone, but the recovery code still opens it
    with pytest.raises(InvalidTag):
        V.unlock_env(v.path, OTHER_ENV)
    v2 = V.unlock_recovery(v.path, code)
    assert v2.read_bytes(v2.list_entries()[0]["blob"])[1] == b"recoverable"


def test_bad_recovery_code_rejected(tmp_path):
    v, _ = _new(tmp_path)
    v.lock()
    with pytest.raises((V.VaultError, InvalidTag)):
        V.unlock_recovery(v.path, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH")


# ── sealed signal list ───────────────────────────────────────────────────────

def test_signal_list_is_sealed_under_index_key(tmp_path):
    v, _ = _new(tmp_path)
    assert V.read_signal_ids(v.path, INDEX_KEY) == sorted(SIGNALS)
    # Wrong index key cannot read which environment the vault needs
    with pytest.raises(InvalidTag):
        V.read_signal_ids(v.path, bytes(32))
    # And it is not sitting in meta.json as plaintext
    meta = (Path(v.path) / V.META_NAME).read_text(encoding="utf-8")
    assert "hw_cpu" not in meta


# ── re-wrap after drift ──────────────────────────────────────────────────────

def test_rewrap_binds_to_a_new_environment(tmp_path):
    v, _ = _new(tmp_path)
    v.add_bytes("f.txt", b"survives rewrap")
    new_sigs = ["hw_cpu", "hw_disk"]
    v.rewrap_env(INDEX_KEY, OTHER_ENV, new_sigs)
    v.lock()

    # Old environment no longer works; the new one does
    with pytest.raises(InvalidTag):
        V.unlock_env(v.path, ENV_KEY)
    v2 = V.unlock_env(v.path, OTHER_ENV)
    assert v2.read_bytes(v2.list_entries()[0]["blob"])[1] == b"survives rewrap"
    assert V.read_signal_ids(v.path, INDEX_KEY) == sorted(new_sigs)
