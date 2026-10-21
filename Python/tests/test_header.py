"""
EnvStego — v3 token-encrypted header tests (no hardware required)

The v3 format removes the plaintext "ENV2" marker and stores the payload
parameters and the signal list inside a header encrypted under a token-only
"index key". These tests use the software token twin from test_offline.py.

Checks: the header round-trips; it carries the signal list; a wrong token can't
read it; the whole stego image carries no plaintext marker; a full v3 image
round-trips through the engine; and an undersized carrier is rejected.

Run from the Python/ directory:
    python -m pytest tests/test_header.py -v
"""

import os
import sys
from pathlib import Path

import numpy as np
import pytest
from cryptography.exceptions import InvalidTag
from PIL import Image

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import crypto_engine as ce
import stego_engine as se
import token_comms as tc
from test_offline import SimToken, run_transaction


def index_key_for(sim):
    return run_transaction(sim, sim.auth_key, sim.token_id, tc.OP_DERIVE, ce.INDEX_HASH)


def carrier(path, w=256, h=256):
    x = np.arange(w, dtype=np.uint8)
    arr = np.dstack([np.tile(x, (h, 1)), np.tile((np.arange(h, dtype=np.uint8)).reshape(h, 1), (1, w)),
                     np.full((h, w), 80, np.uint8)])
    Image.fromarray(arr, "RGB").save(path, format="PNG")
    return str(path)


def test_header_round_trips_with_signal_list():
    sim = SimToken()
    ik = index_key_for(sim)
    salt, nonce = os.urandom(16), os.urandom(12)
    ids = ["hw_cpu", "hw_disk", "os_machineguid"]
    header = ce.pack_header(ik, salt, nonce, 1234, ids)

    assert len(header) == ce.OUTER_SIZE
    r_salt, r_nonce, r_len, r_ids = ce.unpack_header(ik, header)
    assert (r_salt, r_nonce, r_len, r_ids) == (salt, nonce, 1234, ids)


def test_header_unreadable_with_wrong_token():
    maker, attacker = SimToken(), SimToken()
    header = ce.pack_header(index_key_for(maker), os.urandom(16), os.urandom(12), 10, ["hw_cpu"])
    with pytest.raises(InvalidTag):
        ce.unpack_header(index_key_for(attacker), header)


def test_index_key_is_environment_independent_but_token_bound():
    a, b = SimToken(), SimToken()
    # Same token, two calls -> same index key; different token -> different key
    assert index_key_for(a) == index_key_for(a)
    assert index_key_for(a) != index_key_for(b)
    # And it differs from a normal environment key on the same token
    env = run_transaction(a, a.auth_key, a.token_id, tc.OP_DERIVE, bytes(32))
    assert index_key_for(a) != env


def test_header_rejects_too_many_signals():
    ik = index_key_for(SimToken())
    huge = [f"signal_{i}" for i in range(60)]
    with pytest.raises(ValueError):
        ce.pack_header(ik, os.urandom(16), os.urandom(12), 1, huge)


def test_stego_image_has_no_plaintext_marker(tmp_path):
    sim = SimToken()
    ik = index_key_for(sim)
    salt, nonce, ct = ce.encrypt_payload(ce.pack_payload("x.bin", b"data" * 20),
                                         os.urandom(32), ce.PAYLOAD_AAD)
    header = ce.pack_header(ik, salt, nonce, len(ct), ["hw_cpu"])
    out = se.embed_blob(carrier(tmp_path / "c.png"), header + ct, str(tmp_path / "s.png"))

    first = se.extract_lsb_bytes(out, 8)
    assert first[:4] != se.MAGIC and first[:4] != se.LEGACY_MAGIC


def test_full_v3_round_trip(tmp_path, monkeypatch):
    sim = SimToken()
    monkeypatch.setattr(ce, "request_env_key",
                        lambda h: run_transaction(sim, sim.auth_key, sim.token_id, tc.OP_DERIVE, h))

    class Sig:
        def __init__(self, sid, value):
            self.id, self.value, self.stability = sid, value, 8

    signals = [Sig("hw_cpu", "AMD"), Sig("hw_disk", "WD123"), Sig("os_machineguid", "GUID-1")]
    payload, name = b"classified bytes \x00\x01\x02" * 40, "notes.bin"

    env_key, _ = ce.derive_env_key(signals)
    index_key = ce.request_index_key()
    salt, nonce, ct = ce.encrypt_payload(ce.pack_payload(name, payload), env_key, ce.PAYLOAD_AAD)
    header = ce.pack_header(index_key, salt, nonce, len(ct), sorted(s.id for s in signals))
    out = se.embed_blob(carrier(tmp_path / "c.png"), header + ct, str(tmp_path / "s.png"))

    # Decrypt side: read header with index key, then payload with env key
    r_salt, r_nonce, r_len, r_ids = ce.unpack_header(ce.request_index_key(),
                                                     se.extract_lsb_bytes(out, ce.OUTER_SIZE))
    assert r_ids == sorted(s.id for s in signals)
    blob = se.extract_lsb_bytes(out, ce.OUTER_SIZE + r_len)
    rec_name, rec_data = ce.unpack_payload(
        ce.decrypt_payload(r_salt, r_nonce, blob[ce.OUTER_SIZE:], env_key, ce.PAYLOAD_AAD))
    assert (rec_name, rec_data) == (name, payload)


def test_embed_blob_rejects_undersized_carrier(tmp_path):
    small = carrier(tmp_path / "tiny.png", 8, 8)
    with pytest.raises(ValueError):
        se.embed_blob(small, os.urandom(ce.OUTER_SIZE + 500), str(tmp_path / "o.png"))
