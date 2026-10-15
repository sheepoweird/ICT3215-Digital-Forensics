"""
EnvStego — offline test suite (no hardware required)

A faithful software model of the 3T token firmware (ESP32 Files/main.cpp) drives
the REAL production protocol code in token_comms.py, so these tests exercise the
actual challenge/response, key-derivation, crypto and steganography paths.

What is covered (maps to the report's evaluation section):
  * key derivation      — env_key == HMAC(master, "3T-ENV-v1" | env_hash)
  * stego round trip    — encrypt+embed then extract+decrypt restores bytes + name
  * wrong env / token    — a different signal set or a different token fails to decrypt
  * tamper / JPEG        — a flipped LSB or a JPEG re-save makes extraction/decryption fail
  * per-file salt        — the same payload encrypts to a fresh salt + ciphertext each time
  * replay / impostor    — a consumed nonce, a stale request and a wrong auth key are rejected
  * filename traversal   — "../../etc/passwd" is reduced to a bare basename on unpack
  * legacy ENVS image    — v1 images are detected and refused
  * max pixel diff <= 1  — the carrier and stego image differ by at most 1 per channel

Run from the Python/ directory:
    python -m pytest tests/test_offline.py -v
"""

import hashlib
import hmac
import os
import sys
from pathlib import Path

import numpy as np
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

# Make the app modules (one directory up) importable when pytest is run from anywhere.
APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import crypto_engine
import stego_engine
import token_comms as tc
from crypto_engine import (
    decrypt_payload,
    encrypt_payload,
    environment_hash,
    pack_payload,
    unpack_payload,
)
from stego_engine import LEGACY_MAGIC, MAGIC, embed, extract

# Firmware request length: type | host_nonce | iv | (op+hash) | tag
REQUEST_LEN = 1 + tc.NONCE_LEN + tc.IV_LEN + (1 + tc.HASH_LEN) + tc.TAG_LEN  # 78
ENV_LABEL = b"3T-ENV-v1"


# ─────────────────────────────────────────────────────────────────────────────
# Simulated token — mirrors ESP32 Files/main.cpp state machine exactly
# ─────────────────────────────────────────────────────────────────────────────
class SimToken:
    """Software twin of the firmware. Consumes/produces the same wire bytes."""

    def __init__(self, master_secret=None, auth_key=None, token_id=None):
        self.master_secret = master_secret or os.urandom(tc.HASH_LEN)
        self.auth_key = auth_key or os.urandom(32)
        self.token_id = token_id or os.urandom(tc.TOKEN_ID_LEN)
        self.paired = True
        self._token_nonce = b""
        self._challenge_active = False
        self._auth_failures = 0
        self.locked = False
        self.max_failures = 5  # MAX_AUTH_FAILURES in firmware

    # --- firmware helpers -------------------------------------------------
    def _env_key(self, env_hash):
        return hmac.new(self.master_secret, ENV_LABEL + env_hash, hashlib.sha256).digest()

    def _session_key(self, host_nonce):
        return hmac.new(self.auth_key, b"3T-SK-v1" + self._token_nonce + host_nonce,
                        hashlib.sha256).digest()

    def _record_failure(self):
        self._auth_failures += 1
        if self._auth_failures >= self.max_failures:
            self.locked = True
            self._auth_failures = 0

    # --- the onWrite() dispatcher ----------------------------------------
    def handle(self, msg: bytes) -> bytes:
        if not self.paired:
            return bytes([tc.MSG_ERROR, 0x01])            # ERR_NOT_PAIRED
        if self.locked:
            return bytes([tc.MSG_ERROR, 0x05])            # ERR_LOCKED_OUT
        if len(msg) == 1 and msg[0] == tc.MSG_HELLO:
            return self._hello()
        if msg and msg[0] == tc.MSG_REQUEST:
            return self._request(msg)
        return bytes([tc.MSG_ERROR, 0x04])                # ERR_BAD_FORMAT

    def _hello(self) -> bytes:
        self._token_nonce = os.urandom(tc.NONCE_LEN)
        self._challenge_active = True
        return bytes([tc.MSG_CHALLENGE]) + self._token_nonce + self.token_id

    def _request(self, msg: bytes) -> bytes:
        if not self._challenge_active:
            return bytes([tc.MSG_ERROR, 0x02])            # ERR_NO_CHALLENGE
        self._challenge_active = False                    # single-use nonce
        if len(msg) != REQUEST_LEN:
            return bytes([tc.MSG_ERROR, 0x04])            # ERR_BAD_FORMAT

        host_nonce = msg[1:1 + tc.NONCE_LEN]
        iv = msg[1 + tc.NONCE_LEN:1 + tc.NONCE_LEN + tc.IV_LEN]
        ct = msg[1 + tc.NONCE_LEN + tc.IV_LEN:]
        sk = self._session_key(host_nonce)
        try:
            plain = AESGCM(sk).decrypt(iv, ct, b"3T-REQ-v1" + self.token_id)
        except InvalidTag:
            self._record_failure()
            return bytes([tc.MSG_ERROR, 0x03])            # ERR_AUTH_FAILED
        self._auth_failures = 0

        op, env_hash = plain[0], plain[1:]
        if op == tc.OP_DERIVE:
            data = self._env_key(env_hash)
        elif op == tc.OP_PING:
            data = bytes(tc.HASH_LEN)
        else:
            return bytes([tc.MSG_ERROR, 0x04])
        resp_plain = bytes([0x00]) + data
        resp_iv = os.urandom(tc.IV_LEN)
        resp_ct = AESGCM(sk).encrypt(resp_iv, resp_plain, b"3T-RSP-v1" + self.token_id)
        return bytes([tc.MSG_RESPONSE]) + resp_iv + resp_ct


def run_transaction(sim: SimToken, auth_key, token_id, op, env_hash):
    """Full HELLO -> CHALLENGE -> REQUEST -> RESPONSE using the real protocol code."""
    token_nonce = tc.parse_challenge(sim.handle(bytes([tc.MSG_HELLO])), token_id)
    request, sk = tc.build_request(auth_key, token_id, token_nonce, op, env_hash)
    return tc.parse_response(sim.handle(request), sk, token_id)


class Sig:
    """Minimal stand-in for signals.EnvSignal (crypto_engine only reads .id/.value)."""

    def __init__(self, sid, value):
        self.id = sid
        self.value = value


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def sim():
    return SimToken()


@pytest.fixture
def env_key(sim, monkeypatch):
    """env_key derived through the full protocol, with request_env_key routed to sim."""
    monkeypatch.setattr(
        crypto_engine, "request_env_key",
        lambda env_hash: run_transaction(sim, sim.auth_key, sim.token_id, tc.OP_DERIVE, env_hash),
    )
    signals = [Sig("cpu", "AMD"), Sig("host", "DESKTOP-1"), Sig("tz", "UTC+8")]
    key, _fp = crypto_engine.derive_env_key(signals)
    return key


def make_carrier(path, w=256, h=256):
    """Deterministic gradient PNG — real pixel variety, reproducible across runs."""
    xs = np.arange(w, dtype=np.uint8)
    ys = np.arange(h, dtype=np.uint8)
    r = np.tile(xs, (h, 1))
    g = np.tile(ys.reshape(h, 1), (1, w))
    b = ((r.astype(int) + g.astype(int)) // 2).astype(np.uint8)
    arr = np.dstack([r, g, b]).astype(np.uint8)
    Image.fromarray(arr, "RGB").save(path, format="PNG")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# 1. Key derivation
# ─────────────────────────────────────────────────────────────────────────────
def test_key_derivation_matches_firmware_formula(sim, monkeypatch):
    monkeypatch.setattr(
        crypto_engine, "request_env_key",
        lambda env_hash: run_transaction(sim, sim.auth_key, sim.token_id, tc.OP_DERIVE, env_hash),
    )
    signals = [Sig("cpu", "AMD"), Sig("host", "DESKTOP-1"), Sig("tz", "UTC+8")]
    key, fp = crypto_engine.derive_env_key(signals)

    expected = hmac.new(sim.master_secret, ENV_LABEL + environment_hash(signals),
                        hashlib.sha256).digest()
    assert key == expected
    assert len(key) == 32
    assert fp == crypto_engine.key_fingerprint(key)


def test_environment_hash_is_order_independent():
    a = [Sig("cpu", "AMD"), Sig("tz", "UTC+8")]
    b = [Sig("tz", "UTC+8"), Sig("cpu", "AMD")]
    assert environment_hash(a) == environment_hash(b)
    assert environment_hash(a) != environment_hash([Sig("cpu", "Intel"), Sig("tz", "UTC+8")])


def test_ping_returns_zeroes(sim):
    data = run_transaction(sim, sim.auth_key, sim.token_id, tc.OP_PING, bytes(tc.HASH_LEN))
    assert data == bytes(tc.HASH_LEN)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Stego round trip + 9. max pixel diff <= 1
# ─────────────────────────────────────────────────────────────────────────────
def test_stego_round_trip_and_pixel_diff(tmp_path, env_key):
    carrier = make_carrier(tmp_path / "carrier.png")
    payload = b"Top secret evidence \x00\x01\x02 payload bytes" * 20
    name = "report.pdf"

    salt, nonce, ct = encrypt_payload(pack_payload(name, payload), env_key, MAGIC)
    out = embed(str(carrier), salt, nonce, ct, str(tmp_path / "stego.png"))

    # Round trip
    r_salt, r_nonce, r_ct = extract(out)
    rec_name, rec_data = unpack_payload(decrypt_payload(r_salt, r_nonce, r_ct, env_key, MAGIC))
    assert rec_name == name
    assert rec_data == payload

    # Max pixel difference <= 1 per channel (LSB-only change)
    a = np.array(Image.open(str(carrier)).convert("RGB"), dtype=np.int16)
    b = np.array(Image.open(out).convert("RGB"), dtype=np.int16)
    assert int(np.abs(a - b).max()) <= 1


# ─────────────────────────────────────────────────────────────────────────────
# 3. Wrong environment / wrong token
# ─────────────────────────────────────────────────────────────────────────────
def test_wrong_environment_fails(tmp_path, env_key):
    carrier = make_carrier(tmp_path / "c.png")
    salt, nonce, ct = encrypt_payload(pack_payload("a.txt", b"data"), env_key, MAGIC)
    embed(str(carrier), salt, nonce, ct, str(tmp_path / "s.png"))
    r_salt, r_nonce, r_ct = extract(str(tmp_path / "s.png"))

    wrong_env_key = os.urandom(32)  # a different signal set yields a different env_key
    with pytest.raises(InvalidTag):
        decrypt_payload(r_salt, r_nonce, r_ct, wrong_env_key, MAGIC)


def test_wrong_token_fails(monkeypatch):
    """A second token (different master secret) derives a different env_key."""
    signals = [Sig("cpu", "AMD"), Sig("host", "DESKTOP-1")]
    tok_a, tok_b = SimToken(), SimToken()

    monkeypatch.setattr(crypto_engine, "request_env_key",
                        lambda h: run_transaction(tok_a, tok_a.auth_key, tok_a.token_id, tc.OP_DERIVE, h))
    key_a, _ = crypto_engine.derive_env_key(signals)
    monkeypatch.setattr(crypto_engine, "request_env_key",
                        lambda h: run_transaction(tok_b, tok_b.auth_key, tok_b.token_id, tc.OP_DERIVE, h))
    key_b, _ = crypto_engine.derive_env_key(signals)

    assert key_a != key_b
    salt, nonce, ct = encrypt_payload(pack_payload("x", b"secret"), key_a, MAGIC)
    with pytest.raises(InvalidTag):
        decrypt_payload(salt, nonce, ct, key_b, MAGIC)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Tamper / JPEG
# ─────────────────────────────────────────────────────────────────────────────
def test_tampered_lsb_fails_decrypt(tmp_path, env_key):
    carrier = make_carrier(tmp_path / "c.png")
    salt, nonce, ct = encrypt_payload(pack_payload("a", b"data" * 50), env_key, MAGIC)
    out = embed(str(carrier), salt, nonce, ct, str(tmp_path / "s.png"))

    arr = np.array(Image.open(out).convert("RGB"), dtype=np.uint8)
    flat = arr.flatten()
    idx = stego_engine.HEADER_BITS + 100  # a bit well inside the ciphertext region
    flat[idx] ^= np.uint8(1)              # flip one embedded LSB
    tampered = tmp_path / "tampered.png"
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(str(tampered), format="PNG")

    r_salt, r_nonce, r_ct = extract(str(tampered))
    with pytest.raises(InvalidTag):
        decrypt_payload(r_salt, r_nonce, r_ct, env_key, MAGIC)


def test_jpeg_recompression_destroys_payload(tmp_path, env_key):
    carrier = make_carrier(tmp_path / "c.png")
    salt, nonce, ct = encrypt_payload(pack_payload("a", b"data" * 50), env_key, MAGIC)
    out = embed(str(carrier), salt, nonce, ct, str(tmp_path / "s.png"))

    jpeg = tmp_path / "s.jpg"
    Image.open(out).convert("RGB").save(str(jpeg), format="JPEG", quality=90)
    # Lossy JPEG wrecks the LSB plane: the magic header no longer parses.
    with pytest.raises(ValueError):
        extract(str(jpeg))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Per-file salt
# ─────────────────────────────────────────────────────────────────────────────
def test_per_file_salt_is_unique(env_key):
    plaintext = pack_payload("same.bin", b"identical payload bytes")
    salt1, nonce1, ct1 = encrypt_payload(plaintext, env_key, MAGIC)
    salt2, nonce2, ct2 = encrypt_payload(plaintext, env_key, MAGIC)
    assert salt1 != salt2
    assert nonce1 != nonce2
    assert ct1 != ct2  # fresh salt -> fresh file key -> different ciphertext
    # Both still decrypt correctly under their own salt.
    assert decrypt_payload(salt1, nonce1, ct1, env_key, MAGIC) == plaintext
    assert decrypt_payload(salt2, nonce2, ct2, env_key, MAGIC) == plaintext


# ─────────────────────────────────────────────────────────────────────────────
# 6. Replay / impostor rejection (protocol level)
# ─────────────────────────────────────────────────────────────────────────────
def test_replayed_request_without_new_challenge(sim):
    """Re-sending a captured request without a fresh HELLO hits the consumed nonce."""
    token_nonce = tc.parse_challenge(sim.handle(bytes([tc.MSG_HELLO])), sim.token_id)
    request, sk = tc.build_request(sim.auth_key, sim.token_id, token_nonce, tc.OP_DERIVE, bytes(32))
    tc.parse_response(sim.handle(request), sk, sim.token_id)        # first use succeeds

    with pytest.raises(tc.TokenError):                              # ERR_NO_CHALLENGE
        tc.parse_response(sim.handle(request), sk, sim.token_id)


def test_replayed_request_against_fresh_challenge_fails_auth(sim):
    """A stale request replayed after a new HELLO fails: nonce changed, session key mismatches."""
    nonce1 = tc.parse_challenge(sim.handle(bytes([tc.MSG_HELLO])), sim.token_id)
    old_request, old_sk = tc.build_request(sim.auth_key, sim.token_id, nonce1, tc.OP_DERIVE, bytes(32))
    tc.parse_response(sim.handle(old_request), old_sk, sim.token_id)

    tc.parse_challenge(sim.handle(bytes([tc.MSG_HELLO])), sim.token_id)  # fresh token nonce
    with pytest.raises(tc.TokenAuthError):
        tc.parse_response(sim.handle(old_request), old_sk, sim.token_id)


def test_impostor_host_without_auth_key_rejected(sim):
    """An attacker who never paired does not hold auth_key -> GCM tag fails."""
    token_nonce = tc.parse_challenge(sim.handle(bytes([tc.MSG_HELLO])), sim.token_id)
    wrong_auth_key = os.urandom(32)
    request, sk = tc.build_request(wrong_auth_key, sim.token_id, token_nonce, tc.OP_DERIVE, bytes(32))
    with pytest.raises(tc.TokenAuthError):
        tc.parse_response(sim.handle(request), sk, sim.token_id)


def test_impostor_token_wrong_id_rejected(sim):
    """A device answering at the paired address but with the wrong token_id is caught."""
    wrong_expected_id = os.urandom(tc.TOKEN_ID_LEN)
    with pytest.raises(tc.TokenAuthError):
        tc.parse_challenge(sim.handle(bytes([tc.MSG_HELLO])), wrong_expected_id)


def test_lockout_after_five_failures(sim):
    """Five bad requests lock the token; the sixth is refused outright."""
    for _ in range(5):
        token_nonce = tc.parse_challenge(sim.handle(bytes([tc.MSG_HELLO])), sim.token_id)
        bad, sk = tc.build_request(os.urandom(32), sim.token_id, token_nonce, tc.OP_DERIVE, bytes(32))
        with pytest.raises(tc.TokenAuthError):
            tc.parse_response(sim.handle(bad), sk, sim.token_id)

    assert sim.locked
    # Even a correctly-keyed request is now refused with ERR_LOCKED_OUT.
    token_nonce_msg = sim.handle(bytes([tc.MSG_HELLO]))
    with pytest.raises(tc.TokenError) as exc:
        tc.parse_challenge(token_nonce_msg, sim.token_id)
    assert "locked" in str(exc.value).lower()


# ─────────────────────────────────────────────────────────────────────────────
# 7. Filename path-traversal
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("evil,expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\Windows\\System32\\evil.dll", "evil.dll"),
    ("/absolute/secret.key", "secret.key"),
    ("C:\\Users\\victim\\.ssh\\id_rsa", "id_rsa"),
])
def test_filename_path_traversal_is_neutralised(evil, expected):
    blob = pack_payload(evil, b"payload")
    name, data = unpack_payload(blob)
    assert name == expected
    assert "/" not in name and "\\" not in name
    assert data == b"payload"


def test_separator_only_filename_falls_back():
    # A name that reduces to empty after basename+strip gets the safe default.
    name, _ = unpack_payload(pack_payload("/", b"x"))
    assert name == "recovered_payload.bin"


def test_dotdot_filename_stays_literal_and_cannot_traverse():
    # "." / ".." survive as literal names, but with no separator they address no
    # other directory — open() treats them as a (failing) file entry, not a path.
    name, _ = unpack_payload(pack_payload("..", b"x"))
    assert name == ".."
    assert "/" not in name and "\\" not in name


# ─────────────────────────────────────────────────────────────────────────────
# 8. Legacy ENVS image
# ─────────────────────────────────────────────────────────────────────────────
def test_legacy_envs_image_rejected(tmp_path):
    # Craft a 36-byte header whose magic is the v1 LEGACY_MAGIC, then embed it in LSBs.
    header = LEGACY_MAGIC + b"\x00\x00\x00\x20" + os.urandom(16) + os.urandom(12)
    bits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))

    arr = np.array(Image.open(make_carrier(tmp_path / "c.png", 64, 64)).convert("RGB"),
                   dtype=np.uint8)
    flat = arr.flatten()
    flat[:len(bits)] = (flat[:len(bits)] & np.uint8(0xFE)) | bits.astype(np.uint8)
    legacy = tmp_path / "legacy.png"
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(str(legacy), format="PNG")

    with pytest.raises(ValueError) as exc:
        extract(str(legacy))
    assert "older" in str(exc.value).lower() or "hardcoded" in str(exc.value).lower()


def test_no_payload_image_rejected(tmp_path):
    plain = make_carrier(tmp_path / "plain.png", 64, 64)
    with pytest.raises(ValueError):
        extract(str(plain))
