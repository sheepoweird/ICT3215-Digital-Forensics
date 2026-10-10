"""
EnvStego - crypto_engine.py
Key derivation and AES-256-GCM encryption.

Key hierarchy:
    env_hash = SHA-256(canonical encoding of the selected signal IDs + values)
    env_key  = HMAC-SHA256(token master secret, env_hash)     <- computed on the token
    file_key = HKDF-SHA256(env_key, salt = random per file)   <- computed here

The env_key needs both the live environment and the physical token, and the
per-file salt gives every stego image an independent AES key.
"""

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from token_comms import request_env_key

SALT_LEN = 16
NONCE_LEN = 12


def estimate_entropy_bits(signals: list) -> int:
    """Estimates the entropy bits of the selected signals."""
    return sum(getattr(s, 'stability', 5) * 4 for s in signals)


def environment_hash(signals: list) -> bytes:
    """Canonical, order-independent hash of the selected signals."""
    pairs = sorted([s.id, s.value] for s in signals)
    encoded = json.dumps(["EnvStego-env-v1", pairs], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).digest()


def key_fingerprint(env_key: bytes) -> str:
    """Stable display fingerprint of an env key, e.g. 'D993-8D9E-DA56-3DEA'."""
    h = hashlib.sha256(b"EnvStego-fp-v1" + env_key).hexdigest()[:16].upper()
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))


def derive_env_key(signals: list) -> tuple[bytes, str]:
    """
    Sends the environment hash to the paired token over BLE and returns
    (env_key, fingerprint). Raises token_comms.TokenError on token failures.
    """
    if not signals:
        raise ValueError("Select at least one environment signal.")
    env_key = request_env_key(environment_hash(signals))
    return env_key, key_fingerprint(env_key)


def pack_payload(filename: str, data: bytes) -> bytes:
    """Prefixes the payload with its original filename so decryption can restore it."""
    name = os.path.basename(filename).encode("utf-8")[:255]
    return bytes([1, len(name)]) + name + data


def unpack_payload(blob: bytes) -> tuple[str, bytes]:
    """Inverse of pack_payload. Returns (safe filename, data)."""
    if len(blob) < 2 or blob[0] != 1 or len(blob) < 2 + blob[1]:
        raise ValueError("Decrypted payload has an unknown format.")
    name = blob[2:2 + blob[1]].decode("utf-8", errors="replace")
    # Never trust a path from the file: keep only a plain name
    name = os.path.basename(name.replace("\\", "/")).strip() or "recovered_payload.bin"
    return name, blob[2 + blob[1]:]


def packed_size(filename: str, data_len: int) -> int:
    """Bytes the encrypted payload will occupy (wrapper + data + GCM tag)."""
    return 2 + len(os.path.basename(filename).encode("utf-8")[:255]) + data_len + 16


def _file_key(env_key: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"EnvStego-v2 file key").derive(env_key)


def encrypt_payload(plaintext: bytes, env_key: bytes, aad: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypts with a fresh salt and nonce. Returns (salt, nonce, ciphertext+tag)."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_file_key(env_key, salt)).encrypt(nonce, plaintext, aad + salt)
    return salt, nonce, ciphertext


def decrypt_payload(salt: bytes, nonce: bytes, ciphertext: bytes, env_key: bytes, aad: bytes) -> bytes:
    """Decrypts data. Raises cryptography.exceptions.InvalidTag if the environment or token is wrong."""
    return AESGCM(_file_key(env_key, salt)).decrypt(nonce, ciphertext, aad + salt)
