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
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from token_comms import request_env_key

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16

# ── v3 token-encrypted header ────────────────────────────────────────────────
# The old format began with the plaintext bytes "ENV2", which an examiner could
# scan a disk for. The v3 format has no marker: its whole header is encrypted
# under a key only the paired token can produce, so the hidden data looks like
# random noise and even the list of signals used is unreadable without the token.
#
# index_key = HMAC(master_secret, "3T-ENV-v1" | INDEX_HASH), from the token.
# INDEX_HASH is a reserved constant that a real signal selection can never hash to,
# so the index key is bound to the token but independent of the environment. This
# reuses the existing OP_DERIVE request, so the firmware does not change.
INDEX_HASH = hashlib.sha256(b"EnvStego-index-v1").digest()
HEADER_AAD = b"EnvStego-hdr-v3"
PAYLOAD_AAD = b"EnvStego-v3"

# Fixed inner-header fields: payload salt, payload nonce, ciphertext length, signal-id length
_HDR_STRUCT = struct.Struct(">16s12sIH")          # 34 bytes
INNER_SIZE = 384                                   # padded to a constant size
OUTER_SIZE = SALT_LEN + NONCE_LEN + INNER_SIZE + TAG_LEN   # 428 bytes written to the image
MAX_SIGLIST = INNER_SIZE - _HDR_STRUCT.size        # room for the signal-id list


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


def request_index_key() -> bytes:
    """
    Asks the token for the environment-independent index key used to encrypt the
    v3 header. Same BLE round-trip as a normal key request; no firmware change.
    """
    return request_env_key(INDEX_HASH)


def _header_key(index_key: bytes, index_salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=index_salt,
               info=b"EnvStego-v3 header key").derive(index_key)


def pack_header(index_key: bytes, payload_salt: bytes, payload_nonce: bytes,
                ct_len: int, signal_ids: list[str]) -> bytes:
    """
    Build the fixed-size, token-encrypted header. Returns OUTER_SIZE random-looking bytes:
    index_salt | gcm_nonce | AES-GCM( payload_salt | payload_nonce | ct_len | signal_ids ).
    """
    sig = "\n".join(signal_ids).encode("utf-8")
    if len(sig) > MAX_SIGLIST:
        raise ValueError("Too many signals to fit in the header.")
    inner = _HDR_STRUCT.pack(payload_salt, payload_nonce, ct_len, len(sig)) + sig
    inner += os.urandom(INNER_SIZE - len(inner))      # pad to a constant size with random
    index_salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(_header_key(index_key, index_salt)).encrypt(nonce, inner, HEADER_AAD)
    return index_salt + nonce + ct                    # 16 + 12 + (INNER_SIZE + 16)


def unpack_header(index_key: bytes, blob: bytes) -> tuple[bytes, bytes, int, list[str]]:
    """
    Decrypt a v3 header. Returns (payload_salt, payload_nonce, ct_len, signal_ids).
    Raises cryptography.exceptions.InvalidTag if this is not a v3 payload or the
    token is wrong — the caller turns that into a friendly message.
    """
    if len(blob) < OUTER_SIZE:
        raise ValueError("Image too small to contain a header.")
    index_salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = blob[SALT_LEN + NONCE_LEN:OUTER_SIZE]
    inner = AESGCM(_header_key(index_key, index_salt)).decrypt(nonce, ct, HEADER_AAD)
    payload_salt, payload_nonce, ct_len, sig_len = _HDR_STRUCT.unpack(inner[:_HDR_STRUCT.size])
    sig = inner[_HDR_STRUCT.size:_HDR_STRUCT.size + sig_len].decode("utf-8")
    return payload_salt, payload_nonce, ct_len, (sig.split("\n") if sig else [])


# ── v3 multi-image shards ────────────────────────────────────────────────────
# A payload too big for one carrier is split across several PNGs. Each shard
# carries a small token-encrypted tag (which set it belongs to, its position and
# its length) followed by its slice of the blob. Like the header, the tag is
# unreadable without the token and looks like random noise, so nothing on disk
# marks the images as related — the set can only be regrouped with the token.
SHARD_AAD = b"EnvStego-shard-v3"
_SHARD_STRUCT = struct.Struct(">16sHHI")                   # manifest | index | total | shard_len = 24 bytes
SHARD_INNER = 32                                           # padded to a constant size
SHARD_OUTER_SIZE = SALT_LEN + NONCE_LEN + SHARD_INNER + TAG_LEN   # 16 + 12 + 32 + 16 = 76 bytes


def _shard_key(index_key: bytes, index_salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=index_salt,
               info=b"EnvStego-v3 shard key").derive(index_key)


def new_manifest_id() -> bytes:
    """A random id that ties the shards of one payload together."""
    return os.urandom(16)


def pack_shard_tag(index_key: bytes, manifest_id: bytes, index: int, total: int,
                   shard_len: int) -> bytes:
    """Fixed-size (SHARD_OUTER_SIZE) token-encrypted tag written ahead of a shard's bytes."""
    inner = _SHARD_STRUCT.pack(manifest_id, index, total, shard_len)
    inner += os.urandom(SHARD_INNER - len(inner))          # pad to a constant size
    index_salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(_shard_key(index_key, index_salt)).encrypt(nonce, inner, SHARD_AAD)
    return index_salt + nonce + ct


def unpack_shard_tag(index_key: bytes, blob: bytes) -> tuple[bytes, int, int, int]:
    """
    Decrypt a shard tag. Returns (manifest_id, index, total, shard_len).
    Raises cryptography.exceptions.InvalidTag if this is not a shard (e.g. a
    single-image v3 header, which uses different AAD/key) or the token is wrong.
    """
    if len(blob) < SHARD_OUTER_SIZE:
        raise ValueError("Image too small to contain a shard tag.")
    index_salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = blob[SALT_LEN + NONCE_LEN:SHARD_OUTER_SIZE]
    inner = AESGCM(_shard_key(index_key, index_salt)).decrypt(nonce, ct, SHARD_AAD)
    manifest_id, index, total, shard_len = _SHARD_STRUCT.unpack(inner[:_SHARD_STRUCT.size])
    return manifest_id, index, total, shard_len


# Payload kinds (the first wrapper byte)
KIND_FILE = 1       # a single file: data is the file's bytes
KIND_FOLDER = 2     # a folder: data is a ZIP to extract, name is the folder name


def pack_payload(filename: str, data: bytes, kind: int = KIND_FILE) -> bytes:
    """Prefixes the payload with a kind byte and its original name so decryption can restore it."""
    name = os.path.basename(filename.rstrip("/\\")).encode("utf-8")[:255]
    return bytes([kind, len(name)]) + name + data


def unpack_payload(blob: bytes) -> tuple[str, bytes]:
    """Inverse of pack_payload. Returns (safe name, data). See payload_kind() for the kind."""
    if len(blob) < 2 or blob[0] not in (KIND_FILE, KIND_FOLDER) or len(blob) < 2 + blob[1]:
        raise ValueError("Decrypted payload has an unknown format.")
    name = blob[2:2 + blob[1]].decode("utf-8", errors="replace")
    # Never trust a path from the file: keep only a plain name
    name = os.path.basename(name.replace("\\", "/")).strip() or "recovered_payload.bin"
    return name, blob[2 + blob[1]:]


def payload_kind(blob: bytes) -> int:
    """KIND_FILE or KIND_FOLDER from a decrypted payload blob."""
    return blob[0] if blob else KIND_FILE


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
