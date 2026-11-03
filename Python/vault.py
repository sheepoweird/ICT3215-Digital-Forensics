"""
EnvStego - vault.py
"Env Vault": an encrypted store whose key is bound to the token + environment.

Design (see the project notes):
  * Each imported file is AES-256-GCM encrypted under a random per-vault key and
    written as a random-named blob (no name, no extension, no header on disk).
  * The real names/sizes/dates live only in an encrypted index (index.bin),
    unreadable without the vault key.
  * The vault key itself is random and never derived straight from the environment.
    It is WRAPPED twice:
        - under HKDF(env_key)       — the token + this PC's signals (normal unlock)
        - under HKDF(recovery_key)  — a one-time code shown at creation (fallback)
    So a signal change (e.g. Wi-Fi drift) causes a *lock*, not data loss: re-wrap
    with the new environment and carry on. Losing the token is survivable via the
    recovery code.
  * The list of signals the vault is bound to is itself sealed under the token-only
    index key, so a disk image does not reveal which environment it needs.

This module is TOKEN-AGNOSTIC: callers pass in `index_key` and `env_key` (obtained
from token_comms in the UI), so it can be fully tested with stand-in keys.

ICT3215 Digital Forensics — SIT
"""

import base64
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

META_NAME = "vault.json"
INDEX_NAME = "index.bin"
VERSION = 1
NONCE_LEN = 12
SALT_LEN = 16
KEY_LEN = 32

# Each blob is zero-padded up to the next bucket before encryption so its size on
# disk reveals only a coarse bucket, not the item's exact byte count (which would
# let an examiner fingerprint a known file). The true length is kept in the sealed
# index and used to trim on read. Old, unpadded blobs still read correctly because
# the trim is a no-op when the stored size already matches.
_SIZE_BUCKET = 4096

def _bucketed(n: int) -> int:
    return max(_SIZE_BUCKET, ((n + _SIZE_BUCKET - 1) // _SIZE_BUCKET) * _SIZE_BUCKET)

# AAD / HKDF context strings keep the three uses of a key independent.
_SIG_AAD = b"EnvVault-signals-v1"
_ENV_AAD = b"EnvVault-envwrap-v1"
_REC_AAD = b"EnvVault-recwrap-v1"
_INDEX_AAD = b"EnvVault-index-v1"
_BLOB_AAD = b"EnvVault-blob-v1"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _wrap_key(key_material: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=info).derive(key_material)


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> str:
    """AES-GCM with a fresh nonce; returns base64(nonce | ct)."""
    nonce = os.urandom(NONCE_LEN)
    return _b64(nonce + AESGCM(key).encrypt(nonce, plaintext, aad))


def _open(key: bytes, blob_b64: str, aad: bytes) -> bytes:
    raw = _ub64(blob_b64)
    return AESGCM(key).decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], aad)


# ── recovery code (shown once) ───────────────────────────────────────────────
_RECOVERY_BYTES = 20          # 160 bits -> 32 base32 chars

def _new_recovery_code() -> tuple[bytes, str]:
    raw = secrets.token_bytes(_RECOVERY_BYTES)
    s = base64.b32encode(raw).decode("ascii").rstrip("=")
    grouped = "-".join(s[i:i + 4] for i in range(0, len(s), 4))
    return raw, grouped


def recovery_bytes_from_code(code: str) -> bytes:
    s = code.strip().upper().replace("-", "").replace(" ", "")
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad)


class VaultError(Exception):
    pass


def is_vault(path: str) -> bool:
    return (Path(path) / META_NAME).is_file()


class Vault:
    """An unlocked vault: holds the vault key and decrypted index in RAM only."""

    def __init__(self, path: str, vault_key: bytes, index: list[dict]):
        self._path = Path(path)
        self._key = vault_key
        self._index = index

    # -- lifecycle ------------------------------------------------------------
    @property
    def path(self) -> str:
        return str(self._path)

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def lock(self):
        """Drop the key and the decrypted index from memory."""
        # Best-effort overwrite (Python cannot guarantee erasure; see report notes).
        if self._key is not None:
            self._key = b"\x00" * len(self._key)
        self._key = None
        self._index = []

    def _require(self):
        if self._key is None:
            raise VaultError("Vault is locked.")

    # -- index ----------------------------------------------------------------
    def list_entries(self) -> list[dict]:
        """Metadata only: [{blob, name, size, added}, …] (newest first)."""
        self._require()
        return sorted(self._index, key=lambda e: e.get("added", 0), reverse=True)

    def count(self) -> int:
        return len(self._index)

    def total_bytes(self) -> int:
        return sum(int(e.get("size", 0)) for e in self._index)

    def _save_index(self):
        blob = _seal(self._key, json.dumps(self._index).encode("utf-8"), _INDEX_AAD)
        (self._path / INDEX_NAME).write_text(blob, encoding="ascii")

    # -- files ----------------------------------------------------------------
    def add_bytes(self, name: str, data: bytes) -> dict:
        """Encrypt raw bytes into the vault under a given display name. Returns the entry."""
        self._require()
        blob_id = secrets.token_hex(16)
        nonce = os.urandom(NONCE_LEN)
        padded = data + b"\x00" * (_bucketed(len(data)) - len(data))   # blur the on-disk size
        ct = AESGCM(self._key).encrypt(nonce, padded, _BLOB_AAD + blob_id.encode())
        (self._path / blob_id).write_bytes(nonce + ct)
        entry = {
            "blob": blob_id,
            "name": os.path.basename(name) or "unnamed",
            "size": len(data),
            "added": int(time.time()),
        }
        self._index.append(entry)
        self._save_index()
        return entry

    def add_file(self, src_path: str, *, shred_original: bool = True) -> dict:
        """Import a file: encrypt it in, then (optionally) shred the original."""
        with open(src_path, "rb") as f:
            data = f.read()
        entry = self.add_bytes(os.path.basename(src_path), data)
        if shred_original:
            try:
                from winutils import shred_file
                shred_file(src_path)
            except OSError:
                pass   # import succeeded; a failed shred must not lose the entry
        return entry

    def read_bytes(self, blob_id: str) -> tuple[str, bytes]:
        """Decrypt a blob in memory. Returns (name, data)."""
        self._require()
        entry = self._find(blob_id)
        raw = (self._path / blob_id).read_bytes()
        data = AESGCM(self._key).decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], _BLOB_AAD + blob_id.encode())
        return entry["name"], data[:entry["size"]]      # drop any size-blurring padding

    def export(self, blob_id: str, dest_dir: str) -> str:
        """Decrypt a blob to a real file on disk (explicit, leaves plaintext)."""
        name, data = self.read_bytes(blob_id)
        dest = Path(dest_dir) / name
        i = 1
        while dest.exists():
            dest = Path(dest_dir) / f"{Path(name).stem} ({i}){Path(name).suffix}"
            i += 1
        dest.write_bytes(data)
        return str(dest)

    def remove(self, blob_id: str):
        """Shred the blob and drop its index entry."""
        self._require()
        self._find(blob_id)            # validates existence
        blob_path = self._path / blob_id
        try:
            from winutils import shred_file
            shred_file(str(blob_path))
        except OSError:
            if blob_path.exists():
                blob_path.unlink()
        self._index = [e for e in self._index if e["blob"] != blob_id]
        self._save_index()

    def _find(self, blob_id: str) -> dict:
        for e in self._index:
            if e["blob"] == blob_id:
                return e
        raise VaultError("No such item in the vault.")

    # -- re-wrap (after environment drift) ------------------------------------
    def rewrap_env(self, index_key: bytes, env_key: bytes, signal_ids: list[str]):
        """Re-seal the vault key under a new environment (and update the sealed signal list)."""
        self._require()
        meta = _read_meta(self._path)
        env_salt = os.urandom(SALT_LEN)
        meta["env_salt"] = _b64(env_salt)
        meta["env_wrapped"] = _seal(_wrap_key(env_key, env_salt, _ENV_AAD), self._key, _ENV_AAD)
        meta["signals"] = _seal(index_key, json.dumps(sorted(signal_ids)).encode(), _SIG_AAD)
        _write_meta(self._path, meta)


# ── module-level key management ──────────────────────────────────────────────

def _read_meta(path) -> dict:
    return json.loads((Path(path) / META_NAME).read_text(encoding="utf-8"))


def _write_meta(path, meta: dict):
    (Path(path) / META_NAME).write_text(json.dumps(meta, indent=2), encoding="utf-8")


def create_vault(path: str, index_key: bytes, env_key: bytes,
                 signal_ids: list[str]) -> tuple["Vault", str]:
    """
    Create a new vault at `path`. Returns (unlocked Vault, recovery_code).
    The recovery code is shown to the user ONCE and never stored in the clear.
    """
    p = Path(path)
    if is_vault(path):
        raise VaultError("A vault already exists here.")
    p.mkdir(parents=True, exist_ok=True)
    if any(p.iterdir()):
        raise VaultError("Choose an empty folder for a new vault.")

    vault_key = secrets.token_bytes(KEY_LEN)
    rec_raw, rec_code = _new_recovery_code()
    env_salt, rec_salt = os.urandom(SALT_LEN), os.urandom(SALT_LEN)
    meta = {
        "version": VERSION,
        "created": int(time.time()),
        "signals": _seal(index_key, json.dumps(sorted(signal_ids)).encode(), _SIG_AAD),
        "env_salt": _b64(env_salt),
        "env_wrapped": _seal(_wrap_key(env_key, env_salt, _ENV_AAD), vault_key, _ENV_AAD),
        "rec_salt": _b64(rec_salt),
        "rec_wrapped": _seal(_wrap_key(rec_raw, rec_salt, _REC_AAD), vault_key, _REC_AAD),
    }
    _write_meta(p, meta)
    v = Vault(path, vault_key, [])
    v._save_index()
    return v, rec_code


def read_signal_ids(path: str, index_key: bytes) -> list[str]:
    """Which signals the vault is bound to (needs the token-only index key)."""
    meta = _read_meta(path)
    return json.loads(_open(index_key, meta["signals"], _SIG_AAD).decode("utf-8"))


def _load_index(path, vault_key) -> list[dict]:
    f = Path(path) / INDEX_NAME
    if not f.is_file():
        return []
    return json.loads(_open(vault_key, f.read_text(encoding="ascii"), _INDEX_AAD).decode("utf-8"))


def unlock_env(path: str, env_key: bytes) -> "Vault":
    """Unlock with the token + environment. Raises InvalidTag if the key is wrong."""
    meta = _read_meta(path)
    wrap = _wrap_key(env_key, _ub64(meta["env_salt"]), _ENV_AAD)
    vault_key = _open(wrap, meta["env_wrapped"], _ENV_AAD)
    return Vault(path, vault_key, _load_index(path, vault_key))


def unlock_recovery(path: str, recovery_code: str) -> "Vault":
    """Unlock with the recovery code (token/environment not required)."""
    meta = _read_meta(path)
    try:
        rec_raw = recovery_bytes_from_code(recovery_code)
    except Exception:
        raise VaultError("That recovery code is not valid.")
    wrap = _wrap_key(rec_raw, _ub64(meta["rec_salt"]), _REC_AAD)
    vault_key = _open(wrap, meta["rec_wrapped"], _REC_AAD)
    return Vault(path, vault_key, _load_index(path, vault_key))
