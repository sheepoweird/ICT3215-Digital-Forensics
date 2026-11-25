"""Env Vault: per-file encryption with token-authorized keys and public-key recovery.

The open desktop session holds a metadata key only. Production import/export
operations run in vault_worker so file keys are never returned to the GUI.
See md/VAULT_SECURITY.md for the key hierarchy and on-disk format.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import token_comms
from winutils import atomic_write_text

META_NAME = "vault.json"
INDEX_NAME = "index.bin"
LOCK_NAME = ".vault.lock"
VERSION = 3
_CHUNK = 1 << 20
_NONCE_LEN = 12
# Plaintext is zero-padded to a 4 KiB bucket, so a blob's size on disk reveals only
# its bucket. The true size is kept in the sealed index and used to trim on export.
_SIZE_BUCKET = 4096
# The signal list and creation time in vault.json are sealed under the token-only index key.
_SIG_AAD = b"EnvVault-signals-v1"
_CREATED_AAD = b"EnvVault-created-v1"


class VaultError(Exception):
    pass


class UnsupportedVault(VaultError):
    pass


def _bucketed(n):
    return max(_SIZE_BUCKET, ((n + _SIZE_BUCKET - 1) // _SIZE_BUCKET) * _SIZE_BUCKET)


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _ub64(text):
    return base64.b64decode(text.encode("ascii"))


def _seal(key, plaintext, aad):
    """AES-GCM with a fresh nonce; returns base64(nonce | ciphertext)."""
    nonce = os.urandom(_NONCE_LEN)
    return _b64(nonce + AESGCM(key).encrypt(nonce, plaintext, aad))


def _open(key, sealed, aad):
    raw = _ub64(sealed)
    return AESGCM(key).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], aad)


def recovery_bytes_from_code(code):
    text = code.strip().upper().replace("-", "").replace(" ", "")
    return base64.b32decode(text + "=" * (-len(text) % 8))


@contextmanager
def _vault_file_lock(path):
    """Serialize vault writes across processes. Closing the handle releases the lock."""
    with (Path(path) / LOCK_NAME).open("a+b") as lock_file:
        if os.name == "nt":
            import msvcrt
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        yield


def is_vault(path):
    return (Path(path) / META_NAME).is_file()


def _read_meta(path):
    return json.loads((Path(path) / META_NAME).read_text(encoding="utf-8"))


def _write_meta(path, meta):
    atomic_write_text(Path(path) / META_NAME, json.dumps(meta, indent=2), "utf-8")


def read_signal_ids(path, index_key):
    """Which signals the vault is bound to (needs the token-only index key)."""
    return json.loads(_open(index_key, _read_meta(path)["signals"], _SIG_AAD).decode("utf-8"))


def _meta(path):
    meta = _read_meta(path)
    if meta.get("version") != VERSION:
        raise UnsupportedVault("Unsupported vault format. Choose an empty folder to create a new vault.")
    for field, length in (("vault_id", 16), ("recovery_pub", 32)):
        if len(bytes.fromhex(meta[field])) != length:
            raise VaultError("Invalid vault metadata.")
    return meta


def _binding(meta):
    fields = {key: meta[key] for key in ("version", "vault_id", "recovery_pub", "signals", "created")}
    return b"EnvVault-v3" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def _id_bytes(hex_id, what):
    try:
        raw = bytes.fromhex(hex_id)
    except (TypeError, ValueError) as exc:
        raise VaultError(f"Invalid vault {what} identifier.") from exc
    if len(raw) != 16:
        raise VaultError(f"Invalid vault {what} identifier.")
    return raw


def key_context(meta, env_hash):
    """The token context for this vault in the live environment.

    The environment hash is never stored: a different environment gives a different
    context, so the token derives keys that fail to open the index.
    """
    if env_hash is None or len(env_hash) != 32:
        raise VaultError("The vault environment is unavailable.")
    return hashlib.sha256(b"EnvVault-v3" + bytes.fromhex(meta["vault_id"]) + env_hash).digest()


def export_context(meta, env_hash, entry):
    return (key_context(meta, env_hash) + _id_bytes(entry.get("batch"), "batch")
            + _id_bytes(entry["blob"], "file"))


def _recovery_private(code):
    try:
        raw = recovery_bytes_from_code(code)
        if len(raw) != 32:
            raise ValueError("length")
        return X25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise VaultError("Invalid recovery code.") from exc


def _recovery_wrap(public, key, aad):
    ephemeral = X25519PrivateKey.generate()
    ep = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(public))
    wrapping = HKDF(hashes.SHA256(), 32, None, b"EnvVault-recovery-v2" + ep + public).derive(shared)
    return _b64(ep + _ub64(_seal(wrapping, key, aad)))


def _recovery_open(meta, code, wrapped, aad):
    private = _recovery_private(code)
    public = private.public_key().public_bytes_raw()
    if public != bytes.fromhex(meta["recovery_pub"]):
        raise InvalidTag
    raw = _ub64(wrapped)
    shared = private.exchange(X25519PublicKey.from_public_bytes(raw[:32]))
    wrapping = HKDF(hashes.SHA256(), 32, None, b"EnvVault-recovery-v2" + raw[:32] + public).derive(shared)
    return _open(wrapping, _b64(raw[32:]), aad)


def _entries(path, metadata_key, meta):
    data = (Path(path) / INDEX_NAME).read_text(encoding="ascii")
    entries = json.loads(_open(metadata_key, data, _binding(meta)).decode())
    if not isinstance(entries, list):
        raise VaultError("Invalid vault index.")
    seen = set()
    for entry in entries:
        _id_bytes(entry["blob"], "file")
        if entry["blob"] in seen or entry["size"] < 0 or not isinstance(entry["size"], int):
            raise VaultError("Invalid vault index entry.")
        if entry["name"] != os.path.basename(entry["name"]) or entry["name"] in ("", ".", ".."):
            raise VaultError("Invalid vault filename.")
        seen.add(entry["blob"])
    return entries


def _save_entries(path, key, meta, entries):
    sealed = _seal(key, json.dumps(entries).encode(), _binding(meta))
    atomic_write_text(Path(path) / INDEX_NAME, sealed, "ascii")


def _worker(request, cancel=None):
    """Pass secrets over stdin. Only opening the list returns a key, scoped to metadata."""
    if request["action"] == "export" and "temporary_dir" not in request:
        with tempfile.TemporaryDirectory(dir=request["destination"], prefix=".vault-operation-") as temporary:
            return _worker({**request, "temporary_dir": temporary}, cancel)
    command = [sys.executable, str(Path(__file__).with_name("vault_worker.py"))]
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--vault-worker"]
    with subprocess.Popen(command, stdin=subprocess.PIPE, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          creationflags=0x08000000 if os.name == "nt" else 0) as process:
        message = json.dumps(request)
        while True:
            if cancel is not None and cancel.is_set():
                process.terminate()
                process.communicate()
                raise VaultError("Vault operation cancelled because the file list was locked.")
            try:
                output, _ = process.communicate(message, timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                message = None
        status = process.returncode
    try:
        result = json.loads(output)
    except ValueError as exc:
        raise VaultError("The vault operation ended unexpectedly. Check the token connection.") from exc
    if status or "error" in result:
        raise VaultError(result.get("error", "The vault operation failed."))
    return result["result"]


class Vault:
    """An open metadata session. No vault root, recovery secret, or file key is cached."""

    def __init__(self, path, metadata_key, *, recovery=False, key_provider=None, local=False, signal_ids=None,
                 env_hash=None):
        self._path = Path(path)
        self._metadata_key = metadata_key
        self._env_hash = env_hash
        self.recovery = recovery
        self._signal_ids = tuple(signal_ids) if signal_ids is not None else None
        self._provider = key_provider
        self._local = local or key_provider is not None
        self._cancel = threading.Event()
        self._index = self.list_entries()

    @property
    def path(self):
        return str(self._path)

    @property
    def unlocked(self):
        return self._metadata_key is not None

    def lock(self):
        self._cancel.set()
        self._metadata_key = None
        self._env_hash = None
        self._signal_ids = None
        self._index = []

    def _require(self):
        if not self.unlocked:
            raise VaultError("Vault is locked.")

    def list_entries(self):
        self._require()
        self._index = _entries(self._path, self._metadata_key, _meta(self._path))
        return sorted(self._index, key=lambda item: item["added"], reverse=True)

    def count(self):
        return len(self._index)

    def total_bytes(self):
        return sum(entry["size"] for entry in self._index)

    def _entry(self, blob_id):
        for entry in self.list_entries():
            if entry["blob"] == blob_id:
                return entry
        raise VaultError("No such file in the vault.")

    def _action_worker(self, request):
        # The list was already physically approved. Send its metadata key via stdin
        # so a short-lived worker can authenticate the index without reopening it.
        request = {**request, "path": self.path, "metadata_key": self._metadata_key.hex()}
        if self._env_hash is not None:
            request["env_hash"] = self._env_hash.hex()
        return _worker(request, self._cancel)

    def add_file(self, src_path, *, shred_original=True):
        self._require()
        if self.recovery:
            raise VaultError("Use the token and matching environment to import files.")
        if self._local:
            meta = _meta(self.path)
            return self._import_file(src_path, shred_original, meta, self._new_batch(meta))
        result = self.add_files([src_path], shred_original=shred_original)[0]
        if "error" in result:
            raise VaultError(result["error"])
        return result

    def _new_batch(self, meta):
        context = key_context(meta, self._env_hash)
        response = (self._provider("batch", context) if self._provider else
                    token_comms.request_import_batch(context))
        if len(response) != 48:
            raise VaultError("Invalid batch key response from the token.")
        return response[:16], response[16:]

    def add_files(self, sources, *, shred_original=True):
        self._require()
        if self.recovery:
            raise VaultError("Use the token and matching environment to import files.")
        sources = [str(source) for source in sources]
        if not sources:
            return []
        if not self._local:
            results = self._action_worker({"action": "import", "sources": sources,
                                           "signal_ids": self._signal_ids, "shred_original": shred_original})
            self.list_entries()
            return results

        results = []
        meta = _meta(self.path)
        try:
            batch = self._new_batch(meta)
        except (token_comms.TokenError, VaultError, OSError) as exc:
            return [{"error": str(exc), "unreachable": isinstance(exc, token_comms.TokenTransientError)}
                    for _ in sources]
        try:
            for source in sources:
                self._require()
                try:
                    entry = self._import_file(source, shred_original, meta, batch)
                except (OSError, VaultError) as exc:
                    results.append({"error": str(exc)})
                else:
                    results.append(entry)
        finally:
            del batch
        return results

    def _import_file(self, src_path, shred_original, meta, batch):
        with open(src_path, "rb") as source:
            entry = self._add_stream(os.path.basename(src_path), source, os.fstat(source.fileno()).st_size,
                                     meta=meta, batch=batch)
        status = "kept"
        if shred_original:
            try:
                from winutils import shred_file
                status = "shredded" if shred_file(src_path) else "unconfirmed"
            except OSError:
                status = "unconfirmed"
        return {**entry, "shred_status": status}

    def add_bytes(self, name, data):
        self._require()
        if not self._local:
            raise VaultError("Use add_file to import through the vault worker.")
        if self.recovery:
            raise VaultError("Use the token and matching environment to import files.")
        meta = _meta(self.path)
        return self._add_stream(os.path.basename(name), io.BytesIO(data), len(data),
                                meta=meta, batch=self._new_batch(meta))

    def _add_stream(self, name, source, size, *, meta, batch):
        self._require()
        batch_id, seed = batch
        blob = secrets.token_bytes(16)
        entry = {"blob": blob.hex(), "batch": batch_id.hex(), "name": name, "size": size, "added": int(time.time())}
        blob_path = self._path / entry["blob"]
        key = hmac.digest(seed, b"3T-VAULT-CHILD-v1" + blob, "sha256")
        aad = _binding(meta) + bytes.fromhex(entry["blob"])
        entry["recovery_wrapped"] = _recovery_wrap(bytes.fromhex(meta["recovery_pub"]), key, aad)
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)
        original_hash = hashlib.sha256()
        total = 0
        committed = False
        out = blob_path.open("xb")
        try:
            with out:
                out.write(nonce)
                for chunk in iter(lambda: source.read(_CHUNK), b""):
                    total += len(chunk)
                    if total > size:
                        raise VaultError("The source file changed during import.")
                    original_hash.update(chunk)
                    out.write(encryptor.update(chunk))
                if total != size:
                    raise VaultError("The source file changed during import.")
                out.write(encryptor.update(bytes(_bucketed(size) - size)))
                out.write(encryptor.finalize())
                out.write(encryptor.tag)
                out.flush()
                os.fsync(out.fileno())
            verified = hashlib.sha256()
            self._decrypt_to(entry, key, meta, verified.update)
            if verified.digest() != original_hash.digest():
                raise VaultError("The encrypted copy did not match the source file.")
            with _vault_file_lock(self._path):
                self._require()
                current_meta = _meta(self._path)
                if current_meta != meta:
                    raise VaultError("The vault changed during import.")
                entries = _entries(self.path, self._metadata_key, meta)
                _save_entries(self.path, self._metadata_key, meta, [*entries, entry])
                committed = True
                self._index = [*entries, entry]
            return entry
        finally:
            key = None
            encryptor = None
            if not committed:
                blob_path.unlink(missing_ok=True)

    def _decrypt_to(self, entry, key, meta, write):
        with (self._path / entry["blob"]).open("rb") as source:
            source.seek(0, 2)
            length = source.tell()
            if length < 28 or entry["size"] > length - 28:
                raise VaultError("The encrypted file is truncated.")
            source.seek(-16, 2)
            tag = source.read(16)
            source.seek(0)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(source.read(12), tag)).decryptor()
            decryptor.authenticate_additional_data(_binding(meta) + bytes.fromhex(entry["blob"]))
            remaining, needed = length - 28, entry["size"]
            while remaining:
                chunk = source.read(min(_CHUNK, remaining))
                if not chunk:
                    raise VaultError("The encrypted file is truncated.")
                plain = decryptor.update(chunk)
                write(plain[:needed])
                needed = max(0, needed - len(plain))
                remaining -= len(chunk)
            decryptor.finalize()

    def export(self, blob_id, dest_dir, *, recovery_code=None, temporary_dir=None):
        return self.export_many([blob_id], dest_dir, recovery_code=recovery_code, temporary_dir=temporary_dir)[0]

    def export_many(self, blobs, dest_dir, *, recovery_code=None, temporary_dir=None):
        self._require()
        if not blobs or len(set(blobs)) != len(blobs):
            raise VaultError("Select distinct files for export.")
        if self.recovery and not recovery_code:
            raise VaultError("Enter the recovery code for this export.")
        if not self._local:
            return self._action_worker({"action": "export", "blobs": list(blobs),
                                        "destination": str(dest_dir), "recovery_code": recovery_code})
        meta = _meta(self.path)
        indexed = {entry["blob"]: entry for entry in self.list_entries()}
        if any(blob not in indexed for blob in blobs):
            raise VaultError("A selected file is no longer in the vault.")
        entries = [indexed[blob] for blob in blobs]
        outputs = []

        def consume(index, key):
            self._require()
            outputs.append(self._export_file(entries[index], key, meta, dest_dir, temporary_dir))

        if recovery_code:
            for i, entry in enumerate(entries):
                key = _recovery_open(meta, recovery_code, entry["recovery_wrapped"],
                                     _binding(meta) + bytes.fromhex(entry["blob"]))
                consume(i, key)
                del key
        else:
            contexts = [export_context(meta, self._env_hash, entry) for entry in entries]
            if self._provider:
                for i, context in enumerate(contexts):
                    consume(i, self._provider("read", context))
            else:
                token_comms.export_selected_keys(contexts, consume)
        return outputs

    def _export_file(self, entry, key, meta, dest_dir, temporary_dir):
        target = Path(dest_dir) / entry["name"]
        # Authenticate before creating plaintext output. Recheck the tag while writing.
        self._decrypt_to(entry, key, meta, lambda _: None)
        with tempfile.NamedTemporaryFile(dir=temporary_dir or dest_dir, prefix=".vault-export-", delete=False) as out:
            temporary = Path(out.name)
            try:
                self._decrypt_to(entry, key, meta, out.write)
                out.flush()
                os.fsync(out.fileno())
                out.close()
                number = 0
                while True:
                    try:
                        # Publish atomically without overwriting an existing file.
                        if os.name == "nt":
                            os.rename(temporary, target)  # Windows refuses existing targets, including on exFAT.
                        else:
                            os.link(temporary, target)
                        break
                    except FileExistsError:
                        number += 1
                        target = Path(dest_dir) / f"{Path(entry['name']).stem} ({number}){Path(entry['name']).suffix}"
                return str(target)
            finally:
                key = None
                out.close()
                temporary.unlink(missing_ok=True)

    def remove(self, blob_id):
        self._require()
        with _vault_file_lock(self._path):
            meta = _meta(self.path)
            entries = _entries(self.path, self._metadata_key, meta)
            if not any(entry["blob"] == blob_id for entry in entries):
                raise VaultError("No such file in the vault.")
            updated = [entry for entry in entries if entry["blob"] != blob_id]
            _save_entries(self.path, self._metadata_key, meta, updated)
            self._index = updated
            (self._path / blob_id).unlink(missing_ok=True)


def _open_metadata(meta, env_hash, provider, cancel):
    context = key_context(meta, env_hash)
    if cancel is not None and cancel.is_set():
        raise VaultError("Vault opening cancelled.")
    if cancel is not None and provider is None:
        # Isolate the physical-button wait so locking or closing can disconnect it.
        result = _worker({"action": "open", "context": context.hex()}, cancel)
        return bytes.fromhex(result)
    return (provider or token_comms.request_vault_key)("metadata", context)


def create_vault(path, index_key, env_hash, signal_ids, *, key_provider=None, local=False, cancel=None):
    if len(env_hash) != 32:
        raise VaultError("Invalid environment hash.")
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    private = X25519PrivateKey.generate()
    raw = private.private_bytes_raw()
    encoded = base64.b32encode(raw).decode().rstrip("=")
    code = "-".join(encoded[i:i + 4] for i in range(0, len(encoded), 4))
    meta = {"version": VERSION, "vault_id": secrets.token_hex(16),
            "recovery_pub": private.public_key().public_bytes_raw().hex(),
            "signals": _seal(index_key, json.dumps(sorted(signal_ids)).encode(), _SIG_AAD),
            "created": _seal(index_key, str(int(time.time())).encode(), _CREATED_AAD)}
    metadata_key = _open_metadata(meta, env_hash, key_provider, cancel)
    meta["recovery_index"] = _recovery_wrap(bytes.fromhex(meta["recovery_pub"]), metadata_key, _binding(meta))
    with _vault_file_lock(directory):
        if any(item.name != LOCK_NAME for item in directory.iterdir()):
            raise VaultError("Choose an empty folder for the vault.")
        _save_entries(path, metadata_key, meta, [])
        try:
            _write_meta(directory, meta)
        except Exception:
            (directory / INDEX_NAME).unlink(missing_ok=True)
            raise
    return Vault(path, metadata_key, key_provider=key_provider, local=local, signal_ids=signal_ids,
                 env_hash=env_hash), code


def unlock_env(path, env_hash, *, key_provider=None, local=False, cancel=None, signal_ids=None):
    """Open the file list. A wrong environment or token raises InvalidTag on the index."""
    meta = _meta(path)
    key = _open_metadata(meta, env_hash, key_provider, cancel)
    return Vault(path, key, key_provider=key_provider, local=local, signal_ids=signal_ids, env_hash=env_hash)


def unlock_recovery(path, recovery_code, *, local=False):
    meta = _meta(path)
    key = _recovery_open(meta, recovery_code, meta["recovery_index"], _binding(meta))
    return Vault(path, key, recovery=True, local=local)
