"""Key isolation, public-key recovery, batch export, and interrupted write regressions."""

import hmac
import io
import json
import os
import sys
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vault as V

INDEX = bytes(range(32))
ENV = bytes(range(32, 64))


class Token:
    def __init__(self):
        self.calls = []
        self.master = os.urandom(32)

    def __call__(self, operation, context):
        self.calls.append((operation, context))
        if operation == "batch":
            batch = os.urandom(16)
            return batch + hmac.digest(self.master, b"3T-VAULT-BATCH-v1" + context + batch, "sha256")
        if operation == "read" and len(context) == 64:
            seed = hmac.digest(self.master, b"3T-VAULT-BATCH-v1" + context[:48], "sha256")
            return hmac.digest(seed, b"3T-VAULT-CHILD-v1" + context[48:], "sha256")
        label = b"3T-VAULT-META-v2" if operation == "metadata" else b"3T-VAULT-FILE-v2"
        return hmac.digest(self.master, label + context, "sha256")


def new(tmp_path):
    token = Token()
    vault, code = V.create_vault(str(tmp_path / "vault"), INDEX, ENV, ["hw_cpu"], key_provider=token)
    return vault, code, token


def test_browsing_caches_only_a_metadata_key(tmp_path):
    vault, code, token = new(tmp_path)
    entry = vault.add_bytes("sample.docx", b"private file")
    assert len(token.calls) == 2
    assert token.calls[0][0] == "metadata" and token.calls[1][0] == "batch"
    vault.list_entries()
    assert len(token.calls) == 2
    file_key = token("read", V.export_context(V._meta(vault.path), entry))
    assert vault._metadata_key != file_key
    assert file_key not in vault.__dict__.values()
    assert not hasattr(vault, "_key")
    assert not hasattr(vault, "read_bytes")
    vault.lock()
    assert vault._metadata_key is None and vault._index == []
    with pytest.raises(V.VaultError, match="locked"):
        vault.export(entry["blob"], str(tmp_path))


def test_each_file_requires_its_own_key_and_each_export_requests_again(tmp_path):
    vault, _, token = new(tmp_path)
    first = vault.add_bytes("a.pdf", os.urandom(2000))
    second = vault.add_bytes("b.docx", os.urandom(2000))
    assert first["blob"] != second["blob"]
    meta = V._meta(vault.path)
    wrong_key = token("read", V.export_context(meta, first))
    with pytest.raises(InvalidTag):
        vault._decrypt_to(second, wrong_key, meta, lambda _: None)
    vault.export(first["blob"], str(tmp_path))
    vault.export(first["blob"], str(tmp_path))
    assert [op for op, _ in token.calls[-2:]] == ["read", "read"]


def test_recovery_needs_code_for_each_export_without_caching_it(tmp_path):
    vault, code, _ = new(tmp_path)
    entry = vault.add_bytes("secret.pdf", b"sample data")
    recovered = V.unlock_recovery(vault.path, code, local=True)
    assert recovered.count() == 1 and code not in recovered.__dict__.values()
    with pytest.raises(V.VaultError, match="recovery code"):
        recovered.export(entry["blob"], str(tmp_path))
    output = recovered.export(entry["blob"], str(tmp_path), recovery_code=code)
    assert Path(output).read_bytes() == b"sample data"
    with pytest.raises(V.VaultError, match="matching environment"):
        recovered.add_file(output)
    with pytest.raises(InvalidTag):
        V.unlock_recovery(vault.path, "A" * 52)


def test_public_recovery_wrap_cannot_be_opened_with_metadata_key(tmp_path):
    vault, _, _ = new(tmp_path)
    entry = vault.add_bytes("x", b"plaintext")
    raw = V._ub64(entry["recovery_wrapped"])
    with pytest.raises(InvalidTag):
        V._open(vault._metadata_key, V._b64(raw[32:]), V._binding(V._meta(vault.path)))


def test_drift_or_different_token_cannot_open_metadata(tmp_path):
    vault, _, _ = new(tmp_path)
    with pytest.raises(InvalidTag):
        V.unlock_env(vault.path, bytes(32), key_provider=Token())
    with pytest.raises(InvalidTag):
        V.unlock_env(vault.path, ENV, key_provider=Token())


def test_export_authentication_fails_without_publishing_plaintext(tmp_path):
    vault, _, _ = new(tmp_path)
    entry = vault.add_bytes("sample", b"secret")
    blob = Path(vault.path) / entry["blob"]
    raw = bytearray(blob.read_bytes())
    raw[-1] ^= 1
    blob.write_bytes(raw)
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(InvalidTag):
        vault.export(entry["blob"], str(destination))
    assert list(destination.iterdir()) == []


def test_concurrent_additions_keep_both_entries(tmp_path):
    first, code, token = new(tmp_path)
    second = V.unlock_env(first.path, ENV, key_provider=token)
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(session.add_bytes, name, name.encode())
                   for session, name in ((first, "a"), (second, "b"))]
        for future in futures:
            future.result()
    assert {entry["name"] for entry in V.unlock_recovery(first.path, code).list_entries()} == {"a", "b"}


def test_failed_index_commit_keeps_original_and_removes_orphan(tmp_path, monkeypatch):
    vault, _, _ = new(tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"precious original")
    original_files = set(Path(vault.path).iterdir())
    monkeypatch.setattr(V, "_save_entries", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        vault.add_file(source)
    assert source.read_bytes() == b"precious original"
    assert set(Path(vault.path).iterdir()) == original_files


def test_large_file_streams_and_export_never_overwrites(tmp_path):
    vault, _, _ = new(tmp_path)
    source = tmp_path / "large.bin"
    content = os.urandom(3 * V._CHUNK + 19)
    source.write_bytes(content)
    entry = vault.add_file(source, shred_original=False)
    output = vault.export(entry["blob"], str(tmp_path))
    assert Path(output) != source and source.read_bytes() == Path(output).read_bytes() == content


def test_old_vault_rejected_without_changing_it(tmp_path):
    old = tmp_path / "old"
    old.mkdir()
    (old / V.META_NAME).write_text(json.dumps({"version": 1, "env_wrapped": "AAAA"}), encoding="utf-8")
    before = (old / V.META_NAME).read_bytes()
    with pytest.raises(V.UnsupportedVault, match="empty folder"):
        V.unlock_env(str(old), ENV, key_provider=Token())
    assert (old / V.META_NAME).read_bytes() == before


def test_on_disk_leaks_no_names_plaintext_or_temporary_files(tmp_path):
    vault, _, _ = new(tmp_path)
    vault.add_bytes("passwords.txt", b"hunter2 is the secret")
    files = list(Path(vault.path).iterdir())
    assert {V.META_NAME, V.INDEX_NAME} <= {p.name for p in files}
    assert not [p for p in files if p.name.endswith(".tmp")]   # atomic writes leave none behind
    for path in files:
        raw = path.read_bytes()
        assert b"passwords" not in raw and b"hunter2" not in raw


def test_blob_size_reveals_only_its_bucket(tmp_path):
    vault, _, _ = new(tmp_path)
    small, larger = vault.add_bytes("a.bin", b"A" * 100), vault.add_bytes("b.bin", b"B" * 3000)
    sizes = {(Path(vault.path) / entry["blob"]).stat().st_size for entry in (small, larger)}
    assert len(sizes) == 1
    assert (small["size"], larger["size"]) == (100, 3000)   # true sizes live in the sealed index


def test_signal_list_and_creation_time_are_sealed_under_index_key(tmp_path):
    vault, _, _ = new(tmp_path)
    meta = V._read_meta(vault.path)
    assert V.read_signal_ids(vault.path, INDEX) == ["hw_cpu"]
    assert "hw_cpu" not in json.dumps(meta)
    with pytest.raises(InvalidTag):
        V.read_signal_ids(vault.path, bytes(32))
    created = int(V._open(INDEX, meta["created"], V._CREATED_AAD))
    assert created > 1_700_000_000 and isinstance(meta["created"], str)


def test_worker_process_does_not_return_file_keys_to_parent(tmp_path, monkeypatch):
    vault, _, _ = new(tmp_path)
    # Production sessions dispatch through the separate process boundary.
    session = V.Vault(vault.path, vault._metadata_key)
    seen = []
    monkeypatch.setattr(V, "_worker", lambda request, cancel: seen.append(request) or [str(tmp_path / "export")])
    session.export("ab" * 16, str(tmp_path))
    assert seen == [{"action": "export", "path": vault.path, "blobs": ["ab" * 16],
                     "destination": str(tmp_path), "recovery_code": None, "metadata_key": vault._metadata_key.hex()}]


def test_actual_recovery_worker_exports_and_exits(tmp_path):
    vault, code, _ = new(tmp_path)
    entry = vault.add_bytes("recovered.txt", b"child process result")
    session = V.unlock_recovery(vault.path, code)
    output = session.export(entry["blob"], str(tmp_path), recovery_code=code)
    assert Path(output).read_bytes() == b"child process result"
    assert not list(tmp_path.glob(".vault-operation-*"))
    assert code not in session.__dict__.values()


@pytest.mark.skipif(os.name != "nt", reason="Windows windowed executable handles")
def test_worker_restores_redirected_streams_for_windowed_build(tmp_path):
    vault, code, _ = new(tmp_path)
    entry = vault.add_bytes("windowed.txt", b"windowed worker")
    script = (f"import sys; sys.path.insert(0, {str(Path(V.__file__).parent)!r}); "
              "sys.stdin=None; sys.stdout=None; import vault_worker; sys.exit(vault_worker.main())")
    result = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True,
                            input=json.dumps({"action": "export", "path": vault.path, "blobs": [entry["blob"]],
                                              "destination": str(tmp_path), "recovery_code": code}), timeout=15)
    assert result.returncode == 0, result.stderr
    assert Path(json.loads(result.stdout)["result"][0]).read_bytes() == b"windowed worker"


def test_worker_rechecks_environment_before_requesting_content_key(tmp_path, monkeypatch):
    import vault_worker
    vault, _, token = new(tmp_path)
    entry = vault.add_bytes("file", b"content")
    calls_before = len(token.calls)
    request = {"action": "export", "path": vault.path, "blobs": [entry["blob"]], "destination": str(tmp_path)}
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(vault_worker.token_comms, "request_env_key", lambda _: INDEX)
    monkeypatch.setattr(vault_worker, "live_environment", lambda _: os.urandom(32))
    monkeypatch.setattr(vault_worker.token_comms, "request_vault_key", token)
    assert vault_worker.main() == 1
    assert "error" in json.loads(output.getvalue())
    assert len(token.calls) == calls_before


def test_cross_process_ble_lock_is_released_when_holder_exits(tmp_path):
    from winutils import process_file_lock
    lock_path = tmp_path / "ble.lock"
    script = (f"import sys,time; from pathlib import Path; sys.path.insert(0, {str(Path(V.__file__).parent)!r}); "
              "from winutils import process_file_lock; "
              f"\nwith process_file_lock(Path({str(lock_path)!r})):\n print('locked', flush=True); time.sleep(30)")
    child = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(TimeoutError):
            with process_file_lock(lock_path, timeout=0.1):
                pytest.fail("Lock admitted a second process")
    finally:
        child.terminate()
        child.communicate(timeout=5)
    with process_file_lock(lock_path, timeout=1):
        pass


def test_lock_terminates_export_child_and_cleans_partial_plaintext(tmp_path, monkeypatch):
    real_popen = V.subprocess.Popen
    children = []
    cancel = threading.Event()
    script = ("import json,sys,time; from pathlib import Path; r=json.load(sys.stdin); "
              "Path(r['temporary_dir'], 'partial').write_bytes(b'plaintext'); time.sleep(30)")

    def launch(_command, **options):
        child = real_popen([sys.executable, "-c", script], **options)
        children.append(child)
        return child

    monkeypatch.setattr(V.subprocess, "Popen", launch)
    timer = threading.Timer(1, cancel.set)
    timer.start()
    try:
        with pytest.raises(V.VaultError, match="cancelled"):
            V._worker({"action": "export", "destination": str(tmp_path)}, cancel)
    finally:
        timer.cancel()
    assert children and children[0].poll() is not None
    assert list(tmp_path.iterdir()) == []


def test_open_worker_uses_one_approval_for_all_selected_files(tmp_path, monkeypatch):
    vault, _, token = new(tmp_path)
    entries = [vault.add_bytes(name, name.encode()) for name in ("a", "b", "c")]
    session = V.Vault(vault.path, vault._metadata_key, local=True)
    calls = []
    def approve(contexts, consume):
        calls.append(contexts)
        for i, context in enumerate(contexts):
            consume(i, token("read", context))
    monkeypatch.setattr(V.token_comms, "export_selected_keys", approve)
    selected = [entries[2]["blob"], entries[0]["blob"]]
    outputs = session.export_many(selected, tmp_path)
    assert [Path(p).read_bytes() for p in outputs] == [b"c", b"a"]
    assert calls == [[V.export_context(V._meta(vault.path), entries[i]) for i in (2, 0)]]
    assert not (tmp_path / "b").exists()


@pytest.mark.parametrize("field,value", [("recovery_pub", "ab" * 32), ("env_hash", "cd" * 32),
                                         ("vault_id", "ef" * 16)])
def test_modified_vault_binding_cannot_open_recovery_index(tmp_path, field, value):
    vault, code, _ = new(tmp_path)
    meta = V._meta(vault.path)
    meta[field] = value
    V._write_meta(Path(vault.path), meta)
    with pytest.raises(InvalidTag):
        V.unlock_recovery(vault.path, code)


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 4097])
def test_padding_boundaries_round_trip(tmp_path, size):
    vault, _, _ = new(tmp_path)
    content = os.urandom(size)
    entry = vault.add_bytes(f"{size}.bin", content)
    assert Path(vault.export(entry["blob"], str(tmp_path))).read_bytes() == content

def test_cancelled_open_never_requests_metadata(tmp_path, monkeypatch):
    session, _, _ = new(tmp_path)
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(V, "_worker", lambda *args: pytest.fail("requested a key after cancellation"))
    with pytest.raises(V.VaultError, match="cancelled"):
        V.unlock_env(session.path, ENV, cancel=cancel)


@pytest.mark.parametrize("disconnect", [False, True])
def test_import_worker_reports_each_file_and_preserves_committed_entries(tmp_path, monkeypatch, disconnect):
    import vault_worker
    session, code, token = new(tmp_path)
    sources = [tmp_path / name for name in ("one.pdf", "two.docx", "three.png")]
    for source in sources:
        source.write_bytes(source.name.encode())
    request = {"action": "import", "path": session.path, "sources": list(map(str, sources)),
               "shred_original": False, "signal_ids": ["hw_cpu"], "metadata_key": session._metadata_key.hex()}
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(vault_worker, "live_environment", lambda _: ENV)
    def mint(context):
        if disconnect:
            raise V.token_comms.TokenTransientError("unavailable")
        return token("batch", context)
    monkeypatch.setattr(V.token_comms, "request_import_batch", mint)
    monkeypatch.setattr(V.token_comms, "request_env_key", lambda _: pytest.fail("extra BLE exchange"))
    assert vault_worker.main() == 0
    results = json.loads(output.getvalue())["result"]
    expected = [] if disconnect else sources
    if not disconnect:
        assert [op for op, _ in token.calls] == ["metadata", "batch"]
        assert len({e["batch"] for e in results}) == 1
        assert len({e["blob"] for e in results}) == 3
    if disconnect:
        assert results[-1] == {"error": "unavailable", "unreachable": True}
    assert [r["name"] for r in results if "name" in r] == [p.name for p in expected]
    recovered = V.unlock_recovery(session.path, code, local=True)
    assert recovered.count() == len(expected)
    assert all(p.read_bytes() == p.name.encode() for p in sources)
    for entry in recovered.list_entries():
        path = recovered.export(entry["blob"], tmp_path, recovery_code=code)
        assert Path(path).read_bytes() == entry["name"].encode()

def test_mixed_legacy_and_batch_entries_export(tmp_path):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session, _, token = new(tmp_path)
    modern = session.add_bytes("modern", b"new")
    meta = V._meta(session.path)
    blob = os.urandom(16)
    old = {"blob": blob.hex(), "size": 3, "name": "legacy", "added": 1}
    aad = V._binding(meta) + blob
    key = token("read", V.key_context(meta, old["blob"]))
    nonce = os.urandom(12)
    (Path(session.path) / old["blob"]).write_bytes(nonce + AESGCM(key).encrypt(nonce, b"old", aad))
    old["recovery_wrapped"] = V._recovery_wrap(bytes.fromhex(meta["recovery_pub"]), key, aad)
    V._save_entries(session.path, session._metadata_key, meta, [old, modern])
    outputs = session.export_many([old["blob"], modern["blob"]], tmp_path)
    assert [Path(path).read_bytes() for path in outputs] == [b"old", b"new"]
