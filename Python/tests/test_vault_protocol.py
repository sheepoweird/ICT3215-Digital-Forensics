"""Exercise the real BLE transport using scripted, encrypted v7/v8 wire responses.

These are host protocol tests, not a substitute for executing firmware on hardware.
"""

import asyncio
import hashlib
import hmac
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import token_comms as tc

AUTH, MASTER, TOKEN_ID = os.urandom(32), os.urandom(32), os.urandom(16)


class Link:
    def __init__(self, mode="approve"):
        self.mode = mode
        self.exchanges = []
        self.cursor = bytes(32)
        self.prompts = []
        self.stopped = False
        self.closed = False
        self.nonce = os.urandom(tc.NONCE_LEN)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        self.closed = True

    async def start_notify(self, _uuid, callback):
        self.notify = lambda data: callback(None, data)

    async def stop_notify(self, _uuid):
        self.stopped = True

    def reply(self, key, status, value=bytes(32)):
        iv = os.urandom(tc.IV_LEN)
        return bytes([tc.MSG_RESPONSE]) + iv + AESGCM(key).encrypt(
            iv, bytes([status]) + value, b"3T-RSP-v1" + TOKEN_ID)

    async def write_gatt_char(self, _uuid, request, **_):
        if request == bytes([tc.MSG_HELLO]):
            self.notify(bytes([tc.MSG_CHALLENGE]) + self.nonce + TOKEN_ID)
            return
        host = request[1:1 + tc.NONCE_LEN]
        key = tc._session_key(AUTH, self.nonce, host)
        offset = 1 + tc.NONCE_LEN
        plain = AESGCM(key).decrypt(request[offset:offset + tc.IV_LEN], request[offset + tc.IV_LEN:],
                                   b"3T-REQ-v1" + TOKEN_ID)
        op, context = plain[0], plain[1:]
        self.exchanges.append(op)
        if self.mode == "drop_batch" and op == tc.OP_IMPORT_BATCH:
            raise OSError("Bluetooth device disconnected")
        if self.mode == "old":
            self.notify(bytes([tc.MSG_ERROR, 0x04]))
            return
        approval = op in (tc.OP_VAULT_OPEN, tc.OP_EXPORT_BEGIN)
        if (approval and self.mode != "skip") or self.mode == "unexpected":
            self.prompts.append(op)
            pending = self.reply(key, 1)
            if self.mode == "forged":
                pending = pending[:-1] + bytes([pending[-1] ^ 1])
            self.notify(pending)
            if self.mode in ("hold", "forged", "unexpected"):
                return
            if self.mode == "timeout":
                self.notify(bytes([tc.MSG_ERROR, 0x07]))
                return
        if op == tc.OP_EXPORT_BEGIN:
            self.cursor = context
            value = bytes(32)
        elif op in (tc.OP_EXPORT_NEXT, tc.OP_EXPORT_CHILD):
            if self.cursor == bytes(32) or hashlib.sha256(context).digest() != self.cursor:
                self.notify(bytes([tc.MSG_ERROR, 0x04]))
                return
            context, self.cursor = context[:-32], context[-32:]
            if op == tc.OP_EXPORT_CHILD:
                seed = hmac.digest(MASTER, b"3T-VAULT-BATCH-v1" + context[:48], "sha256")
                value = hmac.digest(seed, b"3T-VAULT-CHILD-v1" + context[48:], "sha256")
            else:
                value = hmac.digest(MASTER, b"3T-VAULT-FILE-v2" + context, "sha256")
        elif op == tc.OP_IMPORT_BATCH:
            batch = os.urandom(16)
            value = batch + hmac.digest(MASTER, b"3T-VAULT-BATCH-v1" + context + batch, "sha256")
        elif op == tc.OP_VAULT_MINT:
            blob = os.urandom(16)
            ctx = hashlib.sha256(b"EnvVault-v2" + context + blob).digest()
            value = blob + hmac.digest(MASTER, b"3T-VAULT-FILE-v2" + ctx, "sha256")
        else:
            label = b"3T-VAULT-META-v2" if op == tc.OP_VAULT_OPEN else b"3T-ENV-v1"
            value = hmac.digest(MASTER, label + context, "sha256")
        final_key = os.urandom(32) if self.mode == "stale" else key
        self.notify(self.reply(final_key, 0, value))


def connect(monkeypatch, mode="approve"):
    link = Link(mode)
    monkeypatch.setattr(tc, "_load_credentials", lambda: ({"ble_mac": "test"}, AUTH, TOKEN_ID))
    monkeypatch.setattr(tc, "BleakClient", lambda *_, **__: link)
    return link


def test_mint_and_one_tap_export_for_a_selection(monkeypatch, tmp_path):
    link = connect(monkeypatch)
    monkeypatch.setattr(tc, "_app_dir", lambda: tmp_path)
    vault = os.urandom(48)
    files = [tc.request_vault_key("mint", vault) for _ in range(3)]
    assert len(set(files)) == 3 and link.prompts == []
    contexts = [hashlib.sha256(b"EnvVault-v2" + vault + file[:16]).digest() for file in files]
    expected = [files[2][16:], files[0][16:]]
    received = []
    tc.export_selected_keys([contexts[2], contexts[0]], lambda i, key: received.append((i, key)))
    assert received == list(enumerate(expected))
    assert link.prompts == [tc.OP_EXPORT_BEGIN] and link.cursor == bytes(32)
    assert link.closed and link.stopped


def test_selected_context_cannot_be_substituted(monkeypatch):
    link = connect(monkeypatch)
    step = os.urandom(32) + bytes(32)
    with pytest.raises(tc.TokenError):
        asyncio.run(tc._transaction(tc.OP_EXPORT_BEGIN, hashlib.sha256(step).digest(),
                                    steps=[os.urandom(64)], consume=lambda *_: pytest.fail("released key")))
    assert link.closed


def test_open_requires_one_prompt_and_key_domains_do_not_overlap(monkeypatch):
    link = connect(monkeypatch)
    context = os.urandom(32)
    index = asyncio.run(tc._transaction(tc.OP_VAULT_OPEN, context))
    assert index == hmac.digest(MASTER, b"3T-VAULT-META-v2" + context, "sha256")
    assert index != asyncio.run(tc._transaction(tc.OP_DERIVE, context))
    assert link.prompts == [tc.OP_VAULT_OPEN]


@pytest.mark.parametrize("mode,error,match", [
    ("forged", tc.TokenAuthError, "authentication"),
    ("stale", tc.TokenAuthError, "authentication"),
    ("timeout", tc.TokenError, "confirmed"),
    ("skip", tc.TokenAuthError, "Missing authenticated"),
    ("old", tc.TokenError, "firmware v7"),
    ("unexpected", tc.TokenAuthError, "Unexpected vault approval"),
])
def test_rejected_approval_never_returns_key(monkeypatch, mode, error, match):
    link = connect(monkeypatch, mode)
    op = tc.OP_PING if mode == "unexpected" else tc.OP_VAULT_OPEN
    with pytest.raises(error, match=match):
        asyncio.run(tc._transaction(op, bytes(32)))
    assert link.stopped and link.closed


def test_unapproved_request_can_be_cancelled_and_disconnects(monkeypatch):
    link = connect(monkeypatch, "hold")

    async def cancel():
        await asyncio.wait_for(tc._transaction(tc.OP_EXPORT_BEGIN, bytes(32)), timeout=0.05)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(cancel())
    assert link.stopped and link.closed

@pytest.mark.parametrize("drop", [False, True])
def test_one_import_secret_then_disconnect(monkeypatch, tmp_path, drop):
    links = []
    def make_link(*args, **kwargs):
        link = Link("drop_batch" if drop and not links else "normal")
        links.append(link)
        return link

    monkeypatch.setattr(tc, "BleakClient", make_link)
    monkeypatch.setattr(tc, "_app_dir", lambda: tmp_path)
    monkeypatch.setattr(tc, "_load_credentials", lambda: ({"ble_mac": "test"}, AUTH, TOKEN_ID))
    ctx = os.urandom(32)
    batch = tc.request_import_batch(ctx)
    assert len(links) == (2 if drop else 1)
    assert all(link.exchanges == [tc.OP_IMPORT_BATCH] and link.closed for link in links)
    assert batch[16:] == hmac.digest(MASTER, b"3T-VAULT-BATCH-v1" + ctx + batch[:16], "sha256")
    files = [os.urandom(16) for _ in range(3)]
    keys = [hmac.digest(batch[16:], b"3T-VAULT-CHILD-v1" + file, "sha256") for file in files]
    obtained = []
    legacy = os.urandom(32)
    tc.export_selected_keys([ctx + batch[:16] + files[2], legacy], lambda _, key: obtained.append(key))
    assert obtained == [keys[2], hmac.digest(MASTER, b"3T-VAULT-FILE-v2" + legacy, "sha256")]
    assert batch[16:] not in obtained and keys[0] not in obtained
    assert links[-1].exchanges == [tc.OP_EXPORT_BEGIN, tc.OP_EXPORT_CHILD, tc.OP_EXPORT_NEXT]


def test_v7_cannot_silently_fall_back_to_per_file_imports(monkeypatch, tmp_path):
    link = connect(monkeypatch, "old")
    monkeypatch.setattr(tc, "_app_dir", lambda: tmp_path)
    with pytest.raises(tc.TokenError, match="firmware v8"):
        tc.request_import_batch(bytes(32))
    assert link.exchanges == [tc.OP_IMPORT_BATCH]
