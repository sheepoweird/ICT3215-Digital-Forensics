"""
EnvStego - token_comms.py
Communication with the 3T hardware token (ESP32).

Phase 1 — USB pairing (physical confirmation, with proof for re-pairing):
    The token generates a master secret that never leaves it, plus an auth key
    and token ID that it hands to this PC. The auth key is stored encrypted
    with Windows DPAPI so it is bound to the current Windows user account.

Phase 2 — BLE key requests (untrusted wireless channel):
    Challenge-response with a fresh nonce from each side. The session key is
    derived from the auth key and both nonces, and every message is AES-GCM
    encrypted, so a sniffer learns nothing, a replayed exchange fails, and an
    impostor device without the auth key is detected. Only a hash of the
    environment is sent, never the raw signal values.

The byte layout must match "ESP32 Files/main.cpp".
"""

import asyncio
import base64
import concurrent.futures
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import serial
import serial.tools.list_ports
from bleak import BleakClient
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from winutils import atomic_write_text, process_file_lock


def _app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


CONFIG_FILE = _app_dir() / "token_config.json"
CONFIG_VERSION = 2
CHARACTERISTIC_UUID = "beb5483f-36e1-4688-b7f5-ea07361b26a8"

# ── Protocol constants ───────────────────────────────────────────
MSG_HELLO, MSG_CHALLENGE = 0x10, 0x11
MSG_REQUEST, MSG_RESPONSE = 0x20, 0x21
MSG_ERROR = 0x7F

OP_DERIVE, OP_PING = 0x01, 0x02
OP_VAULT_OPEN, OP_VAULT_MINT, OP_EXPORT_BEGIN, OP_EXPORT_NEXT = 0x13, 0x14, 0x15, 0x16
OP_IMPORT_BATCH, OP_EXPORT_CHILD = 0x17, 0x18

NONCE_LEN, TOKEN_ID_LEN, IV_LEN, TAG_LEN, HASH_LEN = 16, 16, 12, 16, 32
CHALLENGE_LEN = 1 + NONCE_LEN + TOKEN_ID_LEN
RESPONSE_LEN = 1 + IV_LEN + (1 + HASH_LEN) + TAG_LEN

TOKEN_ERRORS = {
    0x01: "Token is not paired. It may have been factory reset — pair it again over USB.",
    0x02: "Token rejected the request (no active challenge). Please retry.",
    0x03: "Token rejected this PC's credentials. The pairing is stale or was replaced — pair again over USB.",
    0x04: "Token rejected a malformed request. Check the firmware version matches this app.",
    0x05: "Token is locked out after repeated failed requests. Wait 30 seconds and retry.",
    0x06: "The token could not complete the request. Try again.",
    0x07: "Vault access was not confirmed on the token within 60 seconds.",
}


class TokenError(Exception):
    """Any failure talking to the hardware token, with a user-facing message."""


class TokenNotPairedError(TokenError):
    pass


class TokenAuthError(TokenError):
    """The device answered but could not prove it is the paired token."""


class TokenTransientError(TokenError):
    """The connection failed or timed out without a token identity failure."""


class TokenConfirmationPending(TokenError):
    """An authenticated response is waiting for a physical IO0 confirmation."""


# ── Credential storage (Windows DPAPI) ───────────────────────────

def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    entropy_raw = b"EnvStego-3T-token"
    ebuf = ctypes.create_string_buffer(entropy_raw, len(entropy_raw))
    entropy = DATA_BLOB(len(entropy_raw), ctypes.cast(ebuf, ctypes.POINTER(ctypes.c_char)))

    crypt32 = ctypes.windll.crypt32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    ok = fn(ctypes.byref(blob_in), None, ctypes.byref(entropy), None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _protect_secret(secret: bytes) -> tuple[str, str]:
    if os.name == "nt":
        return base64.b64encode(_dpapi(secret, True)).decode(), "dpapi"
    return base64.b64encode(secret).decode(), "none"


def _unprotect_secret(blob: str, scheme: str) -> bytes:
    raw = base64.b64decode(blob)
    if scheme == "dpapi":
        try:
            return _dpapi(raw, False)
        except OSError:
            raise TokenNotPairedError(
                "The stored token credentials cannot be unlocked by this Windows account.\n"
                "They were created by another user or on another machine — pair the token again."
            )
    return raw


def load_config() -> dict | None:
    """Returns the saved pairing, or None if this PC is not paired (or uses the old insecure format)."""
    try:
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(cfg, dict) or cfg.get("version") != CONFIG_VERSION or "auth_key" not in cfg:
        return None
    return cfg


def forget_pairing():
    """Deletes this PC's copy of the pairing credentials."""
    try:
        CONFIG_FILE.unlink()
    except FileNotFoundError:
        pass


def token_fingerprint(token_id_hex: str) -> str:
    """Short human-readable form of the token ID, e.g. 'A1B2-C3D4'."""
    t = token_id_hex.upper()
    return f"{t[:4]}-{t[4:8]}"


# ── Phase 1: USB pairing ─────────────────────────────────────────

def list_serial_ports() -> list[tuple[str, str]]:
    """Returns [(device, description)], likely ESP32 USB-serial bridges first."""
    bridges = ("CH340", "CP210", "USB-SERIAL", "USB SERIAL", "UART", "FTDI")
    ports = []
    for p in serial.tools.list_ports.comports():
        desc = p.description or p.device
        likely = any(b in desc.upper() for b in bridges)
        ports.append((not likely, p.device, desc))
    ports.sort()
    return [(dev, desc) for _, dev, desc in ports]


def _parse_fields(line: str) -> dict:
    fields = {}
    for part in line.split(";")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


# Long enough for the token to finish starting up (3 s reset window + BLE start) and for
# the user to pick it up and press its IO0 button to confirm (the token waits 60 s).
PAIR_WINDOW_S = 75.0

PRESS_BUTTON_MESSAGE = (
    "Confirm on the token: its light is now on steadily. Press the IO0 button "
    "(not RST) within 60 seconds.")

NOT_CONFIRMED_MESSAGE = (
    "Pairing was not confirmed on the token in time.\n"
    "Click Pair Token again, and when the token's light stays on, press its IO0 button.")

OUTDATED_FIRMWARE_MESSAGE = (
    "USB pairing requires firmware v5 or later. Update the firmware without erasing "
    "its saved credentials. Your existing pairing still works over Bluetooth.")

EXISTING_CREDENTIAL_MESSAGE = (
    "This token is already paired. Re-pairing requires the saved credential for this token. "
    "Use the original Windows account or restore its pairing config before trying again.")

CANCELLED_MESSAGE = "Pairing cancelled."

POWER_MESSAGE = (
    "The token keeps restarting because this USB port is not giving it enough power.\n"
    "Its light repeats the start-up blinks but never gives the 2 short 'ready' flashes.\n"
    "Try a USB port on the back of the PC, a shorter cable, or a powered USB hub."
)


def _friendly_port_error(com_port: str, e: Exception) -> str:
    text = str(e)
    if "PermissionError" in text or "Access is denied" in text:
        return (f"{com_port} is being used by another program, or the token was unplugged.\n"
                "Close any serial monitor (PlatformIO, Arduino IDE), check the cable, and try again.")
    if "FileNotFoundError" in text or "cannot find" in text.lower():
        return f"{com_port} is not available. Is the token plugged in? Click ↻ to rescan the ports."
    return f"Could not use {com_port}: {text}"


def _open_port(com_port: str) -> serial.Serial:
    ser = serial.Serial()
    ser.port = com_port
    ser.baudrate = 115200
    ser.timeout = 0.5
    # DTR/RTS low before opening so Windows does not reset the board
    ser.dtr = False
    ser.rts = False
    ser.open()
    ser.reset_input_buffer()
    return ser


# An older token may print boot messages while ignoring the v5 request.
ECDH_PROBE_S = 8.0


def _save_pairing(token_id, auth_key, mac, fields) -> tuple[bool, str]:
    key_blob, scheme = _protect_secret(auth_key)
    config = {
        "version": CONFIG_VERSION,
        "token_id": token_id.hex(),
        "ble_mac": mac,
        "char_uuid": fields.get("CHAR_UUID", CHARACTERISTIC_UUID),
        "firmware": fields.get("FW", "?"),
        "pairing": "ecdh",
        "auth_key": key_blob,
        "auth_key_protection": scheme,
        "paired_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    atomic_write_text(CONFIG_FILE, json.dumps(config, indent=2), "utf-8")
    return True, f"Token {token_fingerprint(token_id.hex())} bound (BLE {mac})"


def _extract_auth_key(fields, pc_priv, pc_pub):
    """Return (token_id, auth_key) from an ECDH pairing reply. Raises ValueError.

    Only the encrypted form is accepted: a reply carrying the auth key in plaintext
    (the old PAIR_DEVICE format) is refused, so a downgraded or spoofed token cannot
    make the key cross the wire in the clear."""
    if fields.get("MODE") != "ECDH":
        raise ValueError("the token did not use encrypted pairing")
    token_id = bytes.fromhex(fields["TOKEN_ID"])
    if len(token_id) != TOKEN_ID_LEN:
        raise ValueError("bad token id")
    from pair_crypto import open_auth_key
    tok_pub = bytes.fromhex(fields["TOK_PUB"])
    enc = bytes.fromhex(fields["ENC"])
    try:
        auth_key = open_auth_key(pc_priv, pc_pub, tok_pub, token_id, enc)
    except InvalidTag:
        raise ValueError("encrypted pairing failed authentication")
    if len(auth_key) != 32:
        raise ValueError("bad auth key length")
    return token_id, auth_key


def _pair(com_port, request_id, pc_priv, pc_pub, existing, report, deadline, should_cancel=None):
    """Run the v5 exchange, retrying with the same ephemeral key and request ID."""
    from pair_crypto import pairing_proof

    mode = "REPAIR" if existing is not None else "ENROLL"
    begin = f"PAIR_V5:{request_id}:{pc_pub.hex()}:{mode}\n".encode()
    command = begin

    ser, opened, open_error = None, False, None
    drops = restarts = 0
    alive_since = None
    prompted = False
    try:
        while time.time() < deadline:
            if should_cancel is not None and should_cancel():
                if ser is not None:
                    try:
                        ser.write(f"PAIR_CANCEL:{request_id}\n".encode())
                        ser.flush()
                    except serial.SerialException:
                        pass
                return False, CANCELLED_MESSAGE
            if ser is None:
                try:
                    ser = _open_port(com_port)
                except serial.SerialException as e:
                    open_error = e
                    time.sleep(0.5)
                    continue
                opened = True
            try:
                ser.write(command)          # repeating the same request ID is safe
                ser.flush()
                line = ser.readline().decode("utf-8", errors="ignore").strip()
            except serial.SerialException:
                drops += 1
                ser.close(); ser = None
                command = begin
                report("Lost the connection to the token. Reconnecting…")
                time.sleep(0.5)
                continue

            if "Brownout detector was triggered" in line:
                restarts += 1
                if restarts >= 3:
                    return False, POWER_MESSAGE
                report("The token restarted (low power). Still trying…")
                continue
            if line:
                alive_since = alive_since or time.time()
            if not line.startswith("PAIRING_"):
                if (not prompted and alive_since
                        and time.time() - alive_since > ECDH_PROBE_S):
                    return False, OUTDATED_FIRMWARE_MESSAGE
                continue
            fields = _parse_fields(line)
            if fields.get("REQ") != request_id:
                continue
            if line.startswith("PAIRING_PROOF"):
                if existing is None:
                    return False, EXISTING_CREDENTIAL_MESSAGE
                saved_key, saved_id = existing
                try:
                    nonce = bytes.fromhex(fields["NONCE"])
                    token_id = bytes.fromhex(fields["TOKEN_ID"])
                except (KeyError, ValueError):
                    return False, "The token sent an invalid pairing challenge."
                if len(nonce) != NONCE_LEN or not hmac.compare_digest(token_id, saved_id):
                    return False, EXISTING_CREDENTIAL_MESSAGE
                proof = pairing_proof(saved_key, saved_id, nonce, request_id, pc_pub)
                command = f"PAIR_PROVE:{request_id}:{proof.hex()}\n".encode()
                continue
            if line.startswith("PAIRING_PENDING"):
                command = begin
                if not prompted:
                    report(PRESS_BUTTON_MESSAGE)
                    prompted = True
                continue
            if line.startswith("PAIRING_REFUSED"):
                reason = fields.get("REASON")
                if reason in {"PROOF_REQUIRED", "AUTH_FAILED"}:
                    return False, EXISTING_CREDENTIAL_MESSAGE
                if reason == "TOKEN_UNPAIRED":
                    return False, ("This token has no pairing. Your app still has credentials for a paired "
                                   "token. Keep a backup of those credentials before enrolling a replacement.")
                if reason == "NO_PENDING" and command != begin:
                    command = begin
                    continue
                if reason == "NOT_CONFIRMED":
                    return False, NOT_CONFIRMED_MESSAGE
                return False, f"Token refused pairing ({reason or 'unknown'})."
            if not line.startswith("PAIRING_SUCCESS"):
                continue
            try:
                token_id, auth_key = _extract_auth_key(fields, pc_priv, pc_pub)
                mac = fields["BLE_MAC"]
            except (KeyError, ValueError) as e:
                return False, f"Token sent an unreadable pairing reply ({e}). Is the firmware up to date?"
            if not fields.get("FW", "").isdecimal() or int(fields["FW"]) < 5:
                return False, OUTDATED_FIRMWARE_MESSAGE
            if existing is not None:
                saved_key, saved_id = existing
                if not (hmac.compare_digest(token_id, saved_id) and hmac.compare_digest(auth_key, saved_key)):
                    return False, EXISTING_CREDENTIAL_MESSAGE
            report("Confirmed on the token. Saving the pairing…")
            return _save_pairing(token_id, auth_key, mac, fields)
    finally:
        if ser is not None:
            ser.close()

    if restarts:
        return False, POWER_MESSAGE
    if not opened and open_error is not None:
        return False, _friendly_port_error(com_port, open_error)
    if drops:
        return False, (f"The connection to the token kept dropping. Check the cable and close any "
                       f"other program using {com_port}, then try again.")
    if prompted:
        return False, NOT_CONFIRMED_MESSAGE
    return False, ("The token did not answer. Check its firmware is flashed and no serial monitor is "
                   "open. After start-up its light should give 2 short flashes; if it doesn't, see "
                   "Troubleshooting on this page.")


def pair_token_usb(com_port: str, progress=None, should_cancel=None) -> tuple[bool, str]:
    """
    Bind the token over USB with an encrypted (ECDH) exchange, so the auth key never
    crosses the wire in plaintext. The token asks for a press of its IO0 button before
    it binds, so nothing can re-pair it silently while it is plugged in.

    progress, if given, is called with short status lines for the UI. should_cancel, if
    given, is polled so the UI can abort a pairing started on the wrong port.
    """
    from pair_crypto import new_keypair
    report = progress or (lambda _msg: None)
    cfg = load_config()
    existing = None
    if cfg is not None:
        try:
            _, key, token_id = _load_credentials(cfg)
            existing = key, token_id
        except TokenError as exc:
            return False, str(exc)
    request_id = os.urandom(8).hex()
    pc_priv, pc_pub = new_keypair()

    report(f"Connecting to {com_port}…")
    report("Pairing securely (encrypted key exchange). You will be asked to press the "
           "token's IO0 button…")
    return _pair(com_port, request_id, pc_priv, pc_pub, existing, report,
                 time.time() + PAIR_WINDOW_S, should_cancel=should_cancel)


# ── Phase 2: BLE protocol (pure functions, testable without hardware) ──

def _session_key(auth_key: bytes, token_nonce: bytes, host_nonce: bytes) -> bytes:
    return hmac.new(auth_key, b"3T-SK-v1" + token_nonce + host_nonce, hashlib.sha256).digest()


def _check_error(msg: bytes):
    if msg and msg[0] == MSG_ERROR:
        code = msg[1] if len(msg) > 1 else 0
        text = TOKEN_ERRORS.get(code, f"Token reported error 0x{code:02X}.")
        if code == 0x01:
            raise TokenNotPairedError(text)
        if code == 0x03:
            raise TokenAuthError(text)
        if code in (0x02, 0x05):
            raise TokenTransientError(text)
        raise TokenError(text)


def parse_challenge(msg: bytes, expected_token_id: bytes) -> bytes:
    """Validates the token's challenge and returns its nonce."""
    _check_error(msg)
    if len(msg) != CHALLENGE_LEN or msg[0] != MSG_CHALLENGE:
        raise TokenError(f"Unexpected challenge from token ({len(msg)} bytes). "
                         "Check the firmware version, or the BLE MTU may be too small.")
    token_nonce = msg[1:1 + NONCE_LEN]
    token_id = msg[1 + NONCE_LEN:]
    if not hmac.compare_digest(token_id, expected_token_id):
        raise TokenAuthError(
            "The device at the paired address is not the paired token "
            f"(expected {token_fingerprint(expected_token_id.hex())}, "
            f"got {token_fingerprint(token_id.hex())})."
        )
    return token_nonce


def build_request(auth_key: bytes, token_id: bytes, token_nonce: bytes,
                  op: int, env_hash: bytes) -> tuple[bytes, bytes]:
    """Returns (request message, session key)."""
    host_nonce = os.urandom(NONCE_LEN)
    sk = _session_key(auth_key, token_nonce, host_nonce)
    iv = os.urandom(IV_LEN)
    ct = AESGCM(sk).encrypt(iv, bytes([op]) + env_hash, b"3T-REQ-v1" + token_id)
    return bytes([MSG_REQUEST]) + host_nonce + iv + ct, sk


def parse_response(msg: bytes, session_key: bytes, token_id: bytes, data_len=HASH_LEN) -> bytes:
    """Authenticates and decrypts the token's response, returning its 32-byte data field."""
    _check_error(msg)
    if len(msg) != RESPONSE_LEN + data_len - HASH_LEN or msg[0] != MSG_RESPONSE:
        raise TokenError(f"Unexpected response from token ({len(msg)} bytes).")
    iv, ct = msg[1:1 + IV_LEN], msg[1 + IV_LEN:]
    try:
        plain = AESGCM(session_key).decrypt(iv, ct, b"3T-RSP-v1" + token_id)
    except InvalidTag:
        raise TokenAuthError(
            "The token's response failed authentication. The device may be an impostor, "
            "or the pairing was replaced — pair the token again over USB."
        )
    if plain[0] != 0x00:
        if plain[0] == 0x01:
            raise TokenConfirmationPending("Tap IO0 on the token to approve this vault action.")
        raise TokenError(f"Token returned status 0x{plain[0]:02X}.")
    return plain[1:]


# ── Phase 2: BLE transport ───────────────────────────────────────

def _load_credentials(cfg=None) -> tuple[dict, bytes, bytes]:
    if cfg is None:
        cfg = load_config()
    if cfg is None:
        raise TokenNotPairedError("No hardware token is paired with this PC. Use 'Pair Token' first.")
    try:
        auth_key = _unprotect_secret(cfg["auth_key"], cfg.get("auth_key_protection", "none"))
        token_id = bytes.fromhex(cfg["token_id"])
        if len(auth_key) != HASH_LEN or len(token_id) != TOKEN_ID_LEN:
            raise ValueError("invalid credential length")
    except (KeyError, ValueError, TypeError) as exc:
        raise TokenNotPairedError("The saved token credentials are invalid.") from exc
    return cfg, auth_key, token_id


# The UI looks for this phrase to tell "token offline" apart from other failures.
UNREACHABLE_MSG = "Could not reach the hardware token over Bluetooth."
_BLE_EXCHANGE_LOCK = threading.Lock()
PING_TIMEOUT_S = 12.0


@contextmanager
def _ble_errors():
    try:
        yield
    except TokenError:
        raise
    except Exception as exc:
        raise TokenTransientError(
            f"{UNREACHABLE_MSG} Is it powered on and in range?\n\nDetails: {exc}"
        ) from exc


@asynccontextmanager
async def _ble_link():
    """Keep notifications on one connection. Every exchange still authenticates a fresh challenge."""
    cfg, auth_key, token_id = _load_credentials()
    uuid = cfg.get("char_uuid", CHARACTERISTIC_UUID)
    inbox: asyncio.Queue[bytes] = asyncio.Queue()

    async def receive(timeout=5.0) -> bytes:
        try:
            return await asyncio.wait_for(inbox.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TokenTransientError("The token stopped responding mid-exchange.")

    async with AsyncExitStack() as cleanup:
        with _ble_errors():
            client = await cleanup.enter_async_context(BleakClient(
                cfg["ble_mac"], timeout=10.0, winrt={"use_cached_services": False}))
            await client.start_notify(uuid, lambda _s, data: inbox.put_nowait(bytes(data)))

        async def exchange(operation, context):
            with _ble_errors():
                await client.write_gatt_char(uuid, bytes([MSG_HELLO]), response=True)
                token_nonce = parse_challenge(await receive(), token_id)
                request, sk = build_request(auth_key, token_id, token_nonce, operation, context)
                await client.write_gatt_char(uuid, request, response=True)
                reply = await receive()
                if operation in (OP_IMPORT_BATCH, OP_EXPORT_CHILD) and reply == bytes([MSG_ERROR, 0x04]):
                    raise TokenError("Batch-imported vault files require firmware v8. Check the firmware and export selection.")
                if operation in (OP_VAULT_OPEN, OP_VAULT_MINT, OP_EXPORT_BEGIN) and reply == bytes([MSG_ERROR, 0x04]):
                    raise TokenError("Vault operations require token firmware v7.")
                approval = operation in (OP_VAULT_OPEN, OP_EXPORT_BEGIN)
                try:
                    data = parse_response(reply, sk, token_id, 48 if operation in (OP_VAULT_MINT, OP_IMPORT_BATCH) else 32)
                except TokenConfirmationPending:
                    if not approval:
                        raise TokenAuthError("Unexpected vault approval response.")
                    return parse_response(await receive(65), sk, token_id)
                if approval:
                    raise TokenAuthError("Missing authenticated vault approval prompt.")
                return data

        try:
            yield exchange
        finally:
            try:
                await client.stop_notify(uuid)
            except Exception:
                pass


async def _transaction(op: int, env_hash: bytes, *, steps=(), consume=None):
    with _ble_errors():
        async with _ble_link() as exchange:
            result = await exchange(op, env_hash)
            if consume is None:
                return result
            for index, step in enumerate(steps):
                operation = OP_EXPORT_CHILD if len(step) == 96 else OP_EXPORT_NEXT
                key = await exchange(operation, step)
                try:
                    await asyncio.to_thread(consume, index, key)
                except Exception as exc:
                    raise TokenError(f"Export stopped after {index} completed file(s). {exc}") from exc
                finally:
                    del key


def request_import_batch(vault_context):
    """Acquire a new batch ID and secret. Disconnect before any source is encrypted."""
    if len(vault_context) != HASH_LEN:
        raise ValueError("Invalid vault context.")

    async def acquire():
        try:
            return await _transaction(OP_IMPORT_BATCH, vault_context)
        except TokenTransientError:
            # A lost reply can only abandon a fresh ID. File processing has not started.
            await asyncio.sleep(1)
            return await _transaction(OP_IMPORT_BATCH, vault_context)

    with _BLE_EXCHANGE_LOCK:
        with process_file_lock(_app_dir() / ".token-ble.lock", timeout=80):
            return _run_isolated(acquire())


def _run_isolated(coro) -> bytes:
    # A dedicated thread with its own event loop keeps asyncio away from the Qt GUI thread
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coro).result()


def request_env_key(env_hash: bytes) -> bytes:
    """Asks the token for HMAC(master_secret, env_hash). Blocking."""
    if len(env_hash) != HASH_LEN:
        raise ValueError("env_hash must be 32 bytes")
    with _BLE_EXCHANGE_LOCK:
        with process_file_lock(_app_dir() / ".token-ble.lock"):
            return _run_isolated(_transaction(OP_DERIVE, env_hash))


def request_vault_key(operation: str, context: bytes) -> bytes:
    """Open an index with IO0, or mint a fresh file ID and key without IO0."""
    operations = {"metadata": (OP_VAULT_OPEN, 32), "mint": (OP_VAULT_MINT, 48)}
    if operation not in operations or len(context) != operations[operation][1]:
        raise ValueError("Invalid vault key request.")
    with _BLE_EXCHANGE_LOCK:
        with process_file_lock(_app_dir() / ".token-ble.lock", timeout=80):
            return _run_isolated(_transaction(operations[operation][0], context))


def export_selected_keys(contexts, consume):
    """Commit to the ordered selection before IO0. Consume keys on the same BLE link."""
    if not contexts or any(len(context) not in (HASH_LEN, 2 * HASH_LEN) for context in contexts):
        raise ValueError("Invalid vault export selection.")
    cursor = bytes(HASH_LEN)
    steps = []
    for context in reversed(contexts):
        step = context + cursor
        steps.append(step)
        cursor = hashlib.sha256(step).digest()
    with _BLE_EXCHANGE_LOCK:
        with process_file_lock(_app_dir() / ".token-ble.lock", timeout=80):
            _run_isolated(_transaction(OP_EXPORT_BEGIN, cursor, steps=reversed(steps), consume=consume))


def ping_token():
    """Performs a full authenticated handshake without deriving a key. Raises TokenError on failure."""
    deadline = time.monotonic() + PING_TIMEOUT_S

    async def bounded_ping():
        try:
            await asyncio.wait_for(_transaction(OP_PING, bytes(HASH_LEN)),
                                   timeout=max(0, deadline - time.monotonic()))
        except asyncio.TimeoutError as exc:
            raise TokenTransientError(f"{UNREACHABLE_MSG} The check timed out.") from exc

    if not _BLE_EXCHANGE_LOCK.acquire(timeout=PING_TIMEOUT_S):
        raise TokenTransientError("Another Bluetooth exchange is still in progress.")
    try:
        try:
            with process_file_lock(_app_dir() / ".token-ble.lock", timeout=PING_TIMEOUT_S):
                _run_isolated(bounded_ping())
        except TimeoutError as exc:
            raise TokenTransientError("Another Bluetooth operation is in progress.") from exc
    finally:
        _BLE_EXCHANGE_LOCK.release()
