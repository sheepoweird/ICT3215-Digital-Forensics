"""
EnvStego - token_comms.py
Communication with the 3T hardware token (ESP32).

Phase 1 — USB pairing (trusted wired channel):
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
import hashlib
import hmac
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import serial
import serial.tools.list_ports
from bleak import BleakClient
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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

NONCE_LEN, TOKEN_ID_LEN, IV_LEN, TAG_LEN, HASH_LEN = 16, 16, 12, 16, 32
CHALLENGE_LEN = 1 + NONCE_LEN + TOKEN_ID_LEN
RESPONSE_LEN = 1 + IV_LEN + (1 + HASH_LEN) + TAG_LEN

TOKEN_ERRORS = {
    0x01: "Token is not paired. It may have been factory reset — pair it again over USB.",
    0x02: "Token rejected the request (no active challenge). Please retry.",
    0x03: "Token rejected this PC's credentials. The pairing is stale or was replaced — pair again over USB.",
    0x04: "Token rejected a malformed request. Check the firmware version matches this app.",
    0x05: "Token is locked out after repeated failed requests. Wait 30 seconds and retry.",
}


class TokenError(Exception):
    """Any failure talking to the hardware token, with a user-facing message."""


class TokenNotPairedError(TokenError):
    pass


class TokenAuthError(TokenError):
    """The device answered but could not prove it is the paired token."""


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


def get_host_id() -> str:
    """Derives a stable ID for this PC. Used by the token to refuse re-binding to other hosts."""
    raw_id = platform.node() + platform.system()
    return hashlib.sha256(raw_id.encode()).hexdigest()[:16].upper()


def load_config() -> dict | None:
    """Returns the saved pairing, or None if this PC is not paired (or uses the old insecure format)."""
    try:
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    if cfg.get("version") != CONFIG_VERSION or "auth_key" not in cfg:
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


def pair_token_usb(com_port: str) -> tuple[bool, str]:
    """Binds the token over USB by repeating the pairing command until it answers."""
    host_id = get_host_id()
    request_id = os.urandom(8).hex()

    try:
        # Configure port manually to try and prevent Windows from resetting the board
        ser = serial.Serial()
        ser.port = com_port
        ser.baudrate = 115200
        ser.timeout = 0.5
        ser.dtr = False
        ser.rts = False

        ser.open()

        try:
            ser.reset_input_buffer()
            command = f"PAIR_DEVICE:{host_id}:{request_id}\n".encode("utf-8")

            # The ESP32 takes ~5 seconds to fully boot (3s grace + 2s BLE init).
            # We continuously ping it for up to 10 seconds until it is ready to respond.
            # The token answers a repeated request ID with the same reply, so this is safe.
            start_time = time.time()
            while time.time() - start_time < 10.0:
                ser.write(command)
                ser.flush()

                line = ser.readline().decode("utf-8", errors="ignore").strip()
                if not line.startswith("PAIRING_"):
                    continue
                fields = _parse_fields(line)
                if fields.get("REQ") != request_id:
                    continue

                if line.startswith("PAIRING_REFUSED"):
                    if fields.get("REASON") == "BOUND_TO_OTHER_HOST":
                        return False, (
                            "This token is already bound to a different PC.\n"
                            "Hold the IO0 button while it boots to factory reset it. "
                            "Note: a reset destroys its master secret, so files encrypted "
                            "with it can never be decrypted again."
                        )
                    return False, f"Token refused pairing ({fields.get('REASON', 'unknown')})."

                try:
                    token_id = bytes.fromhex(fields["TOKEN_ID"])
                    auth_key = bytes.fromhex(fields["AUTH_KEY"])
                    mac = fields["BLE_MAC"]
                except (KeyError, ValueError):
                    return False, "Token sent an unreadable pairing reply. Is the firmware up to date?"
                if len(token_id) != TOKEN_ID_LEN or len(auth_key) != 32:
                    return False, "Token sent invalid key material. Is the firmware up to date?"

                key_blob, scheme = _protect_secret(auth_key)
                config = {
                    "version": CONFIG_VERSION,
                    "host_id": host_id,
                    "token_id": token_id.hex(),
                    "ble_mac": mac,
                    "char_uuid": fields.get("CHAR_UUID", CHARACTERISTIC_UUID),
                    "firmware": fields.get("FW", "?"),
                    "auth_key": key_blob,
                    "auth_key_protection": scheme,
                    "paired_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                with open(CONFIG_FILE, "w") as f:
                    json.dump(config, f, indent=2)

                return True, f"Token {token_fingerprint(token_id.hex())} bound (BLE {mac})"

            return False, "Token did not reply. Verify the PlatformIO serial monitor is closed and the firmware is flashed."
        finally:
            ser.close()

    except serial.SerialException as e:
        return False, f"Port error: {e}"


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


def parse_response(msg: bytes, session_key: bytes, token_id: bytes) -> bytes:
    """Authenticates and decrypts the token's response, returning its 32-byte data field."""
    _check_error(msg)
    if len(msg) != RESPONSE_LEN or msg[0] != MSG_RESPONSE:
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
        raise TokenError(f"Token returned status 0x{plain[0]:02X}.")
    return plain[1:]


# ── Phase 2: BLE transport ───────────────────────────────────────

def _load_credentials() -> tuple[dict, bytes, bytes]:
    cfg = load_config()
    if cfg is None:
        raise TokenNotPairedError("No hardware token is paired with this PC. Use 'Pair Token' first.")
    auth_key = _unprotect_secret(cfg["auth_key"], cfg.get("auth_key_protection", "none"))
    return cfg, auth_key, bytes.fromhex(cfg["token_id"])


async def _transaction(op: int, env_hash: bytes) -> bytes:
    cfg, auth_key, token_id = _load_credentials()
    uuid = cfg.get("char_uuid", CHARACTERISTIC_UUID)
    inbox: asyncio.Queue[bytes] = asyncio.Queue()

    async def receive() -> bytes:
        try:
            return await asyncio.wait_for(inbox.get(), timeout=5.0)
        except asyncio.TimeoutError:
            raise TokenError("The token stopped responding mid-exchange.")

    try:
        async with BleakClient(cfg["ble_mac"], timeout=10.0,
                               winrt={"use_cached_services": False}) as client:
            await client.start_notify(uuid, lambda _s, data: inbox.put_nowait(bytes(data)))
            try:
                await client.write_gatt_char(uuid, bytes([MSG_HELLO]), response=True)
                token_nonce = parse_challenge(await receive(), token_id)

                request, sk = build_request(auth_key, token_id, token_nonce, op, env_hash)
                await client.write_gatt_char(uuid, request, response=True)
                return parse_response(await receive(), sk, token_id)
            finally:
                try:
                    await client.stop_notify(uuid)
                except Exception:
                    pass
    except TokenError:
        raise
    except Exception as e:
        raise TokenError(
            "Could not reach the hardware token over Bluetooth. "
            f"Is it powered on and in range?\n\nDetails: {e}"
        )


def _run_isolated(coro) -> bytes:
    # A dedicated thread with its own event loop keeps asyncio away from the Qt GUI thread
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coro).result()


def request_env_key(env_hash: bytes) -> bytes:
    """Asks the token for HMAC(master_secret, env_hash). Blocking."""
    if len(env_hash) != HASH_LEN:
        raise ValueError("env_hash must be 32 bytes")
    return _run_isolated(_transaction(OP_DERIVE, env_hash))


def ping_token():
    """Performs a full authenticated handshake without deriving a key. Raises TokenError on failure."""
    _run_isolated(_transaction(OP_PING, bytes(HASH_LEN)))
