import hashlib
import asyncio
import os
import concurrent.futures
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from token_comms import request_key_ble

def estimate_entropy_bits(signals: list) -> int:
    """Estimates the entropy bits of the selected signals."""
    return sum(getattr(s, 'stability', 5) * 4 for s in signals)

def _run_async_ble(env_str: str) -> str:
    """Helper function to run the async BLE request in a clean, isolated thread."""
    return asyncio.run(request_key_ble(env_str))

def derive_key(signals: list) -> tuple[bytes, str]:
    """
    Formats selected signals into an environment payload, sends it to the ESP32 via BLE,
    and derives a 32-byte AES-GCM key from the hardware token's secure response.
    """
    # 1. Format environment data (e.g. "hw_cpu:BFEBFBFF000806E9|net_bssid:ab:cd:ef:12:34:56")
    env_str = "|".join([f"{s.id}:{s.value}" for s in signals])
    if not env_str:
        env_str = "EMPTY_ENV"
        
    print(f"[CRYPTO] Requesting hardware key via BLE for env string: {env_str}")
    
    # 2. Fetch the hardware-anchored key wirelessly in an isolated thread
    # This prevents the Windows GUI thread from crashing asyncio
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_run_async_ble, env_str)
        hw_key_string = future.result()
        
    if not hw_key_string:
        raise Exception("Hardware token not found or BLE connection failed. Is the token paired and on?")
        
    # 3. Security Check: Ensure the token hasn't been factory reset
    if hw_key_string == "ERROR: NOT_PAIRED":
        raise Exception(
            "Hardware token refused BLE connection: NOT PAIRED.\n\n"
            "The token may have been factory reset. Please use the "
            "'Pair Hardware Token' button to re-establish the USB trust anchor."
        )
        
    # 4. Hash the hardware string into a valid 32-byte AES-256 key
    key_hash = hashlib.sha256(hw_key_string.encode('utf-8')).digest()
    
    # 5. Generate a short visual fingerprint for the UI
    fp = hashlib.sha256(key_hash).hexdigest()[:12].upper()
    
    return key_hash, fp

def encrypt_payload(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypts data using AES-256-GCM. Returns (nonce, ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_payload(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts data using AES-256-GCM. Returns plaintext."""
    aesgcm = AESGCM(key)
    # Raises cryptography.exceptions.InvalidTag if key/environment is wrong
    return aesgcm.decrypt(nonce, ciphertext, None)