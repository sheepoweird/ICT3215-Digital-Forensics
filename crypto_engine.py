"""
EnvStego - crypto_engine.py
Cryptographic key derivation (HKDF-SHA256) and AES-256-GCM encryption.

Key derivation takes selected environment signals, canonicalizes them,
and feeds into HKDF to produce a stable 256-bit AES key. The same
environment produces the same key; a forensic lab environment does not.

Team member: Cryptographic Key Derivation Function
ICT3215 Digital Forensics — SIT
"""

import os
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Application-specific HKDF constants — change these to make the tool your own
HKDF_SALT = b"EnvStego-ICT3215-SIT-2026-anti-forensics"
HKDF_INFO = b"envkeyed-aes256gcm-stego-payload"

# Rough entropy estimate per signal type (bits)
# Used for the UI entropy display only — not security-critical
_ENTROPY_MAP = {
    "hw_mobo":        40,
    "hw_cpu":         48,
    "hw_disk":        40,
    "hw_bios":        32,
    "hw_gpu":         28,
    "hw_volume":      32,
    "hw_battery":     16,
    "hw_ram":         32,
    "hw_edid":        28,
    "net_bssid":      48,
    "net_ipv6":       64,
    "net_adapterguid":96,
    "net_gatewaymac": 48,
    "net_dns":        24,
    "os_machineguid": 128,
    "os_machinesid":  64,
    "os_installdate": 32,
    "os_usbhistory":  48,
    "os_prefetchseed":24,
    "os_certs":       48,
    "os_audio":       64,
    "os_activation":  96,
}


def derive_key(selected_signals: list) -> tuple:
    """
    Derive a 256-bit AES key from a list of selected EnvSignal objects.

    Only signals where available=True and value is non-empty are used.
    Signals are sorted by ID before concatenation for determinism.

    Returns:
        (key_bytes: bytes, fingerprint: str)
        fingerprint is a short formatted hex string for UI display only.

    Raises:
        ValueError if no available signals are provided.
    """
    available = [s for s in selected_signals if s.available and s.value]
    if not available:
        raise ValueError(
            "No available environment signals selected.\n"
            "Please go to the Signals tab and select at least one available signal."
        )

    # Canonical representation: sort by signal ID, join as key=value pairs
    # Sorting ensures same key regardless of collection order
    parts = sorted(f"{s.id}={s.value}" for s in available)
    ikm = "|".join(parts).encode("utf-8")

    # HKDF-SHA256: extract + expand
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # 256-bit output for AES-256
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    key = hkdf.derive(ikm)

    # Fingerprint: a short hash of the key for UI verification
    # This lets users confirm their environment is stable WITHOUT exposing the key
    raw_fp = hashlib.sha256(key + b"envstego-fingerprint-v1").hexdigest()[:16].upper()
    fingerprint = "-".join(raw_fp[i:i+4] for i in range(0, 16, 4))

    return key, fingerprint


def encrypt_payload(plaintext: bytes, key: bytes) -> tuple:
    """
    Encrypt plaintext using AES-256-GCM.

    AES-GCM provides both confidentiality and authenticated integrity.
    A wrong decryption key will raise InvalidTag, not return garbage.
    This is the forensic defense mechanism: wrong environment = key mismatch =
    authenticated decryption failure = payload is mathematically unrecoverable.

    Args:
        plaintext: raw bytes of the payload file
        key: 32-byte AES key from derive_key()

    Returns:
        (nonce: bytes[12], ciphertext_with_tag: bytes)
        The ciphertext includes the 16-byte GCM authentication tag appended.
    """
    nonce = os.urandom(12)   # 96-bit nonce — standard for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # AAD = None
    return nonce, ciphertext


def decrypt_payload(nonce: bytes, ciphertext_with_tag: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Args:
        nonce: 12-byte nonce used during encryption
        ciphertext_with_tag: ciphertext with 16-byte GCM tag appended
        key: 32-byte AES key from derive_key()

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag if key is wrong or data is corrupted.
        This is the expected behavior when run in the wrong environment.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def estimate_entropy_bits(selected_signals: list) -> int:
    """
    Estimate the total key entropy contributed by selected signals.
    Capped at 256 bits (AES-256 maximum useful entropy).
    Used for UI display only.
    """
    available = [s for s in selected_signals if s.available and s.value]
    total = sum(_ENTROPY_MAP.get(s.id, 20) for s in available)
    return min(total, 256)