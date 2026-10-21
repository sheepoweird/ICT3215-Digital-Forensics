"""
EnvStego - pair_crypto.py
Encrypted USB pairing (ECDH), so the auth key never crosses the wire in plaintext.

Legacy pairing sent the 32-byte auth key as hex over the serial line. A USB sniffer
during pairing captured it. ECDH pairing fixes that:

  1. The PC and the token each make a one-time X25519 key pair.
  2. They exchange public keys (safe to see).
  3. Both derive the same shared secret; a wrapping key comes from it via HKDF.
  4. The token sends the auth key AES-256-GCM encrypted under the wrapping key.

A sniffer sees only two public keys and ciphertext. The byte layout and KDF here
must match the firmware (ESP32 Files/main.cpp / encryption.cpp).

Wire (USB serial, newline-terminated):
  PC   -> Token : PAIR_ECDH:<host_id>:<request_id>:<pc_pub hex(32)>
  Token -> PC   : PAIRING_SUCCESS;REQ=..;MODE=ECDH;TOKEN_ID=<hex(16)>;
                  TOK_PUB=<hex(32)>;ENC=<hex(iv12|ct32|tag16)>;BLE_MAC=..;CHAR_UUID=..;FW=..
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

PAIR_INFO = b"EnvStego-pair-v1"
PUB_LEN = 32
IV_LEN = 12
TAG_LEN = 16


def new_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Return (private key, 32-byte raw public key)."""
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def wrapping_key(shared: bytes, pc_pub: bytes, tok_pub: bytes, token_id: bytes) -> bytes:
    """HKDF of the shared secret, bound to both public keys and the token ID."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=PAIR_INFO + pc_pub + tok_pub + token_id).derive(shared)


def _aad(pc_pub: bytes, tok_pub: bytes, token_id: bytes) -> bytes:
    return pc_pub + tok_pub + token_id


def seal_auth_key(tok_priv: X25519PrivateKey, tok_pub: bytes, pc_pub_bytes: bytes,
                  token_id: bytes, auth_key: bytes) -> bytes:
    """Token side: encrypt the auth key for the PC. Returns iv | ct | tag (60 bytes)."""
    import os
    shared = tok_priv.exchange(X25519PublicKey.from_public_bytes(pc_pub_bytes))
    key = wrapping_key(shared, pc_pub_bytes, tok_pub, token_id)
    iv = os.urandom(IV_LEN)
    ct = AESGCM(key).encrypt(iv, auth_key, _aad(pc_pub_bytes, tok_pub, token_id))
    return iv + ct


def open_auth_key(pc_priv: X25519PrivateKey, pc_pub: bytes, tok_pub_bytes: bytes,
                  token_id: bytes, enc: bytes) -> bytes:
    """PC side: recover the auth key from the token's reply. Raises InvalidTag on failure."""
    shared = pc_priv.exchange(X25519PublicKey.from_public_bytes(tok_pub_bytes))
    key = wrapping_key(shared, pc_pub, tok_pub_bytes, token_id)
    iv, ct = enc[:IV_LEN], enc[IV_LEN:]
    return AESGCM(key).decrypt(iv, ct, _aad(pc_pub, tok_pub_bytes, token_id))
