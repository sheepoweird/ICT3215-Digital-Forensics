"""
EnvStego - stego_engine.py
LSB (Least Significant Bit) steganography engine for PNG carrier images.

Embeds encrypted payloads in the LSB of each RGB channel value.
PNG is required for the carrier — JPEG's lossy compression destroys LSB data.

Embedded layout (in LSBs of sequential pixels, RGB channels):
  Bytes  0–3:   Magic header b"ENVS"
  Bytes  4–7:   Ciphertext length as big-endian uint32
  Bytes  8–19:  AES-GCM nonce (12 bytes)
  Bytes 20–N:   AES-256-GCM ciphertext (includes 16-byte tag)

Team member: Steganography Engine
ICT3215 Digital Forensics — SIT
"""

import struct
from pathlib import Path

import numpy as np
from PIL import Image


# Header constants
MAGIC = b"ENVS"                        # 4-byte magic identifier
HEADER_SIZE = 4 + 4 + 12              # magic + length + nonce = 20 bytes
HEADER_BITS = HEADER_SIZE * 8         # 160 bits


def get_capacity_bytes(image_path: str) -> int:
    """
    Returns the usable payload capacity in bytes for a given image.
    Subtracts the 20-byte header overhead.
    """
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    total_bits = w * h * 3    # 3 RGB channels, 1 bit per channel
    return max(0, (total_bits // 8) - HEADER_SIZE)


def embed(carrier_path: str, nonce: bytes, ciphertext: bytes, output_path: str) -> str:
    """
    Embed an encrypted payload (nonce + ciphertext) into a PNG carrier image.

    The carrier is loaded as RGB, the payload bits are written to the LSB
    of each channel byte in raster order. Output is always saved as PNG
    to prevent lossy recompression from destroying the embedded data.

    Args:
        carrier_path:  Path to the carrier PNG image
        nonce:         12-byte AES-GCM nonce
        ciphertext:    Ciphertext with 16-byte GCM tag (from encrypt_payload)
        output_path:   Desired output path (extension forced to .png)

    Returns:
        The actual output path used (with .png extension).

    Raises:
        ValueError if the carrier image is too small for the payload.
    """
    if len(nonce) != 12:
        raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")

    # Build the complete byte sequence to embed
    header = (
        MAGIC +
        struct.pack(">I", len(ciphertext)) +
        nonce
    )
    payload = header + ciphertext

    # Load carrier
    img = Image.open(carrier_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)

    # Check capacity
    total_bytes = arr.size // 8
    if len(payload) > total_bytes:
        raise ValueError(
            f"Carrier image is too small.\n"
            f"  Payload requires: {len(payload):,} bytes\n"
            f"  Image capacity:   {total_bytes:,} bytes\n"
            f"  Use a larger carrier image (at least "
            f"{int(len(payload) ** 0.5) + 50}×{int(len(payload) ** 0.5) + 50} px)."
        )

    # Convert payload to individual bits (0 or 1)
    payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    # Flatten image, clear LSBs, write payload bits
    flat = arr.flatten().copy()
    n = len(payload_bits)
    flat[:n] = (flat[:n] & np.uint8(0xFE)) | payload_bits.astype(np.uint8)

    # Reshape, convert back to image
    result = flat.reshape(arr.shape)
    out_img = Image.fromarray(result.astype(np.uint8), "RGB")

    # Force .png extension — non-negotiable (JPEG destroys LSB data)
    out_path = Path(output_path)
    if out_path.suffix.lower() != ".png":
        out_path = out_path.with_suffix(".png")

    out_img.save(str(out_path), format="PNG", optimize=False, compress_level=1)
    return str(out_path)


def extract(stego_path: str) -> tuple:
    """
    Extract the embedded nonce and ciphertext from a stego PNG image.

    Reads the LSBs of RGB channel values in raster order, parses the
    header, and extracts the ciphertext of the length specified in the header.

    Args:
        stego_path: Path to the stego PNG image

    Returns:
        (nonce: bytes[12], ciphertext: bytes)

    Raises:
        ValueError on missing/invalid magic bytes or corrupted length field.
    """
    img = Image.open(stego_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.flatten()

    if flat.size < HEADER_BITS:
        raise ValueError(
            f"Image too small to contain an EnvStego payload "
            f"(need at least {HEADER_SIZE} bytes capacity)."
        )

    # ── Read 20-byte header ──────────────────────────────────────
    header_lsbs = (flat[:HEADER_BITS] & np.uint8(1)).astype(np.uint8)
    header_bytes = np.packbits(header_lsbs).tobytes()

    magic   = header_bytes[0:4]
    ct_len  = struct.unpack(">I", header_bytes[4:8])[0]
    nonce   = header_bytes[8:20]

    if magic != MAGIC:
        raise ValueError(
            f"No EnvStego payload detected in this image.\n"
            f"  Expected magic: {MAGIC!r}\n"
            f"  Found:          {magic!r}\n"
            f"Make sure you selected a stego image output by this tool."
        )

    # ── Sanity check embedded length ─────────────────────────────
    max_capacity = (flat.size // 8) - HEADER_SIZE
    if ct_len == 0 or ct_len > max_capacity:
        raise ValueError(
            f"Embedded payload length ({ct_len:,}) is invalid or exceeds image capacity.\n"
            f"The image may be corrupted or was recompressed."
        )

    # ── Read ciphertext bits ──────────────────────────────────────
    ct_start = HEADER_BITS
    ct_end   = ct_start + ct_len * 8

    if ct_end > flat.size:
        raise ValueError(
            f"Payload extends beyond image bounds — image may be corrupted."
        )

    ct_lsbs    = (flat[ct_start:ct_end] & np.uint8(1)).astype(np.uint8)
    ciphertext = np.packbits(ct_lsbs).tobytes()

    return nonce, ciphertext


def get_image_info(image_path: str) -> dict:
    """
    Return image metadata for the UI capacity display.

    Returns dict with: width, height, channels, capacity_bytes, capacity_kb
    """
    img = Image.open(image_path)
    img_rgb = img.convert("RGB")
    w, h = img_rgb.size
    total_bits = w * h * 3
    capacity = max(0, (total_bits // 8) - HEADER_SIZE)
    return {
        "width":         w,
        "height":        h,
        "channels":      3,
        "capacity_bytes": capacity,
        "capacity_kb":   capacity / 1024,
        "mode":          img.mode,
    }