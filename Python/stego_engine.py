"""
EnvStego - stego_engine.py
Image steganography: native JPEG coefficient parity and lossless pixel LSBs.

JPEG functions and their isolated worker live in this module. JPEG modifies only
eligible AC coefficient parity; other supported outputs preserve pixel low bits.

Embedded layout (in LSBs of sequential pixels, RGB channels):
  Bytes  0–3:   Magic header b"ENV2"
  Bytes  4–7:   Ciphertext length as big-endian uint32
  Bytes  8–23:  HKDF salt (16 bytes)
  Bytes 24–35:  AES-GCM nonce (12 bytes)
  Bytes 36–N:   AES-256-GCM ciphertext (includes 16-byte tag)

The magic and salt are authenticated as GCM associated data.

Team member: Steganography Engine
ICT3215 Digital Forensics — SIT
"""

import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

import numpy as np
from PIL import Image, ImageOps


# ── Scatter order ────────────────────────────────────────────────────────────
# v3 can spread the embedded bits across the whole carrier in a token-secret order
# instead of a contiguous run from pixel 0. This removes the "payload is a block at
# the start, noise stops at its length" signature and hides where the payload is
# without the token. The order is a permutation of all channel positions, seeded by
# the token-only index key, so embed and extract agree and nobody without the token
# can reconstruct it. order_key=None keeps the plain sequential layout (legacy v2).

def _permutation(order_key: bytes, total: int, domain=b"EnvStego-scatter-v1") -> np.ndarray:
    """A deterministic permutation of range(total), seeded by the index key."""
    seed = int.from_bytes(hashlib.sha256(domain + order_key).digest()[:8], "big")
    idx = np.arange(total, dtype=np.int64)
    np.random.default_rng(seed).shuffle(idx)        # in place, keeps dtype
    return idx


# Header constants
MAGIC = b"ENV2"                        # 4-byte magic identifier
LEGACY_MAGIC = b"ENVS"                 # v1 images, keyed by the old hardcoded token secret
SALT_SIZE = 16
NONCE_SIZE = 12
GCM_TAG_SIZE = 16
HEADER_SIZE = 4 + 4 + SALT_SIZE + NONCE_SIZE   # magic + length + salt + nonce = 36 bytes
HEADER_BITS = HEADER_SIZE * 8                  # 288 bits

JPEG_EXTS = (".jpg", ".jpeg", ".jfif")
PIXEL_OUTPUT_EXTS = (".png", ".webp", ".bmp", ".tif", ".tiff")


def image_output_suffix(path):
    suffix = Path(path).suffix.lower()
    return suffix if suffix in JPEG_EXTS + PIXEL_OUTPUT_EXTS else ".png"


def _jpeg_call(action, source, *, output=None, blob=None, count=None, order_key=None):
    """Keep native codec failures and its temporary files inside a short-lived worker."""
    with tempfile.TemporaryDirectory(prefix="envstego-jpeg-") as work:
        directory = Path(work)
        shutil.copyfile(source, directory / "source.jpg")
        request = {"action": action, "source": str(directory / "source.jpg"),
                   "output": str(directory / "result.jpg"), "count": count,
                   "key": order_key.hex() if order_key is not None else None,
                   "blob": base64.b64encode(blob).decode("ascii") if blob is not None else None}
        command = [sys.executable, str(Path(__file__).resolve()), "--jpeg-worker"]
        if getattr(sys, "frozen", False):
            command = [sys.executable, "--jpeg-worker"]
        environment = {**os.environ, "TMP": work, "TEMP": work, "TMPDIR": work}
        try:
            process = subprocess.run(command, input=json.dumps(request), text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                                     env=environment, creationflags=0x08000000 if os.name == "nt" else 0)
        except subprocess.TimeoutExpired as exc:
            raise ValueError("JPEG processing timed out. Try a smaller carrier.") from exc
        try:
            response = json.loads(process.stdout)
        except ValueError as exc:
            raise ValueError("The JPEG codec could not process this image. The original was kept.") from exc
        if process.returncode or "error" in response:
            raise ValueError(response.get("error", "JPEG processing failed. The original was kept."))
        result = response["result"]
        if output is not None:
            target = Path(output)
            with tempfile.NamedTemporaryFile(dir=target.parent, suffix=".jpg.tmp", delete=False) as handle:
                temporary = Path(handle.name)
                try:
                    with (directory / "result.jpg").open("rb") as encoded:
                        shutil.copyfileobj(encoded, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                    handle.close()
                    os.replace(temporary, target)
                finally:
                    handle.close()
                    temporary.unlink(missing_ok=True)
        return result


@lru_cache(maxsize=16)
def _jpeg_info_cached(path, modified_ns, size):
    return _jpeg_call("info", path)


def _jpeg_info(path):
    path = Path(path).resolve()
    stat = path.stat()
    return _jpeg_info_cached(str(path), stat.st_mtime_ns, stat.st_size).copy()


def _jpeg_components(image):
    # A coefficient's even/odd magnitude pair stays eligible after embedding.
    # Never use DC, zeros or +/-1, so parity changes cannot create/remove a slot.
    components = []
    for name in ("Y", "Cb", "Cr"):
        array = getattr(image, name)
        if array is None:
            continue
        magnitude = np.abs(array.astype(np.int32))
        eligible = (magnitude >= 2) & (magnitude <= 32767)
        eligible[..., 0, 0] = False
        components.append((array, np.flatnonzero(eligible.ravel())))
    return components


def _jpeg_read_bits(image, order_key, count=None):
    components = _jpeg_components(image)
    values = np.concatenate([np.abs(array.ravel()[positions].astype(np.int32)) & 1
                             for array, positions in components]).astype(np.uint8)
    available = len(values) // 8
    if count is None:
        count = available
    if not isinstance(count, int) or count < 0 or count > available:
        raise ValueError("JPEG is too small for the requested data, or its payload is damaged.")
    if order_key is not None:
        values = values[_permutation(order_key, len(values), b"EnvStego-jpeg-scatter-v1")[:count * 8]]
    else:
        values = values[:count * 8]
    return np.packbits(values).tobytes()


def _jpeg_worker_main():
    from winutils import restore_worker_streams
    restore_worker_streams()
    try:
        try:
            import jpeglib
        except ImportError as exc:
            raise ValueError("Native JPEG support needs jpeglib. Install Python/requirements.txt.") from exc
        # jpeglib otherwise defaults to libjpeg 6b. Use the tested bundled 9f codec.
        jpeglib.version.set("9f")
        request = json.load(sys.stdin)
        with Image.open(request["source"]) as check:
            if check.format != "JPEG" or check.mode not in ("RGB", "L"):
                raise ValueError("Choose a grayscale or RGB JPEG carrier.")
            check.verify()
        image = jpeglib.read_dct(request["source"])
        components = _jpeg_components(image)
        total = sum(len(positions) for _, positions in components)
        action = request["action"]
        key = bytes.fromhex(request["key"]) if request["key"] is not None else None
        if action == "info":
            result = {"capacity_bytes": total // 8}
        elif action in ("extract", "read"):
            data = _jpeg_read_bits(image, key, request["count"] if action == "extract" else None)
            result = base64.b64encode(data).decode("ascii")
        elif action == "embed":
            blob = base64.b64decode(request["blob"], validate=True)
            bits = np.unpackbits(np.frombuffer(blob, dtype=np.uint8))
            if len(bits) > total:
                raise ValueError(f"JPEG carrier is too small: needs {len(blob):,} bytes, holds {total // 8:,}. "
                                 "Choose another carrier or split across more files.")
            order = (_permutation(key, total, b"EnvStego-jpeg-scatter-v1")[:len(bits)]
                     if key is not None else np.arange(len(bits)))
            start = 0
            for array, positions in components:
                selected = (order >= start) & (order < start + len(positions))
                slots = positions[order[selected] - start]
                flat = array.ravel()
                old = flat[slots].astype(np.int32)
                magnitude = (np.abs(old) & ~1) | bits[selected].astype(np.int32)
                flat[slots] = (np.where(old < 0, -magnitude, magnitude)).astype(array.dtype)
                start += len(positions)
            image.write_dct(request["output"])
            # Verify actual encoded coefficients before the parent publishes output.
            verified = jpeglib.read_dct(request["output"])
            if not np.array_equal(image.qt, verified.qt) or _jpeg_read_bits(verified, key, len(blob)) != blob:
                raise ValueError("JPEG verification failed. No output was published.")
            result = True
        else:
            raise ValueError("Unknown JPEG operation.")
        print(json.dumps({"result": result}))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc) or "JPEG processing failed."}))
        return 1


def _require_single_frame(image: Image.Image):
    if getattr(image, "n_frames", 1) != 1:
        raise ValueError("Choose a still image with one frame or page.")


def get_capacity_bytes(image_path: str) -> int:
    """
    Returns the usable payload capacity in bytes for a given image.
    Subtracts the 36-byte header overhead.
    """
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    total_bits = w * h * 3    # 3 RGB channels, 1 bit per channel
    return max(0, (total_bits // 8) - HEADER_SIZE)


def embed(carrier_path: str, salt: bytes, nonce: bytes, ciphertext: bytes, output_path: str,
          match_timestamps: bool = False) -> str:
    """
    Embed an encrypted payload (salt + nonce + ciphertext) into a PNG carrier image.

    The carrier is loaded as RGB, the payload bits are written to the LSB
    of each channel byte in raster order. Output is always saved as PNG
    to prevent lossy recompression from destroying the embedded data.

    Args:
        carrier_path:  Path to the carrier PNG image
        salt:          16-byte HKDF salt
        nonce:         12-byte AES-GCM nonce
        ciphertext:    Ciphertext with 16-byte GCM tag (from encrypt_payload)
        output_path:   Desired output path (extension forced to .png)

    Returns:
        The actual output path used (with .png extension).

    Raises:
        ValueError if the carrier image is too small for the payload.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be {SALT_SIZE} bytes, got {len(salt)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    # Build the complete byte sequence to embed
    header = (
        MAGIC +
        struct.pack(">I", len(ciphertext)) +
        salt +
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

    # Flatten image (flatten() already returns a copy), clear LSBs, write payload bits
    flat = arr.flatten()
    n = len(payload_bits)
    flat[:n] = (flat[:n] & np.uint8(0xFE)) | payload_bits.astype(np.uint8)

    # Reshape, convert back to image
    result = flat.reshape(arr.shape)
    out_img = Image.fromarray(result.astype(np.uint8), "RGB")

    # Force .png extension — non-negotiable (JPEG destroys LSB data)
    out_path = Path(output_path)
    if out_path.suffix.lower() != ".png":
        out_path = out_path.with_suffix(".png")

    # Lossless compression changes the PNG encoding, not pixels or embedded bits.
    out_img.save(str(out_path), format="PNG", optimize=True, compress_level=9)

    # Optionally make the stego image inherit the carrier's dates so it blends into
    # a photo library instead of showing a fresh timestamp.
    if match_timestamps:
        from winutils import copy_file_times
        copy_file_times(carrier_path, str(out_path))

    return str(out_path)


def embed_blob(carrier_path: str, blob: bytes, output_path: str,
               match_timestamps: bool = False, order_key: bytes | None = None) -> str:
    """
    Embed raw bytes using native JPEG coefficients or lossless RGB low bits.

    Used by the v3 format, whose own token-encrypted header carries the length.
    The written bits therefore look like random noise. With order_key the bits are
    scattered across the whole image in a token-secret order (see _permutation).
    Returns the output path.
    """
    suffix = image_output_suffix(carrier_path)
    out_path = Path(output_path).with_suffix(suffix)
    if out_path.resolve() == Path(carrier_path).resolve():
        raise ValueError("Choose an output path different from the carrier.")
    if suffix in JPEG_EXTS:
        _jpeg_call("embed", carrier_path, output=out_path, blob=blob, order_key=order_key)
        if match_timestamps:
            from winutils import copy_file_times
            copy_file_times(carrier_path, str(out_path))
        return str(out_path)
    with Image.open(carrier_path) as source:
        _require_single_frame(source)
        if source.format != "PNG":
            ImageOps.exif_transpose(source, in_place=True)
        alpha = None
        if "A" in source.getbands() or "transparency" in source.info:
            alpha = source.convert("RGBA").getchannel("A")
        arr = np.array(source.convert("RGB"), dtype=np.uint8)
        metadata = {key: source.info[key] for key in ("icc_profile", "exif") if key in source.info}
    if len(blob) > arr.size // 8:
        raise ValueError(
            f"Carrier image is too small.\n"
            f"  Needs:          {len(blob):,} bytes\n"
            f"  Image capacity: {arr.size // 8:,} bytes\n"
            f"  Use a larger carrier image."
        )

    bits = np.unpackbits(np.frombuffer(blob, dtype=np.uint8))
    flat = arr.flatten()        # flatten() already returns a copy, so arr is untouched
    n = len(bits)
    if order_key is None:
        flat[:n] = (flat[:n] & np.uint8(0xFE)) | bits.astype(np.uint8)
    else:
        pos = _permutation(order_key, flat.size)[:n]
        flat[pos] = (flat[pos] & np.uint8(0xFE)) | bits.astype(np.uint8)
    out_img = Image.fromarray(flat.reshape(arr.shape))
    if alpha is not None:
        out_img.putalpha(alpha)

    if suffix == ".webp":
        out_img.save(str(out_path), format="WEBP", lossless=True, exact=True,
                     quality=100, method=6, **metadata)
    elif suffix == ".bmp":
        out_img.save(str(out_path), format="BMP")
    elif suffix in (".tif", ".tiff"):
        out_img.save(str(out_path), format="TIFF", compression="tiff_adobe_deflate", **metadata)
    else:
        out_img.save(str(out_path), format="PNG", optimize=True, compress_level=9, **metadata)

    if match_timestamps:
        from winutils import copy_file_times
        copy_file_times(carrier_path, str(out_path))
    return str(out_path)


def extract_lsb_bytes(stego_path: str, nbytes: int, order_key: bytes | None = None) -> bytes:
    """
    Read the first nbytes logical bytes carried in a PNG's LSBs.

    Sequential (raster order) by default; with order_key the bytes are read back from
    their token-secret scattered positions. The v3 format reads the fixed-size header
    first, learns the ciphertext length, then reads header-plus-payload in a second call.
    """
    if Path(stego_path).suffix.lower() in JPEG_EXTS:
        return base64.b64decode(_jpeg_call("extract", stego_path, count=nbytes, order_key=order_key), validate=True)
    img = Image.open(stego_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()
    nbits = nbytes * 8
    if nbits > flat.size:
        raise ValueError("Image is too small for the requested data — it may be corrupted.")
    lsb = (flat & np.uint8(1))
    sel = lsb[:nbits] if order_key is None else lsb[_permutation(order_key, flat.size)[:nbits]]
    return np.packbits(sel).tobytes()


def lsb_capacity_bytes(image_path: str) -> int:
    """Total bytes available in an image's RGB channels before header overhead."""
    if Path(image_path).suffix.lower() in JPEG_EXTS:
        return _jpeg_info(image_path)["capacity_bytes"]
    with Image.open(image_path) as img:
        _require_single_frame(img)
        return img.width * img.height * 3 // 8


def read_lsb_all(stego_path: str, order_key: bytes | None = None) -> bytes:
    """
    Decode the carrier once and return its entire LSB byte stream in logical order.

    Extraction needs the header, then the header-plus-payload; reading the whole
    stream once and slicing it avoids decoding the PNG twice. With order_key the LSBs
    are first put back into logical order (undoing the token-secret scatter), so the
    caller can still slice. The returned length equals lsb_capacity_bytes(path).
    """
    if Path(stego_path).suffix.lower() in JPEG_EXTS:
        return base64.b64decode(_jpeg_call("read", stego_path, order_key=order_key), validate=True)
    img = Image.open(stego_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()
    lsb = (flat & np.uint8(1))
    if order_key is not None:
        lsb = lsb[_permutation(order_key, flat.size)]  # physical -> logical order
    usable = (flat.size // 8) * 8                       # whole bytes only
    return np.packbits(lsb[:usable]).tobytes()


def extract(stego_path: str) -> tuple:
    """
    Extract the embedded salt, nonce and ciphertext from a stego PNG image.

    Reads the LSBs of RGB channel values in raster order, parses the
    header, and extracts the ciphertext of the length specified in the header.

    Args:
        stego_path: Path to the stego PNG image

    Returns:
        (salt: bytes[16], nonce: bytes[12], ciphertext: bytes)

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

    # ── Read 36-byte header ──────────────────────────────────────
    header_lsbs = (flat[:HEADER_BITS] & np.uint8(1)).astype(np.uint8)
    header_bytes = np.packbits(header_lsbs).tobytes()

    magic   = header_bytes[0:4]
    ct_len  = struct.unpack(">I", header_bytes[4:8])[0]
    salt    = header_bytes[8:8 + SALT_SIZE]
    nonce   = header_bytes[8 + SALT_SIZE:HEADER_SIZE]

    if magic == LEGACY_MAGIC:
        raise ValueError(
            "This image was made by an older EnvStego build that used a hardcoded "
            "token secret. It is not supported by the secure token protocol."
        )
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

    return salt, nonce, ciphertext


def get_image_info(image_path: str) -> dict:
    """
    Return image metadata for the UI capacity display.

    Returns dict with: width, height, channels, capacity_bytes, capacity_kb
    """
    with Image.open(image_path) as img:
        _require_single_frame(img)
        w, h = img.size
        mode = img.mode
        if img.format != "PNG" and img.getexif().get(274) in (5, 6, 7, 8):
            w, h = h, w
    total_bits = lsb_capacity_bytes(image_path) * 8
    capacity = max(0, (total_bits // 8) - HEADER_SIZE)
    return {
        "width":         w,
        "height":        h,
        "channels":      3,
        "capacity_bytes": capacity,
        "capacity_kb":   capacity / 1024,
        "mode":          mode,
    }


if __name__ == "__main__" and "--jpeg-worker" in sys.argv:
    sys.exit(_jpeg_worker_main())
