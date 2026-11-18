"""
EnvStego - media.py
Carrier dispatcher for native JPEG, lossless image outputs and PCM WAV audio.

ICT3215 Digital Forensics — SIT
"""

from pathlib import Path

import stego_engine as se
import audio_engine as ae

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".jfif", ".webp", ".bmp", ".tif", ".tiff", ".gif")
AUDIO_EXTS = (".wav", *ae.DECODED_AUDIO_EXTS)
CARRIER_EXTS = IMAGE_EXTS + AUDIO_EXTS
STEGO_EXTS = (*se.JPEG_EXTS, *se.PIXEL_OUTPUT_EXTS, ".wav")


def is_audio(path: str) -> bool:
    return Path(path).suffix.lower() in AUDIO_EXTS


def is_image(path: str) -> bool:
    return Path(path).suffix.lower() in IMAGE_EXTS


def is_jpeg(path: str) -> bool:
    return Path(path).suffix.lower() in se.JPEG_EXTS


def is_carrier(path: str) -> bool:
    return Path(path).suffix.lower() in CARRIER_EXTS


def is_stego_carrier(path: str) -> bool:
    return Path(path).suffix.lower() in STEGO_EXTS


def output_suffix(carrier_path: str) -> str:
    """Output extension for the carrier's supported embedding method."""
    return ".wav" if is_audio(carrier_path) else se.image_output_suffix(carrier_path)


def stego_output_path(carrier_path: str, requested_path: str) -> Path:
    path = Path(requested_path)
    suffix = output_suffix(carrier_path)
    return path if path.suffix.lower() == suffix else path.with_suffix(suffix)


def lsb_capacity_bytes(path: str) -> int:
    if is_audio(path):
        return ae.get_audio_info(path)["capacity_bytes"]
    if is_image(path):
        return se.lsb_capacity_bytes(path)
    raise ValueError("Choose a supported image or audio carrier.")


def embed_blob(carrier_path: str, blob: bytes, output_path: str,
               match_timestamps: bool = False, order_key: bytes | None = None) -> str:
    if not is_carrier(carrier_path):
        raise ValueError("Choose a supported image or audio carrier.")
    target = stego_output_path(carrier_path, output_path)
    if target.resolve() == Path(carrier_path).resolve():
        raise ValueError("Choose an output path different from the carrier.")
    if is_audio(carrier_path):
        return ae.embed_blob_wav(carrier_path, blob, str(target),
                                 match_timestamps=match_timestamps, order_key=order_key)
    return se.embed_blob(carrier_path, blob, str(target),
                         match_timestamps=match_timestamps, order_key=order_key)


def extract_lsb_bytes(stego_path: str, nbytes: int, order_key: bytes | None = None) -> bytes:
    if not is_stego_carrier(stego_path):
        raise ValueError("Choose a stego image or WAV file created by Encrypt.")
    if is_audio(stego_path):
        return ae.extract_lsb_bytes_wav(stego_path, nbytes, order_key=order_key)
    return se.extract_lsb_bytes(stego_path, nbytes, order_key=order_key)


def read_lsb_all(stego_path: str, order_key: bytes | None = None) -> bytes:
    """Whole LSB byte stream in one decode, so extraction need not re-decode the carrier."""
    if not is_stego_carrier(stego_path):
        raise ValueError("Choose a stego image or WAV file created by Encrypt.")
    if is_audio(stego_path):
        return ae.read_lsb_all_wav(stego_path, order_key=order_key)
    return se.read_lsb_all(stego_path, order_key=order_key)


def carrier_info(path: str) -> dict:
    """
    Uniform metadata for the capacity display. Always includes capacity_bytes and
    a one-line 'summary' describing the carrier.
    """
    if is_audio(path):
        a = ae.get_audio_info(path)
        a["summary"] = (f"{a['duration_s']:.1f}s · {a['sample_rate']/1000:.1f} kHz · "
                        f"{a['sample_width']}-bit · {a['channels']} ch")
        a["kind"] = "audio"
        return a
    if not is_image(path):
        raise ValueError("Choose a supported image or audio carrier.")
    i = se.get_image_info(path)
    i["summary"] = f"{i['width']} × {i['height']} px"
    i["capacity_bytes"] = se.lsb_capacity_bytes(path)
    i["capacity_kb"] = i["capacity_bytes"] / 1024
    i["kind"] = "image"
    return i
