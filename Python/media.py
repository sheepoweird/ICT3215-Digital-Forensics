"""
EnvStego - media.py
Carrier dispatcher: route embed/extract to the image (PNG) or audio (WAV) engine
by file extension, so the rest of the app has one carrier-agnostic interface.

Adding another carrier type later means adding one branch here and nothing else.

ICT3215 Digital Forensics — SIT
"""

from pathlib import Path

import stego_engine as se
import audio_engine as ae

IMAGE_EXTS = (".png",)
AUDIO_EXTS = (".wav",)
CARRIER_EXTS = IMAGE_EXTS + AUDIO_EXTS


def is_audio(path: str) -> bool:
    return Path(path).suffix.lower() in AUDIO_EXTS


def is_image(path: str) -> bool:
    return Path(path).suffix.lower() in IMAGE_EXTS


def is_carrier(path: str) -> bool:
    return Path(path).suffix.lower() in CARRIER_EXTS


def output_suffix(carrier_path: str) -> str:
    """The extension a stego output must have for this carrier type (lossless)."""
    return ".wav" if is_audio(carrier_path) else ".png"


def lsb_capacity_bytes(path: str) -> int:
    return ae.wav_capacity_bytes(path) if is_audio(path) else se.lsb_capacity_bytes(path)


def embed_blob(carrier_path: str, blob: bytes, output_path: str,
               match_timestamps: bool = False) -> str:
    if is_audio(carrier_path):
        return ae.embed_blob_wav(carrier_path, blob, output_path, match_timestamps=match_timestamps)
    return se.embed_blob(carrier_path, blob, output_path, match_timestamps=match_timestamps)


def extract_lsb_bytes(stego_path: str, nbytes: int) -> bytes:
    if is_audio(stego_path):
        return ae.extract_lsb_bytes_wav(stego_path, nbytes)
    return se.extract_lsb_bytes(stego_path, nbytes)


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
    i = se.get_image_info(path)
    i["summary"] = f"{i['width']} × {i['height']} px"
    i["capacity_bytes"] = se.lsb_capacity_bytes(path)   # total LSB bytes (header subtracted by caller)
    i["kind"] = "image"
    return i
