"""
EnvStego - audio_engine.py
LSB steganography for WAV audio carriers (the audio twin of stego_engine).

A payload is hidden in the least-significant bit of each PCM sample. WAV is
required for the same reason PNG is for images: it is lossless, so the LSBs
survive. Lossy formats (MP3, AAC, OGG) re-quantise the audio and destroy them.

Supported: uncompressed PCM WAV, 8 / 16 / 32-bit, any channel count. The written
bits look like dithering noise and are inaudible at 1 bit of a 16-bit sample.

Like stego_engine.embed_blob/extract_lsb_bytes, these carry no magic header —
the v3 token-encrypted header on top of the payload provides the length.

ICT3215 Digital Forensics — SIT
"""

import wave
from pathlib import Path

import numpy as np

# PCM sample width (bytes) -> numpy dtype for in-place LSB edits
_DTYPE = {1: np.uint8, 2: np.int16, 4: np.int32}


def _open_wav(path: str):
    """wave.open, but a malformed file raises ValueError (like the image engine) instead
    of leaking the wave module's own wave.Error."""
    try:
        return wave.open(path, "rb")
    except (wave.Error, EOFError) as e:
        raise ValueError(f"Not a valid WAV file: {e}")


def _read_wav(path: str):
    with _open_wav(path) as w:
        params = w.getparams()
        frames = w.readframes(params.nframes)
    if params.sampwidth not in _DTYPE:
        raise ValueError(
            f"Unsupported WAV sample width ({params.sampwidth * 8}-bit). "
            f"Use an 8, 16 or 32-bit PCM WAV carrier."
        )
    if params.comptype != "NONE":
        raise ValueError("This WAV is compressed. Use an uncompressed PCM WAV carrier.")
    samples = np.frombuffer(frames, dtype=_DTYPE[params.sampwidth]).copy()
    return params, samples


def wav_capacity_bytes(path: str) -> int:
    """Total bytes carriable in a WAV's sample LSBs (1 bit per sample, no header subtracted)."""
    with _open_wav(path) as w:
        p = w.getparams()
    if p.sampwidth not in _DTYPE:
        return 0
    n_samples = p.nframes * p.nchannels
    return n_samples // 8


def embed_blob_wav(carrier_path: str, blob: bytes, output_path: str,
                   match_timestamps: bool = False) -> str:
    """
    Write raw bytes into a WAV's sample LSBs, with no magic header or length field.
    Output is forced to .wav. Returns the output path.
    """
    params, samples = _read_wav(carrier_path)
    if len(blob) > samples.size // 8:
        raise ValueError(
            f"Carrier audio is too small.\n"
            f"  Needs:          {len(blob):,} bytes\n"
            f"  Audio capacity: {samples.size // 8:,} bytes\n"
            f"  Use a longer or higher-rate WAV carrier."
        )

    bits = np.unpackbits(np.frombuffer(blob, dtype=np.uint8)).astype(samples.dtype)
    n = len(bits)
    # Clear then set the LSB of the first n samples (works for signed ints too:
    # ~1 masks off bit 0 while preserving the sign and all higher bits).
    samples[:n] = (samples[:n] & ~samples.dtype.type(1)) | bits

    out_path = Path(output_path)
    if out_path.suffix.lower() != ".wav":
        out_path = out_path.with_suffix(".wav")
    with wave.open(str(out_path), "wb") as w:
        w.setparams(params)
        w.writeframes(samples.tobytes())

    if match_timestamps:
        from winutils import copy_file_times
        copy_file_times(carrier_path, str(out_path))
    return str(out_path)


def extract_lsb_bytes_wav(stego_path: str, nbytes: int) -> bytes:
    """Read the first nbytes bytes carried in a WAV's sample LSBs."""
    _params, samples = _read_wav(stego_path)
    nbits = nbytes * 8
    if nbits > samples.size:
        raise ValueError("Audio is too small for the requested data — it may be corrupted.")
    lsbs = (samples[:nbits] & samples.dtype.type(1)).astype(np.uint8)
    return np.packbits(lsbs).tobytes()


def read_lsb_all_wav(stego_path: str) -> bytes:
    """Read the whole LSB byte stream from a WAV in one pass (see stego_engine.read_lsb_all)."""
    _params, samples = _read_wav(stego_path)
    usable = (samples.size // 8) * 8
    lsbs = (samples[:usable] & samples.dtype.type(1)).astype(np.uint8)
    return np.packbits(lsbs).tobytes()


def get_audio_info(path: str) -> dict:
    """Metadata for the UI capacity display (mirrors stego_engine.get_image_info)."""
    with _open_wav(path) as w:
        p = w.getparams()
    cap = wav_capacity_bytes(path)
    seconds = p.nframes / p.framerate if p.framerate else 0
    return {
        "channels":       p.nchannels,
        "sample_rate":    p.framerate,
        "sample_width":   p.sampwidth * 8,
        "duration_s":     seconds,
        "capacity_bytes": cap,
        "capacity_kb":    cap / 1024,
    }
