"""
EnvStego - audio_engine.py
LSB steganography for audio carriers, written as PCM WAV.

A payload is hidden in the least-significant bit of each PCM sample. Other
audio formats are decoded to PCM before embedding, and the output is stored
as WAV so re-encoding does not change the embedded bits.

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
DECODED_AUDIO_EXTS = (".mp3", ".flac", ".ogg", ".oga", ".opus", ".aif", ".aiff")


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


def _open_encoded_audio(path: str):
    try:
        import soundfile
    except (ImportError, OSError) as e:
        raise ValueError("Install the project requirements to open this audio format.") from e
    try:
        return soundfile.SoundFile(path)
    except soundfile.SoundFileError as e:
        raise ValueError(f"Cannot open audio carrier: {e}") from e


def _read_audio_carrier(path: str):
    if Path(path).suffix.lower() == ".wav":
        return _read_wav(path)
    with _open_encoded_audio(path) as audio:
        # Preserve the original channel count and sample rate. Normalize all
        # non-WAV sources to 16-bit PCM, including float-based audio files.
        samples = audio.read(dtype="float32").reshape(-1)
        np.nan_to_num(samples, copy=False, nan=0.0, posinf=1.0, neginf=-1.0)
        np.clip(samples, -1.0, 32767 / 32768, out=samples)
        samples *= 32768
        params = (audio.channels, 2, audio.samplerate, samples.size // audio.channels,
                  "NONE", "not compressed")
    return params, np.rint(samples, out=samples).astype(np.int16)


def embed_blob_wav(carrier_path: str, blob: bytes, output_path: str,
                   match_timestamps: bool = False, order_key: bytes | None = None) -> str:
    """
    Write raw bytes into audio sample LSBs and save a PCM WAV.
    With order_key the bits are scattered across the samples in a token-secret order.
    Output is forced to .wav. Returns the output path.
    """
    from stego_engine import _permutation
    params, samples = _read_audio_carrier(carrier_path)
    if len(blob) > samples.size // 8:
        raise ValueError(
            f"Carrier audio is too small.\n"
            f"  Needs:          {len(blob):,} bytes\n"
            f"  Audio capacity: {samples.size // 8:,} bytes\n"
            f"  Use a longer or higher-rate WAV carrier."
        )

    bits = np.unpackbits(np.frombuffer(blob, dtype=np.uint8)).astype(samples.dtype)
    n = len(bits)
    # Clear then set the LSB of the chosen samples (works for signed ints too:
    # ~1 masks off bit 0 while preserving the sign and all higher bits).
    if order_key is None:
        samples[:n] = (samples[:n] & ~samples.dtype.type(1)) | bits
    else:
        pos = _permutation(order_key, samples.size)[:n]
        samples[pos] = (samples[pos] & ~samples.dtype.type(1)) | bits

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


def extract_lsb_bytes_wav(stego_path: str, nbytes: int, order_key: bytes | None = None) -> bytes:
    """Read the first nbytes logical bytes carried in a WAV's sample LSBs."""
    from stego_engine import _permutation
    _params, samples = _read_wav(stego_path)
    nbits = nbytes * 8
    if nbits > samples.size:
        raise ValueError("Audio is too small for the requested data — it may be corrupted.")
    lsb = (samples & samples.dtype.type(1)).astype(np.uint8)
    sel = lsb[:nbits] if order_key is None else lsb[_permutation(order_key, samples.size)[:nbits]]
    return np.packbits(sel).tobytes()


def read_lsb_all_wav(stego_path: str, order_key: bytes | None = None) -> bytes:
    """Read the whole LSB byte stream from a WAV in one pass (see stego_engine.read_lsb_all)."""
    from stego_engine import _permutation
    _params, samples = _read_wav(stego_path)
    lsbs = (samples & samples.dtype.type(1)).astype(np.uint8)
    if order_key is not None:
        lsbs = lsbs[_permutation(order_key, samples.size)]
    usable = (samples.size // 8) * 8
    return np.packbits(lsbs[:usable]).tobytes()


def get_audio_info(path: str) -> dict:
    """Metadata for the UI capacity display (mirrors stego_engine.get_image_info)."""
    if Path(path).suffix.lower() == ".wav":
        with _open_wav(path) as w:
            channels, width, rate, frames, _, _ = w.getparams()
    else:
        with _open_encoded_audio(path) as audio:
            channels, width, rate, frames = audio.channels, 2, audio.samplerate, audio.frames
    cap = frames * channels // 8 if width in _DTYPE else 0
    return {
        "channels":       channels,
        "sample_rate":    rate,
        "sample_width":   width * 8,
        "duration_s":     frames / rate if rate else 0,
        "capacity_bytes": cap,
        "capacity_kb":    cap / 1024,
    }
