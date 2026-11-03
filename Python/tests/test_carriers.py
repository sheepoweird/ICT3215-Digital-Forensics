"""
EnvStego — carrier & packaging tests (no hardware required)

Combines what used to be test_archive, test_multi_image and test_audio:
  * folder packaging (zip + zip-slip-safe extract)        — archive.py
  * multi-image split across carriers (token-encrypted shards) — multi_image.py
  * WAV audio carrier + the PNG/WAV dispatcher             — audio_engine.py / media.py

The index key is a fixed stand-in here, so no token/BLE is involved. These tests
exercise the real shard crypto, LSB I/O and dispatcher.

Run from the Python/ directory:
    python -m pytest tests/test_carriers.py -v
"""

import io
import os
import sys
import wave
import zipfile
from pathlib import Path

import numpy as np
import pytest
from cryptography.exceptions import InvalidTag
from PIL import Image

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import audio_engine as ae
import crypto_engine as ce
import media
import multi_image as mi
from archive import zip_folder, safe_extract_zip, is_zip

INDEX_KEY = bytes(range(32))          # deterministic stand-in for the token index key
OTHER_KEY = bytes(range(32, 64))


# ── shared helpers ───────────────────────────────────────────────────────────

def _make_tree(root):
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / "b.bin").write_bytes(bytes(range(256)))
    (root / "sub" / "deep").mkdir()
    (root / "sub" / "deep" / "c.txt").write_text("gamma", encoding="utf-8")


def _png(path, w, h):
    arr = (np.random.rand(h, w, 3) * 255).astype("uint8")
    Image.fromarray(arr, "RGB").save(str(path), format="PNG")
    return str(path)


def _carriers(tmp_path, sizes):
    return [_png(tmp_path / f"c{i}.png", w, h) for i, (w, h) in enumerate(sizes)]


def _outs(tmp_path, carriers, sub="out"):
    out_dir = tmp_path / sub
    out_dir.mkdir(exist_ok=True)
    return mi.suggest_outputs(carriers, str(out_dir))


def _wav(path, seconds=1.0, rate=44100, channels=2, width=2):
    n = int(seconds * rate) * channels
    dtype = {1: np.uint8, 2: np.int16, 4: np.int32}[width]
    peak = 2 ** (width * 8 - 2)
    sig = (np.sin(np.linspace(0, 400 * np.pi, n)) * peak).astype(dtype)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(sig.tobytes())
    return str(path)


# ════════════════════════════════════════════════════════════════════════════
#  Folder archive (zip + safe extract)
# ════════════════════════════════════════════════════════════════════════════

def test_zip_and_extract_round_trip(tmp_path):
    src = tmp_path / "case files"
    src.mkdir()
    _make_tree(src)

    data = zip_folder(str(src))
    assert is_zip(data)

    # Paths are relative to the folder itself (the caller names the restore folder)
    dest = tmp_path / "case files"
    written = safe_extract_zip(data, str(dest))
    assert len(written) == 3
    assert (dest / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (dest / "sub" / "b.bin").read_bytes() == bytes(range(256))
    assert (dest / "sub" / "deep" / "c.txt").read_text(encoding="utf-8") == "gamma"


def test_empty_folder_extracts_to_an_empty_dir(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    data = zip_folder(str(src))
    dest = tmp_path / "out"
    safe_extract_zip(data, str(dest))
    assert dest.is_dir() and list(dest.iterdir()) == []


@pytest.mark.parametrize("evil_name", [
    "../escape.txt",
    "sub/../../escape.txt",
    "/abs/escape.txt",
    "..\\winescape.txt",
])
def test_zip_slip_is_blocked(tmp_path, evil_name):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(evil_name, "pwned")
    dest = tmp_path / "out"
    with pytest.raises(ValueError):
        safe_extract_zip(buf.getvalue(), str(dest))
    # Nothing was written outside the destination
    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path / "winescape.txt").exists()


def test_bad_archive_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        safe_extract_zip(b"not a zip at all", str(tmp_path / "out"))


# ════════════════════════════════════════════════════════════════════════════
#  Multi-image split (token-encrypted shards)
# ════════════════════════════════════════════════════════════════════════════

def test_shard_tag_round_trip():
    manifest = ce.new_manifest_id()
    tag = ce.pack_shard_tag(INDEX_KEY, manifest, 2, 5, 1234)
    assert len(tag) == ce.SHARD_OUTER_SIZE
    mid, idx, total, slen = ce.unpack_shard_tag(INDEX_KEY, tag)
    assert mid == manifest and idx == 2 and total == 5 and slen == 1234


def test_shard_tag_wrong_key_fails():
    tag = ce.pack_shard_tag(INDEX_KEY, ce.new_manifest_id(), 0, 2, 10)
    with pytest.raises(InvalidTag):
        ce.unpack_shard_tag(OTHER_KEY, tag)


def test_v3_header_is_not_mistaken_for_a_shard():
    # A single-image v3 header uses a different key/AAD, so reading it as a shard fails.
    header = ce.pack_header(INDEX_KEY, os.urandom(16), os.urandom(12), 100, ["cpu", "disk"])
    with pytest.raises(InvalidTag):
        ce.unpack_shard_tag(INDEX_KEY, header[:ce.SHARD_OUTER_SIZE])


def test_split_and_join_round_trip(tmp_path):
    carriers = _carriers(tmp_path, [(200, 200), (200, 200), (260, 260)])
    outs = _outs(tmp_path, carriers)
    blob = os.urandom(40_000)                     # bigger than any one carrier
    written = mi.split_embed(INDEX_KEY, blob, carriers, outs)
    assert len(written) == 3                      # all three carriers used
    for p in written:
        assert Path(p).exists()
    recovered = mi.join_extract(INDEX_KEY, written)
    assert recovered == blob


def test_join_is_order_independent(tmp_path):
    carriers = _carriers(tmp_path, [(220, 220), (220, 220), (220, 220)])
    blob = os.urandom(30_000)
    written = mi.split_embed(INDEX_KEY, blob, carriers, _outs(tmp_path, carriers))
    shuffled = list(reversed(written))
    assert mi.join_extract(INDEX_KEY, shuffled) == blob


def test_skips_a_carrier_too_small_to_help(tmp_path):
    # Middle carrier is tiny (capacity < shard tag) and must be skipped, not fatal.
    carriers = _carriers(tmp_path, [(300, 300), (8, 8), (300, 300)])
    blob = os.urandom(50_000)        # too big for one 300×300 carrier, spills past the tiny one
    written = mi.split_embed(INDEX_KEY, blob, carriers, _outs(tmp_path, carriers))
    assert len(written) == 2
    assert mi.join_extract(INDEX_KEY, written) == blob


def test_capacity_exceeded_raises(tmp_path):
    carriers = _carriers(tmp_path, [(64, 64), (64, 64)])
    blob = os.urandom(500_000)
    with pytest.raises(ValueError, match="cannot hold"):
        mi.split_embed(INDEX_KEY, blob, carriers, _outs(tmp_path, carriers))


def test_needs_at_least_two_carriers(tmp_path):
    carriers = _carriers(tmp_path, [(300, 300)])
    with pytest.raises(ValueError, match="at least two"):
        mi.split_embed(INDEX_KEY, blob=os.urandom(100), carriers=carriers,
                       output_paths=_outs(tmp_path, carriers))


def test_missing_shard_is_reported(tmp_path):
    carriers = _carriers(tmp_path, [(220, 220), (220, 220), (220, 220)])
    blob = os.urandom(30_000)
    written = mi.split_embed(INDEX_KEY, blob, carriers, _outs(tmp_path, carriers))
    with pytest.raises(ValueError, match="Incomplete set"):
        mi.join_extract(INDEX_KEY, written[:-1])      # drop the last shard


def test_mixed_sets_are_rejected(tmp_path):
    a = _carriers(tmp_path, [(220, 220), (220, 220)])
    b = _carriers(tmp_path, [(220, 220), (220, 220)])
    out_a = mi.split_embed(INDEX_KEY, os.urandom(20_000), a, _outs(tmp_path, a))
    out_b = mi.split_embed(INDEX_KEY, os.urandom(20_000), b, _outs(tmp_path, b, sub="out2"))
    with pytest.raises(ValueError, match="different payloads"):
        mi.join_extract(INDEX_KEY, [out_a[0], out_b[0]])


def test_wrong_token_cannot_read_shards(tmp_path):
    carriers = _carriers(tmp_path, [(220, 220), (220, 220)])
    written = mi.split_embed(INDEX_KEY, os.urandom(20_000), carriers, _outs(tmp_path, carriers))
    with pytest.raises(InvalidTag):
        mi.join_extract(OTHER_KEY, written)


# ════════════════════════════════════════════════════════════════════════════
#  WAV audio carrier + dispatcher
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("width", [1, 2, 4])
def test_round_trip_each_width(tmp_path, width):
    carrier = _wav(tmp_path / f"c{width}.wav", width=width)
    blob = bytes((i * 13) % 256 for i in range(5000))
    out = ae.embed_blob_wav(carrier, blob, str(tmp_path / f"out{width}.wav"))
    assert Path(out).suffix == ".wav"
    assert ae.extract_lsb_bytes_wav(out, len(blob)) == blob


def test_capacity_matches_samples(tmp_path):
    carrier = _wav(tmp_path / "c.wav", seconds=1.0, rate=44100, channels=2, width=2)
    # 44100 frames * 2 channels = 88200 samples -> 88200 // 8 bytes
    assert ae.wav_capacity_bytes(carrier) == (44100 * 2) // 8


def test_too_small_raises(tmp_path):
    carrier = _wav(tmp_path / "tiny.wav", seconds=0.01)
    with pytest.raises(ValueError, match="too small"):
        ae.embed_blob_wav(carrier, bytes(100_000), str(tmp_path / "o.wav"))


def test_output_is_forced_to_wav(tmp_path):
    carrier = _wav(tmp_path / "c.wav")
    out = ae.embed_blob_wav(carrier, b"hello world", str(tmp_path / "o.mp3"))
    assert out.endswith(".wav")


def test_only_lsb_changes(tmp_path):
    carrier = _wav(tmp_path / "c.wav", width=2)
    _p, before = ae._read_wav(carrier)
    out = ae.embed_blob_wav(carrier, bytes(range(256)) * 4, str(tmp_path / "o.wav"))
    _p, after = ae._read_wav(out)
    # Every sample changed by at most its least-significant bit.
    assert np.all(np.abs(after.astype(np.int64) - before.astype(np.int64)) <= 1)


def test_compressed_or_odd_width_rejected(tmp_path):
    # 24-bit (sampwidth 3) is unsupported.
    path = tmp_path / "odd.wav"
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(3)
        w.setframerate(8000)
        w.writeframes(b"\x00\x00\x00" * 1000)
    with pytest.raises(ValueError, match="sample width"):
        ae.extract_lsb_bytes_wav(str(path), 10)


def test_dispatcher_routes_by_extension(tmp_path):
    wav = _wav(tmp_path / "c.wav")
    assert media.is_audio(wav) and not media.is_image(wav)
    assert media.output_suffix(wav) == ".wav"
    assert media.output_suffix("photo.png") == ".png"
    assert media.lsb_capacity_bytes(wav) == ae.wav_capacity_bytes(wav)
    info = media.carrier_info(wav)
    assert info["kind"] == "audio" and "kHz" in info["summary"]


def test_dispatcher_embed_extract_wav(tmp_path):
    wav = _wav(tmp_path / "c.wav")
    blob = bytes((i * 7) % 256 for i in range(4000))
    out = media.embed_blob(wav, blob, str(tmp_path / "o.wav"))
    assert media.extract_lsb_bytes(out, len(blob)) == blob


def test_read_lsb_all_matches_piecewise_png(tmp_path):
    # The single-pass reader (used by the decrypt worker) must agree byte-for-byte
    # with reading prefixes via extract_lsb_bytes, and be capacity-long.
    carrier = _png(tmp_path / "c.png", 60, 40)
    blob = bytes((i * 13) % 256 for i in range(900))
    out = media.embed_blob(str(carrier), blob, str(tmp_path / "o.png"))
    full = media.read_lsb_all(out)
    assert len(full) == media.lsb_capacity_bytes(out)
    assert full[:len(blob)] == blob
    assert full[:ce.OUTER_SIZE] == media.extract_lsb_bytes(out, ce.OUTER_SIZE)


def test_read_lsb_all_matches_piecewise_wav(tmp_path):
    carrier = _wav(tmp_path / "c.wav")
    blob = bytes((i * 29) % 256 for i in range(1500))
    out = media.embed_blob(carrier, blob, str(tmp_path / "o.wav"))
    full = media.read_lsb_all(out)
    assert len(full) == media.lsb_capacity_bytes(out)
    assert full[:len(blob)] == blob


def test_v3_header_and_payload_in_wav(tmp_path):
    carrier = _wav(tmp_path / "song.wav", seconds=2.0)
    salt, nonce = bytes(16), bytes(12)
    header = ce.pack_header(INDEX_KEY, salt, nonce, 123, ["cpu", "disk"])
    ct = bytes((i * 5) % 256 for i in range(123))
    blob = header + ct
    out = media.embed_blob(carrier, blob, str(tmp_path / "song_stego.wav"))
    # Read the header back from audio and decrypt it with the same index key.
    got_header = media.extract_lsb_bytes(out, ce.OUTER_SIZE)
    r_salt, r_nonce, r_len, ids = ce.unpack_header(INDEX_KEY, got_header)
    assert (r_salt, r_nonce, r_len, ids) == (salt, nonce, 123, ["cpu", "disk"])


def test_multi_image_split_works_with_wav(tmp_path):
    # The split engine is carrier-agnostic via media: WAV carriers work too.
    carriers = [_wav(tmp_path / f"c{i}.wav", seconds=0.6) for i in range(3)]
    outs = [str(tmp_path / f"o{i}.wav") for i in range(3)]
    blob = bytes((i * 11) % 256 for i in range(12_000))
    written = mi.split_embed(INDEX_KEY, blob, carriers, outs)
    assert mi.join_extract(INDEX_KEY, written) == blob
