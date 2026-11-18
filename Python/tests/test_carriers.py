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
import soundfile
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
    "C:/Windows/winabs.txt",        # Windows drive-letter path (zip-slip variant)
    "C:winabs.txt",                 # drive-relative, no root
    "//server/share/unc.txt",       # UNC path
])
def test_zip_slip_is_blocked(tmp_path, evil_name):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(evil_name, "pwned")
    dest = tmp_path / "out"
    with pytest.raises(ValueError):
        safe_extract_zip(buf.getvalue(), str(dest))
    # Nothing was written outside the destination
    for stray in ("escape.txt", "winescape.txt", "winabs.txt", "unc.txt"):
        assert not (tmp_path / stray).exists()


def test_bad_archive_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        safe_extract_zip(b"not a zip at all", str(tmp_path / "out"))


def test_zip_bomb_is_rejected(tmp_path, monkeypatch):
    import archive
    monkeypatch.setattr(archive, "MAX_EXTRACTED_BYTES", 100)   # tiny cap for the test
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("big.bin", b"A" * 5000)                    # 5000 > 100 cap
    with pytest.raises(ValueError, match="unreasonable size"):
        archive.safe_extract_zip(buf.getvalue(), str(tmp_path / "out"))


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


def test_small_payload_is_split_across_every_selected_carrier(tmp_path):
    carriers = _carriers(tmp_path, [(200, 200)] * 3)
    blob = b"small payload that fits inside the first carrier"
    written = mi.split_embed(INDEX_KEY, blob, carriers, _outs(tmp_path, carriers))
    assert len(written) == 3
    tags = [mi.inspect_shard(INDEX_KEY, path) for path in written]
    assert [tag[1] for tag in tags] == [0, 1, 2]
    assert all(tag[2] == 3 and tag[3] > 0 for tag in tags)
    assert mi.join_extract(INDEX_KEY, written[::-1]) == blob
    with pytest.raises(ValueError, match="Incomplete set"):
        mi.join_extract(INDEX_KEY, written[:1])


@pytest.mark.parametrize("sizes", [[(300, 300), (24, 24), (24, 24)],
                                    [(24, 24), (300, 300), (24, 24)],
                                    [(24, 24), (24, 24), (300, 300)]])
def test_split_respects_unequal_capacities_and_uses_every_carrier(tmp_path, sizes):
    carriers = _carriers(tmp_path, sizes)
    blob = os.urandom(5000)
    written = mi.split_embed(INDEX_KEY, blob, carriers, _outs(tmp_path, carriers))
    assert len(written) == len(carriers)
    lengths = [mi.inspect_shard(INDEX_KEY, path)[3] for path in written]
    assert all(0 < length <= mi.usable_capacity(carrier) for length, carrier in zip(lengths, carriers))
    assert mi.join_extract(INDEX_KEY, written) == blob


def test_split_refuses_to_make_only_one_usable_piece(tmp_path):
    carriers = _carriers(tmp_path, [(200, 200), (8, 8)])
    outputs = _outs(tmp_path, carriers)
    with pytest.raises(ValueError, match="at least two usable"):
        mi.split_embed(INDEX_KEY, b"small", carriers, outputs)
    assert not any(Path(path).exists() for path in outputs)


@pytest.mark.parametrize("size", [3, 4, "full"])
def test_split_nonempty_pieces_at_minimum_and_full_capacity(tmp_path, size):
    carriers = _carriers(tmp_path, [(24, 24), (32, 32), (64, 64)])
    length = mi.total_capacity(carriers) if size == "full" else size
    blob = os.urandom(length)
    written = mi.split_embed(INDEX_KEY, blob, carriers, _outs(tmp_path, carriers))
    assert len(written) == 3
    assert all(mi.inspect_shard(INDEX_KEY, path)[3] > 0 for path in written)
    assert mi.join_extract(INDEX_KEY, written) == blob


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


@pytest.mark.parametrize("extension, file_format, subtype", [
    ("mp3", "MP3", "MPEG_LAYER_III"),
    ("flac", "FLAC", "PCM_16"),
    ("ogg", "OGG", "VORBIS"),
    ("opus", "OGG", "OPUS"),
    ("aiff", "AIFF", "PCM_16"),
])
def test_new_audio_carriers_convert_to_wav(tmp_path, extension, file_format, subtype):
    carrier = tmp_path / f"track.{extension}"
    rate = 48000
    samples = np.sin(np.arange(rate // 2) * (2 * np.pi * 440 / rate)) * 0.3
    soundfile.write(carrier, np.column_stack((samples, samples)), rate, format=file_format, subtype=subtype)
    original = carrier.read_bytes()
    blob = bytes(range(256)) * 2

    info = media.carrier_info(carrier)
    output = media.embed_blob(carrier, blob, str(tmp_path / f"output.{extension}"), order_key=INDEX_KEY)
    assert Path(output).suffix == ".wav"
    assert info["capacity_bytes"] == media.lsb_capacity_bytes(output)
    with wave.open(output, "rb") as pcm:
        assert (pcm.getnchannels(), pcm.getsampwidth(), pcm.getframerate()) == (2, 2, rate)
    assert media.extract_lsb_bytes(output, len(blob), order_key=INDEX_KEY) == blob
    assert carrier.read_bytes() == original


@pytest.mark.parametrize("extension", ["jpg", "webp", "bmp", "tiff", "gif"])
def test_image_carriers_keep_supported_native_format(tmp_path, extension):
    carrier = tmp_path / f"photo.{extension}"
    pixels = np.random.default_rng(3).integers(0, 256, (120, 160, 3), dtype=np.uint8)
    Image.fromarray(pixels).save(carrier)
    original = carrier.read_bytes()
    blob = bytes(range(256)) * 2

    info = media.carrier_info(carrier)
    output = media.embed_blob(carrier, blob, str(tmp_path / f"output.{extension}"), order_key=INDEX_KEY)
    assert Path(output).suffix == (".png" if extension == "gif" else f".{extension}")
    assert info["capacity_bytes"] == media.lsb_capacity_bytes(output)
    assert media.extract_lsb_bytes(output, len(blob), order_key=INDEX_KEY) == blob
    assert carrier.read_bytes() == original


@pytest.mark.parametrize("mode", ["RGB", "RGBA"])
def test_optimized_png_preserves_pixels_and_payload_with_smaller_output(tmp_path, mode):
    width, height = 640, 480
    horizontal = np.tile(np.arange(width, dtype=np.uint16) % 256, (height, 1)).astype(np.uint8)
    vertical = np.tile((np.arange(height, dtype=np.uint16) % 256)[:, None], (1, width)).astype(np.uint8)
    pixels = np.dstack((horizontal, vertical, np.full_like(horizontal, 100)))
    if mode == "RGBA":
        pixels = np.dstack((pixels, np.full_like(horizontal, 123)))
    carrier = tmp_path / "carrier.png"
    Image.fromarray(pixels).save(carrier)
    blob = bytes(range(256))
    output = media.embed_blob(str(carrier), blob, str(tmp_path / "optimized.png"), order_key=INDEX_KEY)
    # Compare identical stego pixels using the old encoder settings.
    weak = tmp_path / "old_compression.png"
    with Image.open(output) as image:
        optimized_pixels = np.array(image)
        image.save(weak, format="PNG", optimize=False, compress_level=1)
    with Image.open(weak) as image:
        assert np.array_equal(np.array(image), optimized_pixels)
    assert Path(output).stat().st_size < weak.stat().st_size
    assert media.extract_lsb_bytes(output, len(blob), order_key=INDEX_KEY) == blob
    assert np.max(np.abs(optimized_pixels[..., :3].astype(int) - pixels[..., :3].astype(int))) <= 1
    if mode == "RGBA":
        assert np.array_equal(optimized_pixels[..., 3], pixels[..., 3])


def test_jpeg_orientation_and_webp_transparency_are_preserved(tmp_path):
    jpeg = tmp_path / "rotated.jpg"
    exif = Image.Exif()
    exif[274] = 6  # rotate 90 degrees in viewers
    pixels = np.random.default_rng(4).integers(0, 256, (60, 80, 3), dtype=np.uint8)
    Image.fromarray(pixels).save(jpeg, exif=exif)
    output = media.embed_blob(jpeg, b"sample", str(tmp_path / "rotated_stego.jpg"))
    assert media.carrier_info(jpeg)["summary"] == "60 × 80 px"
    with Image.open(output) as image:
        assert image.size == (80, 60) and image.getexif().get(274) == 6
    assert media.extract_lsb_bytes(output, 6) == b"sample"

    webp = tmp_path / "transparency.webp"
    Image.new("RGBA", (80, 60), (10, 20, 30, 93)).save(webp, lossless=True)
    output = media.embed_blob(webp, b"sample", str(tmp_path / "transparency_stego.webp"))
    with Image.open(output) as image:
        assert image.getchannel("A").getextrema() == (93, 93)
    assert media.extract_lsb_bytes(output, 6) == b"sample"


def test_mixed_jpeg_mp3_shards_round_trip(tmp_path):
    jpeg = tmp_path / "photo.jpg"
    pixels = np.random.default_rng(5).integers(0, 256, (64, 64, 3), dtype=np.uint8)
    Image.fromarray(pixels).save(jpeg)
    mp3 = tmp_path / "audio.mp3"
    soundfile.write(mp3, np.zeros(16000, dtype=np.int16), 16000)
    carriers = [str(jpeg), str(mp3)]
    payload = os.urandom(200)  # Fits the JPEG alone; split mode must still write both.
    written = mi.split_embed(INDEX_KEY, payload, carriers, mi.suggest_outputs(carriers, str(tmp_path)))
    assert [Path(path).suffix for path in written] == [".jpg", ".wav"]
    assert mi.join_extract(INDEX_KEY, written[::-1]) == payload


def test_scatter_order_round_trips_and_hides_location(tmp_path):
    carrier = _png(tmp_path / "c.png", 200, 200)
    blob = bytes((i * 13) % 256 for i in range(600))
    out = media.embed_blob(str(carrier), blob, str(tmp_path / "o.png"), order_key=INDEX_KEY)

    # Recovers only with the right key; sequential or wrong-key reads do not.
    assert media.read_lsb_all(out, order_key=INDEX_KEY)[:len(blob)] == blob
    assert media.extract_lsb_bytes(out, len(blob), order_key=INDEX_KEY) == blob
    assert media.read_lsb_all(out)[:len(blob)] != blob
    assert media.read_lsb_all(out, order_key=bytes(32))[:len(blob)] != blob

    # The modified pixels are spread across the whole image, not a block from pixel 0.
    import numpy as np
    from PIL import Image
    a = np.array(Image.open(carrier).convert("RGB"), np.uint8).flatten()
    b = np.array(Image.open(out).convert("RGB"), np.uint8).flatten()
    changed = np.where(a != b)[0]
    assert changed.max() - changed.min() > b.size * 0.5


def test_multi_image_split_is_scattered_but_rejoins(tmp_path):
    carriers = _carriers(tmp_path, [(160, 160), (160, 160), (160, 160)])
    outs = _outs(tmp_path, carriers)
    blob = bytes((i * 11) % 256 for i in range(9000))
    written = mi.split_embed(INDEX_KEY, blob, carriers, outs)
    assert mi.join_extract(INDEX_KEY, written) == blob      # token rejoins the scattered shards
    with pytest.raises(InvalidTag):
        mi.join_extract(bytes(32), written)                 # wrong token cannot


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
