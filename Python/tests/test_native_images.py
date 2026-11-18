"""Native coefficient preservation, lossless image bytes and codec isolation."""

import json
import os
import subprocess
import sys
from pathlib import Path

import jpeglib
import numpy as np
import pytest
from PIL import Image, ImageCms

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import media
import stego_engine as se

KEY = bytes(range(32))


def jpeg(path, mode="RGB", progressive=False, subsampling=2):
    shape = (240, 320) if mode == "L" else (240, 320, 3)
    pixels = np.random.default_rng(27).integers(0, 256, shape, dtype=np.uint8)
    exif = Image.Exif()
    exif[270], exif[274] = "native carrier", 6
    profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    Image.fromarray(pixels).save(path, quality=90, subsampling=subsampling,
                                 progressive=progressive, exif=exif, icc_profile=profile)
    return str(path)


@pytest.mark.parametrize("mode,progressive,subsampling", [
    ("RGB", False, 0), ("RGB", True, 2), ("L", False, 0), ("L", True, 0),
])
def test_jpeg_round_trip_preserves_coefficients_tables_and_metadata(tmp_path, mode, progressive, subsampling):
    source = jpeg(tmp_path / "photo.jpeg", mode, progressive, subsampling)
    original = Path(source).read_bytes()
    blob = os.urandom(1024)
    target = media.embed_blob(source, blob, str(tmp_path / "result.png"), order_key=KEY)
    assert Path(target).suffix == ".jpeg"
    assert media.extract_lsb_bytes(target, len(blob), order_key=KEY) == blob
    assert media.read_lsb_all(target, order_key=KEY)[:len(blob)] == blob
    assert media.extract_lsb_bytes(target, len(blob), order_key=bytes(32)) != blob
    assert media.lsb_capacity_bytes(source) == media.lsb_capacity_bytes(target)
    assert media.carrier_info(source)["capacity_bytes"] == media.lsb_capacity_bytes(source)
    assert Path(source).read_bytes() == original
    assert Path(target).stat().st_size < len(original) * 1.5
    before, after = jpeglib.read_dct(source), jpeglib.read_dct(target)
    assert np.array_equal(before.qt, after.qt)
    assert np.array_equal(before.samp_factor, after.samp_factor)
    changed = 0
    for name in ("Y", "Cb", "Cr"):
        left, right = getattr(before, name), getattr(after, name)
        if left is None:
            assert right is None
            continue
        difference = np.abs(left.astype(np.int32) - right.astype(np.int32))
        assert difference.max() <= 1
        assert np.array_equal(left[..., 0, 0], right[..., 0, 0])
        assert np.array_equal(left[np.abs(left) < 2], right[np.abs(left) < 2])
        assert np.array_equal(left < 0, right < 0)
        changed += np.count_nonzero(difference)
    assert changed > 0
    with Image.open(source) as left, Image.open(target) as right:
        assert right.format == "JPEG" and right.size == left.size
        assert right.getexif().get(274) == left.getexif().get(274)
        assert right.getexif().get(270) == "native carrier"
        assert right.info["icc_profile"] == left.info["icc_profile"]


def test_full_jpeg_capacity_remains_readable(tmp_path):
    source = jpeg(tmp_path / "full.jpg")
    capacity = media.lsb_capacity_bytes(source)
    blob = os.urandom(capacity)
    target = media.embed_blob(source, blob, str(tmp_path / "full_stego.jpg"), order_key=KEY)
    assert media.lsb_capacity_bytes(target) == capacity
    assert media.read_lsb_all(target, order_key=KEY) == blob


def test_smooth_jpeg_has_no_invented_pixel_capacity(tmp_path):
    source = tmp_path / "smooth.jpg"
    Image.new("RGB", (320, 240), (80, 100, 120)).save(source)
    assert media.lsb_capacity_bytes(source) == 0
    with pytest.raises(ValueError, match="too small"):
        media.embed_blob(str(source), b"data", str(tmp_path / "result.jpg"), order_key=KEY)
    assert not (tmp_path / "result.jpg").exists()


def test_jpeg_unicode_paths_are_supported(tmp_path):
    source = jpeg(tmp_path / "日本語-évidence.jpg")
    target = media.embed_blob(source, b"payload", str(tmp_path / "秘密-stego.jpg"), order_key=KEY)
    assert media.extract_lsb_bytes(target, 7, order_key=KEY) == b"payload"


def test_native_worker_failure_keeps_existing_output_and_cleans_temporary_files(tmp_path, monkeypatch):
    source = jpeg(tmp_path / "source.jpg")
    target = tmp_path / "existing.jpg"
    target.write_bytes(b"existing output must survive")
    monkeypatch.setattr(se.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(se.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 42, "", "native failure"))
    with pytest.raises(ValueError, match="codec"):
        media.embed_blob(source, b"payload", str(target), order_key=KEY)
    assert target.read_bytes() == b"existing output must survive"
    assert not list(tmp_path.glob("envstego-jpeg-*"))


def test_malformed_jpeg_is_rejected_in_worker(tmp_path):
    source = tmp_path / "bad.jpg"
    source.write_bytes(b"not a JPEG")
    with pytest.raises(ValueError):
        media.embed_blob(str(source), b"payload", str(tmp_path / "result.jpg"))
    assert source.read_bytes() == b"not a JPEG" and not (tmp_path / "result.jpg").exists()


def test_lossless_webp_preserves_hidden_bits_even_under_zero_alpha(tmp_path):
    pixels = np.random.default_rng(8).integers(0, 256, (100, 120, 4), dtype=np.uint8)
    pixels[:, :60, 3] = 0
    source = tmp_path / "transparent.webp"
    Image.fromarray(pixels).save(source, lossless=True, exact=True)
    blob = os.urandom(1024)
    target = media.embed_blob(str(source), blob, str(tmp_path / "output.png"), order_key=KEY)
    assert Path(target).suffix == ".webp"
    assert media.extract_lsb_bytes(target, len(blob), order_key=KEY) == blob
    with Image.open(target) as encoded:
        after = np.array(encoded.convert("RGBA"))
    assert np.array_equal(pixels[..., 3], after[..., 3])
    assert np.abs(pixels[..., :3].astype(int) - after[..., :3].astype(int)).max() <= 1


@pytest.mark.skipif(os.name != "nt", reason="Windows windowed worker handles")
def test_jpeg_worker_restores_windowed_streams(tmp_path):
    source = jpeg(tmp_path / "windowed.jpg")
    script = (f"import sys; sys.path.insert(0, {str(Path(se.__file__).parent)!r}); "
              "sys.stdin=None; sys.stdout=None; import stego_engine; sys.exit(stego_engine._jpeg_worker_main())")
    request = {"action": "info", "source": source, "key": None}
    result = subprocess.run([sys.executable, "-c", script], input=json.dumps(request), text=True,
                            capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["result"]["capacity_bytes"] > 0
