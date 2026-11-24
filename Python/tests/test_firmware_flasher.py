"""
EnvStego — firmware flasher tests (no hardware required)

esptool is replaced by a recorder, and the board's flash by a partition-table dump,
so these tests check the decisions the one-click flasher makes:
  * a blank board gets the full image, an existing install only its app partition
  * nothing ever writes over the token's NVS key storage unless the user erased it
  * unknown layouts, unsupported chips and damaged bundles are refused

Run from the Python/ directory:
    python -m pytest tests/test_firmware_flasher.py -v
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import firmware_flasher as ff

# Arduino's default layouts: NVS 0x9000, otadata 0xe000, app0 0x10000
DEFAULT_LAYOUT = [(1, 2, 0x9000, 0x5000, "nvs"), (1, 0, 0xE000, 0x2000, "otadata"),
                  (0, 0x10, 0x10000, 0x640000, "app0"), (0, 0x11, 0x650000, 0x640000, "app1"),
                  (1, 0x82, 0xC90000, 0x360000, "spiffs")]


def table(entries) -> bytes:
    data = b""
    for ptype, subtype, offset, size, label in entries:
        data += b"\xAA\x50" + struct.pack("<BBII", ptype, subtype, offset, size)
        data += label.encode().ljust(16, b"\0") + b"\0\0\0\0"
    return data.ljust(ff.PARTITION_TABLE_SIZE, b"\xFF")


@pytest.fixture
def bundle_dir(tmp_path, monkeypatch):
    """A firmware/esp32s3 and firmware/esp32cam bundle like build.py writes."""
    monkeypatch.setattr(ff, "firmware_dir", lambda: tmp_path)
    for board, boot_offset in (("esp32s3", 0x0), ("esp32cam", 0x1000)):
        folder = tmp_path / board
        folder.mkdir()
        files = {"bootloader.bin": (boot_offset, b"\xE9" * 0x4000),
                 "partitions.bin": (0x8000, table(DEFAULT_LAYOUT)),
                 "boot_app0.bin": (0xE000, b"\xFF" * 0x2000),
                 "firmware.bin": (0x10000, b"\xE9" * 0x20000)}
        segments = []
        for name, (offset, data) in files.items():
            (folder / name).write_bytes(data)
            segments.append({"offset": hex(offset), "file": name,
                             "sha256": hashlib.sha256(data).hexdigest()})
        (folder / "manifest.json").write_text(json.dumps({
            "board": board, "version": 9, "flash_size_mb": 16 if board == "esp32s3" else 4,
            "app_offset": "0x10000", "nvs_offset": "0x9000", "segments": segments}))
    return tmp_path


class FakeBoard:
    """Stands in for esptool + the serial INFO query; records every esptool call."""

    def __init__(self, monkeypatch, chip="ESP32-S3", flash_mb=16, partitions=None, info=None):
        self.calls = []
        self.chip, self.flash_mb, self.info = chip, flash_mb, info
        self.partitions = b"\xFF" * ff.PARTITION_TABLE_SIZE if partitions is None else partitions
        monkeypatch.setattr(ff, "run_esptool", self.run_esptool)
        monkeypatch.setattr(ff, "query_token_info", lambda port, timeout=2.5: self.info)
        monkeypatch.setattr(ff, "wait_for_token_info", lambda port, timeout=15.0: {"FW": "9"})

    def run_esptool(self, port, args, progress=None, after="hard_reset"):
        self.calls.append(list(args))
        if args[0] == "read_flash":
            Path(args[3]).write_bytes(self.partitions)
        if args[0] == "write_flash" and progress:
            progress(100)
        return (f"Detecting chip type... {self.chip}\nChip is {self.chip} (revision v0.2)\n"
                f"Detected flash size: {self.flash_mb}MB\n")

    def writes(self):
        """[(offset, filename)] of every write_flash call."""
        out = []
        for call in self.calls:
            if call[0] == "write_flash":
                pairs = call[7:]
                out += [(int(pairs[i], 16), Path(pairs[i + 1]).name) for i in range(0, len(pairs), 2)]
        return out


def overlaps_nvs(writes, bundle_dir, board="esp32s3"):
    for offset, name in writes:
        end = offset + (bundle_dir / board / name).stat().st_size
        if offset < 0x9000 + 0x5000 and end > 0x9000:
            return True
    return False


# ── Partition tables ─────────────────────────────────────────────

def test_parse_blank_flash_is_empty():
    assert ff.parse_partition_table(b"\xFF" * ff.PARTITION_TABLE_SIZE) == []


def test_parse_garbage_is_not_a_table():
    assert ff.parse_partition_table(b"\x00" * ff.PARTITION_TABLE_SIZE) is None


def test_parse_default_layout():
    parts = ff.parse_partition_table(table(DEFAULT_LAYOUT))
    assert [(p.label, p.offset) for p in parts][:3] == [("nvs", 0x9000), ("otadata", 0xE000), ("app0", 0x10000)]
    assert ff._nvs(parts).size == 0x5000


# ── Planning ─────────────────────────────────────────────────────

def test_existing_token_is_updated_without_touching_nvs(bundle_dir, monkeypatch):
    board = FakeBoard(monkeypatch, partitions=table(DEFAULT_LAYOUT), info={"FW": "8"})
    plan = ff.inspect_token("COM5")
    assert plan.mode == "update" and plan.running_version == 8 and plan.bundle.board == "esp32s3"
    info = ff.flash_token(plan)
    assert board.writes() == [(0xE000, "boot_app0.bin"), (0x10000, "firmware.bin")]
    assert not overlaps_nvs(board.writes(), bundle_dir)
    assert not any(call[0] == "erase_flash" for call in board.calls)
    assert info == {"FW": "9"}


def test_update_keeps_existing_flash_settings(bundle_dir, monkeypatch):
    board = FakeBoard(monkeypatch, partitions=table(DEFAULT_LAYOUT))
    ff.flash_token(ff.inspect_token("COM5"))
    write = next(c for c in board.calls if c[0] == "write_flash")
    assert write[1:7] == ["--flash_mode", "keep", "--flash_freq", "keep", "--flash_size", "keep"]


def test_blank_board_gets_full_image(bundle_dir, monkeypatch):
    board = FakeBoard(monkeypatch)
    plan = ff.inspect_token("COM5")
    assert plan.mode == "install"
    ff.flash_token(plan)
    assert [o for o, _ in board.writes()] == [0x0, 0x8000, 0xE000, 0x10000]
    assert not overlaps_nvs(board.writes(), bundle_dir)


def test_classic_esp32_uses_cam_bundle_and_its_bootloader_offset(bundle_dir, monkeypatch):
    board = FakeBoard(monkeypatch, chip="ESP32", flash_mb=4)
    plan = ff.inspect_token("COM3")
    assert plan.bundle.board == "esp32cam"
    ff.flash_token(plan)
    assert board.writes()[0] == (0x1000, "bootloader.bin")


def test_different_nvs_layout_is_refused(bundle_dir, monkeypatch):
    moved = [(1, 2, 0x9000, 0x6000, "nvs"), (0, 0x10, 0x10000, 0x300000, "app0")]
    board = FakeBoard(monkeypatch, partitions=table(moved))
    plan = ff.inspect_token("COM5")
    assert plan.mode is None and "NVS" in plan.reason
    with pytest.raises(ff.FlashError):
        ff.flash_token(plan)
    assert board.writes() == []


def test_unknown_flash_contents_are_refused(bundle_dir, monkeypatch):
    FakeBoard(monkeypatch, partitions=b"\x12" * ff.PARTITION_TABLE_SIZE)
    plan = ff.inspect_token("COM5")
    assert plan.mode is None


def test_small_app_partition_is_refused(bundle_dir, monkeypatch):
    tiny = [(1, 2, 0x9000, 0x5000, "nvs"), (0, 0x10, 0x10000, 0x1000, "app0")]
    FakeBoard(monkeypatch, partitions=table(tiny))
    assert ff.inspect_token("COM5").mode is None


def test_blank_board_with_too_little_flash_is_refused(bundle_dir, monkeypatch):
    FakeBoard(monkeypatch, flash_mb=8)
    plan = ff.inspect_token("COM5")
    assert plan.mode is None and "8 MB" in plan.reason


def test_unsupported_chip_is_refused(bundle_dir, monkeypatch):
    FakeBoard(monkeypatch, chip="ESP32-C3")
    with pytest.raises(ff.FlashError, match="ESP32-C3"):
        ff.inspect_token("COM5")


def test_erase_wipes_then_installs(bundle_dir, monkeypatch):
    board = FakeBoard(monkeypatch, partitions=table(DEFAULT_LAYOUT))
    ff.flash_token(ff.inspect_token("COM5"), erase=True)
    kinds = [c[0] for c in board.calls]
    assert kinds.index("erase_flash") < kinds.index("write_flash")
    assert [o for o, _ in board.writes()] == [0x0, 0x8000, 0xE000, 0x10000]


def test_nvs_guard_blocks_a_write_into_key_storage(bundle_dir, monkeypatch):
    # A board whose NVS sits where the app would go: even if planning were wrong,
    # the final check must stop the write.
    FakeBoard(monkeypatch, partitions=table(DEFAULT_LAYOUT))
    plan = ff.inspect_token("COM5")
    plan.device_partitions = [ff.Partition(1, 2, 0x10000, 0x5000, "nvs")]
    with pytest.raises(ff.FlashError, match="NVS"):
        ff.write_segments(plan, erase=False)


# ── Bundles ──────────────────────────────────────────────────────

def test_damaged_bundle_is_refused(bundle_dir, monkeypatch):
    (bundle_dir / "esp32s3" / "firmware.bin").write_bytes(b"tampered")
    with pytest.raises(ff.FlashError, match="damaged"):
        ff.load_bundle("esp32s3")


def test_missing_bundle_explains_how_to_get_it(tmp_path, monkeypatch):
    monkeypatch.setattr(ff, "firmware_dir", lambda: tmp_path)
    with pytest.raises(ff.FlashError, match="missing"):
        ff.load_bundle("esp32s3")
    assert ff.bundled_versions() == {}


def test_bundled_versions(bundle_dir):
    assert ff.bundled_versions() == {"esp32cam": 9, "esp32s3": 9}


# ── esptool plumbing ─────────────────────────────────────────────

def test_frozen_build_runs_esptool_through_the_exe(monkeypatch):
    monkeypatch.setattr(ff.sys, "frozen", True, raising=False)
    assert ff._esptool_command(["flash_id"])[1:] == ["--esptool", "flash_id"]


def test_source_run_uses_python_module(monkeypatch):
    monkeypatch.delattr(ff.sys, "frozen", raising=False)
    assert ff._esptool_command(["flash_id"])[1:] == ["-u", "-m", "esptool", "flash_id"]


@pytest.mark.parametrize("output, expected", [
    ("A fatal error occurred: Failed to connect to ESP32-S3: No serial data received.", "BOOT"),
    ("A fatal error occurred: Could not open COM5, the port is busy or doesn't exist.\n"
     "(could not open port 'COM5': PermissionError(13, 'Access is denied.', None, 5))", "another program"),
    ("A fatal error occurred: Could not open COM99, the port is busy or doesn't exist.\n"
     "(could not open port 'COM99': FileNotFoundError(2, 'The system cannot find the file "
     "specified.', None, 2))", "plugged in"),
    ("A fatal error occurred: Something new", "Something new"),
])
def test_esptool_errors_are_explained(output, expected):
    assert expected in ff._friendly_esptool_error("COM5", output)


def test_missing_esptool_is_explained_before_running(monkeypatch):
    monkeypatch.delattr(ff.sys, "frozen", raising=False)
    monkeypatch.setattr(ff, "_esptool_available", lambda: False)
    started = []
    monkeypatch.setattr(ff.subprocess, "Popen", lambda *a, **k: started.append(a))
    with pytest.raises(ff.FlashError, match="pip install -r requirements.txt"):
        ff.run_esptool("COM5", ["flash_id"])
    assert started == []


def test_missing_esptool_in_child_output_is_explained():
    message = ff._friendly_esptool_error("COM5", "C:\\Python314\\python.exe: No module named esptool")
    assert "pip install -r requirements.txt" in message


def test_frozen_build_always_has_esptool(monkeypatch):
    monkeypatch.setattr(ff.sys, "frozen", True, raising=False)
    assert ff._esptool_available()


def test_progress_lines_are_parsed():
    assert ff._PERCENT.search("Writing at 0x0001c000... (42 %)").group(1) == "42"


def test_chip_detection_from_esptool_output():
    out = ("Detecting chip type... Unsupported detection protocol, switching and trying again...\n"
           "Detecting chip type... ESP32\nChip is ESP32-D0WD-V3 (revision v3.1)\n")
    assert ff._detect_chip(out) == "ESP32"
    assert ff._detect_chip("Chip is ESP32-S3 (QFN56) (revision v0.2)") == "ESP32-S3"
