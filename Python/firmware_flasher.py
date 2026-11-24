"""
EnvStego - firmware_flasher.py
One-click install / update of the 3T token firmware, driven by esptool.

The token's master secret and pairing credential live in its NVS partition. Losing
them makes every stego file protected by the token unreadable, so this module is
built around one rule: **an install or update never writes over NVS.**

  • Update  — the board already has a partition table with NVS and the app where this
              firmware expects them. Only the app partition (and the small OTA-select
              record) is written. Keys and pairing are kept.
  • Install — the flash is blank. The full image is written as separate segments
              (bootloader, partition table, OTA record, app); NVS stays blank.
  • Erase   — only on explicit request: wipes the whole chip (keys included), then
              installs. The UI asks for a typed confirmation first.

Every write plan is checked against the NVS range before esptool is started.

Firmware bundles are built by build.bat into a `firmware/<board>/` folder next to the
app (next to EnvStego.exe when frozen), each with a manifest.json and SHA-256 hashes.

ICT3215 Digital Forensics — SIT
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

PARTITION_TABLE_OFFSET = 0x8000
PARTITION_TABLE_SIZE = 0xC00

# esptool's chip family name -> firmware bundle folder
CHIP_BOARDS = {"ESP32": "esp32cam", "ESP32-S3": "esp32s3"}
BOARD_NAMES = {"esp32cam": "ESP32-CAM", "esp32s3": "ESP32-S3"}

_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class FlashError(Exception):
    """A user-facing explanation of why inspecting or flashing failed."""


def _app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def firmware_dir() -> Path:
    return _app_dir() / "firmware"


# ── Partition tables ─────────────────────────────────────────────

@dataclass(frozen=True)
class Partition:
    type: int        # 0 = app, 1 = data
    subtype: int     # data: 0 = ota, 2 = nvs
    offset: int
    size: int
    label: str

    @property
    def end(self) -> int:
        return self.offset + self.size


def parse_partition_table(data: bytes) -> list[Partition] | None:
    """Return the partitions, [] for blank flash, or None if the data is not a table."""
    if not data or all(b == 0xFF for b in data):
        return []
    parts = []
    for i in range(0, len(data) - 31, 32):
        entry = data[i:i + 32]
        if entry[:2] == b"\xAA\x50":
            ptype, subtype, offset, size = struct.unpack_from("<BBII", entry, 2)
            label = entry[12:28].split(b"\0", 1)[0].decode("ascii", "replace")
            parts.append(Partition(ptype, subtype, offset, size, label))
        elif entry[:2] in (b"\xEB\xEB", b"\xFF\xFF"):   # MD5 record / end of table
            break
        else:
            return None
    return parts or None


def _nvs(parts: list[Partition]) -> Partition | None:
    return next((p for p in parts if p.type == 1 and p.subtype == 2), None)


def _otadata(parts: list[Partition]) -> Partition | None:
    return next((p for p in parts if p.type == 1 and p.subtype == 0), None)


def _app_at(parts: list[Partition], offset: int) -> Partition | None:
    return next((p for p in parts if p.type == 0 and p.offset == offset), None)


# ── Bundled firmware ─────────────────────────────────────────────

@dataclass
class Bundle:
    board: str
    version: int
    flash_size_mb: int
    segments: list[tuple[int, Path]]     # full install: (offset, file), ascending
    app_offset: int
    partitions: list[Partition] = field(default_factory=list)

    @property
    def app(self) -> Path:
        return next(path for offset, path in self.segments if offset == self.app_offset)

    @property
    def otadata_image(self) -> tuple[int, Path] | None:
        ota = _otadata(self.partitions)
        if ota is None:
            return None
        return next(((o, p) for o, p in self.segments if o == ota.offset), None)


def load_bundle(board: str) -> Bundle:
    folder = firmware_dir() / board
    try:
        manifest = json.loads((folder / "manifest.json").read_text("utf-8"))
    except (OSError, ValueError):
        raise FlashError(
            f"The {BOARD_NAMES.get(board, board)} firmware is missing from this copy of EnvStego "
            f"({folder}). Download the full EnvStego zip again, or run build.bat.")
    segments = []
    for item in manifest["segments"]:
        path = folder / item["file"]
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            raise FlashError(f"Firmware file {path.name} is missing. Download the full EnvStego zip again.")
        if digest != item["sha256"]:
            raise FlashError(f"Firmware file {path.name} is damaged (checksum mismatch). "
                             "Download the full EnvStego zip again.")
        segments.append((int(item["offset"], 0), path))
    segments.sort()
    bundle = Bundle(board=board, version=int(manifest["version"]),
                    flash_size_mb=int(manifest["flash_size_mb"]), segments=segments,
                    app_offset=int(manifest["app_offset"], 0))
    table = next((p for o, p in segments if o == PARTITION_TABLE_OFFSET), None)
    bundle.partitions = parse_partition_table(table.read_bytes()) if table else None
    if not bundle.partitions or _nvs(bundle.partitions) is None or bundle.app_offset == 0:
        raise FlashError(f"The bundled {BOARD_NAMES.get(board, board)} firmware has an invalid "
                         "partition table. Rebuild it with build.bat.")
    return bundle


def bundled_versions() -> dict[str, int]:
    """{board: version} for every firmware bundle shipped with the app."""
    found = {}
    for board in CHIP_BOARDS.values():
        try:
            manifest = json.loads((firmware_dir() / board / "manifest.json").read_text("utf-8"))
            found[board] = int(manifest["version"])
        except (OSError, ValueError, KeyError):
            pass
    return found


# ── esptool ──────────────────────────────────────────────────────

def _esptool_command(args: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--esptool", *args]
    return [sys.executable, "-u", "-m", "esptool", *args]


_PERCENT = re.compile(r"Writing at 0x[0-9a-fA-F]+\.*\s*\((\d+)\s*%\)")


MISSING_ESPTOOL_MESSAGE = (
    "esptool is not installed for the Python running EnvStego ({python}).\n"
    "In the Python folder run:  pip install -r requirements.txt\n"
    "then restart EnvStego. (The portable EnvStego.exe already includes it.)")


def _esptool_available() -> bool:
    if getattr(sys, "frozen", False):
        return True
    import importlib.util
    return importlib.util.find_spec("esptool") is not None


def _friendly_esptool_error(port: str, output: str) -> str:
    text = output.lower()
    if "no module named esptool" in text:
        return MISSING_ESPTOOL_MESSAGE.format(python=sys.executable)
    if "filenotfounderror" in text or "cannot find the file" in text:
        return f"{port} is not available. Is the token plugged in? Click ↻ to rescan the ports."
    if "could not open port" in text or "access is denied" in text or "permissionerror" in text:
        return (f"{port} is being used by another program, or the token was unplugged.\n"
                "Close any serial monitor (PlatformIO, Arduino IDE), check the cable, and try again.")
    if "failed to connect" in text or "no serial data received" in text or "wrong boot mode" in text:
        return ("The token did not enter download mode.\n"
                "Hold its BOOT / IO0 button, tap RST (EN), release BOOT, then click again.\n"
                "On an ESP32-S3 board you can also try its other USB-C port.")
    fatal = [line for line in output.splitlines() if "fatal error" in line.lower()]
    if fatal:
        return fatal[-1].strip()
    tail = [line for line in output.strip().splitlines() if line.strip()][-3:]
    return "esptool failed:\n" + "\n".join(tail)


def run_esptool(port: str, args: list[str], progress=None, after: str = "hard_reset") -> str:
    """Run one esptool command against `port`; returns its output or raises FlashError."""
    if not _esptool_available():
        raise FlashError(MISSING_ESPTOOL_MESSAGE.format(python=sys.executable))
    command = _esptool_command(["--port", port, "--chip", "auto", "--baud", "460800",
                                "--before", "default_reset", "--after", after, *args])
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    lines = []
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                   errors="replace", bufsize=1, env=env, creationflags=_NO_WINDOW)
    except OSError as exc:
        raise FlashError(f"Could not start esptool: {exc}")
    with process:
        for line in process.stdout:
            lines.append(line)
            match = _PERCENT.search(line)
            if match and progress:
                progress(int(match.group(1)))
        process.wait()
    output = "".join(lines)
    if process.returncode:
        raise FlashError(_friendly_esptool_error(port, output))
    return output


def _detect_chip(output: str) -> str:
    found = re.findall(r"Detecting chip type\.\.\.\s*(ESP32[-\w]*)", output)
    if found:
        return found[-1]
    match = re.search(r"Chip is (ESP32(?:-S\d|-C\d|-H\d|-P\d)?)", output)
    return match.group(1) if match else "unknown"


def _detect_flash_mb(output: str) -> int | None:
    match = re.search(r"Detected flash size:\s*(\d+)MB", output)
    return int(match.group(1)) if match else None


# ── Talking to the running firmware ──────────────────────────────

def query_token_info(port: str, timeout: float = 2.5) -> dict | None:
    """Ask running firmware for its version (v9+). None if it does not answer."""
    import serial
    try:
        ser = serial.Serial()
        ser.port, ser.baudrate, ser.timeout = port, 115200, 0.2
        ser.dtr = ser.rts = False          # do not reset the board by opening the port
        ser.open()
    except (OSError, serial.SerialException):
        return None
    try:
        ser.reset_input_buffer()
        deadline = time.monotonic() + timeout
        next_send = 0.0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send:
                ser.write(b"INFO\n")
                next_send = time.monotonic() + 0.8
            line = ser.readline().decode("utf-8", "replace").strip()
            if line.startswith("TOKEN_INFO"):
                fields = dict(part.split("=", 1) for part in line.split(";")[1:] if "=" in part)
                return fields
    except (OSError, serial.SerialException):
        return None
    finally:
        ser.close()
    return None


def wait_for_token_info(port: str, timeout: float = 15.0) -> dict | None:
    """After a reset the token runs a 3 s boot window, and an S3's native USB port
    re-enumerates, so keep asking for a while."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        info = query_token_info(port, timeout=1.6)
        if info:
            return info
        time.sleep(0.5)
    return None


# ── Planning ─────────────────────────────────────────────────────

@dataclass
class FlashPlan:
    port: str
    chip: str
    bundle: Bundle
    flash_mb: int | None
    mode: str | None                    # "update", "install" or None (needs erase)
    running_version: int | None         # from INFO; None if older than v9 or not running
    device_partitions: list[Partition]
    reason: str = ""                    # why mode is None

    @property
    def board_name(self) -> str:
        return BOARD_NAMES.get(self.bundle.board, self.bundle.board)


def inspect_token(port: str, status=lambda _msg: None) -> FlashPlan:
    """Identify the chip and what is on its flash. Reads only; writes nothing."""
    status("Asking the token for its firmware version…")
    info = query_token_info(port)
    running = int(info["FW"]) if info and info.get("FW", "").isdecimal() else None

    status("Identifying the chip…")
    out = run_esptool(port, ["flash_id"], after="no_reset")
    chip = _detect_chip(out)
    board = CHIP_BOARDS.get(chip)
    if board is None:
        run_esptool(port, ["chip_id"])  # leave download mode
        raise FlashError(f"This board is an {chip}. The EnvStego token firmware supports the "
                         "ESP32 (ESP32-CAM) and the ESP32-S3.")
    bundle = load_bundle(board)
    flash_mb = _detect_flash_mb(out)

    status("Reading the board's partition table (read-only)…")
    with tempfile.TemporaryDirectory(prefix="envstego-flash-") as tmp:
        dump = Path(tmp) / "partitions.bin"
        run_esptool(port, ["read_flash", hex(PARTITION_TABLE_OFFSET), hex(PARTITION_TABLE_SIZE), str(dump)])
        device = parse_partition_table(dump.read_bytes())

    plan = FlashPlan(port, chip, bundle, flash_mb, None, running, device or [])
    if device == []:
        plan.mode = "install"
    elif device is None:
        plan.reason = "The board's flash holds something that is not an ESP32 partition table."
    else:
        want_nvs, have_nvs = _nvs(bundle.partitions), _nvs(device)
        app = _app_at(device, bundle.app_offset)
        if have_nvs is None:
            plan.reason = "The board's partition table has no NVS key storage."
        elif (have_nvs.offset, have_nvs.size) != (want_nvs.offset, want_nvs.size):
            plan.reason = (f"The board keeps NVS at {have_nvs.offset:#x} (size {have_nvs.size:#x}); "
                           f"this firmware expects {want_nvs.offset:#x} (size {want_nvs.size:#x}).")
        elif app is None:
            plan.reason = f"The board has no app partition at {bundle.app_offset:#x}."
        elif app.size < bundle.app.stat().st_size:
            plan.reason = "The board's app partition is too small for this firmware."
        else:
            plan.mode = "update"
    if plan.mode == "install" and flash_mb is not None and flash_mb < bundle.flash_size_mb:
        plan.mode = None
        plan.reason = (f"This {chip} has {flash_mb} MB of flash; the firmware is built for "
                       f"{bundle.flash_size_mb} MB.")
    return plan


def write_segments(plan: FlashPlan, erase: bool) -> list[tuple[int, Path]]:
    """What a flash would write. Raises FlashError if any of it overlaps NVS."""
    bundle = plan.bundle
    if erase or plan.mode == "install":
        segments = list(bundle.segments)
        keep = None if erase else _nvs(bundle.partitions)
    elif plan.mode == "update":
        segments = [(bundle.app_offset, bundle.app)]
        ota_image, device_ota = bundle.otadata_image, _otadata(plan.device_partitions)
        # Reset the OTA-select record so the board boots app0, but only if the board
        # really has an OTA-data partition at the same place.
        if ota_image and device_ota and device_ota.offset == ota_image[0] \
                and ota_image[1].stat().st_size <= device_ota.size:
            segments.append(ota_image)
        segments.sort()
        keep = _nvs(plan.device_partitions)
    else:
        raise FlashError(plan.reason or "This board cannot be updated in place.")
    if keep is not None:
        for offset, path in segments:
            end = offset + path.stat().st_size
            if offset < keep.end and end > keep.offset:
                raise FlashError(f"Refusing to flash: {path.name} at {offset:#x} would overwrite "
                                 "the token's key storage (NVS).")
    return segments


def flash_token(plan: FlashPlan, erase: bool = False, status=lambda _msg: None,
                progress=lambda _pct: None) -> dict | None:
    """Write the firmware; returns the TOKEN_INFO of the restarted token, or None."""
    segments = write_segments(plan, erase)
    if erase:
        if plan.flash_mb is not None and plan.flash_mb < plan.bundle.flash_size_mb:
            raise FlashError(f"This {plan.chip} has {plan.flash_mb} MB of flash; the firmware is "
                             f"built for {plan.bundle.flash_size_mb} MB.")
        status("Erasing the whole chip…")
        run_esptool(plan.port, ["erase_flash"], after="no_reset")
    status("Writing firmware…")
    args = ["write_flash", "--flash_mode", "keep", "--flash_freq", "keep", "--flash_size", "keep"]
    for offset, path in segments:
        args += [hex(offset), str(path)]
    run_esptool(plan.port, args, progress=progress)
    status("Waiting for the token to restart…")
    return wait_for_token_info(plan.port)


def esptool_entry(argv: list[str]) -> int:
    """`EnvStego.exe --esptool …` in the frozen build: run esptool in this process."""
    from winutils import restore_worker_streams
    restore_worker_streams()
    if sys.stderr is None:
        sys.stderr = sys.stdout
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass
    import esptool
    sys.argv = ["esptool", *argv]
    try:
        esptool._main()
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    return 0
