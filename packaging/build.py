"""
Builds the portable EnvStego zip: both token firmwares, the frozen app, and the zip.

    build.bat                      (sets up .venv, then runs this)
    .venv\\Scripts\\python packaging\\build.py

Always a full build, so the zip's firmware always matches the source. Output:
dist/EnvStego-portable.zip containing an EnvStego/ folder with EnvStego.exe, its
runtime files, and firmware/<board>/ bundles for the in-app flasher. The unzipped
folder and PyInstaller's work files are deleted afterwards; only the zip is left.

ICT3215 Digital Forensics — SIT
"""

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_SRC = ROOT / "ESP32 Files"
APP_SRC = ROOT / "Python"
BUNDLE_DIR = APP_SRC / "firmware"          # used by source runs, copied into the zip
DIST = ROOT / "dist"
WORK = ROOT / "build" / "pyinstaller"       # PyInstaller's work files (deleted after the build)
SCRIPTS = Path(sys.executable).parent

sys.path.insert(0, str(APP_SRC))
from firmware_flasher import parse_partition_table, PARTITION_TABLE_OFFSET  # noqa: E402

# PlatformIO environment -> (bundle folder, bootloader offset for that chip)
ENVIRONMENTS = {
    "esp32cam": ("esp32cam", 0x1000),
    "esp32s3": ("esp32s3", 0x0),
}
# Flash-size code in byte 3 (high nibble) of an ESP image header
FLASH_SIZES_MB = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16, 5: 32, 6: 64, 7: 128}


def run(command, **kwargs):
    print(">", " ".join(str(c) for c in command), flush=True)
    subprocess.run(command, check=True, **kwargs)


def firmware_version() -> int:
    source = (FIRMWARE_SRC / "main.cpp").read_text("utf-8")
    return int(re.search(r"#define\s+FIRMWARE_VERSION\s+(\d+)", source).group(1))


def boot_app0() -> Path:
    home = Path.home() / ".platformio" / "packages" / "framework-arduinoespressif32"
    path = home / "tools" / "partitions" / "boot_app0.bin"
    if not path.is_file():
        raise SystemExit(f"boot_app0.bin not found at {path}")
    return path


def bundle_firmware():
    run([SCRIPTS / "pio", "run", "--project-dir", FIRMWARE_SRC])
    version = firmware_version()
    shutil.rmtree(BUNDLE_DIR, ignore_errors=True)
    for env, (board, bootloader_offset) in ENVIRONMENTS.items():
        build = FIRMWARE_SRC / ".pio" / "build" / env
        out = BUNDLE_DIR / board
        out.mkdir(parents=True)
        table = parse_partition_table((build / "partitions.bin").read_bytes())
        if not table:
            raise SystemExit(f"{env}: unreadable partitions.bin")
        nvs = next(p for p in table if p.type == 1 and p.subtype == 2)
        otadata = next((p for p in table if p.type == 1 and p.subtype == 0), None)
        app = next(p for p in table if p.type == 0)
        # The updater keeps a token's keys by never writing NVS; both builds keep the
        # same layout the existing tokens were flashed with.
        if (nvs.offset, app.offset) != (0x9000, 0x10000):
            raise SystemExit(f"{env}: unexpected layout (NVS {nvs.offset:#x}, app {app.offset:#x})")
        files = [(bootloader_offset, build / "bootloader.bin", "bootloader.bin"),
                 (PARTITION_TABLE_OFFSET, build / "partitions.bin", "partitions.bin"),
                 (app.offset, build / "firmware.bin", "firmware.bin")]
        if otadata is not None:
            files.append((otadata.offset, boot_app0(), "boot_app0.bin"))
        segments = []
        for offset, source, name in sorted(files):
            shutil.copyfile(source, out / name)
            segments.append({"offset": hex(offset), "file": name,
                             "sha256": hashlib.sha256((out / name).read_bytes()).hexdigest()})
        header = (build / "bootloader.bin").read_bytes()[:4]
        manifest = {
            "board": board, "version": version,
            "flash_size_mb": FLASH_SIZES_MB[header[3] >> 4],
            "app_offset": hex(app.offset), "nvs_offset": hex(nvs.offset),
            "segments": segments,
        }
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2), "utf-8")
        print(f"Bundled {board} firmware v{version} ({manifest['flash_size_mb']} MB flash)")


def build_app():
    run([SCRIPTS / "pyinstaller", "--noconfirm", "--clean",
         "--distpath", DIST, "--workpath", WORK,
         ROOT / "packaging" / "EnvStego.spec"])
    app = DIST / "EnvStego"
    shutil.copytree(BUNDLE_DIR, app / "firmware", dirs_exist_ok=True)
    shutil.copyfile(ROOT / "packaging" / "README.txt", app / "README.txt")
    archive = shutil.make_archive(str(DIST / "EnvStego-portable"), "zip", DIST, "EnvStego")
    print(f"Built {archive}")
    # The zip is the deliverable; the folders it came from are only intermediates.
    remove_intermediate(app, "the unzipped app folder")
    remove_intermediate(WORK, "PyInstaller's work files")


def remove_intermediate(path: Path, what: str):
    """Delete a build intermediate. Failing to is not fatal: the zip is already complete."""
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"WARNING: could not delete {what} ({path}): {exc}\n"
              "         The zip is complete. Close anything using that folder (a running "
              "EnvStego.exe, OneDrive sync) and delete it yourself.", flush=True)


def main():
    bundle_firmware()
    build_app()


if __name__ == "__main__":
    main()
