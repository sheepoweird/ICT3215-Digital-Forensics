# Project Two To Tango (3T) — EnvStego

**Hardware-anchored anti-forensics against disk acquisition.**
ICT3215 Digital Forensics · Singapore Institute of Technology

EnvStego encrypts data using a master secret held by a separate ESP32 token and
user-selected environment signals. A PC disk image alone lacks the token secret.
Many environment signals can be reconstructed from disk; they are not a second
high-entropy secret. Vaults also have an offline recovery code, which bypasses the
token and environment. See [the vault security design](md/VAULT_SECURITY.md) for
the memory-exposure boundary and recovery limitations.

> Threat model: the *resettable adversary* — an investigator who images the drive and
> studies unlimited offline copies at leisure. Anything reconstructable from the copied
> disk is eventually recoverable, so 3T keeps the high-entropy secret off the disk
> entirely rather than trying to hide it.

---

## How it works

Normal decryption uses the token and selected environment signals:

1. **The ESP32 token** holds a 256-bit master secret generated on-device by its hardware
   RNG. It never leaves the token. First pairing is over USB (ECDH-encrypted); afterwards
   the PC and token talk over an authenticated, encrypted BLE channel.
2. **The environment** — a user-chosen set of machine signals (CPU/disk/motherboard
   serials, machine GUID, Wi-Fi BSSID, …). The token combines these with its secret.

```
env_hash  = SHA-256(selected signal ids + values)
env_key   = HMAC-SHA256(master_secret, "3T-ENV-v1" | env_hash)
stego_key = HKDF-SHA256(env_key, random per-file salt)
```

Stego encryption uses the environment key on the PC. The vault handles keys differently.

| Vault action | IO0 | Key handling |
| --- | --- | --- |
| Open the file list | One tap | The app holds the metadata key until the list locks. |
| Add one or more files | No additional tap | After checking the environment, the worker requests one batch secret, disconnects Bluetooth, and derives a separate AES-256-GCM key for each file locally. It releases the secret when the import ends. |
| Export selected files | One tap for the selection | The worker keeps the export connection open and requests each selected file's key as it decrypts that file. |

A memory capture during import can expose the whole selection through its batch
secret. An ordinary export exposes the current file's key. The offline recovery
code can recover the entire vault. [Vault security and recovery](md/VAULT_SECURITY.md)

## Features

- **Hardware token (ESP32)** — USB ECDH pairing, authenticated BLE key requests, replay
  protection and lockout. Credentials sealed with Windows DPAPI.
- **Environment signals** — 22 hardware/network/OS signals, each rated for stability, with
  a one-click **Recommended** selection and **Portable / Place-bound** modes.
- **Steganography** — hide any file, including DOCX or PDF, inside an image or audio
  carrier. Inputs include JPEG, PNG, WebP, BMP, TIFF, GIF, WAV, MP3, FLAC, Ogg, Opus,
  and AIFF. JPEG carriers stay JPEG; PNG, WebP, BMP and TIFF keep their format
  using the corresponding JPEG or lossless pixel method. GIF saves as PNG and audio
  saves as WAV. Large payloads can
  split across all usable selected carriers, with a token-encrypted tag for each
  piece. Decrypt receives the complete output set automatically.
  WebP outputs are lossless and may grow from lossy inputs. Native JPEG support is
  implemented inside `stego_engine.py`; native MP3 embedding is not implemented.
  Recovered files are written to disk only; the app never displays their contents.
  See [format behavior and validation](md/STEGO_FORMATS.md).
- **Env Vault v2** — arbitrary file types, including DOCX and PDF; encrypted metadata,
  one token request per import selection, locally derived per-file keys, and offline
  recovery. **No in-app preview.** The list locks on **Ctrl+Shift+L**, when the token stops
  answering, or after 5 minutes without vault activity, and locking cancels active file
  workers. Each import asks whether to keep or delete the originals (keep by default);
  each deletion outcome is reported.
- **Anti-forensic hygiene** — secure delete (overwrite + timestomp + rename + unlink),
  optional free-space wipe, Privacy mode, and settings kept out of the Windows registry.

## Quick start

See **[md/SETUP.md](md/SETUP.md)** for the full install, build, firmware-flash and usage
guide. In short:

1. Unzip `EnvStego-portable.zip` and run `EnvStego.exe` (no Python needed).
2. Plug in the token (ESP32-CAM or ESP32-S3-N16R8), open **Setup › Token**, and click
   **Install / update firmware**. An existing token keeps its keys.
3. Click **Pair Token** and press the token's IO0 / BOOT button when its light stays on.

To build the zip yourself, run `build.bat`. To run from source (Python 3.12):

```bash
cd Python
pip install -r requirements.txt
python main.py
```

Pair the token (Setup › Token) → pick signals (Signals, or click **Recommended**) →
Encrypt a file or create a Vault.

## Repository layout

```
Python/          Host application (PyQt6) + automated tests
  main.py        Entry point
  crypto_engine, stego_engine, audio_engine, media, multi_image, archive, signals,
  vault, vault_worker, token_comms, pair_crypto, winutils, ui_main, firmware_flasher
  tests/         Automated tests (pytest)
ESP32 Files/     3T token firmware (PlatformIO: esp32cam, esp32s3)
packaging/       Portable zip build (used by build.bat)
build.bat        Builds dist/EnvStego-portable.zip
md/              Setup/usage guide and docs
```

## Hardware

The token is a single **ESP32-CAM** module or an **ESP32-S3-N16R8** dev board, flashed
with the firmware in `ESP32 Files/`. No custom PCB, soldering or extra components are required.

**Bill of materials** (either option A or option B)

| Item | Qty | Purpose |
| --- | --- | --- |
| **A:** ESP32-CAM module (ESP32-D0WD, 4 MB flash) | 1 | The token: holds the master secret, BLE radio, IO0 confirmation button, white LED for status |
| **A:** ESP32-CAM-MB USB programmer board (CH340) | 1 | USB power, flashing and first-time USB pairing; the module plugs straight onto it |
| **B:** ESP32-S3-N16R8 dev board (16 MB flash, 8 MB PSRAM) | 1 | The token on one board: USB built in (either USB-C port works), BOOT button as IO0, RGB LED on GPIO48 for coloured status |
| USB data cable (Micro-USB or USB-C, to match the board) | 1 | Connects the token to the PC |
| Windows 10/11 PC with Bluetooth LE | 1 | Runs the EnvStego desktop app |

The camera that ships with the ESP32-CAM is not used. Power the board from a rear
(motherboard) USB port or a powered hub: Bluetooth start-up draws a current spike that
weak ports cannot supply.

The app's **Install / update firmware** button flashes either board. Updating writes only
the firmware and preserves NVS (the token's keys and pairing). Vault v2 needs firmware v8
or later; the current firmware is v9.

## Testing

```bash
python -m pytest Python/tests/ -q
```

All 271 tests pass (2026-11-24). The suite covers stego round trips for every supported
carrier, host BLE protocol behavior, vault key separation, recovery, write failures,
concurrency, batch approvals, subprocess cancellation and Qt UI flows. Host protocol
simulation does not validate the physical IO0 circuit or BLE runtime. See
[validation results](md/VAULT_SECURITY.md#validation).

## Team

Sabrina Lim · Piers Soh · Muhammad Khair Aydil · Naveen Gopalkrishnan · Koh He Kai
Infocomm Technology Cluster, Singapore Institute of Technology.

## Security note

A factory reset destroys the token secret: stego files become unrecoverable and
vaults need their saved recovery codes. This change does not enable flash/NVS
encryption or Secure Boot; token theft remains a separate hardware risk. See
[the hardware security status](md/FLASH_ENCRYPTION.md).
