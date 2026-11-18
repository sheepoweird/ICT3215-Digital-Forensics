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
- **Environment signals** — 21 hardware/network/OS signals, each rated for stability, with
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
  See [format behavior and validation](md/STEGO_FORMATS.md).
- **Env Vault v2** — arbitrary file types, including DOCX and PDF; encrypted metadata,
  one token request per import selection, locally derived per-file keys, and offline recovery. **No vault preview.** Auto-lock and **Ctrl+Shift+L** clear
  the list and cancel active file workers. Deleting imported originals is optional;
  each deletion outcome is reported.
- **Anti-forensic hygiene** — secure delete (overwrite + timestomp + rename + unlink),
  optional free-space wipe, Privacy mode, and settings kept out of the Windows registry.

## Quick start

See **[md/SETUP.md](md/SETUP.md)** for the full install, build, firmware-flash and usage
guide. In short:

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
  crypto_engine, stego_engine, audio_engine, media, multi_image, vault, signals,
  vault_v2, vault_worker, token_comms, pair_crypto, winutils, ui_main
  tests/         Automated tests (pytest)
ESP32 Files/     3T token firmware
md/              Setup/usage guide and docs
```

## Hardware

The token is a single **ESP32-CAM** module, flashed with the firmware in `ESP32 Files/`.
No custom PCB or extra components are required beyond a USB-to-serial programmer and cable.
Vault v2 needs **firmware v8**. Updating the application alone is insufficient.
Preserve NVS and the pairing config when updating the firmware.

## Testing

```bash
python -m pytest Python/tests/ -q
```

The suite covers stego round trips, host BLE protocol behavior, vault key separation,
recovery, write failures, concurrency, batch approvals, subprocess cancellation and Qt UI
flows. Host protocol simulation does not validate the physical IO0 circuit or BLE
runtime. See [validation results](md/VAULT_SECURITY.md#validation).

## Team

Sabrina Lim · Piers Soh · Muhammad Khair Aydil · Naveen Gopalkrishnan · Koh He Kai
Infocomm Technology Cluster, Singapore Institute of Technology.

## Security note

A factory reset destroys the token secret: stego files become unrecoverable and
vaults need their saved recovery codes. This change does not enable flash/NVS
encryption or Secure Boot; token theft remains a separate hardware risk. See
[the hardware security status](md/FLASH_ENCRYPTION.md).
