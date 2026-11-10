# Project Two To Tango (3T) — EnvStego

**Hardware-anchored anti-forensics against disk acquisition.**
ICT3215 Digital Forensics · Singapore Institute of Technology

EnvStego protects a user's data so that, if their device is seized and the disk is
imaged, the data **cannot be recovered without the physical ESP32 token *and* the
original environment**. The root secret never touches the disk — it lives only on a
low-cost ESP32 hardware token the user carries separately. Lose or destroy the token
and the data is permanently unrecoverable, by design.

> Threat model: the *resettable adversary* — an investigator who images the drive and
> studies unlimited offline copies at leisure. Anything reconstructable from the copied
> disk is eventually recoverable, so 3T keeps the high-entropy secret off the disk
> entirely rather than trying to hide it.

---

## How it works

Decryption always requires **two factors together**, never either alone:

1. **The ESP32 token** holds a 256-bit master secret generated on-device by its hardware
   RNG. It never leaves the token. First pairing is over USB (ECDH-encrypted); afterwards
   the PC and token talk over an authenticated, encrypted BLE channel.
2. **The environment** — a user-chosen set of machine signals (CPU/disk/motherboard
   serials, machine GUID, Wi-Fi BSSID, …). The token combines these with its secret.

```
env_hash  = SHA-256(selected signal ids + values)
env_key   = HMAC-SHA256(master_secret, env_hash)      # computed on the token
file_key  = HKDF-SHA256(env_key, random per-file salt) # computed on the PC
```

Every file gets an independent key; the master secret never reaches the PC in a reusable
form. Payloads are encrypted with **AES-256-GCM**.

## Features

- **Hardware token (ESP32)** — USB ECDH pairing, authenticated BLE key requests, replay
  protection and lockout. Credentials sealed with Windows DPAPI.
- **Environment signals** — 21 hardware/network/OS signals, each rated for stability, with
  a one-click **Recommended** selection and **Portable / Place-bound** modes.
- **Steganography** — hide an encrypted payload in the LSBs of a **PNG** image or **WAV**
  audio file under a token-encrypted header with **no plaintext marker**. Large payloads
  **split across several carriers** (sharded), each piece token-tagged.
- **Env Vault** — an encrypted store bound to the token + environment; files encrypted in
  (originals shredded), names/sizes/dates sealed, opened in RAM, **auto-locks** when the
  token leaves range (plus a **Ctrl+Shift+L panic lock**).
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
  token_comms, pair_crypto, winutils, ui_main
  tests/         150 automated tests (pytest)
ESP32 Files/     3T token firmware
md/              Setup/usage guide and docs
```

## Hardware

The token is a single **ESP32-CAM** module, flashed with the firmware in `ESP32 Files/`.
No custom PCB or extra components are required beyond a USB-to-serial programmer and cable.

## Testing

```bash
cd Python && python -m pytest tests/ -q      # 150 tests
```

The project is also evaluated with a disk-acquisition adversary harness and an
app-abuse fuzzing harness (kept locally, not in this repo).

## Team

Sabrina Lim · Piers Soh · Muhammad Khair Aydil · Naveen Gopalkrishnan · Koh He Kai
Infocomm Technology Cluster, Singapore Institute of Technology.

## Security note

A factory reset of the token (hold IO0 while booting) destroys the master secret, making
every file it protected permanently unrecoverable. This is intended behaviour, not a bug.
