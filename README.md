# EnvStego: Project Two To Tango (3T)

**Hide files so a copied hard drive isn't enough to open them.**

ICT3215 Digital Forensics · Singapore Institute of Technology

EnvStego is a Windows app that hides your files inside ordinary pictures and audio
clips, or locks them in an encrypted vault. To open them again you need two things:

1. **Your token**: a small ESP32 board that stores a secret key and never gives it out.
2. **This computer**: the app checks hardware and network details you choose (for
   example the disk serial number or the Wi-Fi network) before it unlocks anything.

Someone who copies your hard drive gets the hidden files but not the token's secret,
so they can't open them. That person might be a forensic investigator working from a
disk image.

<!-- SCREENSHOT: main window. Save as md/images/main-window.png, then uncomment:
![EnvStego main window](md/images/main-window.png)
-->

---

## Contents

- [What you need](#what-you-need)
- [Quick start](#quick-start)
- [Your first time using EnvStego](#your-first-time-using-envstego)
- [Features](#features)
- [Before you rely on it](#before-you-rely-on-it)
- [FAQ and troubleshooting](#faq-and-troubleshooting)
- [How it works](#how-it-works)
- [Hardware](#hardware)
- [For developers](#for-developers)
- [Team](#team)

---

## What you need

- A **Windows 10 or 11** PC with **Bluetooth LE**
- A **token**: either an **ESP32-CAM** with its USB programmer board, or an
  **ESP32-S3-N16R8** dev board. See [Hardware](#hardware) for the parts list.
- A **USB data cable** that fits the board. Some cables only carry power.
- **Python 3.12**, only to build the app. The finished app doesn't need Python.

---

## Quick start

### 1. Build the app

From the repository root, run:

```bat
build.bat
```

This creates `dist\EnvStego-portable.zip`. The first build downloads about 1 GB of
ESP32 tools; after that a build takes a few minutes.

### 2. Unzip and run

1. Unzip `EnvStego-portable.zip` somewhere you can write to, such as your Desktop,
   Documents or a USB stick. **Don't use `C:\Program Files`**: the app saves its
   settings next to `EnvStego.exe`.
2. Double-click **`EnvStego.exe`**. If Windows SmartScreen warns you, click
   **More info → Run anyway**.

Keep the unzipped folder together. `EnvStego.exe` needs the `_internal` and
`firmware` folders beside it.

### 3. Set up your token

1. Plug the token into a **rear (motherboard) USB port** or a powered hub.
2. In the app, open **Setup › Token** and pick the token's port.
3. Click **Install / update firmware**. A token that already has keys keeps them.
4. Click **Pair Token**. When the token's light **stays on**, press its **IO0** button
   (labelled **BOOT** on the ESP32-S3, *not* RST) within 60 seconds.

You're ready. The next section walks through using the app for the first time.

> Want the full detail? **[md/SETUP.md](md/SETUP.md)** has the complete install,
> firmware and usage guide.

---

## Your first time using EnvStego

The sidebar is ordered the way you'll use it: **Setup → Protect → Diagnostics**. A status
next to each page tells you what's ready.

### Step 1: Pair the token (Setup › Token)

Follow [Quick start step 3](#3-set-up-your-token), then click **Test connection**. Once
it passes, the token talks to the PC over Bluetooth and the USB cable is only needed for
power.

<!-- SCREENSHOT: Setup › Token page. Save as md/images/token.png, then uncomment:
![Setup › Token page](md/images/token.png)
-->

### Step 2: Choose which computer details to check (Setup › Signals)

These details are called **signals**: things like the CPU and disk serial numbers, the
Windows machine ID or the Wi-Fi network you're on. Your files only open again when the
same signals have the same values.

1. The **Recommended** preset is already selected on first run. It's a good default.
2. Click **Test Key** twice. If both results match (`✓ stable`), you're set.

Each signal is labelled **Stable** (green), **May change** (amber) or **Volatile**
(red). Avoid volatile signals: if their value changes, your files won't open.

**Moving around with a laptop?** Turn on **Portable mode**. Your files are then tied to
the laptop and token but not to a location, so you can hide a file at home and open it
in a café.

<!-- SCREENSHOT: Setup › Signals page. Save as md/images/signals.png, then uncomment:
![Setup › Signals page](md/images/signals.png)
-->

### Step 3: Hide a file inside a picture or audio clip (Protect › Encrypt)

1. Choose the **file to hide** (any type, such as a PDF or Word document), or click
   **Folder…** to hide a whole folder.
2. Choose a **carrier**: the picture or audio file it will hide inside.
3. Click **Encrypt & Embed**. If the button is greyed out, the hint below it tells you
   what's missing.
4. Optionally click **Shred original** to securely delete the file you just hid.

The output looks like a normal picture or audio file. For a large file, tick **Split
across several carriers** and add several pictures or audio files.

<!-- SCREENSHOT: Protect › Encrypt page. Save as md/images/encrypt.png, then uncomment:
![Protect › Encrypt page](md/images/encrypt.png)
-->

### Step 4: Get the file back (Protect › Decrypt)

1. Choose the stego file, which the app usually fills in for you. For a split file, add
   **every** piece.
2. Click **Decrypt & Extract**. The file is restored next to the stego file under its original name.

Decrypt only works with the **same token** and the **same signals** you used to hide it.
The recovered file is saved to disk; click **Show recovered file** to open its folder.

### Step 5: Store files in a vault (Protect › Vault)

A vault is an encrypted folder for files you want to keep together.

1. Pick an empty folder and click **Create Env Vault**, then tap IO0 when the light
   stays on.
2. **Write down the 52-character recovery code and keep it offline.** It's the only
   way back in if you lose the token.
3. **Add files** (or drag them onto the list). You'll be asked whether to keep or delete
   the originals.
4. To get a file out, select it, click **Export** and tap IO0.
5. Press **Ctrl+Shift+L** to lock the vault. It also locks itself after 5 minutes of
   inactivity, when the token goes out of range, and when you lock Windows (**Win+L**),
   put the PC to sleep or sign out.

There's no preview inside the app. Export a file to open it.

<!-- SCREENSHOT: Protect › Vault page. Save as md/images/vault.png, then uncomment:
![Protect › Vault page](md/images/vault.png)
-->

---

## Features

- **Hardware token**: an ESP32 board holds the secret key, and you approve sensitive
  actions by pressing its button.
- **Computer-bound files**: choose from 22 hardware, network and OS signals, use the
  one-click **Recommended** preset, or switch to **Portable** mode.
- **Hide files in media**: hide any file, or a whole folder, inside JPEG, PNG, WebP,
  BMP, TIFF and GIF images, or WAV, MP3, FLAC, Ogg, Opus and AIFF audio. Large files can
  be split across several carriers.
- **Encrypted vault**: store any file type, with a recovery code in case the token is
  lost.
- **Leave fewer traces**: secure delete, optional free-space wipe, and a **Privacy mode**
  that doesn't remember file paths. Settings are kept out of the Windows registry.

<details>
<summary><b>Technical feature details</b></summary>

- **Hardware token (ESP32)**: USB ECDH pairing, authenticated BLE key requests, replay
  protection and lockout. Credentials sealed with Windows DPAPI.
- **Environment signals**: 22 hardware/network/OS signals, each rated for stability, with
  a one-click **Recommended** selection and **Portable / Place-bound** modes.
- **Steganography**: hide any file, including DOCX or PDF, inside an image or audio
  carrier. Inputs include JPEG, PNG, WebP, BMP, TIFF, GIF, WAV, MP3, FLAC, Ogg, Opus,
  and AIFF. JPEG carriers stay JPEG; PNG, WebP, BMP and TIFF keep their format
  using the corresponding JPEG or lossless pixel method. GIF saves as PNG and audio
  saves as WAV. Large payloads can split across all usable selected carriers, with a
  token-encrypted tag for each piece. Decrypt receives the complete output set
  automatically. WebP outputs are lossless and may grow from lossy inputs. Native JPEG
  support is implemented inside `stego_engine.py`; native MP3 embedding is not
  implemented. Recovered files are written to disk only; the app never displays their
  contents. See [format behavior and validation](md/STEGO_FORMATS.md).
- **Env Vault**: arbitrary file types, including DOCX and PDF; encrypted metadata,
  one token request per import selection, locally derived per-file keys, and offline
  recovery. The environment is part of the vault's keys and is never stored, so the vault
  only opens with matching signals. **No in-app preview.** The list locks on
  **Ctrl+Shift+L**, on Win+L, sleep or sign-out, when the token stops answering, or after
  5 minutes without vault activity, and locking cancels active file workers. Each import asks whether to keep or delete the originals (keep by default);
  each deletion outcome is reported.
- **Anti-forensic hygiene**: secure delete (overwrite + timestomp + rename + unlink),
  optional free-space wipe, Privacy mode, and settings kept out of the Windows registry.

</details>

---

## Before you rely on it

> [!WARNING]
> **A factory reset destroys the token's secret.** Holding IO0 for 2 seconds while the
> token boots wipes it. Hidden files then **can't be recovered**, and vaults can only be
> opened with their recovery code.

- **Keep your vault recovery code safe and offline.** Anyone who has it can open the
  vault without the token.
- **Don't edit, resize or convert stego files.** Resaving a picture in a photo editor or
  sending it through an app that recompresses images can destroy the hidden data.
- **Use the same signals to decrypt.** If a selected signal changes, such as a new Wi-Fi
  network when Portable mode is off, the file won't open on that setup.
- **Back up `token_config.json`** (next to `EnvStego.exe`) if you move the app to a new
  folder. Without it this PC can't talk to the token, and re-pairing requires a factory
  reset.
- **Shredding isn't guaranteed on SSDs and USB flash drives.** Overwriting can't promise
  the data is gone on these drives.

---

## FAQ and troubleshooting

<details>
<summary><b>Windows says the app is unrecognised</b></summary>

SmartScreen warns about unsigned apps. Click **More info → Run anyway**.

</details>

<details>
<summary><b>The token keeps blinking and restarting</b></summary>

The USB port can't supply enough power when Bluetooth starts. Use a **rear (motherboard)
USB port**, a shorter cable, or a powered USB hub.

</details>

<details>
<summary><b>The token stops responding, or pairing says it didn't answer</b></summary>

Press **RST** on the token once and wait for the ready flash. A token that crashed while
starting can stay frozen until it's reset. If you moved the cable, the port may have
changed: click **↻** and pick the new port.

</details>

<details>
<summary><b>Firmware install says the token didn't enter download mode</b></summary>

Hold **BOOT / IO0**, tap **RST / EN**, release BOOT, then click **Install / update
firmware** again.

</details>

<details>
<summary><b>"Pairing was not confirmed on the token in time" or "Token refused pairing (BUSY)"</b></summary>

You have 60 seconds to press IO0 while the light is solid. If an earlier attempt is still
waiting, wait a minute or press RST, then try again.

</details>

<details>
<summary><b>"This token is already paired"</b></summary>

This PC no longer has the pairing credential, for example after **Forget pairing** or
moving to a new folder without `token_config.json`. Restore the original
`token_config.json`, or factory reset the token. A factory reset destroys its secret
and everything protected by it.

</details>

<details>
<summary><b>Decrypt fails even though I'm using my token</b></summary>

The signals don't match the ones used to hide the file. Check that:

- you selected the **same preset or signals** you used to hide it;
- none of those signals changed, such as a different Wi-Fi network or a replaced disk;
- **Test Key** gives a stable result.

**Diagnostics › Inspector** shows each signal's current value.

</details>

<details>
<summary><b>My file is too big for the picture</b></summary>

JPEGs hold far less than other formats. Use a **PNG, BMP, TIFF or WAV** carrier instead
(a 1920×1080 PNG holds about 759 KB), or tick **Split across several carriers**.

</details>

<details>
<summary><b>The stego file got much bigger than the original</b></summary>

Some formats can't be saved in their original form. Lossy WebP is saved losslessly and
MP3/Ogg/FLAC are saved as WAV, which can make them several times larger. An examiner may
notice that, so prefer JPEG, PNG or BMP carriers. See [md/SETUP.md](md/SETUP.md#output-size-and-concealment).

</details>

<details>
<summary><b>I lost my token, or it was factory reset</b></summary>

- **Vaults**: click **Unlock with recovery code** and enter your saved code.
- **Files hidden in pictures or audio**: these can't be recovered without the original
  token secret.

</details>

<details>
<summary><b>The vault locked itself</b></summary>

That's intended. It locks after 5 minutes without activity or when the token stops
answering. Click **Browse files** and tap IO0 to reopen it.

</details>

<details>
<summary><b>What do the token's light patterns mean?</b></summary>

Short flashes are good news; long ones are problems. A solid light means it's waiting
for you to press IO0. See the full [LED table](md/SETUP.md#token-led-signals).

</details>

<details>
<summary><b><code>build.bat</code> fails</b></summary>

It needs Python 3.12 available as `py -3.12`. The first run downloads about 1 GB of
PlatformIO toolchains, so it needs an internet connection and some time.

</details>

---

## How it works

Normal decryption needs the **token's secret** and the **selected signals**. The token
combines the two to make a key, and the app uses that key to encrypt or decrypt. The
secret is created on the token by its own random number generator and never leaves it,
so it never touches the PC's disk.

Vaults also have an **offline recovery code** that bypasses the token and signals.

<details>
<summary><b>Threat model</b></summary>

The *resettable adversary* is an investigator who images the drive and studies unlimited
offline copies at leisure. Anything reconstructable from the copied disk is eventually
recoverable, so 3T keeps the high-entropy secret off the disk entirely rather than trying
to hide it.

A PC disk image alone lacks the token secret. Many environment signals can be
reconstructed from disk; they are not a second high-entropy secret. See
[the vault security design](md/VAULT_SECURITY.md) for the memory-exposure boundary and
recovery limitations.

</details>

<details>
<summary><b>Key derivation</b></summary>

1. **The ESP32 token** holds a 256-bit master secret generated on-device by its hardware
   RNG. It never leaves the token. First pairing is over USB (ECDH-encrypted); afterwards
   the PC and token talk over an authenticated, encrypted BLE channel.
2. **The environment**: a user-chosen set of machine signals (CPU/disk/motherboard
   serials, machine GUID, Wi-Fi BSSID, …). The token combines these with its secret.

```
env_hash  = SHA-256(selected signal ids + values)
env_key   = HMAC-SHA256(master_secret, "3T-ENV-v1" | env_hash)
stego_key = HKDF-SHA256(env_key, random per-file salt)
```

Stego encryption uses the environment key on the PC. The vault handles keys differently
(see below).

</details>

<details>
<summary><b>Vault key handling and memory exposure</b></summary>

| Vault action | IO0 | Key handling |
| --- | --- | --- |
| Open the file list | One tap | The app holds the metadata key until the list locks. |
| Add one or more files | No additional tap | After checking the environment, the worker requests one batch secret, disconnects Bluetooth, and derives a separate AES-256-GCM key for each file locally. It releases the secret when the import ends. |
| Export selected files | One tap for the selection | The worker keeps the export connection open and requests each selected file's key as it decrypts that file. |

A memory capture during import can expose the whole selection through its batch
secret. An ordinary export exposes the current file's key. The offline recovery
code can recover the entire vault. See [vault security and recovery](md/VAULT_SECURITY.md).

</details>

<details>
<summary><b>Hardware security status</b></summary>

Flash/NVS encryption and Secure Boot are not enabled, so token theft remains a separate
hardware risk. See [the hardware security status](md/FLASH_ENCRYPTION.md).

</details>

---

## Hardware

The token is a single **ESP32-CAM** module or an **ESP32-S3-N16R8** dev board. It needs
no custom circuit board, soldering or extra parts. The app installs the firmware for you.

**Parts list** (choose option A *or* option B)

| Item | Qty | Purpose |
| --- | --- | --- |
| **A:** ESP32-CAM module (ESP32-D0WD, 4 MB flash) | 1 | The token: holds the master secret, BLE radio, IO0 confirmation button, white LED for status |
| **A:** ESP32-CAM-MB USB programmer board (CH340) | 1 | USB power, flashing and first-time USB pairing; the module plugs straight onto it |
| **B:** ESP32-S3-N16R8 dev board (16 MB flash, 8 MB PSRAM) | 1 | The token on one board: USB built in (either USB-C port works), BOOT button as IO0, RGB LED on GPIO48 for coloured status |
| USB data cable (Micro-USB or USB-C, to match the board) | 1 | Connects the token to the PC |
| Windows 10/11 PC with Bluetooth LE | 1 | Runs the EnvStego desktop app |

The ESP32-CAM's camera isn't used. Power the board from a rear (motherboard) USB port or
a powered hub, because Bluetooth start-up draws a current spike that weak ports can't
supply.

**Firmware updates** write only the firmware, so the token keeps its keys and pairing.
Vaults need firmware v8 or later; the current firmware is v9.

---

## For developers

<details>
<summary><b>Run from source</b></summary>

Needs Python 3.12.

```bash
cd Python
pip install -r requirements.txt
python main.py
```

The in-app firmware installer looks in `Python/firmware/`, which `build.bat` creates.
See [md/SETUP.md](md/SETUP.md#building-the-portable-zip) for build details and flashing
with PlatformIO directly.

</details>

<details>
<summary><b>Run the tests</b></summary>

```bash
python -m pytest Python/tests/ -q
```

All 271 tests pass (2026-11-24). The suite covers stego round trips for every supported
carrier, host BLE protocol behavior, vault key separation, recovery, write failures,
concurrency, batch approvals, subprocess cancellation and Qt UI flows. Host protocol
simulation does not validate the physical IO0 circuit or BLE runtime. See
[validation results](md/VAULT_SECURITY.md#validation).

</details>

<details>
<summary><b>Repository layout</b></summary>

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

</details>

<details>
<summary><b>Further documentation</b></summary>

- [md/SETUP.md](md/SETUP.md): full setup, firmware and usage guide
- [md/VAULT_SECURITY.md](md/VAULT_SECURITY.md): vault design, recovery and validation
- [md/STEGO_FORMATS.md](md/STEGO_FORMATS.md): per-format behaviour and limits
- [md/FLASH_ENCRYPTION.md](md/FLASH_ENCRYPTION.md): token hardware security status

</details>

---

## Team

Sabrina Lim · Piers Soh · Muhammad Khair Aydil · Naveen Gopalkrishnan · Koh He Kai

Infocomm Technology Cluster, Singapore Institute of Technology
