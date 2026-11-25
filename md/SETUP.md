# EnvStego — Setup & Usage Guide
**ICT3215 Digital Forensics — SIT**

---

## Requirements
- Windows 10 or 11 (signals rely on Windows APIs)
- A token: an **ESP32-CAM** (with its USB programmer board) or an **ESP32-S3-N16R8**
  dev board, and a USB data cable

---

## Quick install (portable zip)

1. Unzip `EnvStego-portable.zip` somewhere you can write to, such as Desktop,
   Documents or a USB stick. **Not** `C:\Program Files`: the app keeps its settings
   and token pairing next to `EnvStego.exe`, and nothing in the Windows registry.
2. Double-click `EnvStego.exe`. Python is not needed. If SmartScreen says the app is
   unrecognised, click **More info → Run anyway**.
3. Open **Setup › Token**, plug the token in and pick its port.
4. Click **Install / update firmware** (see below), then **Pair Token**.

Keep the folder together: `EnvStego.exe` needs `_internal\` and `firmware\` beside it.

---

## Token firmware (one click)

The app ships with firmware for both boards. **Setup › Token › Install / update firmware**:

1. Identifies the chip on the selected port (ESP32 → ESP32-CAM build, ESP32-S3 → S3 build).
2. Reads the board's partition table. This step only reads from the board.
3. Then, depending on what it finds:
   - **Existing token** — writes only the firmware app area. The token's master
     secret and pairing (in NVS) are **not touched**, so stego files, vaults and
     this PC's pairing keep working.
   - **Blank board** — writes the full firmware. Pair it afterwards.
   - **Anything else** (a different partition layout) — refuses rather than risk
     the data on it.

**Erase and start fresh…** wipes the whole chip, master secret included, then installs.
It asks you to type `ERASE`. Use it only for a new board or one whose files you no
longer need.

If flashing reports that the token did not enter download mode, hold **BOOT / IO0**,
tap **RST / EN**, release BOOT and click again.

### ESP32-S3-N16R8 notes
- Either USB-C port works for pairing and flashing: **COM** (CH343 bridge) or
  **USB** (native). The firmware answers on both.
- The IO0 button is the one labelled **BOOT**.
- Status uses the onboard RGB LED on GPIO48, with the same blink patterns as the
  ESP32-CAM, coloured (see below).

> Firmware **v9** adds ESP32-S3 support and a read-only `INFO` serial command that
> the updater uses to show the running version. The BLE protocol and key derivation
> are unchanged from v8, so updating keeps existing pairings, stego files and vaults.
> The vault requires firmware v8 or later; USB pairing requires v5 or later.

---

## Running from source (developers)

Needs Python 3.12.

```
cd Python
pip install -r requirements.txt
python main.py
```

The in-app flasher looks for firmware in `Python/firmware/`, which `build.bat` creates.

## Building the portable zip

From the repository root:

```
build.bat
```

This creates `.venv` (Python 3.12), installs the app and build requirements
(`packaging/requirements-build.txt`: PyInstaller and PlatformIO), builds both firmware
environments, and writes `dist\EnvStego-portable.zip`. The first run downloads
PlatformIO's ESP32 toolchains (about 1 GB); after that a build takes a few minutes.
Every run is a full build, so the zip's firmware always matches the source.

Only the zip is left in `dist\`: the unzipped app folder and PyInstaller's work files
(`build\pyinstaller\`) are deleted after zipping. Unzip it somewhere else to test. If a
folder can't be deleted (for example a copy of `EnvStego.exe` from it is still
running), the build prints a warning and still succeeds; delete the folder yourself.

The frozen exe also serves as its own child processes: `--vault-worker`,
`--jpeg-worker` and `--esptool`.

### Flashing with PlatformIO directly (developers)

`ESP32 Files/` is a PlatformIO project with two environments, `esp32cam` and
`esp32s3` (`src_dir = .`). `pio run --project-dir "ESP32 Files" -e esp32s3 -t upload`
builds and flashes one. PlatformIO's upload writes the bootloader and partition table
but not NVS, so pairing survives. Never use **Erase Flash** on a token holding real
keys. Close the serial monitor before USB pairing so the app can open the COM port.

### Token LED signals
The count tells you what happened; short flashes are good news, long ones are problems.

The ESP32-CAM's LED is white. On the ESP32-S3 the same patterns are coloured.

| Pattern | S3 colour | Meaning |
|---------|-----------|---------|
| Short blink every 0.5 s for 3 s | White | Booting. Hold IO0 for 2 s now to factory reset (a quick tap is ignored) |
| Solid on | Blue | Pairing, opening the vault list or exporting a selection — release, then press IO0 within 60 s |
| 10 rapid flashes | Red | Factory reset done, all secrets wiped |
| 1 short | Green | Ready, paired |
| 2 short | Blue | Ready, waiting for USB pairing |
| 3 short | Green | Pairing succeeded |
| 2 short, straight after an IO0 tap | Green | Vault action approved (opening the list or exporting the selection) |
| 2 very fast | Green | The token served an environment or index key request (Encrypt, Decrypt, Test Key, vault signal check) |
| 1 long | Red | Rejected a bad request |
| 2 long | Red | Pairing confirmation timed out |
| 3 long | Red | The Bluetooth connection was closed after 5 authentication failures on that link |

### Token troubleshooting

- **The boot blink keeps repeating:** the token is resetting itself, usually because the
  USB port cannot supply enough current when Bluetooth starts. Try a rear (motherboard)
  USB port, a short cable or a powered hub.
- **The token stops responding** (no Test connection, pairing says the token did not answer,
  or claims the firmware is older than v5): press **RST** once and wait for the ready
  flashes. A token that crashed during start-up can stay frozen until it is reset. Open a
  serial monitor at 115200 baud to confirm it reaches `BLE Server is running`, then close
  the monitor before pairing.
- **The port changed after moving the cable:** click **↻** and select the new COM port.

| Pairing message | Cause | Fix |
|---|---|---|
| "This token is already paired. Re-pairing requires the saved credential…" | This PC has no credential for an already-paired token (for example after **Forget pairing**) | Restore the original pairing config, or factory reset the token (destroys its secret) |
| "Token refused pairing (BUSY)" | An earlier pairing attempt is still waiting for IO0 (up to 60 s) | Wait a minute or press RST, then retry |
| "Pairing was not confirmed on the token in time" | IO0 was not pressed within 60 s | Retry and press IO0 while the light is solid |

---

## How to Use the App

The sidebar groups the pages by workflow (Setup → Protect → Diagnostics) and shows each
page's status at a glance: token paired, signals selected, Encrypt/Decrypt ready.
Your signal selection, presets, file paths and active page are remembered across
refreshes and restarts.

### Setup › Token (do this first)
1. Plug the token in over USB, pick its **serial port** (ESP32 USB ports — CH340, CP210x, CH343 and the S3's native USB — are listed first)
2. Click **Pair Token**. When the token's light **stays on**, press its **IO0** button (**BOOT** on the ESP32-S3; not RST)
   within 60 seconds to confirm. Nothing can pair the token without this press. The token
   generates its master secret with its hardware RNG and gives this PC an auth key over an
   encrypted (ECDH) exchange; the PC stores it encrypted with Windows DPAPI
3. Click **Test connection** to run the authenticated BLE handshake. The USB cable is no longer needed
- **Re-pair Token** requires the saved credential and an IO0 confirmation. It keeps the token's keys and works after a PC rename.
- **Forget pairing** deletes this PC's credential only; the token stays paired. Keep a backup of the pairing config under the original Windows account if you need to re-pair. Losing the only copy prevents re-pairing without a factory reset.
- **Factory reset** (hold IO0 for 2 seconds while it boots) destroys the master secret.
  Stego files become unrecoverable; vaults need their offline recovery codes
- Firmware **v5 or later** is required for USB pairing.

### Setup › Signals
- The app scans your machine on launch. **Refresh** re-scans and keeps your selection
- Pick a **preset** or tick signals yourself. On first run the **Recommended** preset (a
  strong, steady default) is selected automatically; others are Device-bound,
  Location-bound, Hardware only, and Everything. Clicking anywhere on a row toggles it,
  and hovering shows the current value
- Each signal shows a plain stability label instead of a number: **Stable** (green, a
  permanent identifier), **May change** (amber), or **Volatile** (red — changes in
  everyday use). Categories are collapsible and sorted steadiest-first
- **Save as preset…** stores your own combinations. **Clear selection** unticks everything
- Click **Test Key** twice. A matching fingerprint (`✓ stable`) means the environment is stable

### Privacy mode (sidebar, on by default)
Leaves a forensic examiner less to find. While it is on:
- file paths are **not** remembered between sessions (otherwise the registry would record
  exactly which image hides a payload and the original file's name)
- the stego image **copies the carrier's date**, so it blends into a photo library instead
  of showing a fresh timestamp
- outputs default to your **Pictures** (stego image) and **Downloads** (recovered file) folders

Turn it off if you prefer the app to remember your recent files and save next to the carrier.

### Portable mode (Signals page)
For when you move around a lot. With it on, only signals that **travel with this PC**
(hardware and OS) can be selected; **network/location** signals are disabled and shown
as *Off · portable*. The file is then bound to this laptop and the token, not to a place,
so you can encrypt at home and decrypt in a café on the same machine.

It is less location-specific (anyone with this exact laptop + the token could open the
file), so leave it **off** if you want a file that only opens in one place — use the
*Location-bound* preset instead.

### Protect › Encrypt
1. Choose the **file** to hide, such as a DOCX or PDF, or click **Folder…** to hide a whole
   folder. Then pick a **carrier**. Supported image inputs are PNG, JPEG, WebP, BMP,
   TIFF, and GIF with one frame or page. Supported audio inputs are WAV, MP3, FLAC,
   Ogg Vorbis, Ogg Opus, and AIFF.
2. The suggested output is `<carrier>_stego` with the carrier's supported output
   extension. **JPEG stays JPEG** using native coefficient embedding. PNG, BMP and
   single-page TIFF keep their format; WebP stays WebP using **lossless** compression.
   GIF saves as PNG. Audio inputs save as PCM WAV; compressed audio is decoded to
   16-bit PCM at its original sample rate/channel count. Lossy WebP can grow when
   saved losslessly, and compressed audio can grow as WAV. JPEG's displayed capacity
   now counts usable coefficients; it can be much smaller than the old pixel estimate.
3. **Split across several carriers** (checkbox): add several image or audio carriers
   by browsing or dragging them onto the list. Split mode spreads the encrypted data
   across **every usable selected carrier**, even if it would fit inside the first.
   Three usable carriers produce three output files; all three are needed for recovery.
   Each piece carries a token-encrypted tag identifying its set and position.
   Pick an output folder. Each output uses its carrier's supported image format or WAV.
   Carriers too small for a shard tag and one data byte are skipped; at least two
   usable carriers are required. After encryption, Decrypt automatically switches
   to split mode and selects the complete generated set, replacing the previous selection
4. **Encrypt & Embed** stays disabled until everything is ready. The hint below it says what is missing
5. After it succeeds, **Shred original** overwrites and deletes the source file so the plaintext
   does not linger. The encrypted copy is kept. (On SSDs and USB flash, overwriting cannot
   guarantee the data is unrecoverable — the surest protection is to keep originals only on media
   you fully control.)

### Protect › Decrypt
1. Choose the **stego carrier** (JPEG, PNG, WebP, BMP, TIFF or WAV). The last output
   or complete split set is filled in for you. Images made by builds older than the
   current (v3) format are no longer supported
2. For a payload split across several carriers, tick **This file was split across several
   carriers** and add the whole set. The app regroups and reorders them with the token. If a
   carrier is missing it tells you which pieces are absent
3. Optionally choose a folder. By default the payload is restored next to the stego carrier,
   **under its original filename**, and existing files are never overwritten
4. The same signals (use the same preset) and the same token are required, otherwise
   authentication fails (forensic defense)
5. The recovered file is written to disk only. The app does not display its contents;
   use **Show recovered file** to open its folder

If an older build produced only **one** file while split mode was selected, choose
that file on Decrypt. A complete one-piece split set is recovered in single mode, or
with that one file added in split mode. This does not bypass a missing piece: a real
multi-piece set still requires every generated stego file.

### Output size and concealment

The native JPEG method modifies selected compressed-image coefficients, avoiding
the earlier JPEG-to-PNG expansion. Other image outputs preserve pixel low bits
through lossless encoding; PNG uses optimized compression and WebP preserves
transparent RGB values exactly. Keeping a format or shrinking its file does not
establish that embedded data is statistically undetectable. Progressive JPEG
inputs are currently written as baseline JPEG, and indexed/other pixel modes
may be converted to RGB/RGBA. See [STEGO_FORMATS.md](STEGO_FORMATS.md) for limits.

Typical size changes, measured on 2026-11-22 with carriers produced by real encoders
(ffmpeg/libwebp/LAME) and a hidden payload of up to 4 KiB:

| Carrier | Output | Size change |
|---|---|---|
| JPEG (colour or greyscale) | JPEG | +4 % to +11 % |
| PNG, BMP, TIFF | same format | 0 % (BMP) to about +25 % (TIFF) |
| Lossy WebP | lossless WebP | about **7× larger** (40 KB → 279 KB) |
| GIF | PNG | about 2× larger |
| MP3, Ogg, Opus, FLAC | WAV | **several times larger** (a 194 KB MP3 → 1.4 MB WAV) |

A large size jump or a format change (MP3 → WAV) is something an examiner can notice.
JPEG capacity is far lower than the same picture as PNG (about 3 KB against 112 KB in
that test), so use PNG, BMP, TIFF or WAV carriers for larger payloads. Existing
PNG outputs continue to decrypt; renaming them to JPEG does not convert them.

### Protect › Vault

An encrypted store for any file type, including DOCX, PDF, spreadsheets, archives,
images and audio. No format-specific parser is needed for storing or exporting files.

1. Update the token to **v8** while preserving NVS and the saved pairing. Choose readable
   signals and an empty folder, then select **Create Env Vault**. When the token light
   stays on, tap IO0 once to open the new list. Save the 52-character recovery code offline.
   If you use **Copy**, the clipboard is cleared after 30 seconds; Windows clipboard history
   (Win+V) keeps its own copy if you have it turned on.
2. **Browse files** collects the vault's signals and asks for one IO0 tap each time you open
   a locked list. The open session holds the metadata key and displays filenames, sizes and dates.
   The environment is part of the vault's keys and is never stored, so in a different
   environment the list does not open: you see "environment does not match" after the tap.
3. **Add files** (or drag files onto the list) asks whether to **Keep** or **Delete** the
   originals; Keep is the default. No IO0 tap is needed. The app checks the current
   environment and requests one temporary batch secret for the selection. Bluetooth
   disconnects before file encryption starts. The worker
   derives a separate AES key for each file, verifies the encrypted copy before any
   optional deletion, and releases the batch secret when the import ends. A transient
   connection failure during acquisition can trigger one retry before any files are
   processed. Check the reported outcome for each original.
4. **Export** writes plaintext copies. Select one or more rows, choose the destination,
   then tap IO0 once within 60 seconds. Keep the token powered and in range while
   the worker requests each selected file's key over that connection. A later export requires another tap. If the
   connection drops, previously completed outputs remain and the remaining selection needs
   fresh approval. Existing output filenames are preserved.
5. **Lock now** or **Ctrl+Shift+L** closes the list and cancels active file workers.
   The app also locks by itself when the token stops answering (checked every 25 s),
   after **5 minutes without vault activity** even with the token in range, and as soon as
   Windows is locked (**Win+L**), goes to sleep or hibernates, or signs out or shuts down.
   Selecting files or running an import or export counts as activity.
   There is no in-app preview: use **Export** to open a file.
6. **Unlock with recovery code** opens the list with the offline code. Re-enter it for
   each single-file recovery export. This route works without an IO0 press.

Vaults created before 2026-11-25 used an older format and are no longer supported; create
new vaults in empty folders. See [vault security and recovery](VAULT_SECURITY.md) for key
handling and format details.

### Diagnostics › Inspector
- Shows raw values of every collected signal and which ones are in the key
- Useful for debugging and for the report evaluation section
- **Hide sensitive values** (checkbox): masks the raw identifiers (disk serial, machine
  GUID, SID, …) as e.g. `WD••••••H3`, so the page is safe to screenshot for a report
  without exposing this machine's real hardware IDs. Untick it to read the values locally

---

## Security Design (3T token)

| Step | What happens |
|------|--------------|
| USB pairing | Token creates `master_secret` (never leaves it), `auth_key` and `token_id` from its hardware RNG. `auth_key` + `token_id` go to the PC (DPAPI-encrypted) |
| BLE request | HELLO → token sends a fresh nonce. PC sends its own nonce + an AES-GCM request keyed by `HMAC(auth_key, nonces)`. The token replies AES-GCM encrypted under the same session key |
| Stego key | Domain-separated environment HMAC on the token; per-file HKDF on the PC |
| Vault keys | Separate metadata/file HMAC domains on the token. The context binds the vault ID and the live environment hash (never stored), and file keys add a random file ID. The worker imports with fresh keys and requests selected export keys after one IO0 tap |
| Vault recovery | X25519 public-key envelopes wrap metadata and individual file keys; only the offline code supplies the private recovery key |
| Defences | Raw signal values never leave the PC. Replays fail (single-use nonces). Impostor tokens/hosts fail the GCM tag. Five authentication failures close only the affected link. |

---

## Important Notes

- Keep the generated stego files for decryption. Recompressing, resizing or converting
  them can destroy the embedded data, including resaving a native JPEG through a photo editor.
- Lossless pixel/WAV methods change at most one low bit per RGB channel/PCM sample.
  JPEG changes eligible AC coefficient magnitudes by at most one; decoded JPEG
  pixels do not have the same one-level bound.
- Minimum carrier size: ~200×200 px image, or a WAV a few seconds long, for small payloads
- **Rule of thumb for capacity:** a 1920×1080 PNG holds ~759 KB; a 16-bit stereo WAV holds
  ~1 byte per 8 samples (~10.6 KB per second at 44.1 kHz). A JPEG holds far less (only
  coefficients of magnitude 2 or more are used). For bigger files, split across several carriers

---

## File Structure
```
ICT3215-Digital-Forensics/
├── build.bat              ← Builds dist\EnvStego-portable.zip
├── packaging/             ← build.py, PyInstaller spec, zip README, build requirements
├── Python/
│   ├── main.py            ← Entry point (run this)
│   ├── signals.py         ← Environment signal collection (22 signals)
│   ├── crypto_engine.py   ← HKDF key derivation + AES-256-GCM + v3 header/shard crypto
│   ├── stego_engine.py    ← Native JPEG coefficients + lossless pixel image steganography
│   ├── audio_engine.py    ← LSB steganography for audio (written as PCM WAV)
│   ├── media.py           ← Image and audio carrier dispatcher
│   ├── multi_image.py     ← Split one payload across several carriers (+ rejoin)
│   ├── archive.py         ← Folder payloads (zip, with zip-slip protection)
│   ├── token_comms.py     ← USB pairing and the encrypted BLE protocol
│   ├── pair_crypto.py     ← X25519 pairing key exchange
│   ├── firmware_flasher.py← One-click token firmware install/update (esptool)
│   ├── vault.py           ← Env Vault: metadata sessions, per-file encryption, recovery
│   ├── vault_worker.py    ← Short-lived import/export process
│   ├── winutils.py        ← Secure delete, atomic writes, DPAPI and Windows helpers
│   ├── ui_main.py         ← PyQt6 user interface
│   ├── requirements.txt   ← pip dependencies
│   ├── firmware/          ← (built by build.bat) firmware bundles for the flasher
│   └── tests/             ← Automated tests (pytest)
├── ESP32 Files/           ← 3T token firmware (PlatformIO: esp32cam + esp32s3, firmware v9)
└── md/                    ← This guide and the design/validation documents
```
