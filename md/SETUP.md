# EnvStego — Setup & Usage Guide
**ICT3215 Digital Forensics — SIT**

---

## Requirements
- Windows 10 or 11 (signals rely on Windows APIs)
- Python 3.10, 3.11, or 3.12
- VS Code (optional but recommended)

---

## Step 1 — Install Python

Download from https://python.org/downloads  
During install: **check "Add Python to PATH"**

Verify in a terminal:
```
python --version
```

---

## Step 2 — Open the Project in VS Code

1. Open VS Code
2. **File → Open Folder** → select the `envstego` folder
3. VS Code will detect the `.vscode/launch.json` automatically

---

## Step 3 — Install Dependencies

Open the VS Code terminal (`Ctrl + `` ` ``) and run:

```
pip install -r requirements.txt
```

Run this from `Python/`. This installs PyQt6, cryptography, Pillow, numpy,
SoundFile, jpeglib, pyserial, Bleak and pytest. Native JPEG support uses the pinned
`jpeglib==1.0.2` dependency; it is already installed in this project's `.venv`.

---

## Step 4 — Run the App

**Option A — VS Code (with debugger):**
Press `F5` or go to **Run → Start Debugging**
Select **"Run EnvStego"** from the dropdown

**Option B — Terminal:**
```
python main.py
```

---

## Step 5 — Build a Standalone .exe (Windows only)

Use the Python launcher above for the validated source build. This checkout has
no `build.bat`; a standalone executable was not built during the vault v2 change.
A future frozen build must include `vault_worker`, jpeglib's native libraries
(including libjpeg 9f), and support the `--vault-worker` and `--jpeg-worker`
entry points, including redirected standard handles in windowed mode.

---

## Step 6 — Flash the 3T Token Firmware

Open `ESP32 Files/` as the PlatformIO project. Its configuration sets `src_dir = .`,
so PlatformIO builds the firmware sources directly from that folder. To compile
from the repository root, run `pio run --project-dir "ESP32 Files"`. To install a
build, use PlatformIO's Upload action. Close the serial monitor before USB pairing
so the app can open the COM port.

> Vault v2 requires **firmware v8**; USB pairing still uses the v5 protocol.
> Update a paired older token without erasing NVS
> and keep `Python/token_config.json`. The saved credential still works over Bluetooth.
> Stego images made with the old hardcoded-secret build require that older build.

### Token LED signals
The count tells you what happened; short flashes are good news, long ones are problems.

| Pattern | Meaning |
|---------|---------|
| Short blink every 0.5 s for 3 s | Booting. Hold IO0 for 2 s now to factory reset (a quick tap is ignored) |
| Solid on | Pairing, opening the vault list or exporting a selection — release, then press IO0 within 60 s |
| 10 rapid flashes | Factory reset done, all secrets wiped |
| 1 short | Ready, paired |
| 2 short | Ready, waiting for USB pairing |
| 3 short | Pairing succeeded |
| 2 very fast | The token served a generic environment or index key request. Use the import result in the app to see which files finished. |
| 1 long | Rejected a bad request |
| 2 long | Pairing confirmation timed out |
| 3 long | The Bluetooth connection was closed after 5 authentication failures on that link |

If the boot blink keeps repeating, the token is resetting itself, usually because the
USB port can't supply enough power when Bluetooth starts. Try a rear USB port or a powered hub.

---

## How to Use the App

The sidebar groups the pages by workflow (Setup → Protect → Diagnostics) and shows each
page's status at a glance: token paired, signals selected, Encrypt/Decrypt ready.
Your signal selection, presets, file paths and active page are remembered across
refreshes and restarts.

### Setup › Token (do this first)
1. Plug the token in over USB, pick its **serial port** (CH340/CP210x ports are listed first)
2. Click **Pair Token**. When the token's light **stays on**, press its **IO0** button (not RST)
   within 60 seconds to confirm. Nothing can pair the token without this press. The token
   generates its master secret with its hardware RNG and gives this PC an auth key over an
   encrypted (ECDH) exchange; the PC stores it encrypted with Windows DPAPI
3. Click **Test connection** to run the authenticated BLE handshake. The USB cable is no longer needed
- **Re-pair Token** requires the saved credential and an IO0 confirmation. It keeps the token's keys and works after a PC rename.
- **Forget pairing** deletes this PC's credential. Keep a backup of the pairing config under the original Windows account if you need to re-pair. Losing the only copy prevents re-pairing without a factory reset.
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
   or complete split set is filled in for you. Old PNG/WAV outputs remain readable
2. For a payload split across several carriers, tick **This file was split across several
   carriers** and add the whole set. The app regroups and reorders them with the token. If a
   carrier is missing it tells you which pieces are absent
3. Optionally choose a folder. By default the payload is restored next to the stego carrier,
   **under its original filename**, and existing files are never overwritten
4. The same signals (use the same preset) and the same token are required, otherwise
   authentication fails (forensic defense)

If an older build produced only **one** file while split mode was selected, choose
that file on Decrypt. The updated app can recover a complete one-piece split set
in single mode, or with that one file added in split mode. This does not bypass a
missing piece: a real multi-piece set still requires every generated stego file.
Future split encryptions produce one file per usable selected carrier. This fix
is in the desktop Python app; restart the app to load it.

### Output size and concealment

The native JPEG method modifies selected compressed-image coefficients, avoiding
the earlier JPEG-to-PNG expansion. Other image outputs preserve pixel low bits
through lossless encoding; PNG uses optimized compression and WebP preserves
transparent RGB values exactly. Keeping a format or shrinking its file does not
establish that embedded data is statistically undetectable. Progressive JPEG
inputs are currently written as baseline JPEG, and indexed/other pixel modes
may be converted to RGB/RGBA. See [STEGO_FORMATS.md](STEGO_FORMATS.md) for limits.

In a 4 KiB native JPEG test on 2026-11-18, `_DSC0003.jpg` changed from 6,621,504 to
6,621,532 bytes; `car.jpg` changed from 224,273 to 224,276 bytes. Both test payloads
recovered exactly and the original carriers were unchanged. Test copies are kept
under ignored `build/`; they are not replacements for your encrypted files.
Restart the app and encrypt again to generate native-format outputs. Existing
PNG outputs continue to decrypt as before; renaming them to JPEG does not convert them.

### Protect › Vault

An encrypted store for any file type, including DOCX, PDF, spreadsheets, archives,
images and audio. No format-specific parser is needed for storing or exporting files.

1. Update the token to **v8** while preserving NVS and the saved pairing. Choose readable
   signals and an empty folder, then select **Create Env Vault**. When the token light
   stays on, tap IO0 once to open the new list. Save the 52-character recovery code offline.
2. **Browse files** checks the environment and asks for one IO0 tap each time you open
   a locked list. The open session holds the metadata key and displays filenames, sizes and dates.
3. **Add files** checks the current environment and requests one temporary batch secret
   for the selection. Bluetooth disconnects before file encryption starts. The worker
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
   The app also locks after failed token heartbeat checks while idle.
6. **Unlock with recovery code** opens the list with the offline code. Re-enter it for
   each single-file recovery export. This route works without an IO0 press.

See [vault security and recovery](VAULT_SECURITY.md) for key handling and format compatibility.

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
| Vault v2 keys | Separate metadata/file HMAC domains on the token. File context binds vault ID, environment hash and random file ID. The worker imports with fresh keys and requests selected export keys after one IO0 tap |
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
  ~1 byte per 8 samples (~10.6 KB per second at 44.1 kHz). For bigger files, split across
  several carriers

---

## File Structure
```
envstego/
├── main.py            ← Entry point (run this)
├── signals.py         ← Environment signal collection (22 signals)
├── crypto_engine.py   ← HKDF key derivation + AES-256-GCM + v3 header/shard crypto
├── stego_engine.py    ← Native JPEG coefficients + lossless pixel image steganography
├── audio_engine.py    ← LSB steganography for WAV audio
├── media.py           ← Image and audio carrier dispatcher
├── multi_image.py     ← Split one payload across several carriers (+ rejoin)
├── ui_main.py         ← Full PyQt6 user interface
├── vault_v2.py        ← Metadata sessions, per-file encryption and recovery
├── vault_worker.py    ← Short-lived import/export process
├── vault.py           ← Shared storage helpers and legacy format-1 code
├── requirements.txt   ← pip dependencies
├── build.bat          ← Build EnvStego.exe
└── .vscode/
    └── launch.json    ← VS Code run config
```
