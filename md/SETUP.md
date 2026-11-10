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

This installs: PyQt6, cryptography, Pillow, numpy

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

Double-click `build.bat`  
OR run in terminal:
```
build.bat
```T

The executable will be created at:
```
dist\EnvStego.exe
```

This .exe has no dependencies — copy it anywhere on Windows and run it.

---

## Step 6 — Flash the 3T Token Firmware

The token firmware lives in `ESP32 Files/`. Copy `main.cpp`, `encryption.cpp` and `encryption.h`
into your PlatformIO project's `src/` folder and upload it. **Close the serial monitor afterwards**:
pairing needs the COM port.

> Firmware v2 uses a new BLE protocol. Older pairings and stego images made with the
> hardcoded-secret build will not work. Pair the token again and re-encrypt.

### Token LED signals
The count tells you what happened; short flashes are good news, long ones are problems.

| Pattern | Meaning |
|---------|---------|
| Short blink every 0.5 s for 3 s | Booting. Hold IO0 now to factory reset |
| 10 rapid flashes | Factory reset done, all secrets wiped |
| 1 short | Ready, paired |
| 2 short | Ready, waiting for USB pairing |
| 3 short | Pairing succeeded |
| 2 very fast | Key request served |
| 1 long | Rejected a bad request |
| 2 long | Pairing refused (bound to another PC) |
| 3 long | Locked out for 30 s after 5 bad requests |

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
2. Click **Pair Token**. The token generates its master secret with its hardware RNG and
   gives this PC an auth key, which is stored encrypted with Windows DPAPI
3. Click **Test connection** to run the authenticated BLE handshake. The USB cable is no longer needed
- **Forget pairing** deletes only this PC's credentials. Re-pairing later keeps your files decryptable
- **Factory reset** (hold IO0 while booting) destroys the master secret. Files encrypted with
  that token become permanently unrecoverable

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
1. Choose (or drag in) the **file** to hide — or click **Folder…** to hide a whole folder
   (it is zipped into the carrier and restored as a folder on decrypt). Then pick the
   **carrier**: a **PNG image** or a **WAV audio** file (both are lossless, so the hidden
   bits survive — JPEG/MP3 would destroy them)
2. The output path is suggested automatically (`<carrier>_stego.png` or `.wav`, matching the
   carrier). Change it if you like
3. **Split across several carriers** (checkbox): for a payload too big for one carrier, tick
   this and add several PNGs/WAVs (browse, or **drag them onto the list**). The data is
   spread across them, each piece carrying a
   token-encrypted tag so only your token can tell the set apart or put it back together.
   Pick an output folder; one stego file is written per carrier used
4. **Encrypt & Embed** stays disabled until everything is ready. The hint below it says what is missing
5. After it succeeds, **Shred original** overwrites and deletes the source file so the plaintext
   does not linger. The encrypted copy is kept. (On SSDs and USB flash, overwriting cannot
   guarantee the data is unrecoverable — the surest protection is to keep originals only on media
   you fully control.)

### Protect › Decrypt
1. Choose the **stego carrier** (PNG or WAV). The last one you encrypted is filled in for you
2. For a payload split across several carriers, tick **This file was split across several
   images** and add the whole set — the app regroups and reorders them with the token. If a
   carrier is missing it tells you which pieces are absent
3. Optionally choose a folder. By default the payload is restored next to the stego carrier,
   **under its original filename**, and existing files are never overwritten
4. The same signals (use the same preset) and the same token are required, otherwise
   authentication fails (forensic defense)

### Protect › Vault
An encrypted store bound to the token + this PC, for files you keep and reopen (rather
than hiding a single file in an image).
1. Pick a **location** (an empty folder) and click **Create Env Vault**. Creation needs a
   paired token and a signal selection; a one-time **recovery code** is shown — save it,
   as it is the only way back in if the token is lost
2. **Add files…** (or **drag files from Explorer onto the list**) encrypts each file into
   the vault and (optionally) shreds the original. Names, sizes and dates live only in an
   encrypted index; on disk you see only random-named ciphertext, so nothing reveals what
   is inside
3. **Open** decrypts a file **in memory only** to view it — nothing plaintext is written to
   disk. **Export…** writes a decrypted copy out when you explicitly want one
4. The vault **auto-locks** when the token goes out of BLE range. **Lock now**, or
   **Ctrl+Shift+L** from anywhere (panic lock), locks it immediately and drops the key
5. If the environment drifts (e.g. you change network), unlock with the recovery code and
   re-bind to the new environment

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
| Key | `env_key = HMAC(master_secret, SHA-256(signals))` on the token. `file_key = HKDF(env_key, random per-file salt)` on the PC |
| Defences | Raw signal values never leave the PC. Replays fail (single-use nonces). Impostor tokens/hosts fail the GCM tag. Lockout after 5 bad requests |

---

## Important Notes

- **Use a lossless carrier** — PNG for images, uncompressed PCM WAV for audio. JPEG, MP3
  and other lossy formats recompress the data and destroy the hidden LSBs
- The stego carrier is perceptually identical to the original (max 1-bit change per channel /
  per audio sample)
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
├── stego_engine.py    ← LSB steganography for PNG images
├── audio_engine.py    ← LSB steganography for WAV audio
├── media.py           ← Carrier dispatcher (routes PNG vs WAV by extension)
├── multi_image.py     ← Split one payload across several carriers (+ rejoin)
├── ui_main.py         ← Full PyQt6 user interface
├── requirements.txt   ← pip dependencies
├── build.bat          ← Build EnvStego.exe
└── .vscode/
    └── launch.json    ← VS Code run config
```
