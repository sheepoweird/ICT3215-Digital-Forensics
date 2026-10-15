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
- Pick a **preset** (Device-bound, Location-bound, Hardware only, Everything) or tick signals
  yourself. Clicking anywhere on a row toggles it, and hovering shows the current value
- **Save as preset…** stores your own combinations. **Clear selection** unticks everything
- Click **Test Key** twice. A matching fingerprint (`✓ stable`) means the environment is stable

### Protect › Encrypt
1. Choose (or drag in) the **payload file**, then the **carrier PNG**
2. The output path is suggested automatically (`<carrier>_stego.png`). Change it if you like
3. **Encrypt & Embed** stays disabled until everything is ready. The hint below it says what is missing

### Protect › Decrypt
1. Choose the **stego PNG**. The last image you encrypted is filled in for you
2. Optionally choose a folder. By default the payload is restored next to the stego image,
   **under its original filename**, and existing files are never overwritten
3. The same signals (use the same preset) and the same token are required, otherwise
   authentication fails (forensic defense)

### Diagnostics › Inspector
- Shows raw values of every collected signal and which ones are in the key
- Useful for debugging and for the report evaluation section

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

- **Always use PNG** as the carrier image — JPEG recompression destroys LSB data
- The stego image is visually identical to the carrier (max 1-bit difference per channel)
- Minimum carrier image size: ~200×200 px for small payloads
- **Rule of thumb for capacity:** a 1920×1080 PNG holds ~759 KB of payload

---

## File Structure
```
envstego/
├── main.py            ← Entry point (run this)
├── signals.py         ← Environment signal collection (22 signals)
├── crypto_engine.py   ← HKDF key derivation + AES-256-GCM
├── stego_engine.py    ← LSB steganography (embed/extract)
├── ui_main.py         ← Full PyQt6 user interface
├── requirements.txt   ← pip dependencies
├── build.bat          ← Build EnvStego.exe
└── .vscode/
    └── launch.json    ← VS Code run config
```
