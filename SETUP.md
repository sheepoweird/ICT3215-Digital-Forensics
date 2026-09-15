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
```

The executable will be created at:
```
dist\EnvStego.exe
```

This .exe has no dependencies — copy it anywhere on Windows and run it.

---

## How to Use the App

### Tab 1: Signals
- The app automatically scans your machine when it launches
- Green "Available" badges = signals that could be read
- Grey "N/A" = not available on this machine (no battery, no Wi-Fi, etc.)
- Check the signals you want to form the encryption key
- Click **Test Key** to confirm your environment is stable
- Note the **fingerprint** (e.g. `D993-8D9E-DA56-3DEA`) — you will need the same environment to decrypt

### Tab 2: Encrypt
1. Select your **payload file** (any file — .txt, .pdf, .docx, etc.)
2. Select a **carrier PNG image** (the image that will hide the data)
3. Set an **output PNG path** (where the stego image is saved)
4. Click **Encrypt & Embed**
5. The output PNG looks identical to the original — the payload is hidden in the LSBs

### Tab 3: Decrypt
1. Select the **stego PNG** produced by Encrypt
2. Set an **output file path**
3. Make sure the **same signals are selected** in Tab 1
4. Click **Decrypt & Extract**
5. If you are on a different machine or in a different location → Authentication failed (forensic defense)

### Tab 4: Inspector
- Shows raw values of every collected signal
- Useful for debugging and for the report evaluation section

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
