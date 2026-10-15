# EnvStego — Evidence

Generated for the ICT3215 Digital Forensics report. Each item below maps to one
of the four tasks.

## Task 1 — Firmware build & upload
- `01_firmware_build.log` — PlatformIO build of the v2 3T token firmware. **SUCCESS**
  (RAM 12.0%, Flash 37.1%). Source copied from `ESP32 Files/` into
  `ESP32 Testing/src/` (`main.cpp`, `encryption.cpp`, `encryption.h`).
- `02_firmware_upload.log` — upload to COM3 (CH340). **SUCCESS** on retry, hash
  verified. (The first attempt failed with *"Wrong boot mode detected (0xb)"*; the
  board entered download mode on its own the second time.)
- After flashing, the token **boot-loops on brownout**: it reaches "Token is UNPAIRED",
  then `BLEDevice::init()` draws a current spike, the brownout detector resets the
  chip, and it never answers USB pairing. This is a power-supply issue, not a
  protocol fault. Task 3 is blocked until it boots stably.

## Task 2 — Offline test suite  ✅
- `03_offline_tests.log` — `python -m pytest tests/ -v` → **43 passed**.
- `Python/tests/test_pairing.py` (8 tests). Runs the real USB pairing routine against
  a scripted serial port: success, a token stuck restarting from low power, a busy
  port, a missing port, a connection drop that recovers, a silent token, and a token
  bound to another PC.
- `Python/tests/test_offline.py` (22 tests). A faithful software twin of the firmware
  drives the real `token_comms` protocol code. Covers: key derivation, stego round
  trip, wrong env/token, tamper + JPEG, per-file salt, replay + impostor + lockout,
  filename path-traversal, legacy ENVS image, and max pixel diff ≤ 1.
- `Python/tests/test_ui_smoke.py` (11 tests). Drives the real app window offscreen
  through pairing, test connection, presets, Test Key, encrypt, decrypt, a
  wrong-environment decrypt, an undersized carrier and forgetting the pairing. It
  passes on both the original and the redesigned UI, which shows the redesign did
  not change behaviour.

## Task 3 — Live token security verification  ⏳ (ready, needs the flashed token)
- Source: `Python/tools/verify_token_security.py`. Verifies the real token
  rejects an unpaired client and repeated requests, and locks out after 5
  failures. Run after Task 1's upload succeeds and the token is paired:
  ```
  python tools/verify_token_security.py --pair COM3    # pair over USB once
  python tools/verify_token_security.py                # run the checks (BLE)
  ```
  Output will be saved here as `05_token_security.log`.

## Task 4 — UI screenshots  ✅
- `04_screenshots.log` — offscreen render log, overall layout check **PASS**.
- `ui/tab1_signals.png … ui/tab5_inspector.png` — all five pages
  (Signals, Encrypt, Decrypt, Token, Inspector) of the redesigned sidebar UI at
  1200×800, rendered with `QT_QPA_PLATFORM=offscreen` and a throwaway QSettings
  `.ini` (the app's settings class is swapped for an ini-backed one, so the
  registry is never touched).
- Note: the Inspector screenshot shows this machine's real identifiers (disk
  serial, machine GUID, SID). These are inputs to the encryption key, so consider
  blurring them before the report is shared.
- Source: `Python/tools/render_screenshots.py`.
