# Test plan and results

Status of every test for the EnvStego desktop app and the 3T token, how each was run,
and which screenshots to capture for the report and video. Results are from commit
`eba6bee` plus the vault format 3 and Win+L changes of 2026-11-25, unless a row says otherwise.

**Legend:** ✅ passed · ⚠️ passed with a finding to report · ⏳ pending · ❌ failed

## 1. Summary

| Area | Status | Result |
|---|---|---|
| A. Automated test suite | ✅ | 279 / 279 passed (2026-11-25, vault format 3; re-run 2026-11-28 on Python 3.12.7, 279 passed) |
| S1. Disk-acquisition adversary harness | ⚠️ | 26 held, 3 metadata-only leaks, 0 broken; software-only baseline recovered |
| S2. Fuzz harness | ✅ | 42 hostile-input checks, 0 vulnerabilities |
| S3. Static analysis (Bandit) | ✅ | 0 high, 0 medium, 18 low |
| S4. Dependency CVE audit (pip-audit) | ⏳ | Blocked by HTTPS interception on the campus network; run from home |
| F. Real-file format round trips | ✅ | 15 carrier types + 1 mixed split set, all recovered |
| H1. Token boot and USB pairing (firmware v8) | ⚠️ | Paired 2026-11-19; one crash loop on a front USB port (see §8) |
| H2. Firmware update to v9 | ⏳ | |
| H3. Vault with physical IO0 taps | ⏳ | H3.1, H3.3–H3.5 and H3.10 passed on v9 hardware (2026-11-27); the rest pending |
| M. Manual functional tests | ⏳ | |
| E. Forensic tool evaluation | ⚠️ | E7, E9 done; E10, E11 found memory residue (see §8); E1–E6, E8 pending |

## 2. Test environment

| Item | Value |
|---|---|
| OS | Windows 11 Home (10.0.26200) |
| Python | 3.10.0 (2026-11-25 run); 3.12.7 in the build `.venv` (2026-11-28 run) |
| Token | ESP32-CAM (ESP32-D0WD-V3 rev 3.1) on an ESP32-CAM-MB (CH340) programmer |
| Firmware | v9 in the repository; the test board ran v8 for H1 |
| Automated tests | Simulated token (same key derivations as the firmware); no Bluetooth hardware needed |

## 3. Automated tests (A) ✅

**How:** `cd Python` → `python -m pytest -q tests`. Log: `evidence/03_offline_tests.log`.

| File | Tests | Covers |
|---|---:|---|
| `test_carriers.py` | 60 | Every image and audio format, split sets, capacity, malformed carriers |
| `test_ui_smoke.py` | 63 | The real app window driven offscreen: pairing, encrypt/decrypt, vault, idle lock, Win+L/sleep/sign-out lock, keep/delete prompt, no preview |
| `test_vault.py` | 33 | Per-file keys, key isolation, wrong environment cannot open or export, recovery code, crash safety, worker process, padding |
| `test_offline.py` | 31 | Key derivation vs firmware, wrong environment/token, tamper, replay, impostor, lockout, filename traversal |
| `test_firmware_flasher.py` | 28 | Firmware update plans never write over the token's stored secret |
| `test_antiforensics.py` | 17 | Shredding, timestamp copying, sealed settings, atomic-write retry |
| `test_pairing.py` | 16 | Encrypted USB pairing, re-pairing proof, cancel, power-loss messages |
| `test_vault_protocol.py` | 13 | One-tap approval, selection cannot be substituted, unapproved requests refused |
| `test_native_images.py` | 11 | Native JPEG coefficient embedding, WebP transparency |
| `test_header.py` | 7 | Encrypted header: no plaintext marker, wrong token cannot read it |
| **Total** | **279** | **All passed** in 76 s |

## 4. Security harnesses (S)

Local tools in `devtools/` (not on GitHub). They build real artefacts with the app's own code
and a simulated token, then attack them without the token.

### S1. Disk-acquisition adversary ⚠️

**How:** `python devtools/adversary_harness.py --log` → `evidence/adversary_harness_20261125_115553Z.log`.
**Models:** an examiner holding a full disk image but not the ESP32 token.

| Check | Result |
|---|---|
| Search stego files for any EnvStego marker or secret file name | Held: none found |
| Recover the hidden payload with 20,000 index-key and 5,000 file-key guesses | Held: all rejected |
| Locate the payload without the token's bit-scatter key (PNG and JPEG) | Held: header not found |
| Group or order split-set pieces among decoy images | Held: indistinguishable, 0/76 shared bytes |
| Read vault names, sizes, dates, signal list or creation time from disk | Held: all sealed inside the vault files. Outside the harness, NTFS timestamps on the blob files still show when items were added |
| Open the vault with 20,000 metadata keys or 5,000 random 256-bit recovery codes | Held: all rejected |
| **Token + vault folder, but in a different environment** | Held: the token derives a different key and the index fails to authenticate |
| Find the environment hash in `vault.json` | Held: not stored |
| Use the vault's browsing key, or one file's key, to open other files | Held: neither works |
| Nonce/salt reuse across 3,000 headers; single-bit tamper; swapped salt | Held: unique, detected, rejected |
| Positive control: token + correct environment, and the recovery code | Held: exact files recovered |
| **Leaks (metadata only)** | Vault item count; 4 KiB size buckets; LSB embedding statistically detectable |
| **Baseline:** same carrier keyed from the environment alone (no token) | **Recovered** by rebuilding the signals from the disk |

**Scorecard:** 26 held · 3 leaks · 0 broken (2026-11-25, vault format 3).

### S2. Fuzzing ✅

**How:** `python devtools/fuzz_harness.py --iters 2000 --log` → `evidence/fuzz_harness_20261125_115525Z.log`.
Malformed PNG/JPEG/WebP/WAV/MP3/FLAC/Ogg files, a decompression-bomb image, malicious ZIPs
(path traversal), poisoned vault files (including a correctly sealed index naming `..\..\evil.exe`),
and 2,000 random inputs to each binary parser. **Result:** 42 checks, every input rejected
cleanly; a failed export leaves no file behind.

### S3. Static analysis ✅

**How:** `python -m bandit -r Python -x Python/tests` → `evidence/10_bandit.log`.
**Result:** 0 high, 0 medium, 18 low. The lows are expected: subprocess use for the worker
processes and esptool, and best-effort cleanup handlers.

### S4. Dependency audit ⏳

**How:** from a network without HTTPS interception:
`python -m pip_audit -r devtools/audit_pins.txt --no-deps --disable-pip --vulnerability-service osv`.
**Result:** ______

## 5. File-format round trips (F) ✅

**How:** carriers made with real encoders (ffmpeg, libwebp, LAME, libvorbis, libopus), run
through the app's encryption and embedding code with stand-in keys (2026-11-22). Full table:
`md/STEGO_FORMATS.md`.

| Input | Output | Result |
|---|---|---|
| JPEG (colour, greyscale, two qualities) | JPEG, +4 % to +11 % size | Recovered; capacity about 3–5 KB per photo |
| PNG, BMP, TIFF | Same format | Recovered |
| WebP (lossy, lossless) | Lossless WebP | Recovered; lossy input grows about 7× |
| GIF | PNG | Recovered |
| MP3, FLAC, Ogg, Opus, AIFF, WAV | WAV | Recovered; compressed input grows to WAV size |
| Split across JPEG + WebP + MP3 | .jpg / .webp / .wav | Recovered in any order; refused with a piece missing |

Every carrier also rejected a different token's key and was left unchanged on disk.

## 6. Hardware tests (H)

Firmware is flashed from `ESP32 Files/` with PlatformIO or the in-app flasher.
Keep a serial monitor open at 115200 baud during these tests and save its output.

### H1. Boot and pairing (firmware v8) ⚠️ — 2026-11-19

| Step | Expected | Result |
|---|---|---|
| Boot on rear USB port (COM7) | `BLE Server is running` | ✅ |
| Malformed pairing command over USB | `PAIRING_REFUSED … BAD_FORMAT` | ✅ |
| USB pairing + IO0 press | Paired; Test connection passes | ✅ |
| Boot on front USB port (COM3) | Clean boot | ❌ crash loop during Bluetooth start-up, then frozen until reset (see §8) |

### H2. Firmware update v8 → v9 ⏳

| Step | Expected | Result |
|---|---|---|
| Note the token ID, then flasher → **Update** (not Erase) | Serial shows `3T-Token-v9` | |
| Test connection | Passes with the **same** token ID, no re-pairing | |
| Decrypt a stego file made before the update | Opens | |

### H3. Vault with physical IO0 taps ⏳

Use an empty folder and test files; record SHA-256 hashes first (`certutil -hashfile <file> SHA256`).
Rows marked 2026-11-27 were run on firmware v9 and recorded for the demo video.

| ID | Step | Expected | Result |
|---|---|---|---|
| H3.1 | Create vault | 1 IO0 tap; recovery code shown | ✅ 2026-11-27: LED solid until the tap; recovery code shown |
| H3.2 | Lock, then Browse files | 1 tap opens the list | |
| H3.3 | Add 3 files, choose Keep | No tap; originals still exist | ✅ 2026-11-27: canary folder (4 files) added with Keep; originals still present |
| H3.4 | Add 1 file, choose Delete | Original gone; status "shredded" | ✅ 2026-11-27: test file gone; FTK Imager listings before and after show its MFT record freed (on C:\ the folder's $I30 index still held its short name, size and timestamps) |
| H3.5 | Export several files | 1 tap for all; hashes match originals | ✅ 2026-11-27: 4 canary files exported; SHA-256 of all 4 match the originals |
| H3.6 | Export files from two separate imports | Still 1 tap | |
| H3.7 | Start export, don't tap for 60 s | Fails cleanly; LED off | |
| H3.8 | Hold IO0 before clicking Export | Nothing until released and pressed again | |
| H3.9 | Lock during a large export | No partial file or `.vault-operation-*` folder | |
| H3.10 | Switch the token off with the vault open | Auto-locks within about 50 s | ✅ 2026-11-27: token unplugged with the vault open; the vault auto-locked (time not measured) |
| H3.11 | Leave the vault idle for 5 min, token on | Locks "without vault activity" | |
| H3.12 | Recovery code, token off | Exports 1 file | |
| H3.13 | Open the vault folder in Explorer | Only random hex names, `vault.json`, `index.bin`, `.vault.lock` (empty lock file); no environment hash in `vault.json` | |
| H3.14 | Open the list, then press **Win+L** and sign back in | Vault locked: "Locked because Windows was locked" | |
| H3.15 | Open the list, then put the PC to sleep and wake it | Vault locked: "…going to sleep or hibernate" | |
| H3.16 | Change a vault signal (e.g. another Wi-Fi network for a network-bound vault), then Browse | Fails after the tap: "environment does not match" | |

### H4. Pairing edge cases ⏳

| Step | Expected | Result |
|---|---|---|
| Re-pair while paired | Works (saved credential + IO0) | |
| Forget pairing, then pair again | Refused: "already paired" | |
| Retry within 60 s of a cancelled attempt | "BUSY"; works after waiting or RST | |

## 7. Manual functional tests (M) ⏳

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | Encrypt/decrypt a JPEG | Output stays `.jpg`, similar size | |
| M2 | PNG, WebP, BMP, TIFF | Each round-trips | |
| M3 | MP3 carrier | Output `.wav`; decrypts | |
| M4 | Split across JPEG + PNG + WAV | Decrypts; one piece removed → refused | |
| M5 | Decrypt with the token switched off | Fails | |
| M6 | Decrypt after changing Wi-Fi (network-bound preset) | "Environment mismatch" | |
| M7 | Decrypt page | No preview; file only on disk | |
| M8 | Shred original after Encrypt | Source file gone | |
| M9 | `EnvStego.exe` from `build.bat` on a PC without Python | Launches; JPEG encrypt and vault export work | |

## 8. Findings so far

| Finding | Detail | Handling |
|---|---|---|
| Token crash loop on a weak USB port | Crashed during Bluetooth start-up on a front port, then stayed frozen; clean on a rear port | Documented in `md/SETUP.md`; press RST, use a rear port |
| Windows briefly locks a file being saved | One test run failed when antivirus held `index.bin` during a save | Fixed: saving retries for up to about 1.5 s; covered by a test |
| Metadata visible without the token | Vault item count, 4 KiB size buckets | Stated as limits in the report |
| Vault environment check was only an app rule | Format 2 stored the environment hash in `vault.json`, so anyone with the token and the folder could open the vault anywhere | **Fixed 2026-11-25 (format 3):** hash no longer stored; keys depend on the live signals; verified by S1 and `test_vault.py` |
| Vault stayed open across Win+L and sleep | No reaction to Windows locking, sleeping or signing out | **Fixed 2026-11-25:** the vault locks on each; verified with real Windows messages and `test_ui_smoke.py` |
| Stego needs no physical approval | The token gives stego keys without an IO0 press, so malware holding the pairing key could decrypt stego files while the token is in range | Future work: require a tap for stego keys (firmware change) |
| Token plugged into a compromised PC over USB | The flasher protocol can read the unencrypted flash (master secret) or install other firmware | Plug in over USB only to pair or update; flash encryption is future work |
| Stego is detectable, not readable | LSB embedding is statistically detectable | The report claims recovery resistance, not undetectability |
| Token visible over Bluetooth | It advertises its name, and its ID is sent unencrypted in each challenge | Confirmed in E7; add to the report's limits |
| Token trackable by its Bluetooth address | Fixed public address `84:1f:e8:67:b6:c2` (Espressif prefix); no address randomisation | Confirmed in E7; add to the report's limits |
| No Bluetooth-level link encryption | 0 pairing (SMP) packets: all protection is the app's AES-GCM layer, so only ciphertext, nonces and the token ID cross the air | By design; state it in the report's design section |
| Recovery code lingers in the app's memory | Confirmed in E10: after vault creation (2026-11-25) for minutes, and after a recovery-code unlock (2026-11-27) for over 30 minutes, until the app restarted; Python and Qt cannot wipe them. Matches the documented limit in `md/VAULT_SECURITY.md`. Pagefile or hibernation could copy it to disk | Limitation (low–medium): needs live memory access, or the code paged to disk. Mitigate: close the app after creating or recovering a vault, disable hibernation, clear the pagefile at shutdown |
| Vault metadata key lingers in the app's memory | Confirmed in E10 (2026-11-27): the main app still held the import request (metadata key and environment hash) about 14 h after the import, while the app stayed open. The key decrypts the file list, not file contents | Limitation (medium): same mitigation; future work: restart the app or end the process on lock |
| App process can outlive its window | 2026-11-28: a window-less `EnvStego.exe` was still running about 6.5 h after it started; it held its memory and blocked a rebuild of its folder | Limitation: check Task Manager after closing; future work: force the process to exit on close |
| Vault use leaves timing traces | NTFS timestamps on blob files show when items were added; the 25 s heartbeat is a regular BLE pattern while a vault is open | Limitation; state in the report |
| Token secret not encrypted at rest | ESP32 flash/NVS encryption is not enabled | Stated in `md/FLASH_ENCRYPTION.md` and the report |

## 9. Forensic tool evaluation (E) ⚠️

Hash every image and RAM dump straight after capture (`certutil -hashfile <file> SHA256`)
and record the hash. **Never upload RAM dumps**: they contain everything that was in memory.

| ID | Goal | Tools | How | Expected | Result |
|---|---|---|---|---|---|
| E1 | The token's master secret never enters PC memory | esptool, RAM Capturer, Volatility 3 | Read the secret from token flash; capture RAM with the vault open, after export, after lock, after decrypt; search every dump for it | 0 hits | |
| E2 | How long plaintext stays in memory | RAM Capturer, Volatility 3, strings | Use canary files (`CANARY-CONTENT-91c2-UNIQUE`); count hits per stage in ASCII and UTF-16 | Present while open; fewer after lock | |
| E3 | Seized disk reveals nothing readable | FTK Imager or dd, Autopsy / Sleuth Kit | Image a USB drive holding the vault and stego files; keyword search; carve | No names or content; only random blobs | |
| E4 | Shredded originals are not recoverable | Autopsy, `fls` / `icat` / `blkcat` | Shred a canary file, image the drive, search and carve | Not recovered (SSD caveat applies) | |
| E5 | Windows artefacts of app use | KAPE, Registry Explorer, PECmd, LECmd, WxTCmd, EvtxECmd, MFTECmd | Collect after a session with Privacy mode on | Report what is found, e.g. Prefetch shows the app ran | |
| E6 | Steganalysis detection rate | Aletheia, StegExpose | Run on clean and stego carriers | Some LSB carriers flagged | |
| E7 | Bluetooth traffic is encrypted | Wireshark + USBPcap or `btvs.exe` | Capture a key request | Ciphertext only; token name and ID visible | ⚠️ 2026-11-25, `Decrypting.pcapng` (1 exchange, frames 9289–9329) and `Encrypting.pcapng` (2 exchanges, frames 10525–11037), filter `btatt`. All 3 requests (78 B) and 3 responses (62 B) are ciphertext with 0 byte positions in common after the type byte. The token ID (`ee3649e6…`, identical in all 3 challenges) and the advertised name `3T-Token-v9` are readable |
| E8 | Short-lived worker processes | Process Explorer or System Informer | Watch during an export | Worker appears, then exits | |
| E9 | USB pairing never exposes the auth key | Wireshark + USBPcap | Capture a fresh pairing over USB | Only public keys and ciphertext on the wire | ✅ 2026-11-25, `Pairing.pcapng`: request carries the PC's public key; reply carries `MODE=ECDH`, the token's public key and the auth key encrypted (`ENC`, 60 B = IV + ciphertext + tag). No plaintext key; the master secret is never sent |
| E10 | What process memory holds | System Informer (dump) + string search | Dump the main app and a vault worker | Names while open; no master secret | ⚠️ 2026-11-25, four dumps. During vault creation (18:41) the main app (PID 26788) held the new recovery code as text (with and without hyphens) and its raw 32-byte key 3 times; the creation worker (PID 49012) held neither. An earlier vault's code was present in the main app at 18:30 but gone from the same process by 18:41, so it lingers for minutes, not indefinitely. Vault workers held no recovery code. 2026-11-26, `Pairing.dmp` (main app, taken seconds after pairing at 15:27): the auth key was found 0 times (raw, hex, ASCII or UTF-16) and the token's serial reply (`PAIRING_SUCCESS…ENC=`) was not left in memory; only the token ID (public, also broadcast over BLE) and the DPAPI-encrypted config blob were present. 2026-11-26, `Vault 2.dmp` (main app, current code, 15:41, about 2 min after creating a vault at 15:39 and after an export): recovery code 0 hits (with or without hyphens, any case, ASCII or UTF-16, raw 32-byte key; code verified against `recovery_pub`), unlike `Vault 1.dmp`; auth key 1 raw copy (needed for the BLE session; a process running as the same user could unwrap it with DPAPI anyway); imported file names present (ASCII and UTF-16), as expected after the list was open. 2026-11-27, System Informer memory search of the main app at 16:11: the JSON request sent to the import worker (metadata key and environment hash) and the decrypted file-list JSON were both still in memory about 14 h after the import. After a recovery-code unlock the code was found 3 times (once in Python, twice as Qt UTF-16 text), then once (Qt) for over 30 minutes; after restarting the app it was not found. Canary search pending (needs the test file names) |
| E11 | Keys written to disk by Windows paging or hibernation | FTK Imager (export), byte-string search, Autopsy keyword search, Hibernation Recon | Export `pagefile.sys` and `hiberfil.sys` from the live system; search for the metadata key, environment hash and JSON field names | 0 hits | ⚠️ 2026-11-27. `pagefile.sys` (26.8 GB): 0 hits for the metadata key (hex or raw), the environment hash, or the `metadata_key` / `signal_ids` JSON; Autopsy agreed (the field names only appear as code identifiers). 1,825 `EnvStego` hits show app memory was paged, so the search worked. Windows memory compression can hide compressed pages, so 0 hits is a lower bound. `hiberfil.sys` (13.7 GB): all zeros except a 277-byte `WAKE` header (Hibernation Recon: no valid data). Windows clears the image after resuming, so a live copy cannot show what was hibernated; that needs the disk imaged while the PC is hibernated |

## 10. Screenshots and recordings

Save screenshots to `evidence/screenshots/` (local only) as `SS-xx_short-name.png`.
For the report, crop to the relevant area; for the video, record the live step instead.

| ID | Capture | When | Use |
|---|---|---|---|
| SS-01 | Test suite summary: `279 passed` | §3 | Report |
| SS-02 | Adversary harness scorecard + baseline line | §4 S1 | Report, video |
| SS-03 | Fuzz harness `RESULT: no VULN` | §4 S2 | Report |
| SS-04 | Bandit severity totals | §4 S3 | Report |
| SS-05 | App pages (already rendered: `evidence/ui/tab1–6*.png`) | — | Report, user manual |
| SS-06 | Serial monitor: `3T-Token-v9` and `BLE Server is running` | H2 | Report |
| SS-07 | Token LED solid while waiting for IO0 (photo) | H3.1 | Video |
| SS-08 | Vault list open, with the 1-tap prompt message | H3.2 | Report, video |
| SS-09 | Keep/Delete prompt | H3.3 | Report |
| SS-10 | Export result next to matching `certutil` hashes | H3.5 | Report |
| SS-11 | Vault folder in Explorer (random names only) | H3.13 | Report, video |
| SS-12 | JPEG carrier vs stego output side by side, with file sizes | M1 | Report, video |
| SS-13 | Decrypt failing with the token off | M5 | Video |
| SS-14 | "Environment mismatch" error | M6 | Report, video |
| SS-15 | Volatility search: 0 hits for the master secret | E1 | Report, video |
| SS-16 | Canary hit counts per stage (table) | E2 | Report |
| SS-17 | Autopsy keyword search with no results on the vault drive | E3 | Report, video |
| SS-18 | Prefetch / Registry Explorer entries found | E5 | Report |
| SS-19 | Aletheia output on clean vs stego images | E6 | Report |
| SS-20 | Wireshark: encrypted request bytes | E7 | Report |
| SS-21 | Process Explorer: worker process during export | E8 | Video |
| SS-22 | Autopsy keyword search on `pagefile.sys`: 0 hits for the key prefixes | E11 | Report |
| SS-23 | Hibernation Recon "no valid data" on the zeroed `hiberfil.sys` | E11 | Report |

## 11. Evidence files

| File (in `evidence/`, local only) | Content |
|---|---|
| `03_offline_tests.log` | Full pytest run, 279 passed |
| `adversary_harness_20261125_115553Z.log` | S1 |
| `fuzz_harness_20261125_115525Z.log` | S2 |
| `10_bandit.log` | S3 |
| `ui/tab*.png` | Rendered app pages |
| `01`–`09_*.log` and the `20261103` harness logs | Earlier runs (firmware v2/v3, 106 tests); history only |
