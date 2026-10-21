# Protecting the master secret: Flash Encryption & Secure Boot

**Status: guide only — nothing here is enabled automatically.** These steps burn
one-time fuses (eFuses) on the ESP32. They are **irreversible** and can brick the
board. Read the whole page first, and ideally practise on a spare ESP32, not your
only token.

---

## Why this matters for EnvStego

The token's `master_secret` is stored in the NVS partition in the ESP32's flash
**in clear**. Anyone who physically holds the token can read the whole flash out
over USB in about a minute:

```
esptool.py --port COM3 read_flash 0 0x400000 dump.bin
# the 32-byte master secret is somewhere in the NVS region of dump.bin
```

With that secret and the seized laptop, every file encrypted with the token can be
rebuilt — the environment binding and the auth key no longer matter. This is the
single biggest weakness against a **confiscated token**.

**Flash Encryption** encrypts the entire flash (firmware *and* NVS) with a key that
lives only in an eFuse and can never be read back. A flash dump then yields only
ciphertext. **Secure Boot** additionally refuses to run firmware that isn't signed
with your key, so an attacker can't flash a malicious reader.

---

## The two modes (choose carefully)

| Mode | Re-flashing | Use when |
|------|-------------|----------|
| **Development** | Still allowed (limited number of times) over USB with the `--encrypt` flag | Testing; recommended first |
| **Release** | **Permanently disabled** over USB; updates only via signed OTA | Final build only |

Start in **development mode**. Only move to release mode for the token you actually
carry, once everything works.

---

## Prerequisites

- A **stable-booting** token (the brownout fix is already in `main.cpp`).
- A **full backup** of the current firmware and NVS *before* you start — once
  encryption is on you cannot read the plain flash again:
  ```
  esptool.py --port COM3 read_flash 0 0x400000 backup_before_encryption.bin
  ```
- `espefuse.py` and `esptool.py` (bundled with PlatformIO:
  `C:\Users\<you>\.platformio\packages\tool-esptoolpy\`).

---

## Step 1 — Enable flash encryption in the build (PlatformIO)

The Arduino framework needs a custom `sdkconfig`/menuconfig, which PlatformIO drives
through an ESP-IDF build. The simplest path on the ESP32-CAM is to build the
bootloader and app with flash encryption turned on and let the **first encrypted
boot** generate the key on-device.

Add a dedicated environment to `platformio.ini` (kept separate so the normal build
is untouched):

```ini
[env:esp32cam_encrypted]
extends = env:esp32cam
build_flags =
    ${env:esp32cam.build_flags}
    -DCONFIG_SECURE_FLASH_ENC_ENABLED=1
board_build.partitions = default.csv
; Development mode: the key is generated on the device at first boot and
; re-flashing stays possible with `--encrypt`.
```

> Note: full flash-encryption support with the Arduino core usually means switching
> the build to the ESP-IDF framework, or using `idf.py menuconfig` →
> *Security features → Enable flash encryption on boot (Development)*. The
> EnvStego firmware compiles unchanged under ESP-IDF; only the build wrapper differs.

## Step 2 — First encrypted flash

```
esptool.py --port COM3 --chip esp32 write_flash 0x1000 bootloader.bin \
           0x8000 partitions.bin 0x10000 firmware.bin
```

On the **first boot** the chip generates the flash-encryption key in an eFuse,
encrypts the flash in place, and reboots. From then on the master secret in NVS is
stored encrypted.

## Step 3 — Verify

```
esptool.py --port COM3 read_flash 0 0x400000 dump_after.bin
```

Search `dump_after.bin` for the token's old `master_secret` bytes from your backup —
they must **not** appear. The flash should look like random data.

## Step 4 (optional) — Secure Boot v2

Only after flash encryption works:

1. Generate a signing key and keep it offline:
   `espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem`
2. Enable *Secure Boot v2* in menuconfig and rebuild; the bootloader is signed.
3. The first secure boot burns the public-key digest into eFuses. After that the
   chip runs only firmware signed with your key.

---

## Re-pairing after encryption

Flash encryption does **not** erase NVS, so the existing pairing and master secret
survive — your already-encrypted files stay decryptable. If you instead do a clean
erase + encrypted flash, the token is unpaired and you must pair again (a new master
secret means old files are lost, exactly like a factory reset).

## Risks summary

- **Irreversible.** Burned eFuses cannot be un-burned.
- **Bricking.** A wrong partition offset or a power loss mid-encryption can leave an
  unbootable board.
- **Release mode ends USB flashing.** Keep a development-mode token for testing.
- Always keep the pre-encryption backup until you have confirmed the token works.
