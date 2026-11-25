# Env Vault: opening and exporting with IO0

Vault format 3 (2026-11-25): the environment hash is no longer stored. Imports require
firmware **v8** or later. The implementation is
`Python/vault.py`, with file operations run by `Python/vault_worker.py`.

## Behavior and memory boundary

| Activity | What reaches PC memory | Authorization |
| --- | --- | --- |
| Create | Metadata key and newly generated recovery private key/code | Paired token, selected environment and one IO0 tap |
| Browse | Metadata key, names, sizes, dates and encrypted recovery envelopes | Paired token, the live environment (a wrong one fails after the tap) and one IO0 tap |
| Import selection | Temporary batch secret, current file key and streaming plaintext, in the worker | One authenticated request after a fresh environment check |
| Export one file | That file's key and streaming plaintext, in the worker process | One IO0 tap for the selected export batch |
| Recovery browse | Recovery code/private key temporarily, then metadata key in the session | Offline recovery code |
| Recovery export | Recovery code/private key and selected file key in the worker | Re-enter code for each selected file |

There is no shared content key in a normal v2 metadata session. The GUI does not
receive file keys from import/export workers. Each worker exits after its action;
large normal imports/exports stream in 1 MiB chunks. Vault preview and the
`read_bytes` interface have been removed from the v2 GUI/API. The separate stego
workflow still uses its existing environment-derived key. Its text preview was
removed, so a recovered payload is written to disk without being shown in the window.

Locking drops metadata references, empties the list and signals active file
workers to terminate. An open list locks after 5 minutes without vault activity
(selection or a file action), checked every 25 seconds, when the token stops
answering, and immediately when Windows is locked (Win+L), goes to sleep or hibernates,
or signs out or shuts down. Locking before sleep or hibernation ends the vault workers,
so their file keys are not in the hibernation image; the main window's remnants can be,
which is why full-disk encryption (BitLocker) is recommended. Normal cancellation waits for worker exit and removes its
temporary export directory. This is **not guaranteed RAM zeroization**: Python,
Qt, native cryptographic libraries, OS caches, pagefiles, hibernation and crash
dumps can retain copies. Already exported plaintext remains on disk. A hard crash
can leave an export temporary file or an unfinished worker until it exits.

A memory capture during ordinary browsing should not obtain content keys through
the metadata session. Capturing the import secret can expose **every file in that
import selection**, given the corresponding file identifiers. Capturing a selected
export key can expose that file. A previously captured file key can still decrypt that
file later. A capture of the recovery code/private key during creation or recovery can recover **all** files; recovery is an explicit exception to
per-file key isolation. The recovery dialog and optional clipboard copy also
expose that secret to the desktop environment. A copied code is cleared from the
clipboard after 30 seconds unless something else was copied since; Windows
clipboard history or cloud clipboard sync, if enabled, can still keep it.

## Token derivation and approval

All concatenations below are byte concatenations; IDs are decoded from hex.

```text
live_env_hash = SHA-256(the vault's signal IDs and their values, read now)
context       = SHA256("EnvVault-v3" | vault_id[16] | live_env_hash[32])
metadata_key  = HMAC-SHA256(master, "3T-VAULT-META-v2" | context)
batch_secret  = HMAC-SHA256(master, "3T-VAULT-BATCH-v1" | context | batch_id[16])
file_key      = HMAC-SHA256(batch_secret, "3T-VAULT-CHILD-v1" | file_id[16])
```

The environment hash is **never stored**. When the list is opened, the app reads the
vault's signal IDs (sealed under the token's index key), collects those signals live
and hashes them. In a different environment the context changes, the token derives
different keys, and the index fails AES-GCM authentication, so environment binding
is cryptographic, as it is for stego. A wrong environment is therefore reported after
the IO0 tap rather than before it.

The generic stego opcode uses `3T-ENV-v1`. Knowledge of that environment key or
the metadata key does not directly derive vault file keys. Random vault IDs separate
vaults in the same environment; random 128-bit file IDs separate their files.

| Opcode | Meaning | Response |
| --- | --- | --- |
| `0x13` | Open metadata | Authenticated pending response, then metadata key after IO0 |
| `0x14` | Mint new file (v7) | Fresh token-generated 16-byte file ID and its 32-byte key. Firmware v8 still answers it; the app no longer sends it |
| `0x15` | Authorize selection | Commit to a hash of the ordered file contexts. IO0 activates it on that connection |
| `0x16` | Read next selected key | Present the next context and remaining hash, then consume one entry |
| `0x17` | Mint an import batch | Fresh token-generated 16-byte batch ID and 32-byte batch secret |
| `0x18` | Read a selected batch file | Verify and consume its committed context, derive the batch secret internally and return only the file key |

The token chooses each batch ID. Repeating the import request produces a new batch.
The worker chooses a fresh random 128-bit file ID for every entry and stores its
batch ID in the authenticated index. The recovery envelope still wraps that file's
individual key.

The host builds the export selection backwards from 32 zero bytes. Each link hashes
the file context and the remaining chain hash. File contexts concatenate the 32-byte vault context, 16-byte batch ID and
16-byte file ID. The token records only the
approved head on the BLE connection. Each key request uses a fresh authenticated
challenge, checks the current head and advances it. Exhaustion, a mismatched link
or disconnect ends that authorization. A new selection needs another physical tap.
A pending tap expires after 60 seconds. A button held across prompts must be released.

File workers receive the open session's metadata key and environment hash over stdin,
collect the signals again and refuse to continue if the environment has changed since
the list was opened, so new files are never bound to a different environment. The desktop retains the authenticated signal IDs from opening
the list so the import worker can check them locally. It acquires one batch secret,
closes BLE, then encrypts and verifies the selected files locally. A transient
acquisition failure can be retried once before any file processing starts. Losing
Bluetooth after acquisition does not interrupt that import. Locking the vault cancels
the worker. The worker drops the secret when the import ends and its process exits.
Export uses one worker and BLE connection for the selection,
retrieving each key immediately before decrypting its file. If a batch stops,
files already published in the destination remain available.

The token has no trusted display: IO0 confirms the pending key request, **not a
trustworthy filename or operation description**. A compromised host can request a
different context and mislead its user. The token also cannot independently
measure PC environment signals. No claim is made against an actively compromised
host, malicious firmware or physical extraction of the master secret.

## On-disk format and recovery

`vault.json` stores version 3, a random vault ID, the X25519 recovery public key,
sealed signal IDs/creation time and a recovery envelope for the metadata key. It holds
no environment hash, so it cannot be used to confirm guesses of signal values.
Environment binding is not a replacement for the token secret: signal values that can
be reconstructed from a disk image add little entropy on their own.

`index.bin` is AES-256-GCM encrypted with the metadata key. Its authenticated
entries contain random file IDs, original names/sizes/dates and individual
recovery-wrapped file keys. File blobs contain a fresh 12-byte nonce, padded
ciphertext and 16-byte GCM tag. Plaintext is padded to a minimum 4 KiB and then
4 KiB boundaries. File count and approximate sizes remain visible on disk.

The immutable vault fields are canonically serialized as associated data for the
index and recovery envelopes. File associated data additionally binds its file
ID. Changing the recovery public key, vault identity, sealed signal list or creation
time breaks authentication. Each recovery envelope uses ephemeral X25519, HKDF-SHA256 with
the `EnvVault-recovery-v2` domain and both public keys, and AES-256-GCM. Imports
need only the recovery **public** key to produce new envelopes. The 32-byte
private key is represented by the 52-character Base32 recovery code (hyphens
ignored); it is not stored in the session object or sent to the ESP32.

Imports authenticate and SHA-256-check the freshly encrypted blob against bytes
read from the source before committing the index or attempting original deletion.
Index writes use a flushed temporary file plus `os.replace`; mutations reload the
latest index under an OS file lock. Failed ordinary commits remove their new blob;
a crash can leave harmless orphan ciphertext. These measures do not guarantee
durability against every storage controller failure or loss of power.

Exports authenticate once before creating plaintext output, recheck the GCM tag
while writing a temporary file, and publish with an atomic no-overwrite operation.
Cancellation cleans up that temporary file in the normal running application.
Export destinations and imported originals remain subject to filesystem backups,
snapshots and SSD wear leveling. Original deletion outcomes are reported individually.

## Existing vaults

Only format 3 is supported. Vaults created before 2026-11-25 (format 2, which stored
the environment hash) and format 1 are refused; create new vaults in empty folders.
Firmware updates do not affect format-3 vaults as long as the token's NVS is preserved.
If the environment changes permanently, the offline recovery code exports the files.
See [flash provisioning](FLASH_ENCRYPTION.md) for hardware storage considerations.

## Validation

On 2026-11-25, `python -m pytest -q Python/tests` passed all 279 tests on Windows.
The host tests exercise encrypted BLE responses, missing or forged approval,
a wrong environment failing to open the vault or export its files, locking on Win+L,
sleep and sign-out, single-tap export, selection substitution, single-request batch imports, worker
cancellation, recovery, authenticated file output, the 5-minute idle lock and the Qt
interface. The v8 ESP32-CAM PlatformIO build uses 1,198,685 bytes of program flash and
39,580 bytes of static RAM.

Live v8 status: the board booted firmware v8 (advertising `3T-Token-v8`) and completed a
fresh USB pairing on 2026-11-19 after its NVS had been cleared. One boot on a front-panel
USB port crashed during Bluetooth start-up and the token then stayed unresponsive until
reset; on a different port it booted cleanly. A live v8 import and an IO0-approved
export are still pending.

A local disk-acquisition adversary harness (`devtools/adversary_harness.py`, not
committed) attacks a format-3 vault built through `vault.py` with a simulated token. On
2026-11-25 it reported 26 defences held, 0 broken, and 3 metadata-only exposures: item
count, 4 KiB size buckets and LSB detectability of stego carriers. An attacker holding
the token and the vault folder in a different environment could not open the vault. It confirmed that the metadata key decrypts no file and one file's key decrypts
no other file in the same import.

### Live v7 batch import

A disposable, already-open metadata session imported three test files with the paired
ESP32 and the production worker process. Each original was retained. Offline recovery
exports matched all three originals byte for byte. This historical hardware check
covered the v7 import path, which requested each file key on the open connection.

### Live v6 flash and checks

Flashed on 2026-11-18 through COM4 to the ESP32-D0WD-V3 rev 3.1 on the ESP32-CAM-MB.
Only the application at `0x10000` was written (1,204,384-byte binary); esptool
verified its hash and reset the device. NVS, bootloader and partition table were
not erased or rewritten. Existing pairing authenticated after the update, without
re-pairing. The app's cached firmware-version field was updated to v6 while
preserving all other pairing fields.

Live results:

- Paired device advertises `3T-Token-v6`.
- Existing Windows-protected credential completes authenticated BLE ping.
- Metadata-key opcode returns a repeatable key, distinct from the generic key
  for the same test context. No key material was printed or saved.
- File-key request returns authenticated pending approval before IO0 confirmation.
- Disconnecting without approving is followed by a successful authenticated ping.

The live checks used no IO0 press. Successful button-approved file-key release,
file import/export round trips, the 60-second expiry and concurrent-link behavior
still require physical hardware validation. The ignored helper script is
`build/validate_token_v6.py`.
