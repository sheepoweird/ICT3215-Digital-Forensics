# Vault v2: opening and exporting with IO0

Implemented 2026-11-18. New imports require firmware **v8**. The desktop application uses
`Python/vault_v2.py`; `Python/vault.py` supplies shared storage helpers.

## Behavior and memory boundary

| Activity | What reaches PC memory | Authorization |
| --- | --- | --- |
| Create | Metadata key and newly generated recovery private key/code | Paired token, selected environment and one IO0 tap |
| Browse | Metadata key, names, sizes, dates and encrypted recovery envelopes | Paired token and freshly collected matching signals and one IO0 tap |
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
(selection or a file action), checked every 25 seconds, as well as when the token
stops answering. Normal cancellation waits for worker exit and removes its
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
context = SHA256("EnvVault-v2" | vault_id[16] | env_hash[32] [| file_id[16]])
metadata_key = HMAC-SHA256(master, "3T-VAULT-META-v2" | context_without_file_id)
v7_file_key  = HMAC-SHA256(master, "3T-VAULT-FILE-v2" | context_with_file_id)
batch_secret = HMAC-SHA256(master, "3T-VAULT-BATCH-v1" | context_without_file_id | batch_id[16])
v8_file_key  = HMAC-SHA256(batch_secret, "3T-VAULT-CHILD-v1" | file_id[16])
```

The generic stego opcode uses `3T-ENV-v1`. Knowledge of that environment key or
the metadata key does not directly derive v2 file keys. Random vault IDs separate
vaults in the same environment; random 128-bit file IDs separate their files.

| Opcode | Meaning | Response |
| --- | --- | --- |
| `0x13` | Open metadata | Authenticated pending response, then metadata key after IO0 |
| `0x14` | Mint new file | Fresh token-generated 16-byte file ID and its 32-byte key |
| `0x15` | Authorize selection | Commit to a hash of the ordered file contexts. IO0 activates it on that connection |
| `0x16` | Read next selected key | Present the next context and remaining hash, then consume one entry |
| `0x17` | Mint an import batch | Fresh token-generated 16-byte batch ID and 32-byte batch secret |
| `0x18` | Read a selected batch file | Verify and consume its committed context, derive the batch secret internally and return only the file key |

The token chooses each batch ID. Repeating the import request produces a new batch.
The worker chooses a fresh random 128-bit file ID for every entry and stores its
batch ID in the authenticated index. The recovery envelope still wraps that file's
individual key. Earlier format-2 entries retain their original derivation.

The host builds the export selection backwards from 32 zero bytes. Each link hashes
the file context and the remaining chain hash. Older file contexts are 32 bytes.
Batch-file contexts concatenate the 32-byte vault context, 16-byte batch ID and
16-byte file ID. The token records only the
approved head on the BLE connection. Each key request uses a fresh authenticated
challenge, checks the current head and advances it. Exhaustion, a mismatched link
or disconnect ends that authorization. A new selection needs another physical tap.
A pending tap expires after 60 seconds. A button held across prompts must be released.

File workers receive the open session's metadata key over stdin and verify the live
environment again. The desktop retains the authenticated signal IDs from opening
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

`vault.json` stores version 2, a random vault ID, environment hash, X25519 recovery
public key, sealed signal IDs/creation time and a recovery envelope for the
metadata key. The environment hash is public; it can support guesses about
low-entropy or disk-reconstructable signal values. Environment binding is not a
replacement for the token secret.

`index.bin` is AES-256-GCM encrypted with the metadata key. Its authenticated
entries contain random file IDs, original names/sizes/dates and individual
recovery-wrapped file keys. File blobs contain a fresh 12-byte nonce, padded
ciphertext and 16-byte GCM tag. Plaintext is padded to a minimum 4 KiB and then
4 KiB boundaries. File count and approximate sizes remain visible on disk.

The immutable vault fields are canonically serialized as associated data for the
index and recovery envelopes. File associated data additionally binds its file
ID. Changing the recovery public key, vault identity or environment breaks
authentication. Each recovery envelope uses ephemeral X25519, HKDF-SHA256 with
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

Current format-2 vaults use the same metadata and file keys after an application-only
firmware update. Preserve the token's NVS and the pairing config. Format 1 is
unsupported by the current vault UI. Choose an empty folder for new test vaults.
If the environment changes, the offline recovery code can export format-2 files.
See [flash provisioning](FLASH_ENCRYPTION.md) for hardware storage considerations.

## Validation

On Windows, `python -m pytest -q Python/tests` passed all 254 tests in 70.71 seconds.
The host tests exercise encrypted BLE responses, missing or forged approval,
single-tap mixed v7/v8 export, selection substitution, single-request batch imports, worker
cancellation, recovery, authenticated file output and the Qt interface. The v8
ESP32-CAM PlatformIO build uses 1,198,685 bytes of program flash and 39,580 bytes
of static RAM. The ESP32-CAM-MB used for these checks last ran v7. Validation of v8
covered compilation and scripted BLE exchanges. A live v8 import and an IO0-approved
export on that board are still pending.

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
