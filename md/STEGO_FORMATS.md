# Native carrier formats

Implemented 2026-11-18. All JPEG logic is inside `Python/stego_engine.py`, including
its isolated codec entry point. `media.py` dispatches capacity, embedding,
extraction and output naming. Existing payload AES-GCM, encrypted headers, token
operations, environment derivation and vault format are unchanged. No ESP32
firmware update is needed for this desktop change.

## Supported behavior

| Carrier | Output | Method |
| --- | --- | --- |
| JPEG / JFIF | Same JPEG extension | Parity of eligible quantized AC coefficients |
| PNG | PNG | RGB low bits, optimized lossless encoding |
| WebP, lossy or lossless input | Lossless WebP | RGB low bits; exact transparent RGB preservation |
| BMP | BMP | RGB low bits |
| Single-page TIFF | TIFF | RGB low bits; lossless Deflate compression |
| Single-frame GIF | PNG | Decoded RGB low bits; native palette embedding is not implemented |
| WAV, MP3, FLAC, Ogg, Opus, AIFF | WAV | Existing PCM sample low-bit method; compressed inputs decode to 16-bit PCM |

Still images only; animated or multipage input remains unsupported. Pixel methods
normalize input to 8-bit RGB/RGBA and can change palette/bit-depth representation.
JPEG supports grayscale and RGB/YCbCr images; CMYK/MPO and other JPEG variants are
rejected. Progressive JPEG inputs are currently written as baseline JPEG. EXIF
orientation, ICC profiles and JPEG quantization/sampling tables are retained in
the tested cases, but byte-identical headers/encoding layout are not promised.
Pixel formats normalize EXIF orientation before embedding, except the existing
PNG path. Lossless WebP can be larger than a lossy source even with the same
extension. BMP/TIFF sizes depend on their pixel mode and compression.

## JPEG algorithm and stable capacity

The library reads existing quantized coefficients and writes them back directly,
avoiding a decode-to-pixels/recompression cycle. The eligible slots are AC
coefficients with absolute magnitude at least 2 (excluding the int16 extreme).
DC, zero and +/-1 coefficients are never changed. Bits are embedded by mapping
even/odd magnitude pairs such as `(2,3)` and `(4,5)` while preserving signs. Each
change is at most one coefficient unit and leaves slot eligibility unchanged.

Eligible slots across components form a deterministic stream. With the token index
key, their order is shuffled using the separate `EnvStego-jpeg-scatter-v1` domain.
The existing `EnvStego-scatter-v1` pixel order is unchanged for old PNG/WAV files.
Capacity is `floor(eligible_slots / 8)`, before the existing encrypted header and
per-shard overhead. Smooth JPEGs can have very little or no usable capacity.

The encrypted payload/header format is unchanged. A new JPEG is read back from
disk and its embedded bytes and quantization tables verified before atomic
publication. Output paths may not resolve to a source carrier. Failed writes,
native-code failures and timeouts do not publish an output or overwrite an
existing target. Source carriers are copied/read and are not rewritten.

This is a straightforward coefficient-parity method with keyed ordering. It is
**not an implementation of UNIWARD/F5**, and statistical resistance to steganalysis
has not been established. Preserving format and approximate size addresses the
conversion artifact; it does not guarantee undetectability or robustness against
recompression, cropping, resizing, editing or messaging-platform processing.

## Process boundary and dependencies

`jpeglib==1.0.2` is pinned, with its bundled libjpeg **9f** explicitly selected
instead of the library's default 6b. Installation uses a prebuilt Windows abi3
wheel in this project's `.venv`. JPEG native operations run in a short-lived
subprocess because the native codec can terminate on malformed input. The worker
has a 60-second timeout, and its temporary directory also contains the library's
temporary copies. Keys are passed on stdin, not command-line arguments. Cleanup
is best effort after application/OS crashes. A subprocess is crash isolation,
**not an OS security sandbox** or a fix for native-library vulnerabilities.

Frozen builds use `main.py --jpeg-worker` before Qt initialization. Windowed worker
stream restoration is shared with the vault worker in `winutils.py`. Bundling
must include jpeglib's DLLs (including 9f); no packaged executable was built or
validated for this change.

## Multiple carriers and compatibility

The splitter still uses every usable selected carrier and balances payload bytes
as capacities allow. Mixed JPEG/WebP/PNG/WAV sets use each format's own capacity
and method, while retaining the same encrypted manifest and ordering. The GUI
passes the complete generated set to Decrypt. All pieces of a real split set
remain necessary. Old one-piece split outputs and existing v3 PNG/WAV files remain
readable. Images in the pre-v3 "ENV2" format are no longer supported. New JPEG output must be generated
by encryption; renaming a previous PNG is not sufficient.

## Validation

Windows checks on 2026-11-18 (the current full suite is 279 tests, last passed
2026-11-28; see `md/TESTING.md`):

- `python -m pytest Python/tests -q`: **246 passed in 69.02 seconds**.
- `pip check`: no broken requirements.
- `git diff --check`: no whitespace errors.
- Targeted Bandit scan of the image engine, dispatcher, UI, worker entry points
  and platform helpers: **0 medium/high and 10 low findings**. These include
  subprocess calls/imports, existing Explorer/cipher path lookup and cleanup
  exception handlers. Codec workers use a fixed interpreter/script with no shell;
  keys are sent on stdin. This is not a dependency-CVE or steganalysis assessment.

Tests exercise real native JPEG coefficient I/O in subprocesses, with simulated
token keys for cryptographic/UI flows. They cover:

- Grayscale/colour, baseline/progressive input, sampling factors, quantization
  tables, EXIF/ICC retention and coefficient changes bounded to +/-1.
- Full-capacity JPEG recovery, stable eligible-slot counts, wrong ordering keys,
  smooth images with no capacity and Unicode source/output filenames.
- Malformed images, simulated native-worker death, existing-output preservation,
  temporary-directory cleanup and redirected windowed-worker handles.
- WebP with fully transparent pixels, alpha preservation and exact hidden bytes.
- Single-file JPEG/WebP/BMP/TIFF UI encryption/decryption and mixed-format split
  recovery, alongside all existing PNG/WAV, crypto, pairing and vault regressions.

Actual-carrier checks on 2026-11-18 used 4,096 test bytes per image, not the user's
secret files, and random stand-in ordering keys. Originals were hash-checked:

| Source | Original bytes | Native JPEG bytes | Usable bytes before header/shard overhead |
| --- | ---: | ---: | ---: |
| `_DSC0003.jpg` | 6,621,504 | 6,621,532 | 510,390 |
| `car.jpg` | 224,273 | 224,276 | 18,165 |

Both recovered byte-for-byte. Sizes can vary slightly with payload and stuffing.
The ignored helper `build/validate_native_carriers.py` writes test outputs only
under `build/native-carrier-validation/`. These results are not a measurement of
steganalysis resistance, nor a new live ESP32 pairing/protocol test.

### Real-encoder round trips (2026-11-22)

Carriers were produced by real encoders (ffmpeg with libwebp, LAME, libvorbis, libopus)
from one photograph and an 8-second stereo tone with noise. Each was run through the
app's own header, payload encryption and `media.embed_blob`/`read_lsb_all` path with
random stand-in token keys. Every carrier recovered its payload exactly, rejected a
different ordering/index key, and left its source file unchanged.

| Input | Output | Input bytes | Output bytes | Capacity (bytes) |
| --- | --- | ---: | ---: | ---: |
| JPEG, colour | `.jpg` | 44,315 | 46,109 | 3,027 |
| JPEG, ffmpeg `-q:v 3` | `.jpeg` | 49,077 | 54,499 | 4,979 |
| JPEG, greyscale | `.jpg` | 47,293 | 51,816 | 2,753 |
| PNG | `.png` | 357,982 | 391,666 | 114,581 |
| WebP, lossy | `.webp` (lossless) | 39,696 | 279,044 | 114,581 |
| WebP, lossless | `.webp` | 266,848 | 279,618 | 114,581 |
| BMP | `.bmp` | 918,054 | 918,054 | 114,581 |
| TIFF | `.tiff` | 443,372 | 546,174 | 114,581 |
| GIF | `.png` | 125,047 | 251,728 | 114,581 |
| MP3, 192 kbit/s | `.wav` | 193,767 | 1,411,244 | 88,200 |
| FLAC | `.wav` | 845,731 | 1,411,244 | 88,200 |
| Ogg Vorbis | `.wav` | 81,809 | 1,411,244 | 88,200 |
| Opus, 48 kHz | `.wav` | 73,513 | 1,536,044 | 96,000 |
| AIFF | `.wav` | 1,411,254 | 1,411,244 | 88,200 |
| WAV | `.wav` | 1,411,278 | 1,411,244 | 88,200 |

A 30,000-byte payload split across a JPEG, a lossy WebP and an MP3 produced `.jpg`,
`.webp` and `.wav` pieces. It recovered with the pieces supplied in reverse order and
was rejected when one piece was missing. A JPEG file saved with a `.png` extension is
handled by content and written as PNG.

On 2026-11-24 the full suite passed **242 tests** (after removing the obsolete v1 vault and ENV2 code), and Bandit over `Python/` (tests
excluded) reported **0 medium/high and 16 low** findings. After the vault format 3 changes
(2026-11-25) the suite has **279 tests**, all passing, and Bandit reports **0 medium/high
and 18 low**.

## Sources

- [jpeglib usage and coefficient I/O](https://jpeglib.readthedocs.io/en/latest/usage.html)
- [jpeglib reference, including native error behavior](https://jpeglib.readthedocs.io/en/latest/reference.html)
- [jpeglib 1.0.2 distribution](https://pypi.org/project/jpeglib/1.0.2/)
- [Pillow WebP lossless and exact options](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html#webp)
