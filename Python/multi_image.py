"""
EnvStego - multi_image.py
Split one v3 payload blob across several PNG carriers, and rejoin it.

A payload too large for a single carrier is sharded across a set of images.
Each carrier stores a token-encrypted shard tag (which set it belongs to, its
position and its length) followed by its slice of the blob. Reassembly needs the
token (to read the tags) and every shard of the set; nothing on disk marks the
images as related, and each one looks like ordinary LSB noise on its own.

These helpers are token-agnostic: they take the already-derived `index_key`, so
they can be tested with a stand-in key without any BLE round-trip.

ICT3215 Digital Forensics — SIT
"""

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag

import crypto_engine as ce
import media


def usable_capacity(carrier_path: str) -> int:
    """Payload bytes a carrier can hold once its shard tag is accounted for."""
    return media.lsb_capacity_bytes(carrier_path) - ce.SHARD_OUTER_SIZE


def total_capacity(carriers: list[str]) -> int:
    """Combined usable capacity of a set of carriers (ignoring any too small to help)."""
    return sum(max(0, usable_capacity(c)) for c in carriers)


def split_embed(index_key: bytes, blob: bytes, carriers: list[str],
                output_paths: list[str], match_timestamps: bool = False) -> list[str]:
    """
    Embed `blob` across `carriers`, writing one stego PNG per used carrier.

    Carriers are filled in order; a carrier too small to hold even one byte after
    its tag is skipped. Returns the list of output paths actually written.
    Raises ValueError if the carriers cannot hold the whole blob.
    """
    if len(carriers) != len(output_paths):
        raise ValueError("Each carrier needs a matching output path.")
    if len(carriers) < 2:
        raise ValueError("Multi-image split needs at least two carrier images.")

    caps = [usable_capacity(c) for c in carriers]
    if sum(max(0, c) for c in caps) < len(blob):
        raise ValueError(
            f"The chosen images cannot hold this payload.\n"
            f"  Payload needs:   {len(blob):,} bytes\n"
            f"  Images hold:     {sum(max(0, c) for c in caps):,} bytes total\n"
            f"  Add more or larger carrier images."
        )

    # Assign slices sequentially, skipping carriers with no usable room.
    plan: list[tuple[str, str, bytes]] = []
    remaining = blob
    for carrier, cap, outp in zip(carriers, caps, output_paths):
        if not remaining:
            break
        if cap <= 0:
            continue
        take = min(cap, len(remaining))
        plan.append((carrier, outp, remaining[:take]))
        remaining = remaining[take:]
    if remaining:
        # Shouldn't happen after the capacity check, but guard anyway.
        raise ValueError("Internal error: payload did not fit after planning.")

    total = len(plan)
    manifest = ce.new_manifest_id()
    written: list[str] = []
    for index, (carrier, outp, chunk) in enumerate(plan):
        tag = ce.pack_shard_tag(index_key, manifest, index, total, len(chunk))
        written.append(media.embed_blob(carrier, tag + chunk, outp,
                                     match_timestamps=match_timestamps))
    return written


def inspect_shard(index_key: bytes, stego_path: str) -> tuple[bytes, int, int, int]:
    """Read and decrypt one image's shard tag. Raises InvalidTag if it is not a shard."""
    cap = media.lsb_capacity_bytes(stego_path)
    if cap < ce.SHARD_OUTER_SIZE:
        raise InvalidTag()
    head = media.extract_lsb_bytes(stego_path, ce.SHARD_OUTER_SIZE)
    return ce.unpack_shard_tag(index_key, head)


def join_extract(index_key: bytes, stego_paths: list[str]) -> bytes:
    """
    Read the shard tag from each image, regroup by manifest id, order and
    concatenate the slices. Returns the reassembled blob.

    Raises ValueError with a readable message if the images are not a single
    complete set, or InvalidTag if an image is not a shard / the token is wrong.
    """
    if not stego_paths:
        raise ValueError("No images selected.")

    # manifest -> {index: (path, total, shard_len)}
    sets: dict[bytes, dict[int, tuple[str, int, int]]] = {}
    for p in stego_paths:
        manifest, index, total, slen = inspect_shard(index_key, p)
        sets.setdefault(manifest, {})[index] = (p, total, slen)

    if len(sets) != 1:
        raise ValueError(
            "These images belong to different payloads. Select only the images "
            "that make up one hidden file."
        )

    parts = next(iter(sets.values()))
    totals = {t for (_p, t, _s) in parts.values()}
    if len(totals) != 1:
        raise ValueError("The images disagree on how many pieces the set has — one may be corrupted.")
    total = next(iter(totals))

    missing = [i for i in range(total) if i not in parts]
    if missing:
        shown = ", ".join(f"#{i + 1}" for i in missing[:8]) + ("…" if len(missing) > 8 else "")
        raise ValueError(
            f"Incomplete set — this payload is split across {total} images and "
            f"{len(missing)} {'is' if len(missing) == 1 else 'are'} missing "
            f"(piece{'s' if len(missing) != 1 else ''} {shown}).\n"
            f"Select all {total} images to recover it."
        )

    blob = bytearray()
    for i in range(total):
        path, _t, slen = parts[i]
        data = media.extract_lsb_bytes(path, ce.SHARD_OUTER_SIZE + slen)[ce.SHARD_OUTER_SIZE:]
        blob += data
    return bytes(blob)


def suggest_outputs(carriers: list[str], out_dir: str) -> list[str]:
    """Default stego output names for a set: <out_dir>/<carrier stem>_stego.png (de-duplicated)."""
    out: list[str] = []
    seen: set[str] = set()
    for c in carriers:
        stem = Path(c).stem
        suffix = media.output_suffix(c)       # .png or .wav, matching the carrier
        name = f"{stem}_stego{suffix}"
        i = 1
        while name.lower() in seen:
            name = f"{stem}_stego ({i}){suffix}"
            i += 1
        seen.add(name.lower())
        out.append(str(Path(out_dir) / name))
    return out
