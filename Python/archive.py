"""
EnvStego - archive.py
Pack a folder into a single in-memory ZIP, and restore it safely.

Lets a whole folder be hidden in one stego image: the folder is zipped, the ZIP
becomes the payload, and on decrypt it is extracted back into a folder.

Extraction is hardened against "zip slip" — a crafted archive whose entry names
contain "..\\" or absolute paths to write files outside the chosen folder. Every
destination is checked to stay inside the target directory.
"""

import io
import os
import zipfile

__all__ = ["zip_folder", "safe_extract_zip", "is_zip"]


def zip_folder(folder_path: str) -> bytes:
    """
    Zip a folder (recursively) into bytes. Stored paths are relative to the folder
    itself (no top-level folder name), so the caller controls the restore folder.
    """
    folder_path = os.path.abspath(folder_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(folder_path):
            for name in files:
                full = os.path.join(root, name)
                arcname = os.path.relpath(full, folder_path)
                zf.write(full, arcname)
    return buf.getvalue()


def is_zip(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06"


def _is_within(base: str, target: str) -> bool:
    base = os.path.abspath(base)
    target = os.path.abspath(target)
    try:
        return os.path.commonpath([base, target]) == base
    except ValueError:
        # Raised when the paths are on different drives (e.g. C: vs D:) — not within.
        return False


# Cap on total decompressed size, so a malicious "zip bomb" payload cannot fill the
# disk. 4 GiB is far above any realistic folder a user would hide.
MAX_EXTRACTED_BYTES = 4 * 1024 ** 3


def safe_extract_zip(data: bytes, dest_dir: str) -> list[str]:
    """
    Extract ZIP bytes into dest_dir, refusing any entry that would escape it.

    Returns the list of files written. Raises ValueError on a path-traversal attempt,
    a malformed archive, or an archive that decompresses past MAX_EXTRACTED_BYTES.
    """
    os.makedirs(dest_dir, exist_ok=True)
    written = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ValueError(f"The recovered data is not a valid archive: {e}")

    # Fast reject on the declared sizes, then enforce the real total while writing
    # (in case the headers lie).
    if sum(i.file_size for i in zf.infolist()) > MAX_EXTRACTED_BYTES:
        raise ValueError("Archive decompresses to an unreasonable size (possible zip bomb).")
    extracted = 0

    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        parts = name.split("/")
        # Reject anything that is not a plain relative path: a leading "/" (absolute),
        # "//" (UNC), a ".." component, or any component carrying a drive letter such
        # as "C:" — on Windows os.path.join treats a drive-lettered component as a new
        # root, which can silently escape the destination.
        if (name.startswith("/")
                or ".." in parts
                or any(os.path.splitdrive(p)[0] for p in parts)):
            raise ValueError(f"Archive entry tries to escape the folder: {info.filename!r}")
        safe_parts = [p for p in parts if p not in ("", ".")]
        if not safe_parts:
            continue                       # "." / "" / bare separators address no file
        target = os.path.join(dest_dir, *safe_parts)
        if not _is_within(dest_dir, target):
            raise ValueError(f"Archive entry escapes the destination: {info.filename!r}")
        if name.endswith("/"):
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        # Stream in chunks so a lying header cannot force one huge read, and enforce
        # the running total against the cap.
        with zf.open(info) as src, open(target, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                extracted += len(chunk)
                if extracted > MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive decompresses to an unreasonable size (possible zip bomb).")
                dst.write(chunk)
        written.append(target)
    return written
