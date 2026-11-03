"""
EnvStego - winutils.py
Small Windows / OS platform helpers, grouped in one place:

  • copy_file_times      — copy a file's timestamps onto another (blend-in dates)
  • timestomp            — reset a file's timestamps to a fixed generic value
  • shred_file           — overwrite a file's bytes, then delete it
  • wipe_free_space      — overwrite a volume's free space (cipher /w)
  • pictures_dir / downloads_dir — locate the user's standard folders
  • protect_str / unprotect_str  — DPAPI-seal small settings values

Each helper is best-effort and degrades gracefully off Windows. They are kept
together because they are all thin wrappers over OS / ctypes calls rather than
part of the crypto or steganography logic.

ICT3215 Digital Forensics — SIT
"""

import base64
import os

__all__ = [
    "copy_file_times", "timestomp",
    "shred_file", "wipe_free_space",
    "pictures_dir", "downloads_dir",
    "protect_str", "unprotect_str",
]


# ─── File timestamps ──────────────────────────────────────────────────────────
# A stego image saved fresh gets a brand-new modified/created date, which stands
# out in a timeline of older photos. Copying the carrier's timestamps onto the
# output lets it blend in. This changes only filesystem metadata, not contents.

def _windows_set_creation_time(path: str, mtime: float):
    import ctypes
    from ctypes import wintypes

    # Convert a Unix timestamp to a Windows FILETIME (100-ns ticks since 1601-01-01)
    ticks = int((mtime + 11644473600) * 10_000_000)
    ft = wintypes.FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)

    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.restype = wintypes.HANDLE
    handle = CreateFileW(str(path), GENERIC_WRITE, 0, None,
                         OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError()
    try:
        # Set the creation time only; leave access/write for os.utime
        if not ctypes.windll.kernel32.SetFileTime(handle, ctypes.byref(ft), None, None):
            raise ctypes.WinError()
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def copy_file_times(src: str, dst: str) -> bool:
    """
    Copy src's accessed, modified and (on Windows) created times onto dst.

    Returns True on success. Never raises: timestamp copying is cosmetic, so a
    failure (permissions, odd filesystem) must not break encryption.
    """
    try:
        st = os.stat(src)
        os.utime(dst, (st.st_atime, st.st_mtime))
        if os.name == "nt":
            try:
                _windows_set_creation_time(dst, st.st_mtime)
            except OSError:
                pass
        return True
    except OSError:
        return False


# A fixed, unremarkable timestamp (2001-09-09 01:46:40 UTC). Using a constant —
# rather than "now" or a random date — means a stomped remnant carries no useful
# timeline and does not stand out as freshly touched either.
_NEUTRAL_EPOCH = 1_000_000_000


def timestomp(path: str, when: float = _NEUTRAL_EPOCH) -> bool:
    """
    Reset a file's accessed/modified and (on Windows) created times to a fixed,
    generic value. Done just before deletion so the freed $MFT record leaves no
    meaningful timeline behind.

    HONEST LIMITATION: this changes the file's *current* timestamps only. NTFS
    also records the original create/modify/delete times in the change journal
    ($UsnJrnl) and transaction log ($LogFile); those are not reachable here, so a
    forensic timeline can still be reconstructed from them. Best-effort; never
    raises.
    """
    try:
        os.utime(path, (when, when))
        if os.name == "nt":
            try:
                _windows_set_creation_time(path, when)
            except OSError:
                pass
        return True
    except OSError:
        return False


# ─── Secure delete ────────────────────────────────────────────────────────────
# After encrypting, the original plaintext is still on disk; an ordinary delete
# only unlinks it. This overwrites the data first.
#
# HONEST LIMITATION: on SSDs, USB flash and other wear-levelling storage, an
# overwrite does not reliably reach the original cells, so recovery can still be
# possible. The only sure approach is never to write the plaintext to such a disk.
# The UI states this; this function does the best-effort overwrite.

def shred_file(path: str, passes: int = 3, neutralize_timeline: bool = True) -> bool:
    """Overwrite path with random data (passes times), truncate, then delete it.

    With neutralize_timeline (default), the file's timestamps are reset to a
    generic value before deletion so the freed directory/$MFT entry leaves no
    meaningful timeline. The original name is also removed by renaming to a random
    name before unlinking.

    Returns True on success. Returns False if the path is not a regular file.
    Raises OSError if the file exists but cannot be overwritten or removed.
    """
    if not os.path.isfile(path):
        return False
    length = os.path.getsize(path)
    with open(path, "r+b", buffering=0) as f:
        for _ in range(max(1, passes)):
            f.seek(0)
            remaining = length
            while remaining > 0:
                chunk = min(remaining, 1 << 20)      # 1 MB at a time for large files
                f.write(os.urandom(chunk))
                remaining -= chunk
            f.flush()
            os.fsync(f.fileno())
        f.seek(0)
        f.truncate(0)
        f.flush()
        os.fsync(f.fileno())

    if neutralize_timeline:
        timestomp(path)

    # Rename to a random name before unlinking so the original name is not left in
    # the directory entry.
    folder = os.path.dirname(path) or "."
    scratch = os.path.join(folder, os.urandom(8).hex())
    os.replace(path, scratch)
    os.remove(scratch)
    return True


# ─── Free-space wipe ───────────────────────────────────────────────────────────
# Shredding overwrites a file in place, but on NTFS the data may have been
# relocated (e.g. by defrag) and the freed clusters of earlier copies still hold
# plaintext. `cipher /w` overwrites all *free* space on the volume, clobbering
# those remnants. It needs no admin rights.
#
# HONEST LIMITATION: this is SLOW (it fills the free space three times) and is
# largely ineffective on SSD/flash, where wear-levelling means the physical cells
# are not the ones the OS can address. Offer it explicitly; never run it silently.

def wipe_free_space(folder: str, timeout: float | None = None) -> bool:
    """
    Overwrite the free space on the volume that contains `folder`, using Windows'
    built-in `cipher /w`. Returns True if the command ran and reported success.

    Returns False off Windows, if the folder does not exist, or if the command
    fails. Blocking and potentially very slow; callers should run it off the GUI
    thread and warn the user first.
    """
    if os.name != "nt" or not os.path.isdir(folder):
        return False
    import subprocess
    try:
        # CREATE_NO_WINDOW keeps the console cipher.exe would otherwise pop up hidden.
        proc = subprocess.run(
            ["cipher", f"/w:{folder}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000, timeout=timeout,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ─── User folders ─────────────────────────────────────────────────────────────
# Privacy mode saves outputs to these standard folders instead of remembering the
# exact paths you last used (those would reveal which image hides a payload).

_FOLDERID_Pictures = "{33E28130-4E1E-4676-835A-98395C3BC3BB}"
_FOLDERID_Downloads = "{374DE290-123F-4565-9164-39C4925E467B}"


def _known_folder(guid: str) -> str | None:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_byte * 8)]

        def __init__(self, s):
            super().__init__()
            s = s.strip("{}")
            parts = s.split("-")
            self.Data1 = int(parts[0], 16)
            self.Data2 = int(parts[1], 16)
            self.Data3 = int(parts[2], 16)
            rest = bytes.fromhex(parts[3] + parts[4])
            for i in range(8):
                self.Data4[i] = rest[i]

    path_ptr = ctypes.c_wchar_p()
    res = ctypes.windll.shell32.SHGetKnownFolderPath(
        ctypes.byref(GUID(guid)), 0, None, ctypes.byref(path_ptr))
    if res != 0:
        return None
    try:
        return path_ptr.value
    finally:
        ctypes.windll.ole32.CoTaskMemFree(path_ptr)


def _resolve(guid: str, fallback_name: str) -> str:
    """Known folder on Windows, else ~/<fallback_name>, else the home folder."""
    if os.name == "nt":
        try:
            path = _known_folder(guid)
            if path and os.path.isdir(path):
                return path
        except Exception:
            pass
    guess = os.path.join(os.path.expanduser("~"), fallback_name)
    return guess if os.path.isdir(guess) else os.path.expanduser("~")


def pictures_dir() -> str:
    return _resolve(_FOLDERID_Pictures, "Pictures")


def downloads_dir() -> str:
    return _resolve(_FOLDERID_Downloads, "Downloads")


# ─── Settings sealing (DPAPI) ─────────────────────────────────────────────────
# The saved signal selection and presets name the exact environment a payload is
# bound to. On Windows they are sealed with DPAPI (tied to the Windows account);
# elsewhere stored as-is. Reads tolerate the old plaintext format.

_PREFIX = "dpapi1:"
_ENTROPY = b"EnvStego-settings"


def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b):
        buf = ctypes.create_string_buffer(b, len(b))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    in_blob, _b1 = blob(data)
    ent_blob, _b2 = blob(_ENTROPY)
    out = BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(in_blob), None, ctypes.byref(ent_blob), None, None, 0x01, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def protect_str(text: str) -> str:
    """Return a sealed form of text (prefixed), or the plain text if sealing is unavailable."""
    if os.name != "nt" or text == "":
        return text
    try:
        return _PREFIX + base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode()
    except OSError:
        return text


def unprotect_str(stored: str) -> str:
    """Inverse of protect_str. Unprefixed values are returned unchanged (old format)."""
    if not stored.startswith(_PREFIX):
        return stored
    try:
        return _dpapi(base64.b64decode(stored[len(_PREFIX):]), False).decode("utf-8")
    except (OSError, ValueError):
        return ""
