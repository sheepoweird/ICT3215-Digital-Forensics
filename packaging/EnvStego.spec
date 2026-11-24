# PyInstaller spec for the portable EnvStego build. Run through build.bat.
# One-folder, windowed. The exe also serves as the vault worker (--vault-worker),
# the JPEG worker (--jpeg-worker) and esptool (--esptool) child processes.

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

ROOT = Path(SPECPATH).parent
APP = ROOT / "Python"

datas = []
# jpeglib loads its libjpeg builds (cjpeglib_*.pyd) with ctypes from the jpeglib/cjpeglib
# folder, a namespace package that holds nothing else, so they must sit there on disk.
binaries = collect_dynamic_libs("jpeglib", search_patterns=["cjpeglib_*.pyd"])
# esptool's flasher stubs (JSON) for each chip.
datas += collect_data_files("esptool")

hiddenimports = [
    "vault_worker", "firmware_flasher", "jpeglib.cjpeglib",
    *collect_submodules("esptool"),
    *collect_submodules("bleak.backends.winrt"),
]

a = Analysis(
    [str(APP / "main.py")],
    pathex=[str(APP)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "tests"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="EnvStego",
    console=False,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="EnvStego", upx=False)
