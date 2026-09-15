"""
EnvStego - signals.py
Environment signal collection module.
Each collector returns an EnvSignal dataclass with id, name, value, availability.

Team member: Environmental Profiling Engine
ICT3215 Digital Forensics — SIT
"""

import subprocess
import ctypes
import winreg
import socket
import hashlib
import os
import re
import sys
import shutil
import functools
from dataclasses import dataclass, field
from typing import Optional, Tuple


# ─── DATA CLASS ─────────────────────────────────────────────────────────────

@dataclass
class EnvSignal:
    id: str
    name: str
    category: str           # "Hardware", "Network", "OS"
    description: str
    stability: int          # 1–10 (10 = never changes)
    value: Optional[str] = None
    available: bool = False
    error: Optional[str] = None


# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

# Suppress the console window that would otherwise flash on every subprocess
# call. Only meaningful on Windows; guarded so the module still imports if this
# file is ever inspected on another platform.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _system_root() -> str:
    """Windows directory, resolved from the environment rather than assumed."""
    return os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"


def _system32() -> str:
    """
    Real 64-bit System32 for this process.

    A 32-bit Python on 64-bit Windows is transparently redirected from
    System32 to SysWOW64 by the WOW64 filesystem redirector. 'Sysnative' is
    the virtual escape hatch back to the true 64-bit System32, and it only
    exists for 32-bit processes — which is why it is checked first and only
    when this interpreter is 32-bit.
    """
    root = _system_root()
    if sys.maxsize <= 2 ** 32:
        sysnative = os.path.join(root, "Sysnative")
        if os.path.isdir(sysnative):
            return sysnative
    return os.path.join(root, "System32")


@functools.lru_cache(maxsize=1)
def _find_powershell() -> Optional[str]:
    """
    Locate a PowerShell interpreter WITHOUT relying on PATH.

    Some systems do not have %SystemRoot%\\System32\\WindowsPowerShell\\v1.0 on
    PATH — it gets trimmed, truncated by the legacy 2047-char PATH limit, or
    stripped by the launching environment (services, scheduled tasks, some IDE
    terminals). In that case bare "powershell" raises FileNotFoundError even
    though PowerShell is perfectly healthy and works when typed by hand.

    Resolution order: Windows PowerShell 5.1 at its canonical location, then
    PowerShell 7+, then PATH as a last resort.
    """
    candidates = [
        os.path.join(_system32(), "WindowsPowerShell", "v1.0", "powershell.exe"),
        os.path.join(_system_root(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                     "PowerShell", "7", "pwsh.exe"),
        os.path.join(os.environ.get("ProgramW6432", r"C:\Program Files"),
                     "PowerShell", "7", "pwsh.exe"),
        os.path.join(_system_root(), "SysWOW64", "WindowsPowerShell", "v1.0", "powershell.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return shutil.which("powershell") or shutil.which("pwsh")


@functools.lru_cache(maxsize=None)
def _find_exe(name: str) -> Optional[str]:
    """
    Resolve a Windows system executable (netsh, ipconfig, arp, ping, certutil)
    to an absolute path without depending on PATH, for the same reason as
    _find_powershell above.
    """
    direct = os.path.join(_system32(), name)
    if os.path.isfile(direct):
        return direct
    fallback = os.path.join(_system_root(), "System32", name)
    if os.path.isfile(fallback):
        return fallback
    return shutil.which(name)


def _run_cmd_ex(cmd: list, timeout: int = 10) -> Tuple[str, str, int]:
    """
    Run a system command. Returns (stdout, stderr, returncode).

    cmd[0] is resolved to an absolute path so a missing PATH entry cannot make
    a working tool look like a missing signal. returncode -1 means the process
    never ran (not found, timed out, or raised).
    """
    if not cmd:
        return "", "empty command", -1

    exe = _find_exe(cmd[0])
    if exe is None:
        return "", f"'{cmd[0]}' not found on this system", -1

    try:
        result = subprocess.run(
            [exe] + list(cmd[1:]),
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            creationflags=_NO_WINDOW,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"'{cmd[0]}' timed out after {timeout}s", -1
    except Exception as e:
        return "", f"{type(e).__name__}: {e}", -1


def _run_ps_ex(cmd: str, timeout: int = 12) -> Tuple[str, str, int]:
    """
    Run a PowerShell command. Returns (stdout, stderr, returncode).

    returncode -1 means PowerShell itself could not be launched, which is a
    very different failure from "the query ran and returned nothing".
    """
    exe = _find_powershell()
    if exe is None:
        return "", "No PowerShell interpreter found on this system", -1

    try:
        result = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            creationflags=_NO_WINDOW,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"PowerShell timed out after {timeout}s", -1
    except Exception as e:
        return "", f"{type(e).__name__}: {e}", -1


def _run_cmd(cmd: list, timeout: int = 10) -> str:
    """Run a system command, return stdout or empty string on failure."""
    return _run_cmd_ex(cmd, timeout)[0]


def _run_ps(cmd: str, timeout: int = 12) -> str:
    """Run a PowerShell command, return stdout or empty string on failure."""
    return _run_ps_ex(cmd, timeout)[0]


def _ps_error(err: str, rc: int, fallback: str) -> str:
    """Build a signal error message that distinguishes launch failure from
    an empty-but-successful query."""
    if rc == -1:
        return f"PowerShell unavailable: {err}"
    if rc != 0 or err:
        return f"Query failed (rc={rc}): {err or 'no stderr output'}"
    return fallback


def _clean_lines(output: str, skip_headers: list = None) -> list:
    """Split output into non-empty lines, removing header words."""
    skip = {h.lower() for h in (skip_headers or [])}
    return [
        ln.strip() for ln in output.splitlines()
        if ln.strip() and ln.strip().lower() not in skip
    ]


# ─── HARDWARE SIGNALS ────────────────────────────────────────────────────────

def collect_motherboard_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_mobo", "Motherboard Serial", "Hardware",
        "OEM-programmed mainboard serial number from SMBIOS table", 9
    )
    try:
        # @(...)[0] forces a single value: some boards (and most VMs) expose
        # more than one Win32_BaseBoard instance, which would otherwise come
        # back as a multi-line string.
        out, err, rc = _run_ps_ex(
            "@(Get-CimInstance Win32_BaseBoard | "
            "Select-Object -ExpandProperty SerialNumber)[0]"
        )
        val = out.strip()
        invalid = {"to be filled by o.e.m.", "default string", "none",
                   "n/a", "unknown", "system serial number", ""}
        if rc == 0 and val and val.lower() not in invalid:
            sig.value = val
            sig.available = True
        else:
            sig.error = _ps_error(
                err, rc,
                "OEM did not program a serial (common on consumer boards)"
            )
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_cpu_id() -> EnvSignal:
    sig = EnvSignal(
        "hw_cpu", "CPU Processor ID", "Hardware",
        "CPU-embedded unique ID from the CPUID instruction", 8
    )
    try:
        out, err, rc = _run_ps_ex(
            "@(Get-CimInstance Win32_Processor | "
            "Select-Object -ExpandProperty ProcessorId)[0]"
        )
        val = out.strip()
        if rc == 0 and val:
            sig.value = val
            sig.available = True
        else:
            sig.error = _ps_error(err, rc, "No CPU ID returned")
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_disk_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_disk", "Primary HDD/SSD Serial", "Hardware",
        "Physical serial number of the primary storage device", 9
    )
    try:
        out, err, rc = _run_ps_ex(
            "Get-CimInstance Win32_DiskDrive | Sort-Object Index | "
            "Select-Object -First 1 -ExpandProperty SerialNumber"
        )
        val = out.strip()
        if rc == 0 and val:
            sig.value = val
            sig.available = True
        else:
            sig.error = _ps_error(err, rc, "No disk serial returned")
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_bios_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_bios", "BIOS Serial Number", "Hardware",
        "BIOS/UEFI firmware serial number from SMBIOS", 8
    )
    try:
        out, err, rc = _run_ps_ex(
            "@(Get-CimInstance Win32_BIOS | "
            "Select-Object -ExpandProperty SerialNumber)[0]"
        )
        val = out.strip()
        invalid = {"to be filled by o.e.m.", "default string", "none",
                   "n/a", "unknown", "system serial number", ""}
        if rc == 0 and val and val.lower() not in invalid:
            sig.value = val
            sig.available = True
        else:
            sig.error = _ps_error(
                err, rc, "BIOS serial is generic or not programmed"
            )
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_gpu_id() -> EnvSignal:
    sig = EnvSignal(
        "hw_gpu", "GPU Device ID(s)", "Hardware",
        "Graphics card PnP hardware device identifier", 7
    )
    try:
        out, err, rc = _run_ps_ex(
            "Get-CimInstance Win32_VideoController | "
            "Select-Object -ExpandProperty PNPDeviceID"
        )
        ids = sorted(set(_clean_lines(out, ["pnpdeviceid"])))
        if rc == 0 and ids:
            sig.value = "|".join(ids)
            sig.available = True
        else:
            sig.error = _ps_error(err, rc, "No GPU IDs found")
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_volume_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_volume", "C: Volume Serial Number", "Hardware",
        "Assigned at NTFS format time — absent on forensic clones", 10
    )
    try:
        serial = ctypes.c_ulong(0)
        result = ctypes.windll.kernel32.GetVolumeInformationW(
            "C:\\", None, 0, ctypes.byref(serial), None, None, None, 0
        )
        if result:
            sig.value = f"{serial.value:08X}"
            sig.available = True
        else:
            sig.error = "GetVolumeInformationW returned 0"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_battery() -> EnvSignal:
    sig = EnvSignal(
        "hw_battery", "Battery Design Capacity", "Hardware",
        "Laptop battery mWh — unique per aging cell chemistry", 6
    )
    try:
        out, err, rc = _run_ps_ex(
            "Get-CimInstance Win32_Battery | "
            "Select-Object -ExpandProperty DesignCapacity"
        )
        lines = _clean_lines(out, ["designcapacity"])
        if rc == 0 and lines and lines[0].isdigit():
            sig.value = lines[0]
            sig.available = True
        else:
            sig.error = _ps_error(err, rc, "No battery found (desktop PC, or VM)")
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_ram_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_ram", "RAM DIMM Serial(s)", "Hardware",
        "Physical DRAM module serial numbers from SPD data", 8
    )
    try:
        out, err, rc = _run_ps_ex(
            "Get-CimInstance Win32_PhysicalMemory | "
            "Select-Object -ExpandProperty SerialNumber"
        )
        serials = [
            s for s in _clean_lines(out, ["serialnumber"])
            if s and s.lower() not in ("00000000", "unknown", "none")
        ]
        if rc == 0 and serials:
            sig.value = "|".join(sorted(serials))
            sig.available = True
        else:
            sig.error = _ps_error(
                err, rc, "RAM serials not populated (requires BIOS support)"
            )
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_monitor_edid() -> EnvSignal:
    sig = EnvSignal(
        "hw_edid", "Monitor EDID Hash", "Hardware",
        "Display hardware ROM identifier — unique per physical monitor", 7
    )
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\DISPLAY"
        )
        monitors = []
        i = 0
        while True:
            try:
                monitors.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        if monitors:
            combined = "|".join(sorted(monitors))
            sig.value = hashlib.sha256(combined.encode()).hexdigest()[:20]
            sig.available = True
        else:
            sig.error = "No display entries in registry"
    except Exception as e:
        sig.error = str(e)
    return sig


# ─── NETWORK SIGNALS ─────────────────────────────────────────────────────────

def collect_router_bssid() -> EnvSignal:
    sig = EnvSignal(
        "net_bssid", "Connected AP BSSID", "Network",
        "MAC address of the Wi-Fi access point you are currently connected to", 8
    )
    try:
        # Use 'show interfaces' not 'show networks' — reads only the AP you are
        # actually associated with. Scanning all visible networks is unstable
        # because neighbouring APs appear/disappear between scans.
        out, err, rc = _run_cmd_ex(["netsh.exe", "wlan", "show", "interfaces"])
        match = re.search(r'BSSID\s*:\s*([\da-fA-F:]{17})', out)
        if match:
            sig.value = match.group(1).lower()
            sig.available = True
        elif rc == -1:
            sig.error = f"netsh unavailable: {err}"
        else:
            sig.error = "Not connected to a Wi-Fi network (or no Wi-Fi adapter)"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_ipv6_linklocal() -> EnvSignal:
    sig = EnvSignal(
        "net_ipv6", "IPv6 Link-Local Address", "Network",
        "Derived from NIC MAC via EUI-64 — hardware-bound and stable", 9
    )
    try:
        addrs = []
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0]
            if addr.lower().startswith("fe80"):
                addrs.append(addr.split("%")[0].lower())
        if addrs:
            sig.value = "|".join(sorted(set(addrs)))
            sig.available = True
        else:
            # Fallback: enumerate interfaces
            out, err, rc = _run_ps_ex(
                "Get-NetIPAddress -AddressFamily IPv6 | "
                "Where-Object { $_.IPAddress -like 'fe80*' } | "
                "Select-Object -ExpandProperty IPAddress"
            )
            addrs = [
                a.split("%")[0].lower() for a in _clean_lines(out, ["ipaddress"])
                if a.lower().startswith("fe80")
            ]
            if addrs:
                sig.value = "|".join(sorted(set(addrs)))
                sig.available = True
            else:
                sig.error = _ps_error(
                    err, rc, "No IPv6 link-local addresses found"
                )
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_adapter_guid() -> EnvSignal:
    sig = EnvSignal(
        "net_adapterguid", "Network Adapter GUID(s)", "Network",
        "Registry GUIDs assigned at NIC driver installation — installation-unique", 8
    )
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Network"
            r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        )
        guids = []
        i = 0
        while True:
            try:
                guids.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        if guids:
            sig.value = "|".join(sorted(guids))
            sig.available = True
        else:
            sig.error = "No adapter GUIDs in registry"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_gateway_mac() -> EnvSignal:
    sig = EnvSignal(
        "net_gatewaymac", "Default Gateway MAC", "Network",
        "Physical MAC of your router — stable across reconnections", 8
    )
    try:
        # Get default gateway IP first
        ipcfg, err, rc = _run_cmd_ex(["ipconfig.exe"])
        if rc == -1:
            sig.error = f"ipconfig unavailable: {err}"
            return sig
        gw_match = re.search(r'Default Gateway[^:]*:\s*([\d.]+)', ipcfg)
        if not gw_match:
            sig.error = "No default gateway in ipconfig"
            return sig
        gw_ip = gw_match.group(1)
        # Ping once to ensure ARP cache is populated
        _run_cmd(["ping.exe", "-n", "1", "-w", "500", gw_ip], timeout=5)
        # Look up that specific IP in ARP table
        arp_out = _run_cmd(["arp.exe", "-a", gw_ip])
        mac_match = re.search(r'([\da-fA-F]{2}[-:]){5}[\da-fA-F]{2}', arp_out)
        if mac_match:
            sig.value = mac_match.group(0).lower().replace("-", ":")
            sig.available = True
        else:
            sig.error = f"Gateway {gw_ip} not found in ARP table"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_dns_servers() -> EnvSignal:
    sig = EnvSignal(
        "net_dns", "DNS Server IPs", "Network",
        "DNS resolvers — typically your home/office router", 6
    )
    try:
        out, err, rc = _run_cmd_ex(["ipconfig.exe", "/all"])
        servers = sorted(set(re.findall(
            r'DNS Servers[^:]*:\s*([\d.]+)', out
        )))
        if servers:
            sig.value = ",".join(servers)
            sig.available = True
        elif rc == -1:
            sig.error = f"ipconfig unavailable: {err}"
        else:
            sig.error = "No DNS servers found in ipconfig"
    except Exception as e:
        sig.error = str(e)
    return sig


# ─── OS SIGNALS ──────────────────────────────────────────────────────────────

def collect_machine_guid() -> EnvSignal:
    sig = EnvSignal(
        "os_machineguid", "Windows Machine GUID", "OS",
        "Unique GUID generated during Windows installation — never changes", 10
    )
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        )
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        sig.value = guid
        sig.available = True
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_machine_sid() -> EnvSignal:
    sig = EnvSignal(
        "os_machinesid", "Machine Security Identifier", "OS",
        "Cryptographically unique SID assigned at Windows install time", 9
    )
    try:
        username = os.getenv("USERNAME", "")
        if not username:
            sig.error = "USERNAME not set in environment"
            return sig

        # Escape single quotes for the PowerShell string literal. Without this,
        # a username containing an apostrophe breaks the -Filter expression.
        safe_user = username.replace("'", "''")
        out, err, rc = _run_ps_ex(
            "@(Get-CimInstance Win32_UserAccount -Filter "
            f"\"LocalAccount=True AND Name='{safe_user}'\" | "
            "Select-Object -ExpandProperty SID)[0]"
        )
        val = out.strip()
        if rc == 0 and val.startswith("S-1-5-21"):
            # Strip the trailing RID to leave the machine SID.
            sig.value = "-".join(val.split("-")[:-1])
            sig.available = True
        else:
            sig.error = _ps_error(
                err, rc,
                "Could not retrieve a local machine SID "
                "(domain or Microsoft account?)"
            )
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_install_date() -> EnvSignal:
    sig = EnvSignal(
        "os_installdate", "Windows Install Timestamp", "OS",
        "Unix timestamp of the original Windows OS installation", 8
    )
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        install_date, _ = winreg.QueryValueEx(key, "InstallDate")
        sig.value = str(install_date)
        sig.available = True
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_usb_history() -> EnvSignal:
    sig = EnvSignal(
        "os_usbhistory", "USB Device History Hash", "OS",
        "Hash of all USB devices ever connected — machine forensic fingerprint", 8
    )
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        )
        devices = []
        i = 0
        while True:
            try:
                devices.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        if devices:
            combined = "|".join(sorted(devices))
            sig.value = hashlib.sha256(combined.encode()).hexdigest()[:24]
            sig.available = True
        else:
            sig.error = "No USB device history in registry"
    except FileNotFoundError:
        # USBSTOR only exists once a USB mass-storage device has been attached.
        sig.error = "No USBSTOR key (no USB storage device ever connected)"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_prefetch_seed() -> EnvSignal:
    sig = EnvSignal(
        "os_prefetchseed", "OS Build & Patch String", "OS",
        "Windows build number + UBR — unique per exact patch state", 7
    )
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        build, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
        try:
            ubr, _ = winreg.QueryValueEx(key, "UBR")
            sig.value = f"{build}.{ubr}"
        except FileNotFoundError:
            sig.value = str(build)
        sig.available = True
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_cert_thumbprints() -> EnvSignal:
    sig = EnvSignal(
        "os_certs", "Root Certificate Store Hash", "OS",
        "Hash of installed root cert thumbprints — unique per machine history", 7
    )
    try:
        out, err, rc = _run_cmd_ex(["certutil.exe", "-store", "root"], timeout=20)
        thumbprints = sorted(set(re.findall(
            r'Cert Hash\(sha1\)\s*:\s*([\da-fA-F ]{47,59})', out
        )))
        if thumbprints:
            combined = "|".join(t.replace(" ", "") for t in thumbprints)
            sig.value = hashlib.sha256(combined.encode()).hexdigest()[:24]
            sig.available = True
        elif rc == -1:
            sig.error = f"certutil unavailable: {err}"
        else:
            sig.error = "No cert thumbprints parsed"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_audio_endpoint() -> EnvSignal:
    sig = EnvSignal(
        "os_audio", "Audio Endpoint GUIDs", "OS",
        "WASAPI render device GUIDs — assigned per audio hardware installation", 7
    )
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
        )
        endpoints = []
        i = 0
        while True:
            try:
                endpoints.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        if endpoints:
            sig.value = "|".join(sorted(endpoints))
            sig.available = True
        else:
            sig.error = "No audio endpoints in registry"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_activation_id() -> EnvSignal:
    sig = EnvSignal(
        "os_activation", "Windows Activation ID", "OS",
        "Product activation GUID tied to hardware — changes on major hardware swap", 8
    )
    try:
        out, err, rc = _run_ps_ex(
            "Get-CimInstance SoftwareLicensingProduct "
            "-Filter \"Name like 'Windows%' and LicenseStatus=1\" | "
            "Select-Object -First 1 -ExpandProperty ID",
            timeout=20,  # SLP queries are slow on some machines
        )
        val = out.strip()
        if rc == 0 and "-" in val:
            sig.value = val
            sig.available = True
        else:
            sig.error = _ps_error(err, rc, "Activation ID not readable")
    except Exception as e:
        sig.error = str(e)
    return sig


# ─── MASTER COLLECTOR ────────────────────────────────────────────────────────

ALL_COLLECTORS = [
    # Hardware
    collect_motherboard_serial,
    collect_cpu_id,
    collect_disk_serial,
    collect_bios_serial,
    collect_gpu_id,
    collect_volume_serial,
    collect_battery,
    collect_ram_serial,
    collect_monitor_edid,
    # Network
    collect_router_bssid,
    collect_ipv6_linklocal,
    collect_adapter_guid,
    collect_gateway_mac,
    collect_dns_servers,
    # OS
    collect_machine_guid,
    collect_machine_sid,
    collect_install_date,
    collect_usb_history,
    collect_prefetch_seed,
    collect_cert_thumbprints,
    collect_audio_endpoint,
    collect_activation_id,
]


def collect_all_signals() -> list:
    """Collect all environment signals. Returns list of EnvSignal objects."""
    signals = []
    for collector in ALL_COLLECTORS:
        try:
            signals.append(collector())
        except Exception as e:
            # Individual collector failures are non-fatal, but they must still
            # appear in the result as an unavailable signal — dropping them
            # silently makes a crashed collector indistinguishable from one
            # that was never registered.
            signals.append(EnvSignal(
                id=getattr(collector, "__name__", "unknown"),
                name=getattr(collector, "__name__", "unknown"),
                category="Unknown",
                description="Collector raised an unexpected exception",
                stability=0,
                error=f"{type(e).__name__}: {e}",
            ))
    return signals


def diagnose_environment() -> str:
    """
    Report which external tools this module resolved to.

    Run this first when signals come back unavailable on an unfamiliar machine:
    it distinguishes "the tool is missing" from "the query returned nothing".
    """
    lines = [
        f"Python:       {sys.version.split()[0]} "
        f"({'64' if sys.maxsize > 2 ** 32 else '32'}-bit)",
        f"SystemRoot:   {_system_root()}",
        f"System32:     {_system32()}",
        f"PowerShell:   {_find_powershell() or 'NOT FOUND'}",
    ]
    for exe in ("netsh.exe", "ipconfig.exe", "arp.exe", "ping.exe", "certutil.exe"):
        lines.append(f"{exe:<13} {_find_exe(exe) or 'NOT FOUND'}")

    out, err, rc = _run_ps_ex("$PSVersionTable.PSVersion.ToString()")
    lines.append(f"PS version:   {out or f'FAILED (rc={rc}): {err}'}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(diagnose_environment())
    print()
    for s in collect_all_signals():
        status = "OK " if s.available else "-- "
        print(f"{status} {s.name:<32} {s.value or s.error}")