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
from dataclasses import dataclass, field
from typing import Optional


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

def _run_cmd(cmd: list, timeout: int = 10) -> str:
    """Run a subprocess command, return stdout or empty string on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace"
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _run_ps(cmd: str, timeout: int = 12) -> str:
    """Run a PowerShell command, return stdout or empty string."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace"
        )
        return result.stdout.strip()
    except Exception:
        return ""


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
        val = _run_ps("(Get-WmiObject Win32_BaseBoard).SerialNumber")
        invalid = {"to be filled by o.e.m.", "default string", "none", "n/a", ""}
        if val and val.lower() not in invalid:
            sig.value = val
            sig.available = True
        else:
            sig.error = "OEM did not program a serial (common on consumer boards)"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_cpu_id() -> EnvSignal:
    sig = EnvSignal(
        "hw_cpu", "CPU Processor ID", "Hardware",
        "CPU-embedded unique ID from the CPUID instruction", 8
    )
    try:
        val = _run_ps("(Get-WmiObject Win32_Processor).ProcessorId")
        if val:
            sig.value = val.strip()
            sig.available = True
        else:
            sig.error = "No CPU ID returned"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_disk_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_disk", "Primary HDD/SSD Serial", "Hardware",
        "Physical serial number of the primary storage device", 9
    )
    try:
        val = _run_ps(
            "(Get-WmiObject Win32_DiskDrive | "
            "Sort-Object Index | Select-Object -First 1).SerialNumber"
        )
        if val:
            sig.value = val.strip()
            sig.available = True
        else:
            sig.error = "No disk serial returned"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_bios_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_bios", "BIOS Serial Number", "Hardware",
        "BIOS/UEFI firmware serial number from SMBIOS", 8
    )
    try:
        val = _run_ps("(Get-WmiObject Win32_BIOS).SerialNumber")
        invalid = {"to be filled by o.e.m.", "default string", "none", "n/a", ""}
        if val and val.lower() not in invalid:
            sig.value = val
            sig.available = True
        else:
            sig.error = "BIOS serial is generic or not programmed"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_gpu_id() -> EnvSignal:
    sig = EnvSignal(
        "hw_gpu", "GPU Device ID(s)", "Hardware",
        "Graphics card PnP hardware device identifier", 7
    )
    try:
        out = _run_ps(
            "Get-WmiObject Win32_VideoController | "
            "Select-Object -ExpandProperty PNPDeviceID"
        )
        ids = sorted(set(_clean_lines(out)))
        if ids:
            sig.value = "|".join(ids)
            sig.available = True
        else:
            sig.error = "No GPU IDs found"
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
        out = _run_ps(
            "Get-WmiObject Win32_Battery | "
            "Select-Object -ExpandProperty DesignCapacity"
        )
        lines = _clean_lines(out)
        if lines and lines[0].isdigit():
            sig.value = lines[0]
            sig.available = True
        else:
            sig.error = "No battery found (desktop PC, or VM)"
    except Exception as e:
        sig.error = str(e)
    return sig


def collect_ram_serial() -> EnvSignal:
    sig = EnvSignal(
        "hw_ram", "RAM DIMM Serial(s)", "Hardware",
        "Physical DRAM module serial numbers from SPD data", 8
    )
    try:
        out = _run_ps(
            "Get-WmiObject Win32_PhysicalMemory | "
            "Select-Object -ExpandProperty SerialNumber"
        )
        serials = [
            s for s in _clean_lines(out, ["serialnumber"])
            if s and s.lower() not in ("00000000", "unknown", "none")
        ]
        if serials:
            sig.value = "|".join(sorted(serials))
            sig.available = True
        else:
            sig.error = "RAM serials not populated (requires BIOS support)"
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
        out = _run_cmd(["netsh", "wlan", "show", "interfaces"])
        match = re.search(r'BSSID\s*:\s*([\da-fA-F:]{17})', out)
        if match:
            sig.value = match.group(1).lower()
            sig.available = True
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
            out = _run_ps(
                "Get-NetIPAddress -AddressFamily IPv6 | "
                "Where-Object { $_.IPAddress -like 'fe80*' } | "
                "Select-Object -ExpandProperty IPAddress"
            )
            addrs = [a.split("%")[0].lower() for a in _clean_lines(out) if a.startswith("fe80")]
            if addrs:
                sig.value = "|".join(sorted(set(addrs)))
                sig.available = True
            else:
                sig.error = "No IPv6 link-local addresses found"
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
        ipcfg = _run_cmd(["ipconfig"])
        gw_match = re.search(r'Default Gateway[^:]*:\s*([\d.]+)', ipcfg)
        if not gw_match:
            sig.error = "No default gateway in ipconfig"
            return sig
        gw_ip = gw_match.group(1)
        # Ping once to ensure ARP cache is populated
        _run_cmd(["ping", "-n", "1", "-w", "500", gw_ip], timeout=3)
        # Look up that specific IP in ARP table
        arp_out = _run_cmd(["arp", "-a", gw_ip])
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
        out = _run_cmd(["ipconfig", "/all"])
        servers = sorted(set(re.findall(
            r'DNS Servers[^:]*:\s*([\d.]+)', out
        )))
        if servers:
            sig.value = ",".join(servers)
            sig.available = True
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
        out = _run_ps(
            f"(Get-WmiObject Win32_UserAccount -Filter "
            f"\"Name='{username}'\").SID"
        )
        if out and "S-1-5" in out:
            # Strip last sub-authority to get machine SID
            parts = out.strip().split("-")
            machine_sid = "-".join(parts[:-1])
            sig.value = machine_sid
            sig.available = True
        else:
            sig.error = "Could not retrieve SID"
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
        out = _run_cmd(["certutil", "-store", "root"], timeout=15)
        thumbprints = sorted(set(re.findall(
            r'Cert Hash\(sha1\)\s*:\s*([\da-fA-F ]{47,59})', out
        )))
        if thumbprints:
            combined = "|".join(t.replace(" ", "") for t in thumbprints)
            sig.value = hashlib.sha256(combined.encode()).hexdigest()[:24]
            sig.available = True
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
        out = _run_ps(
            "(Get-WmiObject SoftwareLicensingProduct "
            "-Filter \"Name like 'Windows%' and LicenseStatus=1\""
            " | Select-Object -First 1).ID"
        )
        if out and "-" in out:
            sig.value = out.strip()
            sig.available = True
        else:
            sig.error = "Activation ID not readable"
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
            pass  # Individual collector failures are non-fatal
    return signals