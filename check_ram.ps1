# check_ram.ps1 — diagnose whether this PC exposes RAM SPD serial numbers.
# Run in PowerShell. No admin needed for most checks; Test 5 needs admin.
# Usage:  powershell -ExecutionPolicy Bypass -File .\check_ram.ps1

Write-Host "=== RAM SERIAL DIAGNOSTIC ===" -ForegroundColor Cyan
Write-Host ""

# --- Test 1: the exact query signals.py uses -------------------------------
Write-Host "[1] Raw SerialNumber field" -ForegroundColor Yellow
$serials = Get-CimInstance Win32_PhysicalMemory | Select-Object -ExpandProperty SerialNumber
if ($null -eq $serials -or $serials.Count -eq 0) {
    Write-Host "    NOTHING RETURNED - no modules reported at all" -ForegroundColor Red
} else {
    $i = 0
    foreach ($s in $serials) {
        $i++
        if ([string]::IsNullOrWhiteSpace($s)) {
            Write-Host "    Module ${i}: <EMPTY/BLANK>" -ForegroundColor Red
        } else {
            $clean = $s.Trim()
            # Flag firmware filler: all zeros, all Fs, or a known placeholder word.
            $bare = $clean -replace '[-\s\.]', ''
            $isFiller = ($bare -match '^0+$') -or ($bare -match '^[Ff]+$') -or
                        ($clean -in @('Unknown','None','N/A','Not Available','Not Specified','Undefined'))
            if ($isFiller) {
                Write-Host "    Module ${i}: '$clean'  <-- PLACEHOLDER, not a real serial" -ForegroundColor Red
            } else {
                Write-Host "    Module ${i}: '$clean'  <-- looks like a REAL serial" -ForegroundColor Green
            }
        }
    }
}
Write-Host ""

# --- Test 2: full module detail --------------------------------------------
Write-Host "[2] Full module detail" -ForegroundColor Yellow
$mods = Get-CimInstance Win32_PhysicalMemory |
    Select-Object DeviceLocator, BankLabel, Manufacturer, PartNumber,
                  SerialNumber, @{N='CapacityGB';E={[math]::Round($_.Capacity/1GB,1)}},
                  Speed, @{N='FormFactor';E={$_.FormFactor}}, SMBIOSMemoryType
if ($mods) { $mods | Format-List } else { Write-Host "    (none)" -ForegroundColor Red }

# --- Test 3: soldered vs socketed ------------------------------------------
Write-Host "[3] Is the memory soldered?" -ForegroundColor Yellow
# FormFactor 12 = SODIMM, 8 = DIMM, 13 = RIMM. LPDDR is usually 12 but with
# MemoryDevices reported as 0 removable slots, or Tag/Locator naming that
# indicates on-board placement.
$arrays = Get-CimInstance Win32_PhysicalMemoryArray
foreach ($a in $arrays) {
    Write-Host "    Array slots (MemoryDevices): $($a.MemoryDevices)"
}
foreach ($m in (Get-CimInstance Win32_PhysicalMemory)) {
    $ff = switch ($m.FormFactor) {
        8  { "DIMM (socketed desktop)" }
        12 { "SODIMM (laptop module - may be socketed OR soldered)" }
        13 { "RIMM" }
        default { "Other/Unknown ($($m.FormFactor))" }
    }
    $type = switch ($m.SMBIOSMemoryType) {
        26 { "DDR4" } 27 { "LPDDR3" } 28 { "LPDDR4" }
        34 { "DDR5" } 35 { "LPDDR5" }
        default { "Type $($m.SMBIOSMemoryType)" }
    }
    Write-Host "    $($m.DeviceLocator): $ff / $type"
    if ($type -like "LPDDR*") {
        Write-Host "      ^ LPDDR is almost always SOLDERED - serials usually absent" -ForegroundColor Magenta
    }
}
Write-Host ""

# --- Test 4: does elevation change anything? -------------------------------
Write-Host "[4] Are you running as Administrator?" -ForegroundColor Yellow
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "    YES - elevated. This result is authoritative." -ForegroundColor Green
} else {
    Write-Host "    NO - not elevated." -ForegroundColor Magenta
    Write-Host "    If serials were blank above, re-run this script as Admin to confirm" -ForegroundColor Magenta
    Write-Host "    it is a firmware limit and not a permissions issue." -ForegroundColor Magenta
}
Write-Host ""

# --- Test 5: raw SMBIOS Type 17, bypassing WMI -----------------------------
Write-Host "[5] Raw SMBIOS check (bypasses WMI entirely)" -ForegroundColor Yellow
try {
    $raw = Get-CimInstance -Namespace root\wmi -ClassName MSSmBios_RawSMBiosTables -ErrorAction Stop
    $bytes = $raw.SMBiosData
    Write-Host "    SMBIOS table read OK ($($bytes.Length) bytes)" -ForegroundColor Green

    # Walk the SMBIOS structures looking for Type 17 (Memory Device).
    $p = 0; $found = 0
    while ($p -lt $bytes.Length - 4) {
        $type = $bytes[$p]; $len = $bytes[$p + 1]
        if ($len -lt 4) { break }
        if ($type -eq 17) {
            $found++
            # Serial Number is string-index byte at offset 0x18 in Type 17.
            $strIdx = if ($p + 0x18 -lt $bytes.Length) { $bytes[$p + 0x18] } else { 0 }
            # String table begins right after the formatted area.
            $s = $p + $len; $n = 1; $serial = "<none>"
            while ($s -lt $bytes.Length - 1) {
                $end = $s
                while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
                if ($end -eq $s) { break }   # double NUL = end of this structure
                if ($n -eq $strIdx) {
                    $serial = [Text.Encoding]::ASCII.GetString($bytes[$s..($end-1)])
                    break
                }
                $n++; $s = $end + 1
            }
            Write-Host "    Type17 device #${found}: serial-string-index=$strIdx value='$serial'"
            if ($strIdx -eq 0) {
                Write-Host "      ^ index 0 means FIRMWARE STORES NO SERIAL - hardware limit" -ForegroundColor Red
            }
        }
        # Advance past formatted area + string table terminator.
        $s = $p + $len
        while ($s -lt $bytes.Length - 1 -and -not ($bytes[$s] -eq 0 -and $bytes[$s+1] -eq 0)) { $s++ }
        $p = $s + 2
    }
    if ($found -eq 0) { Write-Host "    No Type 17 structures found" -ForegroundColor Red }
}
catch {
    Write-Host "    Could not read raw SMBIOS: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    (This test requires Administrator. Not fatal - Tests 1-3 are enough.)" -ForegroundColor Magenta
}
Write-Host ""

# --- Verdict ----------------------------------------------------------------
Write-Host "=== VERDICT ===" -ForegroundColor Cyan
$realSerials = @()
foreach ($s in (Get-CimInstance Win32_PhysicalMemory | Select-Object -ExpandProperty SerialNumber)) {
    if (-not [string]::IsNullOrWhiteSpace($s)) {
        $bare = $s.Trim() -replace '[-\s\.]', ''
        if (-not (($bare -match '^0+$') -or ($bare -match '^[Ff]+$') -or
                  ($s.Trim() -in @('Unknown','None','N/A','Not Available','Not Specified','Undefined')))) {
            $realSerials += $s.Trim()
        }
    }
}
if ($realSerials.Count -gt 0) {
    Write-Host "This PC DOES expose real RAM serials:" -ForegroundColor Green
    $realSerials | ForEach-Object { Write-Host "    $_" -ForegroundColor Green }
    Write-Host "If signals.py reports unavailable here, that is a CODE bug." -ForegroundColor Green
} else {
    Write-Host "This PC does NOT expose usable RAM serials." -ForegroundColor Red
    Write-Host "This is a FIRMWARE/HARDWARE limitation, not a bug in signals.py." -ForegroundColor Red
    Write-Host "The fallback (module layout hash) is the correct behaviour here." -ForegroundColor Red
}
