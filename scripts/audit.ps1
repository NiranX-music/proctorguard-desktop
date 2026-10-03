<#
.SYNOPSIS
    ProctorGuard Native OS Auditor - Standalone PowerShell Engine
.DESCRIPTION
    Inspects running processes, loaded modules, and display topology
    for exam integrity verification and anti-cheat enforcement.
#>

param(
    [string]$Action = "full",   # "full", "processes", "modules", "displays"
    [string]$TargetPid = $PID,
    [string]$CustomBlacklistJson = "[]"
)

$ErrorActionPreference = "SilentlyContinue"

# ----------------- Blacklist Definitions -----------------
$Blacklist = @{
    # Cheat Tools & Memory Editors
    "cheatengine.exe"        = @{ Category = "CHEAT_TOOL"; Rule = "Cheat Engine memory scanner" }
    "cheatengine-x86_64.exe" = @{ Category = "CHEAT_TOOL"; Rule = "Cheat Engine x64" }
    "cheatengine-i386.exe"   = @{ Category = "CHEAT_TOOL"; Rule = "Cheat Engine x86" }
    "artmoney.exe"           = @{ Category = "CHEAT_TOOL"; Rule = "ArtMoney memory editor" }

    # Debuggers & Disassemblers
    "x64dbg.exe"             = @{ Category = "DEBUGGER"; Rule = "x64dbg debugger" }
    "x32dbg.exe"             = @{ Category = "DEBUGGER"; Rule = "x32dbg debugger" }
    "ida.exe"                = @{ Category = "DISASSEMBLER"; Rule = "IDA Pro disassembler" }
    "ida64.exe"              = @{ Category = "DISASSEMBLER"; Rule = "IDA Pro x64 disassembler" }
    "ghidra.exe"             = @{ Category = "DISASSEMBLER"; Rule = "Ghidra reverse engineering" }
    "wireshark.exe"          = @{ Category = "PACKET_SNIFFER"; Rule = "Wireshark packet sniffer" }
    "fiddler.exe"            = @{ Category = "PROXY_INSPECTOR"; Rule = "Fiddler HTTP debugging proxy" }
    "charles.exe"            = @{ Category = "PROXY_INSPECTOR"; Rule = "Charles proxy debugger" }
    "processhacker.exe"      = @{ Category = "PROCESS_INSPECTOR"; Rule = "Process Hacker tool" }
    "procexp.exe"            = @{ Category = "PROCESS_INSPECTOR"; Rule = "Sysinternals Process Explorer" }
    "apimonitor.exe"         = @{ Category = "API_MONITOR"; Rule = "API Monitor hook tool" }

    # Screen Recorders & Broadcast Streamers
    "obs64.exe"              = @{ Category = "SCREEN_RECORDER"; Rule = "OBS Studio x64" }
    "obs32.exe"              = @{ Category = "SCREEN_RECORDER"; Rule = "OBS Studio x86" }
    "obs.exe"                = @{ Category = "SCREEN_RECORDER"; Rule = "OBS Studio" }
    "camtasia.exe"           = @{ Category = "SCREEN_RECORDER"; Rule = "Camtasia screen recorder" }
    "camtasiastudio.exe"     = @{ Category = "SCREEN_RECORDER"; Rule = "Camtasia Studio" }
    "bandicam.exe"           = @{ Category = "SCREEN_RECORDER"; Rule = "Bandicam screen recorder" }
    "fraps.exe"              = @{ Category = "SCREEN_RECORDER"; Rule = "Fraps video capture" }
    "sharex.exe"             = @{ Category = "SCREEN_RECORDER"; Rule = "ShareX screen capture" }
    "snagit32.exe"           = @{ Category = "SCREEN_RECORDER"; Rule = "Snagit capture tool" }
    "snagit64.exe"           = @{ Category = "SCREEN_RECORDER"; Rule = "Snagit capture tool" }
    "captura.exe"            = @{ Category = "SCREEN_RECORDER"; Rule = "Captura screen recorder" }

    # Remote Desktop & Screen Sharing
    "anydesk.exe"            = @{ Category = "REMOTE_DESKTOP"; Rule = "AnyDesk remote desktop" }
    "teamviewer.exe"         = @{ Category = "REMOTE_DESKTOP"; Rule = "TeamViewer remote desktop" }
    "teamviewer_service.exe" = @{ Category = "REMOTE_DESKTOP"; Rule = "TeamViewer background service" }
    "tv_w32.exe"             = @{ Category = "REMOTE_DESKTOP"; Rule = "TeamViewer 32-bit helper" }
    "tv_x64.exe"             = @{ Category = "REMOTE_DESKTOP"; Rule = "TeamViewer 64-bit helper" }
    "vncserver.exe"          = @{ Category = "REMOTE_DESKTOP"; Rule = "VNC Server" }
    "winvnc.exe"             = @{ Category = "REMOTE_DESKTOP"; Rule = "UltraVNC server" }
    "tightvnc.exe"           = @{ Category = "REMOTE_DESKTOP"; Rule = "TightVNC server" }
    "ultra_vnc.exe"          = @{ Category = "REMOTE_DESKTOP"; Rule = "UltraVNC server" }
    "mstsc.exe"              = @{ Category = "REMOTE_DESKTOP"; Rule = "Microsoft Remote Desktop (RDP)" }
    "parsec.exe"             = @{ Category = "REMOTE_DESKTOP"; Rule = "Parsec screen sharing" }
    "rustdesk.exe"           = @{ Category = "REMOTE_DESKTOP"; Rule = "RustDesk remote control" }
    "logmein.exe"            = @{ Category = "REMOTE_DESKTOP"; Rule = "LogMeIn remote access" }
    "splashtop.exe"          = @{ Category = "REMOTE_DESKTOP"; Rule = "Splashtop remote access" }
    "nomachine.exe"          = @{ Category = "REMOTE_DESKTOP"; Rule = "NoMachine remote desktop" }
    "supremo.exe"            = @{ Category = "REMOTE_DESKTOP"; Rule = "Supremo remote desktop" }

    # Unauthorized Communication
    "discord.exe"            = @{ Category = "COMMUNICATION"; Rule = "Discord voice/chat client" }
    "slack.exe"              = @{ Category = "COMMUNICATION"; Rule = "Slack workspace client" }
    "teams.exe"              = @{ Category = "COMMUNICATION"; Rule = "Microsoft Teams" }
    "skype.exe"              = @{ Category = "COMMUNICATION"; Rule = "Skype messaging client" }
    "zoom.exe"               = @{ Category = "COMMUNICATION"; Rule = "Zoom video conferencing" }
    "webex.exe"              = @{ Category = "COMMUNICATION"; Rule = "Cisco Webex client" }
    "telegram.exe"           = @{ Category = "COMMUNICATION"; Rule = "Telegram desktop messenger" }
    "whatsapp.exe"           = @{ Category = "COMMUNICATION"; Rule = "WhatsApp desktop client" }
    "signal.exe"             = @{ Category = "COMMUNICATION"; Rule = "Signal private messenger" }
}

# ----------------- Functions -----------------

function Audit-Processes {
    param([array]$CustomList = @())

    $allProcesses = Get-Process
    $totalScanned = $allProcesses.Count
    $detected = @()

    foreach ($proc in $allProcesses) {
        $pName = $proc.ProcessName.ToLower()
        $exeKey = "$pName.exe"

        $match = $null
        if ($Blacklist.ContainsKey($exeKey)) {
            $match = $Blacklist[$exeKey]
        } elseif ($Blacklist.ContainsKey($pName)) {
            $match = $Blacklist[$pName]
        } elseif ($CustomList -contains $exeKey -or $CustomList -contains $pName) {
            $match = @{ Category = "CUSTOM_BLACKLIST"; Rule = "User defined custom blacklist" }
        }

        if ($match) {
            $path = ""
            try { $path = $proc.Path } catch { $path = "" }

            $detected += @{
                pid         = $proc.Id
                name        = "$($proc.ProcessName).exe"
                category    = $match.Category
                rule        = $match.Rule
                fullPath    = $path
            }
        }
    }

    return @{
        totalScanned = $totalScanned
        detected     = $detected
        status       = if ($detected.Count -gt 0) { "THREAT" } else { "OK" }
    }
}

function Audit-Modules {
    param([int]$procId = $PID)

    $suspicious = @()
    $totalModules = 0

    try {
        $targetProc = Get-Process -Id $procId -ErrorAction Stop
        $modules = $targetProc.Modules
        $totalModules = $modules.Count

        foreach ($mod in $modules) {
            $fn = ""
            try { $fn = $mod.FileName.ToLower() } catch { continue }
            $mName = $mod.ModuleName

            $reason = ""
            $severity = ""

            if ($fn -like "*\appdata\local\temp\*" -or $fn -like "*\windows\temp\*" -or $fn -like "*\temp\*") {
                $reason = "DLL loaded from volatile temporary directory (suspicious dropper/injector)"
                $severity = "CRITICAL"
            } elseif ($fn -like "*speedhack*") {
                $reason = "Detected Speedhack timing manipulation library"
                $severity = "CRITICAL"
            } elseif ($fn -like "*minhook*") {
                $reason = "Detected MinHook API hooking framework"
                $severity = "CRITICAL"
            } elseif ($fn -like "*frida*") {
                $reason = "Detected Frida dynamic instrumentation framework agent"
                $severity = "CRITICAL"
            } elseif ($fn -like "*detour*") {
                $reason = "Detected Microsoft Detours binary hooking library"
                $severity = "CRITICAL"
            } elseif ($fn -like "*easyhook*") {
                $reason = "Detected EasyHook injection library"
                $severity = "CRITICAL"
            } elseif ($fn -like "*cehook*" -or $fn -like "*vehdebug*") {
                $reason = "Detected Cheat Engine kernel/VEH hook library"
                $severity = "CRITICAL"
            } elseif ($fn -like "*discordhook*") {
                $reason = "Discord overlay graphics injection hook"
                $severity = "HIGH"
            } elseif ($fn -like "*obshook*" -or $fn -like "*graphics-hook*") {
                $reason = "OBS Studio graphics capture hook"
                $severity = "CRITICAL"
            } elseif ($fn -like "*gameoverlayrenderer*") {
                $reason = "Gaming overlay injection hook"
                $severity = "MEDIUM"
            } elseif ($fn -like "*rtsshooks*") {
                $reason = "RivaTuner Statistics Server hook"
                $severity = "MEDIUM"
            }

            if ($reason -ne "") {
                $suspicious += @{
                    name     = $mName
                    fullPath = $mod.FileName
                    reason   = $reason
                    severity = $severity
                }
            }
        }
    } catch {
        # Fallback if cannot access process modules directly
    }

    return @{
        totalModules = $totalModules
        suspicious   = $suspicious
        status       = if ($suspicious.Count -gt 0) { "THREAT" } else { "OK" }
    }
}

function Audit-Displays {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue

    $screens = [System.Windows.Forms.Screen]::AllScreens
    $displayCount = $screens.Count
    $displayList = @()
    $violations = @()

    $isMultiDisplay = ($displayCount -gt 1)
    if ($isMultiDisplay) {
        $violations += "Multiple monitors connected ($displayCount displays detected)"
    }

    $hasCloned = $false
    for ($i = 0; $i -lt $screens.Count; $i++) {
        $s = $screens[$i]
        $displayList += @{
            deviceName  = $s.DeviceName
            deviceString = ""
            isPrimary   = $s.Primary
            bounds      = @{
                left   = $s.Bounds.X
                top    = $s.Bounds.Y
                right  = ($s.Bounds.X + $s.Bounds.Width)
                bottom = ($s.Bounds.Y + $s.Bounds.Height)
                width  = $s.Bounds.Width
                height = $s.Bounds.Height
            }
        }

        # Check for cloned screens
        for ($j = $i + 1; $j -lt $screens.Count; $j++) {
            $other = $screens[$j]
            if ($s.Bounds.X -eq $other.Bounds.X -and
                $s.Bounds.Y -eq $other.Bounds.Y -and
                $s.Bounds.Width -eq $other.Bounds.Width -and
                $s.Bounds.Height -eq $other.Bounds.Height) {
                $hasCloned = $true
            }
        }
    }

    if ($hasCloned) {
        $violations += "Cloned / duplicate display coordinates detected (hardware splitter or mirroring active)"
    }

    # Query WMI for virtual display adapters
    $hasVirtual = $false
    try {
        $monitors = Get-CimInstance Win32_PnPEntity | Where-Object {
            $_.Service -like "*monitor*" -or $_.ClassGuid -eq "{4d36e96e-e325-11ce-bfc1-08002be10318}"
        }
        foreach ($m in $monitors) {
            $nm = ($m.Name + " " + $m.Description).ToLower()
            if ($nm -like "*virtual*" -or $nm -like "*iddsampledriver*" -or $nm -like "*spacedesk*" -or $nm -like "*duet*") {
                $hasVirtual = $true
                $violations += "Virtual display adapter detected: $($m.Name)"
            }
        }
    } catch {}

    return @{
        displayCount       = $displayCount
        isMultiDisplay     = $isMultiDisplay
        hasClonedDisplays  = $hasCloned
        hasVirtualDisplay  = $hasVirtual
        displays           = $displayList
        violations         = $violations
        status             = if ($violations.Count -gt 0) { "THREAT" } else { "OK" }
    }
}

# ----------------- Execution Dispatcher -----------------

$output = @{}
$customListParsed = @()
try {
    if ($CustomBlacklistJson -and $CustomBlacklistJson -ne "[]") {
        $customListParsed = ConvertFrom-Json $CustomBlacklistJson
    }
} catch {}

switch ($Action.ToLower()) {
    "processes" {
        $output = Audit-Processes -CustomList $customListParsed
    }
    "modules" {
        $output = Audit-Modules -procId ([int]$TargetPid)
    }
    "displays" {
        $output = Audit-Displays
    }
    default {
        $procAudit = Audit-Processes -CustomList $customListParsed
        $modAudit = Audit-Modules -procId ([int]$TargetPid)
        $dispAudit = Audit-Displays

        $threats = @()
        if ($procAudit.status -eq "THREAT") {
            foreach ($p in $procAudit.detected) {
                $threats += @{
                    type     = "PROCESS_BLACKLIST_HIT"
                    severity = "CRITICAL"
                    details  = "$($p.name) running (PID: $($p.pid), Category: $($p.category))"
                    target   = $p
                }
            }
        }
        if ($modAudit.status -eq "THREAT") {
            foreach ($m in $modAudit.suspicious) {
                $threats += @{
                    type     = "INJECTED_DLL_DETECTED"
                    severity = $m.severity
                    details  = "$($m.name): $($m.reason)"
                    target   = $m
                }
            }
        }
        if ($dispAudit.status -eq "THREAT") {
            foreach ($v in $dispAudit.violations) {
                $threats += @{
                    type     = "MULTIPLE_DISPLAYS_DETECTED"
                    severity = "CRITICAL"
                    details  = $v
                    target   = $dispAudit
                }
            }
        }

        $output = @{
            timestamp   = (Get-Date).ToUniversalTime().ToString("o")
            engine      = "win32_powershell_bridge"
            processes   = $procAudit
            modules     = $modAudit
            displays    = $dispAudit
            hasThreats  = ($threats.Count -gt 0)
            threatCount = $threats.Count
            threats     = $threats
        }
    }
}

$output | ConvertTo-Json -Depth 6 -Compress
