# ProctorGuard Desktop — Native Lockdown Container

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Electron](https://img.shields.io/badge/Electron-30%2B-47848F.svg)](https://www.electronjs.org/)
[![C++](https://img.shields.io/badge/Win32-C%2B%2B%20%2F%20PSAPI-00599C.svg)](https://learn.microsoft.com/en-us/windows/win32/)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20Bridge-5391FE.svg)](https://learn.microsoft.com/powershell/)

**ProctorGuard Desktop** is an OS-level lockdown container and companion agent built with Electron and Win32 native APIs. It enforces operating-system telemetry and anti-cheat policies that standard web browser sandboxes cannot access.

---

## 🛡️ Why a Native Companion App?

Standard web applications run inside sandboxed Chromium processes with strict security boundaries:
- ❌ Web pages **cannot** inspect running OS processes or detect background cheat applications.
- ❌ Web pages **cannot** enumerate loaded DLL modules to detect memory injection or hooking.
- ❌ Web pages **cannot** query physical display hardware ports or detect hidden HDMI dummy plugs / splitters.
- ❌ Web pages **cannot** intercept system-level keyboard shortcuts like `Alt+Tab` or `Windows Key`.

**ProctorGuard Desktop** bridges this gap by executing as an OS process with native inspection capabilities.

---

## 🔬 Native Detection Layers

### 1. Win32 Process Snapshot Scanner (`CreateToolhelp32Snapshot`)
Scans the system process table every 3 seconds for prohibited software:
- **Communication & Collaboration**: Discord, Slack, Microsoft Teams, Zoom, Skype
- **Remote Desktop & Screen Sharing**: AnyDesk, TeamViewer, UltraViewer, RustDesk, Chrome Remote Desktop
- **Recording & Virtual Drivers**: OBS Studio, Streamlabs, Camtasia, XSplit
- **Reverse Engineering & Cheating**: Cheat Engine, Wireshark, x64dbg, Process Hacker, Fiddler

### 2. PSAPI Injected DLL Auditor (`EnumProcessModulesEx`)
- Queries loaded modules in the process memory space.
- Detects non-system DLLs loaded from `AppData\Local\Temp` or untrusted directories.
- Identifies known injection signatures (`speedhack.dll`, `cheatengine-x86_64.dll`, hook patterns).

### 3. Display Topology & Multi-Monitor Detection (`EnumDisplayDevices`)
- Queries physical display adapter drivers directly.
- Detects secondary monitors, cloned display mirrors, and virtual display emulators (HDMI dummy plugs).
- Immediately reports `MULTIPLE_DISPLAYS_DETECTED` to the proctor backend.

### 4. Dual-Engine Architecture with Zero-Dependency Fallback
- **Primary Engine**: Compiled C++ Node-API native bindings (`src-native/`).
- **Resilient Fallback**: Pure PowerShell Win32 bridge (`scripts/audit.ps1`) executing WMI and .NET reflection. Works out-of-the-box on any Windows machine without requiring Visual Studio C++ compilers!

### 5. Kiosk Enforcement & Shortcut Interception
- Runs in full kiosk mode (`alwaysOnTop: true`, `kiosk: true`, `frame: false`).
- Disables DevTools and blocks `devtools-opened`.
- Intercepts system shortcuts: `Alt+Tab`, `Alt+F4`, `Windows Key`, `F11`, `F12`, `Ctrl+Shift+I`.

---

## 🛠️ Quickstart

### Prerequisites
- Windows 10 / 11 (64-bit)
- Node.js v18 or higher

### Installation
```bash
# Clone the repository
git clone https://github.com/NiranX-music/proctorguard-desktop.git
cd proctorguard-desktop

# Install dependencies
npm install
```

### Standalone CLI Verification
Verify OS process scanning, loaded DLL auditing, and display enumeration without starting the full Electron UI:
```bash
node test-companion.js
```

### Launch Lockdown Companion
```bash
npm start
```

---

## 📂 Project Structure

```
proctorguard-desktop/
├── index.js                  # Electron main process (Kiosk, Shortcuts, WebSockets)
├── preload.js                # Secure contextBridge telemetry API
├── native-auditor.js         # Dual-engine auditor (C++ & PowerShell bridge)
├── test-companion.js         # Standalone CLI test script
├── binding.gyp               # Node-gyp C++ build configuration
├── package.json              # Project dependencies and npm scripts
├── scripts/
│   └── audit.ps1             # Pure PowerShell Win32 inspection bridge
├── src-native/
│   ├── process_checker.cc    # Win32 Toolhelp32 process scanner
│   ├── module_auditor.cc     # PSAPI EnumProcessModulesEx DLL scanner
│   └── display_auditor.cc    # EnumDisplayDevices monitor topology scanner
└── renderer/
    ├── index.html            # Lockdown HUD dashboard
    ├── style.css             # Glassmorphic dark styling
    └── renderer.js           # HUD telemetry controller
```

---

## 📄 License
Released under the [MIT License](LICENSE).
