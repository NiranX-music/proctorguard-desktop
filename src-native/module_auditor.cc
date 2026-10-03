#include "module_auditor.h"
#include <algorithm>

ModuleAuditor::ModuleAuditor() {}
ModuleAuditor::~ModuleAuditor() {}

std::wstring ModuleAuditor::ToLower(const std::wstring& str) {
    std::wstring lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return lower;
}

bool ModuleAuditor::CheckModuleSuspicious(const std::wstring& path, std::wstring& out_reason, std::wstring& out_severity) {
    std::wstring lower = ToLower(path);

    // 1. Check for modules loaded from Temp directories
    if (lower.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
        lower.find(L"\\windows\\temp\\") != std::wstring::npos ||
        lower.find(L"\\temp\\") != std::wstring::npos) {
        out_reason = L"DLL loaded from volatile temporary directory (suspicious dropper pattern)";
        out_severity = L"CRITICAL";
        return true;
    }

    // 2. Check for known cheat and injection signatures
    if (lower.find(L"speedhack") != std::wstring::npos) {
        out_reason = L"Detected Speedhack timing manipulation library";
        out_severity = L"CRITICAL";
        return true;
    }
    if (lower.find(L"cehook") != std::wstring::npos || lower.find(L"vehdebug") != std::wstring::npos) {
        out_reason = L"Detected Cheat Engine kernel/VEH hook module";
        out_severity = L"CRITICAL";
        return true;
    }
    if (lower.find(L"frida") != std::wstring::npos) {
        out_reason = L"Detected Frida dynamic instrumentation framework agent";
        out_severity = L"CRITICAL";
        return true;
    }
    if (lower.find(L"minhook") != std::wstring::npos) {
        out_reason = L"Detected MinHook API hooking engine";
        out_severity = L"CRITICAL";
        return true;
    }
    if (lower.find(L"detour") != std::wstring::npos) {
        out_reason = L"Detected Microsoft Detours binary interception library";
        out_severity = L"CRITICAL";
        return true;
    }
    if (lower.find(L"easyhook") != std::wstring::npos) {
        out_reason = L"Detected EasyHook library";
        out_severity = L"CRITICAL";
        return true;
    }
    if (lower.find(L"inject") != std::wstring::npos && lower.find(L"injector") != std::wstring::npos) {
        out_reason = L"Detected generic DLL injection signature";
        out_severity = L"HIGH";
        return true;
    }

    // 3. Screen capture & overlay hook injections
    if (lower.find(L"discordhook") != std::wstring::npos) {
        out_reason = L"Discord overlay DirectX/OpenGL injection hook";
        out_severity = L"HIGH";
        return true;
    }
    if (lower.find(L"obshook") != std::wstring::npos || lower.find(L"graphics-hook") != std::wstring::npos) {
        out_reason = L"OBS Studio graphics capture hook injected into process";
        out_severity = L"CRITICAL";
        return true;
    }
    if (lower.find(L"gameoverlayrenderer") != std::wstring::npos) {
        out_reason = L"Steam/Gaming overlay injection hook";
        out_severity = L"MEDIUM";
        return true;
    }
    if (lower.find(L"rtsshooks") != std::wstring::npos) {
        out_reason = L"RivaTuner Statistics Server graphics hook";
        out_severity = L"MEDIUM";
        return true;
    }

    return false;
}

ModuleAuditResult ModuleAuditor::AuditProcessModules(DWORD pid) {
    ModuleAuditResult result;
    result.total_modules = 0;

    HANDLE hProcess = NULL;
    if (pid == 0 || pid == GetCurrentProcessId()) {
        hProcess = GetCurrentProcess();
    } else {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    }

    if (!hProcess) {
        return result;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;

    // Use EnumProcessModulesEx with LIST_MODULES_ALL to inspect both 32-bit and 64-bit modules
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        result.total_modules = (int)count;

        for (DWORD i = 0; i < count; i++) {
            wchar_t szModName[MAX_PATH * 2] = { 0 };
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                std::wstring modPath = szModName;
                std::wstring reason;
                std::wstring severity;

                if (CheckModuleSuspicious(modPath, reason, severity)) {
                    // Extract basename
                    size_t lastSlash = modPath.find_last_of(L"\\/");
                    std::wstring baseName = (lastSlash != std::wstring::npos) ? modPath.substr(lastSlash + 1) : modPath;

                    SuspiciousModule sm;
                    sm.module_name = baseName;
                    sm.full_path = modPath;
                    sm.reason = reason;
                    sm.severity = severity;
                    result.suspicious.push_back(sm);
                }
            }
        }
    }

    if (hProcess != GetCurrentProcess()) {
        CloseHandle(hProcess);
    }

    return result;
}
