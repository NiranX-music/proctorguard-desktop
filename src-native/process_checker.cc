#include "process_checker.h"
#include <algorithm>
#include <map>

struct BlacklistEntry {
    std::wstring category;
    std::wstring description;
};

static std::map<std::wstring, BlacklistEntry> g_blacklist;

void ProcessChecker::InitDefaultBlacklist() {
    if (!g_blacklist.empty()) return;

    // Cheat engines & memory modifiers
    g_blacklist[L"cheatengine.exe"] = { L"CHEAT_TOOL", L"Cheat Engine memory scanner/debugger" };
    g_blacklist[L"cheatengine-x86_64.exe"] = { L"CHEAT_TOOL", L"Cheat Engine x64" };
    g_blacklist[L"cheatengine-i386.exe"] = { L"CHEAT_TOOL", L"Cheat Engine x86" };
    g_blacklist[L"artmoney.exe"] = { L"CHEAT_TOOL", L"ArtMoney memory editor" };

    // Debuggers, Disassemblers & Packet Sniffers
    g_blacklist[L"x64dbg.exe"] = { L"DEBUGGER", L"x64dbg debugger" };
    g_blacklist[L"x32dbg.exe"] = { L"DEBUGGER", L"x32dbg debugger" };
    g_blacklist[L"ida.exe"] = { L"DISASSEMBLER", L"IDA Pro disassembler" };
    g_blacklist[L"ida64.exe"] = { L"DISASSEMBLER", L"IDA Pro x64 disassembler" };
    g_blacklist[L"ghidra.exe"] = { L"DISASSEMBLER", L"Ghidra reverse engineering suite" };
    g_blacklist[L"wireshark.exe"] = { L"PACKET_SNIFFER", L"Wireshark network analyzer" };
    g_blacklist[L"fiddler.exe"] = { L"PROXY_INSPECTOR", L"Fiddler HTTP debugging proxy" };
    g_blacklist[L"charles.exe"] = { L"PROXY_INSPECTOR", L"Charles proxy inspector" };
    g_blacklist[L"processhacker.exe"] = { L"PROCESS_INSPECTOR", L"Process Hacker system inspector" };
    g_blacklist[L"procexp.exe"] = { L"PROCESS_INSPECTOR", L"Sysinternals Process Explorer" };
    g_blacklist[L"apimonitor.exe"] = { L"API_MONITOR", L"API Monitor hook tool" };

    // Screen Recorders & Broadcast Streamers
    g_blacklist[L"obs64.exe"] = { L"SCREEN_RECORDER", L"OBS Studio x64" };
    g_blacklist[L"obs32.exe"] = { L"SCREEN_RECORDER", L"OBS Studio x86" };
    g_blacklist[L"obs.exe"] = { L"SCREEN_RECORDER", L"OBS Studio" };
    g_blacklist[L"camtasia.exe"] = { L"SCREEN_RECORDER", L"Camtasia screen recorder" };
    g_blacklist[L"camtasiastudio.exe"] = { L"SCREEN_RECORDER", L"Camtasia Studio" };
    g_blacklist[L"bandicam.exe"] = { L"SCREEN_RECORDER", L"Bandicam screen capture" };
    g_blacklist[L"fraps.exe"] = { L"SCREEN_RECORDER", L"Fraps video capture" };
    g_blacklist[L"sharex.exe"] = { L"SCREEN_RECORDER", L"ShareX screen capture tool" };
    g_blacklist[L"snagit32.exe"] = { L"SCREEN_RECORDER", L"Snagit 32-bit capture tool" };
    g_blacklist[L"snagit64.exe"] = { L"SCREEN_RECORDER", L"Snagit 64-bit capture tool" };
    g_blacklist[L"captura.exe"] = { L"SCREEN_RECORDER", L"Captura screen recorder" };

    // Remote Desktop & Screen Sharing
    g_blacklist[L"anydesk.exe"] = { L"REMOTE_DESKTOP", L"AnyDesk remote desktop software" };
    g_blacklist[L"teamviewer.exe"] = { L"REMOTE_DESKTOP", L"TeamViewer remote control" };
    g_blacklist[L"teamviewer_service.exe"] = { L"REMOTE_DESKTOP", L"TeamViewer service" };
    g_blacklist[L"tv_w32.exe"] = { L"REMOTE_DESKTOP", L"TeamViewer 32-bit helper" };
    g_blacklist[L"tv_x64.exe"] = { L"REMOTE_DESKTOP", L"TeamViewer 64-bit helper" };
    g_blacklist[L"vncserver.exe"] = { L"REMOTE_DESKTOP", L"VNC Server" };
    g_blacklist[L"winvnc.exe"] = { L"REMOTE_DESKTOP", L"UltraVNC / WinVNC server" };
    g_blacklist[L"tightvnc.exe"] = { L"REMOTE_DESKTOP", L"TightVNC server" };
    g_blacklist[L"ultra_vnc.exe"] = { L"REMOTE_DESKTOP", L"UltraVNC server" };
    g_blacklist[L"mstsc.exe"] = { L"REMOTE_DESKTOP", L"Microsoft Remote Desktop Connection" };
    g_blacklist[L"parsec.exe"] = { L"REMOTE_DESKTOP", L"Parsec low-latency screen sharing" };
    g_blacklist[L"rustdesk.exe"] = { L"REMOTE_DESKTOP", L"RustDesk remote desktop" };
    g_blacklist[L"logmein.exe"] = { L"REMOTE_DESKTOP", L"LogMeIn remote access" };
    g_blacklist[L"splashtop.exe"] = { L"REMOTE_DESKTOP", L"Splashtop remote access" };
    g_blacklist[L"nomachine.exe"] = { L"REMOTE_DESKTOP", L"NoMachine remote desktop" };
    g_blacklist[L"supremo.exe"] = { L"REMOTE_DESKTOP", L"Supremo remote desktop" };

    // Unauthorized Chat & Collaboration
    g_blacklist[L"discord.exe"] = { L"COMMUNICATION", L"Discord chat/voice client" };
    g_blacklist[L"slack.exe"] = { L"COMMUNICATION", L"Slack workspace messaging" };
    g_blacklist[L"teams.exe"] = { L"COMMUNICATION", L"Microsoft Teams communication" };
    g_blacklist[L"skype.exe"] = { L"COMMUNICATION", L"Skype messaging/calling" };
    g_blacklist[L"zoom.exe"] = { L"COMMUNICATION", L"Zoom video conferencing" };
    g_blacklist[L"webex.exe"] = { L"COMMUNICATION", L"Cisco Webex meetings" };
    g_blacklist[L"telegram.exe"] = { L"COMMUNICATION", L"Telegram messenger" };
    g_blacklist[L"whatsapp.exe"] = { L"COMMUNICATION", L"WhatsApp desktop messenger" };
    g_blacklist[L"signal.exe"] = { L"COMMUNICATION", L"Signal private messenger" };
}

ProcessChecker::ProcessChecker() {
    InitDefaultBlacklist();
}

ProcessChecker::~ProcessChecker() {}

std::wstring ProcessChecker::ToLower(const std::wstring& str) {
    std::wstring lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return lower;
}

bool ProcessChecker::IsBlacklisted(const std::wstring& exe_name, std::wstring& out_category, std::wstring& out_rule) {
    std::wstring lower = ToLower(exe_name);
    auto it = g_blacklist.find(lower);
    if (it != g_blacklist.end()) {
        out_category = it->second.category;
        out_rule = it->second.description;
        return true;
    }
    return false;
}

ProcessAuditResult ProcessChecker::ScanProcesses(const std::vector<std::wstring>& custom_blacklist) {
    ProcessAuditResult result;
    result.total_scanned = 0;

    std::unordered_set<std::wstring> custom_set;
    for (const auto& item : custom_blacklist) {
        custom_set.insert(ToLower(item));
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return result;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return result;
    }

    do {
        result.total_scanned++;

        std::wstring exeName = pe32.szExeFile;
        std::wstring lowerExe = ToLower(exeName);

        std::wstring category;
        std::wstring rule;
        bool isHit = false;

        if (IsBlacklisted(lowerExe, category, rule)) {
            isHit = true;
        } else if (custom_set.find(lowerExe) != custom_set.end()) {
            isHit = true;
            category = L"CUSTOM_BLACKLIST";
            rule = L"Specified in custom examination blacklist";
        }

        if (isHit) {
            DetectedProcess hit;
            hit.pid = pe32.th32ProcessID;
            hit.process_name = exeName;
            hit.category = category;
            hit.rule = rule;
            hit.full_path = L"";

            // Query full process image path if possible
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProc != NULL) {
                wchar_t pathBuf[MAX_PATH * 2] = { 0 };
                DWORD size = MAX_PATH * 2;
                if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &size)) {
                    hit.full_path = pathBuf;
                }
                CloseHandle(hProc);
            }

            result.detected.push_back(hit);
        }

    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return result;
}
