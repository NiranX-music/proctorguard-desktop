#include "display_auditor.h"
#include <algorithm>

DisplayAuditor::DisplayAuditor() {}
DisplayAuditor::~DisplayAuditor() {}

BOOL CALLBACK DisplayAuditor::MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) {
    DisplayAuditResult* pResult = reinterpret_cast<DisplayAuditResult*>(dwData);

    MONITORINFOEXW mi;
    mi.cbSize = sizeof(MONITORINFOEXW);

    if (GetMonitorInfoW(hMonitor, &mi)) {
        DisplayInfo info;
        info.device_name = mi.szDevice;
        info.left = mi.rcMonitor.left;
        info.top = mi.rcMonitor.top;
        info.right = mi.rcMonitor.right;
        info.bottom = mi.rcMonitor.bottom;
        info.width = mi.rcMonitor.right - mi.rcMonitor.left;
        info.height = mi.rcMonitor.bottom - mi.rcMonitor.top;
        info.is_primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
        info.is_mirror = false;
        info.is_remoting = false;
        info.device_string = L"";

        pResult->displays.push_back(info);
    }

    return TRUE;
}

static std::wstring ToLowerStr(const std::wstring& s) {
    std::wstring r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::towlower);
    return r;
}

DisplayAuditResult DisplayAuditor::AuditDisplays() {
    DisplayAuditResult result;
    result.display_count = 0;
    result.is_multi_display = false;
    result.has_cloned_displays = false;
    result.has_mirror_driver = false;
    result.has_virtual_display = false;

    // 1. Enumerate visible desktop monitors
    EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, reinterpret_cast<LPARAM>(&result));
    result.display_count = static_cast<int>(result.displays.size());

    // 2. Query EnumDisplayDevices for device metadata, mirror drivers, and virtual displays
    DISPLAY_DEVICEW dd;
    dd.cb = sizeof(DISPLAY_DEVICEW);
    DWORD devNum = 0;

    while (EnumDisplayDevicesW(NULL, devNum, &dd, 0)) {
        if (dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) {
            std::wstring devName = dd.DeviceName;
            std::wstring devString = dd.DeviceString;
            std::wstring lowerDevString = ToLowerStr(devString);

            // Match with display info in result
            for (auto& disp : result.displays) {
                if (disp.device_name == devName) {
                    disp.device_string = devString;
                    if (dd.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) {
                        disp.is_mirror = true;
                        result.has_mirror_driver = true;
                    }
                }
            }

            // Check for virtual display adapter patterns or software screen extenders
            if (lowerDevString.find(L"iddsampledriver") != std::wstring::npos ||
                lowerDevString.find(L"virtual") != std::wstring::npos ||
                lowerDevString.find(L"spacedesk") != std::wstring::npos ||
                lowerDevString.find(L"duet") != std::wstring::npos ||
                lowerDevString.find(L"vnc") != std::wstring::npos ||
                lowerDevString.find(L"rdp") != std::wstring::npos) {
                result.has_virtual_display = true;
            }
        }
        devNum++;
    }

    // 3. Multi-monitor detection
    if (result.display_count > 1) {
        result.is_multi_display = true;
        result.violations.push_back(L"Multiple monitors connected (" + std::to_wstring(result.display_count) + L" displays)");
    }

    // 4. Cloned display detection (multiple monitors with identical top-left coordinates and dimensions)
    if (result.displays.size() > 1) {
        for (size_t i = 0; i < result.displays.size(); i++) {
            for (size_t j = i + 1; j < result.displays.size(); j++) {
                if (result.displays[i].left == result.displays[j].left &&
                    result.displays[i].top == result.displays[j].top &&
                    result.displays[i].width == result.displays[j].width &&
                    result.displays[i].height == result.displays[j].height) {
                    result.has_cloned_displays = true;
                    result.violations.push_back(L"Cloned / duplicate display coordinates detected (hardware splitter or mirroring)");
                    break;
                }
            }
            if (result.has_cloned_displays) break;
        }
    }

    if (result.has_mirror_driver) {
        result.violations.push_back(L"Mirroring driver active (suspected software screen capture or remote projection)");
    }

    if (result.has_virtual_display) {
        result.violations.push_back(L"Virtual display driver or software monitor extender detected");
    }

    return result;
}
