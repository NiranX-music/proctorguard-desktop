/**
 * ProctorGuard Native OS Auditor Bridge
 * 
 * Provides hybrid dual-engine auditing:
 * 1. Native C++ Win32 Addon (Toolhelp32, PSAPI EnumProcessModulesEx, EnumDisplayMonitors)
 * 2. High-reliability pure Node.js / PowerShell bridge fallback for systems without C++ compilers.
 */

const path = require('path');
const fs = require('fs');
const { execFile, spawn } = require('child_process');

class NativeAuditor {
  constructor() {
    this.nativeAddon = null;
    this.isNativeAvailable = false;
    this.psScriptPath = path.join(__dirname, 'scripts', 'audit.ps1');
    this.initNativeEngine();
  }

  /**
   * Attempt to load precompiled C++ native addon
   */
  initNativeEngine() {
    const candidatePaths = [
      path.join(__dirname, 'build', 'Release', 'desktop_auditor.node'),
      path.join(__dirname, '..', 'build', 'Release', 'desktop_auditor.node'),
      path.join(__dirname, 'build', 'Debug', 'desktop_auditor.node'),
      path.join(__dirname, 'desktop_auditor.node')
    ];

    for (const p of candidatePaths) {
      if (fs.existsSync(p)) {
        try {
          this.nativeAddon = require(p);
          this.isNativeAvailable = true;
          console.log(`[NativeAuditor] Loaded Win32 C++ addon from: ${p}`);
          break;
        } catch (err) {
          console.warn(`[NativeAuditor] Failed loading addon at ${p}:`, err.message);
        }
      }
    }

    if (!this.isNativeAvailable) {
      console.log('[NativeAuditor] Using high-reliability Win32 PowerShell bridge fallback.');
    }
  }

  isNative() {
    return this.isNativeAvailable;
  }

  /**
   * Execute PowerShell script and parse JSON output
   * @param {string} action - 'full' | 'processes' | 'modules' | 'displays'
   * @param {Object} options
   */
  runPowerShellBridge(action = 'full', options = {}) {
    return new Promise((resolve, reject) => {
      const targetPid = options.targetPid || process.pid;
      const customList = options.customBlacklist ? JSON.stringify(options.customBlacklist) : '[]';

      const args = [
        '-NoProfile',
        '-NoLogo',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        this.psScriptPath,
        '-Action',
        action,
        '-TargetPid',
        String(targetPid),
        '-CustomBlacklistJson',
        customList
      ];

      execFile('powershell.exe', args, { timeout: 8000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          return reject(new Error(`PowerShell auditor failed: ${error.message} (stderr: ${stderr})`));
        }

        try {
          const trimmed = (stdout || '').trim();
          if (!trimmed) {
            return reject(new Error('PowerShell auditor returned empty output'));
          }
          const parsed = JSON.parse(trimmed);
          resolve(parsed);
        } catch (parseErr) {
          reject(new Error(`Failed to parse PowerShell JSON output: ${parseErr.message}\nRaw: ${stdout.substring(0, 300)}`));
        }
      });
    });
  }

  /**
   * Audit running processes for blacklisted applications
   * @param {string[]} customBlacklist
   */
  async checkProcesses(customBlacklist = []) {
    if (this.isNativeAvailable && this.nativeAddon && typeof this.nativeAddon.checkProcesses === 'function') {
      try {
        const raw = this.nativeAddon.checkProcesses(customBlacklist);
        return {
          totalScanned: raw.totalScanned || 0,
          detected: raw.detected || [],
          status: (raw.detected && raw.detected.length > 0) ? 'THREAT' : 'OK',
          engine: 'native_cpp'
        };
      } catch (e) {
        console.warn('[NativeAuditor] Native checkProcesses error, falling back to PS:', e.message);
      }
    }

    const res = await this.runPowerShellBridge('processes', { customBlacklist });
    return {
      ...res,
      engine: 'win32_powershell_bridge'
    };
  }

  /**
   * Audit loaded modules in process for hooks, injectors, or Temp DLLs
   * @param {number} pid
   */
  async auditModules(pid = 0) {
    if (this.isNativeAvailable && this.nativeAddon && typeof this.nativeAddon.auditModules === 'function') {
      try {
        const raw = this.nativeAddon.auditModules(pid || process.pid);
        return {
          totalModules: raw.totalModules || 0,
          suspicious: raw.suspicious || [],
          status: (raw.suspicious && raw.suspicious.length > 0) ? 'THREAT' : 'OK',
          engine: 'native_cpp'
        };
      } catch (e) {
        console.warn('[NativeAuditor] Native auditModules error, falling back to PS:', e.message);
      }
    }

    const res = await this.runPowerShellBridge('modules', { targetPid: pid || process.pid });
    return {
      ...res,
      engine: 'win32_powershell_bridge'
    };
  }

  /**
   * Audit display configuration for secondary monitors or cloning
   */
  async auditDisplays() {
    if (this.isNativeAvailable && this.nativeAddon && typeof this.nativeAddon.auditDisplays === 'function') {
      try {
        const raw = this.nativeAddon.auditDisplays();
        return {
          displayCount: raw.displayCount || 1,
          isMultiDisplay: Boolean(raw.isMultiDisplay),
          hasClonedDisplays: Boolean(raw.hasClonedDisplays),
          hasMirrorDriver: Boolean(raw.hasMirrorDriver),
          hasVirtualDisplay: Boolean(raw.hasVirtualDisplay),
          displays: raw.displays || [],
          violations: raw.violations || [],
          status: (raw.violations && raw.violations.length > 0) ? 'THREAT' : 'OK',
          engine: 'native_cpp'
        };
      } catch (e) {
        console.warn('[NativeAuditor] Native auditDisplays error, falling back to PS:', e.message);
      }
    }

    const res = await this.runPowerShellBridge('displays');
    return {
      ...res,
      engine: 'win32_powershell_bridge'
    };
  }

  /**
   * Run all three audits and synthesize a unified security report
   * @param {Object} options
   */
  async runFullAudit(options = {}) {
    if (this.isNativeAvailable) {
      try {
        const [proc, mod, disp] = await Promise.all([
          this.checkProcesses(options.customBlacklist || []),
          this.auditModules(options.targetPid || process.pid),
          this.auditDisplays()
        ]);

        const threats = [];
        for (const p of proc.detected) {
          threats.push({
            type: 'PROCESS_BLACKLIST_HIT',
            severity: 'CRITICAL',
            details: `${p.name} running (PID: ${p.pid}, Category: ${p.category})`,
            target: p
          });
        }

        for (const m of mod.suspicious) {
          threats.push({
            type: 'INJECTED_DLL_DETECTED',
            severity: m.severity || 'CRITICAL',
            details: `${m.name}: ${m.reason}`,
            target: m
          });
        }

        for (const v of disp.violations) {
          threats.push({
            type: 'MULTIPLE_DISPLAYS_DETECTED',
            severity: 'CRITICAL',
            details: v,
            target: disp
          });
        }

        return {
          timestamp: new Date().toISOString(),
          engine: 'native_cpp',
          processes: proc,
          modules: mod,
          displays: disp,
          hasThreats: threats.length > 0,
          threatCount: threats.length,
          threats
        };
      } catch (e) {
        console.warn('[NativeAuditor] Error running native full audit, falling back to PS:', e.message);
      }
    }

    return await this.runPowerShellBridge('full', options);
  }
}

module.exports = new NativeAuditor();
