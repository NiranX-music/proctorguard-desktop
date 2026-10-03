/**
 * ProctorGuard Desktop Lockdown Container - Renderer Controller
 */

(function () {
  let sessionConfig = null;

  // DOM Elements
  const examFrame = document.getElementById('examFrame');
  const lockdownStatusBadge = document.getElementById('lockdownStatusBadge');
  const statusLabel = document.getElementById('statusLabel');
  const valDisplays = document.getElementById('valDisplays');
  const valProcesses = document.getElementById('valProcesses');
  const valModules = document.getElementById('valModules');
  const valEngine = document.getElementById('valEngine');
  const wsIndicator = document.getElementById('wsIndicator');
  const wsLabel = document.getElementById('wsLabel');
  const threatTicker = document.getElementById('threatTicker');
  const threatMsg = document.getElementById('threatMsg');
  const lockoutCurtain = document.getElementById('lockoutCurtain');
  const lockoutReason = document.getElementById('lockoutReason');
  const lockSessionId = document.getElementById('lockSessionId');
  const lockCandidateId = document.getElementById('lockCandidateId');
  const btnRescan = document.getElementById('btnRescan');
  const btnEmergencyExit = document.getElementById('btnEmergencyExit');
  const exitModal = document.getElementById('exitModal');
  const exitPinInput = document.getElementById('exitPinInput');
  const btnCancelExit = document.getElementById('btnCancelExit');
  const btnConfirmExit = document.getElementById('btnConfirmExit');
  const exitErrorMsg = document.getElementById('exitErrorMsg');

  // Initialize
  async function init() {
    if (!window.desktopProctor) {
      console.warn('desktopProctor context bridge not available. Running in standard browser?');
      return;
    }

    try {
      sessionConfig = await window.desktopProctor.getConfig();
      lockSessionId.textContent = sessionConfig.sessionId;
      lockCandidateId.textContent = sessionConfig.candidateId;

      // Load exam URL in iframe
      const examUrl = `${sessionConfig.serverUrl}/app/candidate/exam.html?session_id=${encodeURIComponent(sessionConfig.sessionId)}&candidate_id=${encodeURIComponent(sessionConfig.candidateId)}&mode=desktop_companion`;
      examFrame.src = examUrl;

      // Listen for updates from Main process
      window.desktopProctor.onTelemetryUpdate(handleTelemetryUpdate);
      window.desktopProctor.onLockdownStateChange(handleLockdownStateChange);
      window.desktopProctor.onProctorCommand(handleProctorCommand);
      window.desktopProctor.onSecurityViolation(handleSecurityViolation);

      // Trigger initial audit
      const initialAudit = await window.desktopProctor.getLastAudit();
      if (initialAudit) {
        handleTelemetryUpdate({ audit: initialAudit });
      }
    } catch (err) {
      console.error('Initialization error:', err);
    }
  }

  function handleTelemetryUpdate(data) {
    if (!data) return;

    // WebSocket Link Status
    if (typeof data.wsConnected === 'boolean') {
      const dot = wsIndicator.querySelector('.status-dot');
      if (data.wsConnected) {
        dot.className = 'status-dot green';
        wsLabel.textContent = 'LINK ACTIVE';
      } else {
        dot.className = 'status-dot red';
        wsLabel.textContent = 'RECONNECTING';
      }
    }

    // Telemetry from audit
    if (data.audit) {
      const a = data.audit;

      // Displays
      const dCount = a.displayCount || 1;
      valDisplays.textContent = `${dCount} ${dCount === 1 ? '(OK)' : '(FLAGGED)'}`;
      valDisplays.className = `pill-val ${dCount > 1 ? 'threat' : ''}`;

      // Processes
      const pScanned = a.processesScanned || 0;
      const pBlacklist = a.detectedBlacklist || [];
      if (pBlacklist.length > 0) {
        valProcesses.textContent = `${pBlacklist.length} BLOCKED`;
        valProcesses.className = 'pill-val threat';
      } else {
        valProcesses.textContent = `${pScanned} Scanned (OK)`;
        valProcesses.className = 'pill-val';
      }

      // Modules / DLLs
      const mSuspicious = a.suspiciousModules || [];
      if (mSuspicious.length > 0) {
        valModules.textContent = `${mSuspicious.length} HOOKS`;
        valModules.className = 'pill-val threat';
      } else {
        valModules.textContent = 'Verified Clean';
        valModules.className = 'pill-val';
      }

      // Engine
      valEngine.textContent = a.engine === 'native_cpp' ? 'C++ Toolhelp32' : 'Win32 PowerShell';

      // Threat ticker display
      if (a.threatCount > 0 || pBlacklist.length > 0 || dCount > 1 || mSuspicious.length > 0) {
        threatTicker.style.display = 'flex';
        let msgs = [];
        if (pBlacklist.length > 0) msgs.push(`Blacklisted apps: ${pBlacklist.map(p => p.name).join(', ')}`);
        if (dCount > 1) msgs.push(`Multi-monitor topology detected (${dCount} displays)`);
        if (mSuspicious.length > 0) msgs.push(`Suspicious hooks/DLLs in process`);
        threatMsg.textContent = `OS THREATS DETECTED: ${msgs.join(' | ')}`;
      } else {
        threatTicker.style.display = 'none';
      }
    }
  }

  function handleLockdownStateChange(state) {
    if (!state) return;
    const status = state.status || 'ACTIVE';

    if (status === 'LOCKED') {
      lockdownStatusBadge.className = 'security-status locked';
      lockdownStatusBadge.querySelector('.status-dot').className = 'status-dot red';
      statusLabel.textContent = 'LOCKED BY PROCTOR';
      lockoutReason.textContent = state.reason || 'Workstation locked by proctor administrator.';
      lockoutCurtain.style.display = 'flex';
    } else if (status === 'TERMINATED') {
      lockdownStatusBadge.className = 'security-status locked';
      lockdownStatusBadge.querySelector('.status-dot').className = 'status-dot red';
      statusLabel.textContent = 'EXAM TERMINATED';
      lockoutReason.textContent = state.reason || 'This examination session has been disqualified and terminated.';
      lockoutCurtain.style.display = 'flex';
    } else {
      lockdownStatusBadge.className = 'security-status';
      lockdownStatusBadge.querySelector('.status-dot').className = 'status-dot green';
      statusLabel.textContent = 'ACTIVE LOCKDOWN';
      lockoutCurtain.style.display = 'none';
    }
  }

  function handleProctorCommand(cmd) {
    if (cmd && cmd.action === 'PROMPT_EMERGENCY_EXIT') {
      openExitModal();
    }
  }

  function handleSecurityViolation(viol) {
    console.warn('Keyboard or system violation trapped:', viol);
    threatTicker.style.display = 'flex';
    threatMsg.textContent = `RESTRICTED INPUT ATTEMPT: System blocked ${viol.shortcut || 'shortcut'}.`;
    setTimeout(() => {
      threatTicker.style.display = 'none';
    }, 4000);
  }

  // Rescan button
  btnRescan.addEventListener('click', async () => {
    btnRescan.disabled = true;
    btnRescan.textContent = 'Scanning...';
    try {
      const res = await window.desktopProctor.runAudit();
      handleTelemetryUpdate({ audit: res });
    } catch (e) {
      console.error(e);
    } finally {
      btnRescan.disabled = false;
      btnRescan.textContent = '↻ Audit Now';
    }
  });

  // Emergency Exit Handling
  function openExitModal() {
    exitModal.style.display = 'flex';
    exitPinInput.value = '';
    exitErrorMsg.textContent = '';
    exitPinInput.focus();
  }

  btnEmergencyExit.addEventListener('click', openExitModal);

  btnCancelExit.addEventListener('click', () => {
    exitModal.style.display = 'none';
  });

  btnConfirmExit.addEventListener('click', async () => {
    const pin = exitPinInput.value.trim();
    if (!pin) {
      exitErrorMsg.textContent = 'Please enter proctor key.';
      return;
    }
    const res = await window.desktopProctor.requestEmergencyExit(pin);
    if (!res.success) {
      exitErrorMsg.textContent = res.error || 'Invalid key.';
    }
  });

  exitPinInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') btnConfirmExit.click();
    if (e.key === 'Escape') btnCancelExit.click();
  });

  document.addEventListener('DOMContentLoaded', init);
})();
