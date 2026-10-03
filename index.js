/**
 * ProctorGuard Desktop Lockdown Container & Companion Agent
 * Electron Main Process
 */

const { app, BrowserWindow, globalShortcut, ipcMain, screen, dialog } = require('electron');
const path = require('path');
const WebSocket = require('ws');
const nativeAuditor = require('./native-auditor');

// Configuration
const CONFIG = {
  sessionId: process.env.PROCTOR_SESSION_ID || 'DEMO-SESSION-001',
  candidateId: process.env.PROCTOR_CANDIDATE_ID || 'CAND-89421',
  serverUrl: process.env.PROCTOR_SERVER_URL || 'http://127.0.0.1:8080',
  wsUrl: process.env.PROCTOR_WS_URL || 'ws://127.0.0.1:8080',
  isDev: process.argv.includes('--dev') || process.env.NODE_ENV === 'development',
  auditIntervalMs: 4000,
  emergencyExitPin: 'proctor99'
};

// Security flags for Chromium runtime
app.commandLine.appendSwitch('disable-extensions');
app.commandLine.appendSwitch('disable-plugins');
app.commandLine.appendSwitch('disable-software-rasterizer');
app.commandLine.appendSwitch('incognito');
app.commandLine.appendSwitch('disable-features', 'TranslateUI,AutofillServerCommunication');

let mainWindow = null;
let companionWs = null;
let auditTimer = null;
let lastAuditResult = null;
let lockdownStatus = 'ACTIVE'; // 'ACTIVE' | 'LOCKED' | 'TERMINATED'
let activeLockReason = null;
let lastReportedThreats = new Set();

/**
 * Initialize Desktop Lockdown Window
 */
function createLockdownWindow() {
  const primaryDisplay = screen.getPrimaryDisplay();
  const { width, height } = primaryDisplay.workAreaSize;

  mainWindow = new BrowserWindow({
    width: width,
    height: height,
    fullscreen: !CONFIG.isDev,
    kiosk: !CONFIG.isDev,
    alwaysOnTop: !CONFIG.isDev,
    frame: CONFIG.isDev,
    resizable: CONFIG.isDev,
    backgroundColor: '#0a0f1d',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      enableBlinkFeatures: ''
    }
  });

  // Load the Companion Container UI
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Block DevTools in non-dev mode
  mainWindow.webContents.on('devtools-opened', () => {
    if (!CONFIG.isDev) {
      mainWindow.webContents.closeDevTools();
      reportIncidentToBackend({
        eventType: 'CONTEXT_MENU_ATTEMPT',
        severity: 'HIGH',
        metadata: { action: 'devtools_opened', blocked: true }
      });
    }
  });

  // Prevent navigation outside exam portal
  mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
    const parsed = new URL(navigationUrl);
    const allowed = ['127.0.0.1', 'localhost'];
    if (!allowed.includes(parsed.hostname) && !navigationUrl.startsWith('file://')) {
      console.warn('[Lockdown] Blocked navigation attempt to:', navigationUrl);
      event.preventDefault();
      reportIncidentToBackend({
        eventType: 'TAB_BLUR',
        severity: 'HIGH',
        metadata: { blockedUrl: navigationUrl }
      });
    }
  });

  // Display configuration change listener
  screen.on('display-added', (_event, newDisplay) => {
    console.warn('[Lockdown] Secondary display connected:', newDisplay.id);
    reportIncidentToBackend({
      eventType: 'MULTIPLE_DISPLAYS_DETECTED',
      severity: 'CRITICAL',
      metadata: { displayAdded: true, displayId: newDisplay.id }
    });
  });

  screen.on('display-removed', (_event, oldDisplay) => {
    console.warn('[Lockdown] Display removed:', oldDisplay.id);
    reportIncidentToBackend({
      eventType: 'DISPLAY_TOPOLOGY_CHANGED',
      severity: 'HIGH',
      metadata: { displayRemoved: true, displayId: oldDisplay.id }
    });
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

/**
 * Register Global Keyboard Interceptors to trap OS shortcuts
 */
function registerSecurityShortcuts() {
  if (CONFIG.isDev) {
    console.log('[Lockdown] Dev mode: Skipping aggressive global shortcut traps.');
    return;
  }

  const trappedCombos = [
    'Alt+Tab',
    'Alt+F4',
    'Ctrl+Shift+I',
    'F12',
    'F11',
    'Ctrl+W',
    'Ctrl+R',
    'Super',
    'CommandOrControl+Escape'
  ];

  for (const combo of trappedCombos) {
    try {
      globalShortcut.register(combo, () => {
        console.warn(`[Lockdown] Intercepted blocked shortcut: ${combo}`);
        if (mainWindow) {
          mainWindow.webContents.send('security-violation', {
            type: 'KEYBOARD_TRAP',
            shortcut: combo,
            timestamp: new Date().toISOString()
          });
        }
        reportIncidentToBackend({
          eventType: 'CLIPBOARD_VIOLATION',
          severity: 'LOW',
          metadata: { blockedKeyCombination: combo }
        });
      });
    } catch (e) {
      console.warn(`[Lockdown] Could not register shortcut ${combo}:`, e.message);
    }
  }

  // Emergency exit shortcut for proctors: Ctrl+Alt+Shift+Q
  globalShortcut.register('CommandOrControl+Alt+Shift+Q', () => {
    showExitDialog();
  });
}

/**
 * Connect to Backend WebSocket Companion Endpoint
 */
function initCompanionWebSocket() {
  const wsEndpoint = `${CONFIG.wsUrl}/ws/companion/${CONFIG.sessionId}/${CONFIG.candidateId}`;
  console.log(`[Lockdown] Connecting to companion endpoint: ${wsEndpoint}`);

  try {
    companionWs = new WebSocket(wsEndpoint);

    companionWs.on('open', () => {
      console.log('[Lockdown] WebSocket connected to proctor backend.');
      if (mainWindow) {
        mainWindow.webContents.send('telemetry-update', { wsConnected: true });
      }
    });

    companionWs.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        handleBackendMessage(msg);
      } catch (err) {
        console.error('[Lockdown] Error parsing backend message:', err);
      }
    });

    companionWs.on('close', () => {
      console.warn('[Lockdown] WebSocket disconnected. Reconnecting in 3s...');
      if (mainWindow) {
        mainWindow.webContents.send('telemetry-update', { wsConnected: false });
      }
      setTimeout(initCompanionWebSocket, 3000);
    });

    companionWs.on('error', (err) => {
      console.warn('[Lockdown] WebSocket error:', err.message);
    });
  } catch (err) {
    console.error('[Lockdown] Failed to create WebSocket:', err);
    setTimeout(initCompanionWebSocket, 3000);
  }
}

/**
 * Handle remote proctor commands from backend
 */
function handleBackendMessage(msg) {
  const type = msg.type || '';

  if (type === 'pong') return;

  if (type === 'command') {
    const action = (msg.action || '').toUpperCase();
    console.log(`[Lockdown] Received proctor command: ${action}`, msg);

    if (action === 'LOCK') {
      lockdownStatus = 'LOCKED';
      activeLockReason = msg.reason || 'Exam interface locked by proctor';
      if (mainWindow) {
        mainWindow.webContents.send('lockdown-state', {
          status: 'LOCKED',
          reason: activeLockReason,
          message: msg.message
        });
      }
    } else if (action === 'UNLOCK') {
      lockdownStatus = 'ACTIVE';
      activeLockReason = null;
      if (mainWindow) {
        mainWindow.webContents.send('lockdown-state', {
          status: 'ACTIVE',
          reason: null,
          message: 'Exam unlocked by proctor.'
        });
      }
    } else if (action === 'TERMINATE') {
      lockdownStatus = 'TERMINATED';
      activeLockReason = msg.reason || 'Session terminated by proctor';
      if (mainWindow) {
        mainWindow.webContents.send('lockdown-state', {
          status: 'TERMINATED',
          reason: activeLockReason,
          message: msg.message
        });
      }
    } else if (action === 'WARN') {
      if (mainWindow) {
        mainWindow.webContents.send('proctor-command', msg);
      }
    }
  }
}

/**
 * Report security violation or telemetry incident to backend
 */
function reportIncidentToBackend(incident) {
  if (!companionWs || companionWs.readyState !== WebSocket.OPEN) {
    console.warn('[Lockdown] Cannot send incident: WS not open.');
    return;
  }

  const payload = {
    type: 'incident',
    data: {
      sessionId: CONFIG.sessionId,
      candidateId: CONFIG.candidateId,
      timestamp: new Date().toISOString(),
      severity: incident.severity || 'CRITICAL',
      eventType: incident.eventType,
      metadata: {
        ...(incident.metadata || {}),
        hostOS: process.platform,
        source: 'desktop_companion'
      },
      snapshotFrame: incident.snapshotFrame || null
    }
  };

  try {
    companionWs.send(JSON.stringify(payload));
    console.log(`[Lockdown] Dispatched incident: ${incident.eventType} (${incident.severity})`);
  } catch (err) {
    console.error('[Lockdown] Error sending incident to backend:', err);
  }
}

/**
 * Periodic Native OS Security Audit Loop
 */
async function runPeriodicAudit() {
  try {
    const audit = await nativeAuditor.runFullAudit();
    lastAuditResult = audit;

    if (mainWindow) {
      mainWindow.webContents.send('telemetry-update', {
        audit: {
          timestamp: audit.timestamp,
          engine: audit.engine,
          processesScanned: audit.processes?.totalScanned || 0,
          detectedBlacklist: audit.processes?.detected || [],
          modulesInspected: audit.modules?.totalModules || 0,
          suspiciousModules: audit.modules?.suspicious || [],
          displayCount: audit.displays?.displayCount || 1,
          isMultiDisplay: audit.displays?.isMultiDisplay || false,
          threatCount: audit.threatCount || 0
        },
        wsConnected: Boolean(companionWs && companionWs.readyState === WebSocket.OPEN),
        lockdownStatus
      });
    }

    // Check for new threats and report once per signature
    if (audit.hasThreats && audit.threats && audit.threats.length > 0) {
      for (const threat of audit.threats) {
        const threatSig = `${threat.type}:${threat.details}`;
        if (!lastReportedThreats.has(threatSig)) {
          lastReportedThreats.add(threatSig);
          console.warn('[Lockdown] New OS threat detected:', threatSig);
          reportIncidentToBackend({
            eventType: threat.type,
            severity: threat.severity,
            metadata: {
              details: threat.details,
              target: threat.target,
              engine: audit.engine
            }
          });
        }
      }
    }
  } catch (err) {
    console.warn('[Lockdown] Audit cycle error:', err.message);
  }
}

function showExitDialog() {
  if (!mainWindow) return;
  mainWindow.webContents.send('proctor-command', { action: 'PROMPT_EMERGENCY_EXIT' });
}

// ---------------- IPC Handlers ----------------

ipcMain.handle('get-config', () => CONFIG);

ipcMain.handle('get-status', () => ({
  status: lockdownStatus,
  reason: activeLockReason,
  wsConnected: Boolean(companionWs && companionWs.readyState === WebSocket.OPEN),
  isDev: CONFIG.isDev
}));

ipcMain.handle('get-last-audit', () => lastAuditResult);

ipcMain.handle('run-audit', async (_event, options) => {
  return await nativeAuditor.runFullAudit(options);
});

ipcMain.handle('dispatch-incident', (_event, incident) => {
  reportIncidentToBackend(incident);
  return { success: true };
});

ipcMain.handle('emergency-exit', (_event, authKey) => {
  if (authKey === CONFIG.emergencyExitPin) {
    console.log('[Lockdown] Valid emergency PIN supplied. Terminating container.');
    app.isQuitting = true;
    app.quit();
    return { success: true };
  }
  return { success: false, error: 'Invalid Proctor Authentication Key' };
});

ipcMain.on('reload-exam', () => {
  if (mainWindow) {
    mainWindow.reload();
  }
});

// App Lifecycle
app.whenReady().then(() => {
  createLockdownWindow();
  registerSecurityShortcuts();
  initCompanionWebSocket();

  // Run initial audit after window settles
  setTimeout(() => {
    runPeriodicAudit();
    auditTimer = setInterval(runPeriodicAudit, CONFIG.auditIntervalMs);
  }, 1500);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createLockdownWindow();
    }
  });
});

app.on('will-quit', () => {
  if (auditTimer) clearInterval(auditTimer);
  globalShortcut.unregisterAll();
  if (companionWs) companionWs.close();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
