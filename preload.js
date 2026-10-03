/**
 * ProctorGuard Desktop Lockdown Agent - Preload Bridge
 * Exposes a secure, sandboxed IPC bridge to the renderer process.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopProctor', {
  // Session Configuration & Status
  getConfig: () => ipcRenderer.invoke('get-config'),
  getStatus: () => ipcRenderer.invoke('get-status'),
  
  // OS Telemetry & Audits
  runAudit: (options) => ipcRenderer.invoke('run-audit', options),
  getLastAudit: () => ipcRenderer.invoke('get-last-audit'),

  // Event Listeners from Main Process
  onTelemetryUpdate: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('telemetry-update', handler);
    return () => ipcRenderer.removeListener('telemetry-update', handler);
  },

  onLockdownStateChange: (callback) => {
    const handler = (_event, state) => callback(state);
    ipcRenderer.on('lockdown-state', handler);
    return () => ipcRenderer.removeListener('lockdown-state', handler);
  },

  onProctorCommand: (callback) => {
    const handler = (_event, command) => callback(command);
    ipcRenderer.on('proctor-command', handler);
    return () => ipcRenderer.removeListener('proctor-command', handler);
  },

  onSecurityViolation: (callback) => {
    const handler = (_event, violation) => callback(violation);
    ipcRenderer.on('security-violation', handler);
    return () => ipcRenderer.removeListener('security-violation', handler);
  },

  // Actions
  dispatchIncident: (incident) => ipcRenderer.invoke('dispatch-incident', incident),
  requestEmergencyExit: (authKey) => ipcRenderer.invoke('emergency-exit', authKey),
  minimizeCompanionHUD: () => ipcRenderer.send('hud-minimize'),
  maximizeCompanionHUD: () => ipcRenderer.send('hud-maximize'),
  reloadExamView: () => ipcRenderer.send('reload-exam')
});
