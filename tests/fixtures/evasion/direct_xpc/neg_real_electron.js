// Source: electron/lib/browser/api/power-monitor.ts@vX.Y.Z
// Legitimate power-state monitoring in Electron IPC.
// Actual implementation uses Node.js EventEmitter and Chromium internal IPC.
// No raw Apple IPC function calls are present in this file.
const powerMonitor = {
  on: (event, handler) => { emitter.on(event, handler); },
  off: (event, handler) => { emitter.off(event, handler); },
};
module.exports = powerMonitor;
