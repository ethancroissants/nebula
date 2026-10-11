const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nebula', {
  getState: () => ipcRenderer.invoke('nebula:getState'),
  savePrefs: (prefs) => ipcRenderer.invoke('nebula:savePrefs', prefs),
  execute: (code) => ipcRenderer.invoke('nebula:execute', code),
  readLog: () => ipcRenderer.invoke('nebula:readLog'),
  attach: () => ipcRenderer.invoke('nebula:attach'),
  launchSober: () => ipcRenderer.invoke('nebula:launchSober'),
  checkSober: () => ipcRenderer.invoke('nebula:checkSober'),
  installSober: () => ipcRenderer.invoke('nebula:installSober'),
});