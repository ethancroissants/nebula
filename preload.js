const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nebula', {
  getState: () => ipcRenderer.invoke('nebula:getState'),
  savePrefs: (prefs) => ipcRenderer.invoke('nebula:savePrefs', prefs),
  execute: (code) => ipcRenderer.invoke('nebula:execute', code),
  readLog: () => ipcRenderer.invoke('nebula:readLog'),
  attach: () => ipcRenderer.invoke('nebula:attach'),
  launchAndInject: () => ipcRenderer.invoke('nebula:launchAndInject'),
  launchSober: () => ipcRenderer.invoke('nebula:launchSober'),
  stopSober: () => ipcRenderer.invoke('nebula:stopSober'),
  checkSober: () => ipcRenderer.invoke('nebula:checkSober'),
  installSober: () => ipcRenderer.invoke('nebula:installSober'),
  openFile: () => ipcRenderer.invoke('nebula:openFile'),
  saveFile: (content) => ipcRenderer.invoke('nebula:saveFile', content),
  onProgress: (cb) => ipcRenderer.on('nebula:progress', (_e, data) => cb(data)),
});
