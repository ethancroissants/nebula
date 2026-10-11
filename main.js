const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const os = require('os');

// Keep a global reference of the window object
let mainWindow;

// Nebula paths (mirrors the Rust implementation)
const NEBULA_ROOT = path.join(os.homedir(), '.nebula');
const QUEUE_DIR = path.join(NEBULA_ROOT, 'queue');
const LOG_FILE = path.join(QUEUE_DIR, 'log');
const PREFS_FILE = path.join(NEBULA_ROOT, 'prefs.json');
const HOOK_LIB = path.join(NEBULA_ROOT, 'lib', 'libnebula_hook.so');

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 800,
    minHeight: 600,
    title: 'Nebula â for Sober',
    backgroundColor: '#0b0d12',
    titleBarStyle: 'hiddenInset',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Open external links in the default browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
}

// ---------------------------------------------------------------- helpers ---

function ensureDirs() {
  for (const dir of [NEBULA_ROOT, QUEUE_DIR, path.join(NEBULA_ROOT, 'lib')]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

// ------------------------------------------------------------------- IPC ----

ipcMain.handle('nebula:getState', async () => {
  ensureDirs();
  const prefs = loadPrefs();
  const procs = await findSoberProcesses();
  const override = await getOverride();
  return { prefs, procs, override, paths: { root: NEBULA_ROOT, queue: QUEUE_DIR, log: LOG_FILE } };
});

ipcMain.handle('nebula:savePrefs', async (_e, prefs) => {
  ensureDirs();
  fs.writeFileSync(PREFS_FILE, JSON.stringify(prefs, null, 2));
  return true;
});

ipcMain.handle('nebula:execute', async (_e, code) => {
  ensureDirs();
  const file = path.join(QUEUE_DIR, `script_${Date.now()}.lua`);
  fs.writeFileSync(file, code);
  return { file };
});

ipcMain.handle('nebula:readLog', async () => {
  try {
    return fs.readFileSync(LOG_FILE, 'utf8');
  } catch {
    return '';
  }
});

ipcMain.handle('nebula:attach', async () => {
  const res = await run('nebula-attach');
  return res;
});

ipcMain.handle('nebula:launchSober', async () => {
  const res = await run('flatpak run org.vinegarhq.Sober');
  return res;
});

ipcMain.handle('nebula:checkSober', async () => {
  const res = await run('flatpak info org.vinegarhq.Sober');
  return res.ok;
});

ipcMain.handle('nebula:installSober', async () => {
  const res = await run('flatpak install -y flathub org.vinegarhq.Sober');
  return res;
});

// ------------------------------------------------------------------ boot ---

function loadPrefs() {
  try {
    return JSON.parse(fs.readFileSync(PREFS_FILE, 'utf8'));
  } catch {
    return { autoAttach: true, fontSize: 13.5 };
  }
}

async function findSoberProcesses() {
  const res = await run("ps -eo pid,comm,args | grep -i sober | grep -v grep");
  if (!res.ok || !res.stdout) return [];
  return res.stdout.split('\n').map((line) => {
    const [pid, ...rest] = line.trim().split(/\s+/);
    return { pid: parseInt(pid, 10), cmd: rest.join(' ') };
  }).filter((p) => !isNaN(p.pid));
}

async function getOverride() {
  const res = await run('flatpak override --show org.vinegarhq.Sober');
  return res.ok ? res.stdout : '';
}

app.whenReady().then(() => {
  ensureDirs();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});