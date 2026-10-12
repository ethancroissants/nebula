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
const APP_ID = 'org.vinegarhq.Sober';
// Silence Chromium's security-warning spam in the terminal (the fontconfig /
// libva noise comes from the OS libs themselves and is harmless).
process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = 'true';
// Silence noisy fontconfig/va warnings that leak into the terminal on some distros.
process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = 'true';

// Where the hook library might live, in priority order
const HOOK_CANDIDATES = [
  path.join(NEBULA_ROOT, 'lib', 'libnebula_hook.so'),
  path.join(os.homedir(), '.local', 'lib', 'nebula', 'libnebula_hook.so'),
  path.join(os.homedir(), '.local', 'lib', 'nebula', 'hook', 'libnebula_hook.so'),
  '/usr/lib/nebula/libnebula_hook.so',
  '/usr/local/lib/nebula/libnebula_hook.so',
  path.join(__dirname, 'libnebula_hook.so'),
  path.join(__dirname, 'hook', 'libnebula_hook.so'),
  path.join(__dirname, '..', 'hook', 'libnebula_hook.so'),
  path.join(__dirname, 'target', 'release', 'libnebula_hook.so'),
];

// Where the legacy attach helper might live (used only as a fallback)
const ATTACH_CANDIDATES = [
  path.join(os.homedir(), '.local', 'bin', 'nebula-attach'),
  '/usr/local/bin/nebula-attach',
  '/usr/bin/nebula-attach',
  path.join(__dirname, 'nebula-attach'),
  path.join(__dirname, 'hook', 'nebula-attach'),
  path.join(__dirname, '..', 'hook', 'nebula-attach'),
];

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1140,
    height: 780,
    minWidth: 860,
    minHeight: 600,
    title: 'Nebula — for Sober',
    backgroundColor: '#07080d',
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

  mainWindow.on('closed', () => { mainWindow = null; });
}

// ---------------------------------------------------------------- helpers ---

function ensureDirs() {
  for (const dir of [NEBULA_ROOT, QUEUE_DIR, path.join(NEBULA_ROOT, 'lib')]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function run(cmd, timeoutMs = 30000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: timeoutMs }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: (stdout || '').trim(), stderr: (stderr || '').trim() });
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function sendProgress(phase, message) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('nebula:progress', { phase, message });
  }
}

function log(message, kind = '') {
  sendProgress(kind === '' ? 'log' : kind, message);
}

function findHookLib() {
  for (const candidate of HOOK_CANDIDATES) {
    try { if (fs.existsSync(candidate)) return candidate; } catch {}
  }
  return null;
}

function findAttachScript() {
  for (const candidate of ATTACH_CANDIDATES) {
    try { if (fs.existsSync(candidate)) return candidate; } catch {}
  }
  return null;
}

// Where the flatpak runtime's /etc could live (user + system installs).
// glibc reads <sandbox>/etc/ld.so.preload at every process start inside the
// sandbox, which is how we make the hook survive Sober's env-scrubbing stub.
function runtimeEtcDirs() {
  const dirs = [];
  // user runtime installs
  dirs.push(path.join(os.homedir(), '.local/share/flatpak/runtime/org.gnome.Platform'));
  // system runtime installs
  dirs.push('/var/lib/flatpak/runtime/org.gnome.Platform');
  // walk the known x86_64 runtime dirs and return their etc/ paths
  const out = [];
  for (const base of dirs) {
    try {
      for (const entry of fs.readdirSync(base)) {
        out.push(path.join(base, entry, 'active', 'files', 'etc'));
      }
    } catch {}
  }
  return out;
}

function loadPrefs() {
  try {
    return JSON.parse(fs.readFileSync(PREFS_FILE, 'utf8'));
  } catch {
    return { autoAttach: true, fontSize: 13 };
  }
}

async function findSoberProcesses() {
  // Match the flatpak app id, the `sober` binary name and the game process,
  // but never our own grep (ps lists it while running under some shells).
  const res = await run(
    "ps -eo pid,comm,args | grep -Ei 'sober' | grep -Ev 'grep|nebula' || true"
  );
  if (!res.ok || !res.stdout) return [];
  return res.stdout
    .split('\n')
    .map((line) => {
      const [pid, ...rest] = line.trim().split(/\s+/);
      return { pid: parseInt(pid, 10), cmd: rest.join(' ') };
    })
    .filter((p) => !isNaN(p.pid) && p.pid > 0);
}

// Read /proc/<pid>/maps directly — far more reliable than shelling out to grep.
function procHasHook(pid) {
  try {
    const maps = fs.readFileSync(`/proc/${pid}/maps`, 'utf8');
    return maps.includes('libnebula_hook');
  } catch {
    return false;
  }
}

// Seed the hook into a Sober process's filesystem root, whatever that root is
// (the flatpak sandbox, or a chroot libloader prepared for the game).
// Writes /etc/ld.so.preload there and copies the .so to a path that exists
// inside that root (/tmp), so glibc picks the hook up at the next process
// start — immune to environment scrubbing.
function seedHookIntoProcRoot(pid, hookLib) {
  try {
    const root = `/proc/${pid}/root`;
    const etc = path.join(root, 'etc');
    fs.mkdirSync(etc, { recursive: true });
    // Copy the .so into the root's /tmp so the path is valid in that root.
    fs.mkdirSync(path.join(root, 'tmp'), { recursive: true });
    const target = path.join(root, 'tmp', 'libnebula_hook.so');
    fs.copyFileSync(hookLib, target);
    fs.chmodSync(target, 0o755);
    fs.writeFileSync(path.join(etc, 'ld.so.preload'), `${target}\n`);
    return true;
  } catch {
    return false;
  }
}

async function anyProcHasHook() {
  const procs = await findSoberProcesses();
  for (const proc of procs) {
    if (procHasHook(proc.pid)) return true;
  }
  return false;
}

// Apply the flatpak override ourselves (no external script, no PATH issues).
async function applyOverride(hookLib) {
  await run(`flatpak override --user --reset ${APP_ID}`, 15000);
  fs.mkdirSync(QUEUE_DIR, { recursive: true });
  const fsRes = await run(`flatpak override --user --filesystem="${QUEUE_DIR}:rw" ${APP_ID}`, 15000);

  // CRITICAL: the sandbox blocks $HOME entirely (Sober's manifest has no
  // filesystem permissions). LD_PRELOAD pointing into $HOME is silently
  // ignored by the loader if the file can't be read — which is exactly the
  // "stuck waiting for hook" bug. Grant the lib's directory read-only.
  const libDir = path.dirname(hookLib);
  const libRes = await run(`flatpak override --user --filesystem="${libDir}:ro" ${APP_ID}`, 15000);

  const envRes = await run(`flatpak override --user --env=LD_PRELOAD="${hookLib}" ${APP_ID}`, 15000);

  // BELT & SUSPENDERS: Sober's launcher is UPX-style packed and its stub
  // scrubs the environment on its internal re-exec — LD_PRELOAD reaches the
  // launcher process but is gone by the time the actual game process starts
  // (that's the "attached, then back to linking" symptom). glibc's
  // /etc/ld.so.preload lives inside the sandbox's /etc (sourced from the
  // flatpak runtime, which is user-writable on user installs), and it applies
  // to EVERY process launched in the sandbox regardless of environment.
  let preloadRes = { ok: true };
  try {
    const rtDirs = runtimeEtcDirs();
    for (const etc of rtDirs) {
      try {
        fs.mkdirSync(etc, { recursive: true });
        fs.writeFileSync(path.join(etc, 'ld.so.preload'), `${hookLib}\n`);
        break; // first writable runtime wins
      } catch {}
    }
  } catch {}
  void preloadRes;

  if (fsRes.ok && envRes.ok && libRes.ok) {
    // Verify the override actually stuck before launching.
    const show = await run(`flatpak override --user --show ${APP_ID}`, 15000);
    if (show.ok && show.stdout.includes('LD_PRELOAD') && show.stdout.includes('libnebula_hook')) {
      return { ok: true };
    }
    return { ok: false, error: 'Override verification failed: ' + (show.stdout || show.stderr) };
  }

  // Fallback: legacy attach helper script
  const script = findAttachScript();
  if (script) {
    const res = await run(`"${script}" "${hookLib}"`, 30000);
    if (res.ok) return { ok: true };
    return { ok: false, error: res.stderr || res.stdout || 'nebula-attach failed' };
  }
  return {
    ok: false,
    error: [fsRes, libRes, envRes].map((r) => r.stderr).filter(Boolean).join('; ') || 'flatpak override failed',
  };
}

// ------------------------------------------------------------------- IPC ----

ipcMain.handle('nebula:getState', async () => {
  ensureDirs();
  const prefs = loadPrefs();
  const procs = await findSoberProcesses();
  const override = await getOverride();
  const hookStatus = await getHookStatus();
  const hookLib = findHookLib();  return {
    prefs,
    procs,
    override,
    hookStatus,
    hookLib,
    paths: { root: NEBULA_ROOT, queue: QUEUE_DIR, log: LOG_FILE },
  };
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
// Legacy single-purpose handlers (kept for compatibility / scripting)
ipcMain.handle('nebula:attach', async () => {
  const hookLib = findHookLib();
  if (!hookLib) return { ok: false, stderr: 'libnebula_hook.so not found' };
  return applyOverride(hookLib);
});

ipcMain.handle('nebula:launchSober', async () => {
  const child = spawn('flatpak', ['run', APP_ID], { detached: true, stdio: 'ignore' });
  child.unref();
  return { ok: true };
});

ipcMain.handle('nebula:stopSober', async () => {
  await run('pkill -f "org.vinegarhq.Sober" || true', 10000);
  await run('pkill -x sober || true', 10000);
  await sleep(500);
  return { ok: true };
});

ipcMain.handle('nebula:checkSober', async () => {
  const res = await run(`flatpak info ${APP_ID}`, 15000);
  return res.ok;
});

ipcMain.handle('nebula:openFile', async () => {
  const { dialog } = require('electron');
  const win = mainWindow && !mainWindow.isDestroyed() ? mainWindow : undefined;
  const res = await dialog.showOpenDialog(win, {
    title: 'Open script',
    properties: ['openFile'],
    filters: [
      { name: 'Luau / Lua', extensions: ['lua', 'luau'] },
      { name: 'All files', extensions: ['*'] },
    ],
  });
  if (res.canceled || res.filePaths.length === 0) return null;
  try {
    return fs.readFileSync(res.filePaths[0], 'utf8');
  } catch (err) {
    return null;
  }
});

ipcMain.handle('nebula:saveFile', async (_e, content) => {
  const { dialog } = require('electron');
  const win = mainWindow && !mainWindow.isDestroyed() ? mainWindow : undefined;
  const res = await dialog.showSaveDialog(win, {
    title: 'Save script',
    defaultPath: path.join(os.homedir(), 'script.lua'),
    filters: [{ name: 'Luau / Lua', extensions: ['lua', 'luau'] }],
  });
  if (res.canceled || !res.filePath) return null;
  try {
    fs.writeFileSync(res.filePath, content);
    return true;
  } catch {
    return false;
  }
});

ipcMain.handle('nebula:installSober', async () => {
  sendProgress('installing', 'Installing Sober from Flathub…');
  const res = await run(`flatpak install -y flathub ${APP_ID}`, 600000);
  sendProgress('idle', res.ok ? 'Sober installed.' : 'Install failed.');
  return res;
});

// The one button that does everything, in the right order, with live progress:
//   stop stale Sober → apply override → launch detached → wait for the hook
//   to show up in the process' memory maps → report success.
ipcMain.handle('nebula:launchAndInject', async () => {
  try {
    ensureDirs();
    const prefs = loadPrefs();

    const hookLib = findHookLib();
    if (!hookLib) {
      sendProgress('error', 'Hook library not found — reinstall Nebula.');
      return { ok: false, error: 'libnebula_hook.so not found' };
    }

    // 1. A clean slate: LD_PRELOAD only applies at process start, so any
    //    already-running Sober would launch *without* the hook.
    let procs = await findSoberProcesses();
    if (procs.length > 0 && prefs.autoAttach !== false) {
      sendProgress('preparing', 'Stopping existing Sober…');
      await run('pkill -f "org.vinegarhq.Sober" || true', 10000);
      await run('pkill -x sober || true', 10000);
      await sleep(1500);
      procs = await findSoberProcesses();
      if (procs.length > 0) {
        await run('pkill -9 -f "org.vinegarhq.Sober" || true', 10000);
        await sleep(800);
      }
    }

    // 2. Apply + verify the sandbox override
    sendProgress('preparing', 'Applying sandbox override…');
    const override = await applyOverride(hookLib);
    if (!override.ok) {
      sendProgress('error', 'Override failed — see console.');
      log(`Override error details: ${override.error}`, 'err');
      return { ok: false, error: override.error || 'override failed' };
    }

    // 3. Launch Sober detached (never block on it — this was the old hang)
    sendProgress('launching', 'Launching Sober…');
    const child = spawn('flatpak', ['run', APP_ID], { detached: true, stdio: 'ignore' });
    child.unref();

    // 4. Poll for the hook inside the game process (map of wait phase → dot)
    sendProgress('waiting', 'Waiting for Sober to start…');
    const started = Date.now();
    const deadline = started + 120000;
    let lastNotice = 0;
    let seededRoots = new Set();
    while (Date.now() < deadline) {
      await sleep(700);
      const elapsed = Math.round((Date.now() - started) / 1000);
      // Ground truth = the hook's own heartbeat: ATTACHED only after it
      // captures the game's lua_State (immune to launcher-process confusion).
      try {
        const status = fs.readFileSync(path.join(QUEUE_DIR, 'status'), 'utf8').trim();
        if (status === 'ATTACHED') {
          sendProgress('injected', 'Injected — captured Luau VM.');
          return { ok: true, injected: true };
        }
      } catch {}

      procs = await findSoberProcesses();
      if (procs.length === 0) continue;
      const anyHook = procs.some((p) => procHasHook(p.pid));

      // Seed /etc/ld.so.preload into EVERY Sober process's filesystem view.
      // The game process may run in a chroot prepared by Sober's loader, with
      // its own /etc — the flatpak-runtime preload we wrote at apply time
      // doesn't exist there. Writing via /proc/<pid>/root covers both the
      // sandbox root and any chroot the game ends up in. The .so is copied
      // next to it so the preload path always resolves inside that root.
      for (const proc of procs) {
        if (seededRoots.has(proc.pid)) continue;
        if (seedHookIntoProcRoot(proc.pid, hookLib)) {
          seededRoots.add(proc.pid);
        }
      }

      if (anyHook) {
        if (Date.now() - lastNotice > 5000) {
          lastNotice = Date.now();
          sendProgress('waiting', `Hook .so mapped — waiting for VM capture… (${elapsed}s)`);
        }
        continue;
      }
      if (Date.now() - lastNotice > 5000) {
        lastNotice = Date.now();
        sendProgress('waiting', `Sober running — waiting for hook… (${elapsed}s)`);
      }
    }

    sendProgress('timeout', 'Sober launched, but hook not detected yet.');
    return { ok: true, injected: false, error: 'hook not detected within timeout' };
  } catch (err) {
    sendProgress('error', `Launch failed: ${err}`);
    return { ok: false, error: String(err) };
  }
});

// ------------------------------------------------------------------ boot ---

async function getOverride() {
  const res = await run(`flatpak override --user --show ${APP_ID}`, 15000);
  return res.ok ? res.stdout : '';
}

async function getHookStatus() {
  const procs = await findSoberProcesses();
  if (procs.length === 0) return { state: 'idle', message: 'Sober not running' };

  // Heartbeat from the hook's worker thread — the ONLY trustworthy signal:
  //   ATTACHED = lua_State captured (the .so is in the actual game process)
  //   WAITING  = .so loaded somewhere, but the Luau VM hasn't been captured yet
  try {
    const status = fs.readFileSync(path.join(QUEUE_DIR, 'status'), 'utf8').trim();
    if (status === 'ATTACHED') {
      return { state: 'attached', message: 'Captured Luau VM — ready' };
    }
    if (status === 'WAITING') {
      return { state: 'waiting', message: 'Hook loaded — waiting for Luau VM' };
    }
  } catch {}

  // No heartbeat yet. If the maps show the .so loaded it may be in the
  // launcher process only (its stub re-execs and drops LD_PRELOAD), so don't
  // report a false "attached" — report it as a warm-up phase instead.
  for (const proc of procs) {
    if (procHasHook(proc.pid)) {
      return { state: 'waiting', message: 'Hook .so mapped — waiting for VM capture' };
    }
  }

  return { state: 'waiting', message: 'Sober running, hook not yet loaded' };
}

// Tail the hook's own log file (~/.nebula/queue/log) into the console.
let lastLogPos = 0;
setInterval(() => {
  try {
    const data = fs.readFileSync(LOG_FILE, 'utf8');
    if (data.length >= lastLogPos) {
      const chunk = data.slice(lastLogPos);
      lastLogPos = data.length;
      if (chunk.trim()) {
        for (const line of chunk.split('\n')) {
          if (line.trim()) sendProgress('hooklog', line);
        }
      }
    } else {
      lastLogPos = 0; // log was rotated/truncated
    }
  } catch {}
}, 700);

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
