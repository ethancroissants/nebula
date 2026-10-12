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

// Where the remote-dlopen injector might live. It ships next to the hook .so,
// so the first candidates mirror HOOK_CANDIDATES (dirname of the resolved
// hook lib) — in the installed layout both sit in ~/.local/lib/nebula/hook/,
// NOT next to main.js (which lives inside resources/app.asar).
function findInjectHelper(hookLib) {
  const candidates = [];
  if (hookLib) candidates.push(path.join(path.dirname(hookLib), 'nebula-inject'));
  candidates.push(
    path.join(__dirname, 'hook', 'nebula-inject'),
    path.join(__dirname, 'nebula-inject'),
    path.join(NEBULA_ROOT, 'lib', 'nebula-inject'),
    path.join(os.homedir(), '.local', 'lib', 'nebula', 'nebula-inject'),
    path.join(os.homedir(), '.local', 'lib', 'nebula', 'hook', 'nebula-inject'),
    path.join(os.homedir(), '.bin', 'nebula-inject'),
    path.join(os.homedir(), '.local', 'bin', 'nebula-inject'),
    '/usr/lib/nebula/nebula-inject',
    '/usr/local/lib/nebula/nebula-inject',
    path.join(__dirname, 'target', 'release', 'nebula-inject'),
  );
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {}
  }
  // Last resort: is it on PATH?
  for (const dir of (process.env.PATH || '').split(':')) {
    if (!dir) continue;
    const c = path.join(dir, 'nebula-inject');
    try {
      if (fs.existsSync(c)) return c;
    } catch {}
  }
  return null;
}

// Where the hook library might live, in priority order.
// The copy bundled with the app comes FIRST — it always matches this exact
// release. System/user install locations are fallbacks (they may be stale).
const HOOK_CANDIDATES = [
  path.join(__dirname, 'hook', 'libnebula_hook.so'),
  path.join(__dirname, '..', 'hook', 'libnebula_hook.so'),
  path.join(__dirname, 'libnebula_hook.so'),
  path.join(NEBULA_ROOT, 'lib', 'libnebula_hook.so'),
  path.join(os.homedir(), '.local', 'lib', 'nebula', 'libnebula_hook.so'),
  path.join(os.homedir(), '.local', 'lib', 'nebula', 'hook', 'libnebula_hook.so'),
  '/usr/lib/nebula/libnebula_hook.so',
  '/usr/local/lib/nebula/libnebula_hook.so',
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

// Same, but writes to the child's stdin first (used to feed a password).
function runWithStdin(cmd, input, timeoutMs = 30000) {
  return new Promise((resolve) => {
    const child = spawn('/bin/sh', ['-c', cmd], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, stdout: stdout.trim(), stderr: stderr.trim() });
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve({ ok: false, stdout: '', stderr: 'spawn failed' });
    });
    try { child.stdin.end(input); } catch {}
  });
}

// --- Privilege escalation -----------------------------------------------
// Nebula needs root for exactly two things: writing the flatpak runtime's
// /etc/ld.so.preload, and relaxing kernel.yama.ptrace_scope for the
// injector. Neither may ever fall back to a terminal prompt — Nebula is a
// GUI app, so an invisible sudo prompt on a TTY we don't control is just a
// hang. Silent paths come first; we only ask, and we ask graphically.

let cachedSudoPassword = null; // only ever set after the user actually typed one

function shQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function commandExists(cmd) {
  for (const dir of (process.env.PATH || '').split(':')) {
    if (!dir) continue;
    try {
      fs.accessSync(path.join(dir, cmd), fs.constants.X_OK);
      return true;
    } catch {}
  }
  return false;
}

// Ask for a password in a desktop dialog. Returns null if cancelled or if
// no dialog tool is installed.
async function promptPasswordGui() {
  const message = 'Nebula needs administrator access to configure Sober.';
  if (commandExists('zenity')) {
    const r = await run(
      `zenity --password --title=Nebula --text=${shQuote(message)}`,
      120000,
    );
    return r.ok && r.stdout ? r.stdout : null;
  }
  if (commandExists('kdialog')) {
    const r = await run(
      `kdialog --password --title Nebula --inputbox ${shQuote(message)}`,
      120000,
    );
    return r.ok && r.stdout ? r.stdout : null;
  }
  return null;
}

// Run `script` as root, escalating however we can without a terminal.
// Tries passwordless sudo, then PolicyKit (which hands off to the desktop's
// own agent, so the prompt is a real dialog labelled with the app), and
// only then asks for the password ourselves.
async function runPrivileged(script, timeoutMs = 30000) {
  const wrapped = `sh -c ${shQuote(script)}`;

  // 1. Passwordless sudo — silent, and how Nebula has always worked.
  const silent = await run(`sudo -n ${wrapped}`, timeoutMs);
  if (silent.ok) return { ok: true, how: 'sudo (no password needed)' };

  // 2. PolicyKit: uses the session's polkit agent for a graphical prompt.
  if (commandExists('pkexec')) {
    const polkit = await run(`pkexec ${wrapped}`, timeoutMs);
    if (polkit.ok) return { ok: true, how: 'PolicyKit' };
  }

  // 3. Last resort: collect the password in our own dialog and feed it to
  //    sudo -S. Cached, because a single launch can need root two or three
  //    times and re-asking for each would be maddening.
  let password = cachedSudoPassword;
  if (password === null) {
    password = await promptPasswordGui();
    if (!password) return { ok: false, how: 'cancelled by user' };
  }
  const fed = await runWithStdin(`sudo -S -p '' ${wrapped}`, `${password}\n`, timeoutMs);
  if (fed.ok) {
    cachedSudoPassword = password;
    return { ok: true, how: 'GUI password prompt' };
  }
  // Wrong password — don't keep offering it again.
  cachedSudoPassword = null;
  return { ok: false, how: 'denied', error: fed.stderr };
}

function yamaScope() {
  try {
    return parseInt(fs.readFileSync('/proc/sys/kernel/yama/ptrace_scope', 'utf8').trim(), 10);
  } catch {
    return null;
  }
}

// Run `fn` with Yama's ptrace_scope temporarily relaxed, restoring it
// afterwards no matter how it ends. This is a security setting, so it only
// stays off for the duration of the injection.
async function withYamaRelaxed(fn) {
  const previous = yamaScope();
  if (previous === null || previous === 0) return fn();

  log(`Relaxing yama ptrace_scope ${previous} → 0 for the injection…`, 'preparing');
  const relax = await runPrivileged(
    `echo 0 > /proc/sys/kernel/yama/ptrace_scope`,
    120000,
  );
  if (!relax.ok) {
    log(
      `Could not relax ptrace_scope (${relax.how}). Injection may be refused by Yama.`,
      'warn',
    );
    return fn(); // try anyway — the injector reports the real error
  }
  log(`ptrace_scope relaxed (${relax.how}).`);

  try {
    return await fn();
  } finally {
    const restore = await runPrivileged(
      `echo ${previous} > /proc/sys/kernel/yama/ptrace_scope`,
      60000,
    );
    if (restore.ok) {
      log(`ptrace_scope restored to ${previous}.`);
    } else {
      log(
        `WARNING: could not restore ptrace_scope to ${previous} (${restore.how}). ` +
        `Run manually: sudo sh -c 'echo ${previous} > /proc/sys/kernel/yama/ptrace_scope'`,
        'warn',
      );
    }
  }
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
    // CRITICAL: the preload entry must be the path as seen FROM INSIDE the
    // root (/tmp/libnebula_hook.so), not the host-side /proc/<pid>/root
    // spelling — inside the sandbox /proc is a different pid namespace and
    // the host path doesn't resolve, so the loader silently skips it.
    fs.writeFileSync(path.join(etc, 'ld.so.preload'), '/tmp/libnebula_hook.so\n');
    return true;
  } catch (e) {
    sendProgress('log', `Could not seed pid ${pid}: ${e.code || e}`);
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

// Remove any *stale* Nebula preload entries before launching.
//
// Older builds wrote the hook into the flatpak runtime's (and, on some
// setups, the host's) /etc/ld.so.preload during the launch phase. That file
// persists forever, so every later boot preloaded the hook into Sober from
// process start — which is exactly what makes its check_security bail out.
// The seed gate stops us *writing* too early, but it cannot undo a leftover
// from an earlier run, so scrub it here. Only lines that point at our own
// hook are touched; anything else is left alone.
async function clearStalePreloads() {
  const dirs = [...runtimeEtcDirs(), '/etc'];
  let cleared = 0;
  for (const etc of dirs) {
    const file = path.join(etc, 'ld.so.preload');
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue; // absent or unreadable — nothing to clean
    }
    if (!/nebula/i.test(content)) continue;
    const kept = content
      .split('\n')
      .filter((line) => line.trim() && !/nebula/i.test(line));
    const cleaned = kept.length ? `${kept.join('\n')}\n` : '';
    try {
      fs.writeFileSync(file, cleaned);
      cleared++;
      log(`Cleared stale Nebula preload entry from ${file}`);
    } catch (e) {
      if (e.code === 'EACCES' || e.code === 'EPERM') {
        const res = await runPrivileged(`printf '%s' ${shQuote(cleaned)} > ${shQuote(file)}`, 15000);
        if (res.ok) {
          cleared++;
          log(`Cleared stale Nebula preload entry from ${file} (${res.how})`);
        } else {
          log(`Could not clear ${file} — Sober may pre-crash. Run as root: sh -c "echo -n > ${file}"`, 'warn');
        }
      }
    }
  }
  return cleared;
}

// Write the hook path into the flatpak runtime's /etc/ld.so.preload (sandbox
// /etc is sourced from it). glibc reads it at every process start inside the
// sandbox regardless of environment. Tries the user runtime first, then a
// non-interactive sudo for system installs. Returns whether anything stuck.
async function seedRuntimePreload(hookLib) {
  const seedNotes = [];
  let runtimePreloadPath = '';
  try {
    const rtDirs = runtimeEtcDirs();
    let seeded = false;
    for (const etc of rtDirs) {
      try {
        fs.mkdirSync(etc, { recursive: true });
        fs.writeFileSync(path.join(etc, 'ld.so.preload'), `${hookLib}\n`);
        seedNotes.push(`runtime preload OK: ${etc}`);
        runtimePreloadPath = hookLib;
        seeded = true;
        break; // first writable runtime wins
      } catch (e) {
        if (e.code === 'EACCES' || e.code === 'EPERM') {
          // System install — escalate (dialog, never a terminal prompt).
          const res = await runPrivileged(
            `mkdir -p ${shQuote(etc)} && printf '%s\\n' ${shQuote(hookLib)} > ${shQuote(path.join(etc, 'ld.so.preload'))}`,
            15000,
          );
          if (res.ok) {
            seedNotes.push(`runtime preload OK (${res.how}): ${etc}`);
            runtimePreloadPath = hookLib;
            seeded = true;
            break;
          }
          seedNotes.push(`runtime not writable: ${etc} (${res.how})`);
        } else {
          seedNotes.push(`runtime seed failed: ${etc} (${e.code || e})`);
        }
      }
    }
    if (!seeded) {
      seedNotes.push('could not write ld.so.preload into any flatpak runtime');
    }
    for (const note of seedNotes) log(note, seeded ? 'ok' : 'warn');
  } catch {}
  return { seeded: !!runtimePreloadPath, runtimePreloadPath };
}

// Apply the flatpak override ourselves (no external script, no PATH issues).
// `skipRuntimePreload`: leave every ld.so.preload untouched — used when the
// launch must look clean until Sober's check_security has passed.
async function applyOverride(hookLib, { skipRuntimePreload = false } = {}) {
  await run(`flatpak override --user --reset ${APP_ID}`, 15000);
  fs.mkdirSync(QUEUE_DIR, { recursive: true });
  // NOTE: we deliberately do NOT set --env=LD_PRELOAD anymore. When both
  // LD_PRELOAD and /etc/ld.so.preload list the hook (different paths), the
  // loader can map it twice — two constructors, two trampoline installs,
  // a double-patched lua_pcall → crash. /etc/ld.so.preload alone covers
  // every sandbox process and survives Sober's env-scrubbing stub.
  const fsRes = await run(`flatpak override --user --filesystem="${QUEUE_DIR}:rw" ${APP_ID}`, 15000);

  // CRITICAL: the sandbox blocks $HOME entirely (Sober's manifest has no
  // filesystem permissions). Preload paths pointing into $HOME are silently
  // ignored by the loader if the file can't be read. Grant the lib's
  // directory read-only so the runtime-level preload file resolves.
  const libDir = path.dirname(hookLib);
  const libRes = await run(`flatpak override --user --filesystem="${libDir}:ro" ${APP_ID}`, 15000);

  // BELT & SUSPENDERS: seed the runtime-level preload unless the caller wants
  // a clean launch (the seed gate writes it later, after check_security).
  let runtimePreloadPath = '';
  if (!skipRuntimePreload) {
    const seeded = await seedRuntimePreload(hookLib);
    runtimePreloadPath = seeded.runtimePreloadPath;
  }
  void runtimePreloadPath;

  if (fsRes.ok && libRes.ok) {
    // Verify the runtime preload actually stuck before launching.
    let verified = false;
    for (const etc of runtimeEtcDirs()) {
      try {
        const content = fs.readFileSync(path.join(etc, 'ld.so.preload'), 'utf8');
        if (content.includes('libnebula_hook')) { verified = true; break; }
      } catch {}
    }
    if (verified || !runtimePreloadPath) {
      return { ok: true };
    }
    return { ok: false, error: 'Runtime preload verification failed (ld.so.preload missing)' };
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
    error: [fsRes, libRes].map((r) => r.stderr).filter(Boolean).join('; ') || 'flatpak override failed',
  };
}

// ------------------------------------------------------------------- IPC ----

ipcMain.handle('nebula:getState', async () => {
  ensureDirs();
  const prefs = loadPrefs();
  const procs = await findSoberProcesses();
  const override = await getOverride();
  const hookStatus = await getHookStatus();
  const hookLib = findHookLib();
  return {
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

    // 1b. Scrub any preload entry a previous run left behind. A stale one
    // puts the hook into Sober's maps at process start, which is precisely
    // what its check_security rejects — the symptom looks identical to the
    // hook "detecting" Sober, but the cause is an old file on disk.
    await clearStalePreloads();

    // 2. Safe mode? Launch Sober untouched — no override, no seeding.
    if (prefs.safeMode) {
      sendProgress('launching', 'Safe mode: launching Sober without hook…');
      const child = spawn('flatpak', ['run', APP_ID], { detached: true, stdio: 'ignore' });
      child.unref();
      sendProgress('log', 'Sober launched in safe mode (no hook). If it still crashes, the crash is NOT caused by Nebula.');
      return { ok: true, injected: false, safeMode: true };
    }

    // 2b. Override the sandbox — but WITHOUT the runtime ld.so.preload write.
    // That write happens right after check_security (see seed gate below).
    const seedingEnabled = !prefs.safeMode;
    let override;
    if (seedingEnabled) {
      override = await applyOverride(hookLib, { skipRuntimePreload: true });
      if (!override.ok) {
        sendProgress('error', 'Override failed — see console.');
        log(`Override error details: ${override.error}`, 'err');
        return { ok: false, error: override.error || 'override failed' };
      }
    } else {
      override = { ok: true };
    }

    // 3. Launch Sober detached, but capture its stderr — Sober's crash
    // output (panics, libbadcpu FATALs, loader errors) goes there and is
    // the only way to see WHY it dies. Written to a file (never a pipe that
    // dies with Nebula and SIGPIPE-crashes Sober) and relayed live.
    sendProgress('launching', 'Launching Sober…');
    const soberLogPath = path.join(NEBULA_ROOT, 'sober-stderr.log');
    try { fs.writeFileSync(soberLogPath, ''); } catch {}
    const soberLog = fs.openSync(soberLogPath, 'a');
    const child = spawn('flatpak', ['run', APP_ID], { detached: true, stdio: ['ignore', 'ignore', soberLog] });
    child.unref();
    let soberSeen = 0;
    let checkSecurityPassed = false;
    let soberDead = false;
    const soberTail = () => {
      try {
        const data = fs.readFileSync(soberLogPath, 'utf8');
        if (data.length >= soberSeen) {
          const chunk = data.slice(soberSeen);
          soberSeen = data.length;
          return chunk;
        }
        soberSeen = 0;
      } catch {}
      return '';
    };
    const crashPoll = setInterval(() => {
      const chunk = soberTail();
      for (const line of chunk.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        sendProgress('hooklog', `[sober] ${trimmed}`);
        if (trimmed.includes('check_security')) {
          checkSecurityPassed = true;
          sendProgress('log', 'check_security seen — seeding hook preload now');
        }
      }
      // Liveness: `child` is the `flatpak run` launcher, which can exit while
      // the game it spawned keeps running happily. Only declare a crash when
      // no `sober` process is left at all.
      let soberAlive = false;
      try {
        process.kill(child.pid, 0);
        soberAlive = true;
      } catch {}
      if (!soberAlive) {
        soberAlive = findSoberProcessesSync().length > 0;
      }
      if (!soberAlive) {
        if (!soberDead) {
          soberDead = true;
          clearInterval(crashPoll);
          if (Date.now() < deadline) {
            sendProgress('error', 'Sober exited early — the [sober] lines above show why.');
          }
        }
      }
    }, 600);

    // 4. Poll for the hook inside the game process (map of wait phase → dot)
    sendProgress('waiting', 'Waiting for Sober to start…');
    const started = Date.now();
    const deadline = started + 120000;
    let lastNotice = 0;
    let seededRoots = new Set();
    let diagDone = false;
    let lastInject = 0;
    let runtimeSeedDone = false;
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

      // SEED GATE: don't touch any ld.so.preload until Sober's own
      // check_security has PASSED — if the hook is visible in its maps
      // during the check, Sober exits by design. After the gate opens,
      // seed in two layers:
      //   1. The flatpak runtime's /etc/ld.so.preload — covers every
      //      process the sandbox starts from here on (the game exec).
      //   2. Per-process root seeding — belt & suspenders for anything
      //      that already started or runs in a private chroot.
      if (seedingEnabled && checkSecurityPassed && !runtimeSeedDone) {
        runtimeSeedDone = true;
        sendProgress('preparing', 'check_security passed — seeding runtime preload…');
        await seedRuntimePreload(hookLib);
      }
      // Seed /etc/ld.so.preload into EVERY Sober process's filesystem view.
      // Held back until the check_security gate opens (see above).
      if (seedingEnabled && checkSecurityPassed) {
        for (const proc of procs) {
          if (seededRoots.has(proc.pid)) continue;
          const ok = seedHookIntoProcRoot(proc.pid, hookLib);
          // Cache failures too so we don't spam the console every 700 ms.
          seededRoots.add(proc.pid);
          if (ok) {
            sendProgress('log', `Seeded hook into pid ${proc.pid}'s filesystem root`);
          }
        }
      }

      // One-time deep diagnostic ~8s in: what does the sandbox's /etc
      // actually contain? Answers whether the runtime preload propagated.
      if (!diagDone && elapsed >= 8) {
        diagDone = true;
        for (const proc of procs) {
          try {
            const pre = fs.readFileSync(`/proc/${proc.pid}/root/etc/ld.so.preload`, 'utf8').trim();
            const so = fs.existsSync(`/proc/${proc.pid}/root/tmp/libnebula_hook.so`);
            sendProgress('log', `pid ${proc.pid} preload=${pre || '(empty)'} .so=${so ? 'present' : 'missing'}`);
          } catch (e) {
            sendProgress('log', `pid ${proc.pid} /etc/ld.so.preload unreadable (${e.code})`);
          }
          try {
            const comm = fs.readFileSync(`/proc/${proc.pid}/comm`, 'utf8').trim();
            const maps = fs.readFileSync(`/proc/${proc.pid}/maps`, 'utf8');
            const hasHook = maps.includes('libnebula_hook');
            const hasLoader = maps.includes('libloader') || maps.includes('libbadcpu');
            sendProgress('log', `pid ${proc.pid} (${comm}): hook=${hasHook ? 'yes' : 'no'} loader=${hasLoader ? 'yes' : 'no'}`);
          } catch {}
        }
      }

      // REMOTE INJECT: ld.so.preload is only read at process START, but
      // Sober's SingleSurfaceApp keeps the game (and its Luau VM) in the
      // process that already booted — nothing new execs after the gate
      // opens, so seeding alone can never load the hook. Once the gate is
      // open and the .so is present in the sandbox but still unmapped,
      // ptrace-attach and make the running process dlopen it directly.
      if (seedingEnabled && checkSecurityPassed && !anyHook && elapsed >= 12) {
        if (Date.now() - lastInject > 10000) {
          lastInject = Date.now();
          sendProgress('waiting', 'No new process to preload — injecting into the running Sober…');
          try {
            const inj = findInjectHelper(hookLib);
            if (inj) {
              // Try with no privileges first. Joining the target's user
              // namespace (which the injector does itself) is normally enough,
              // and asking for admin rights on every single launch would be
              // both noisy and unnecessary.
              const show = (r, label) => {
                (r.stdout || '').split('\n').filter(Boolean).forEach((l) => sendProgress('log', `[${label}] ${l}`));
                (r.stderr || '').split('\n').filter(Boolean).forEach((l) => sendProgress('log', `[${label}] ${l}`));
              };
              const plain = await run(`"${inj}" /tmp/libnebula_hook.so`, 30000);
              show(plain, 'inject');
              let res = plain;
              if (!plain.ok && /EPERM/.test(plain.stderr || '')) {
                // Refused on capability grounds. Relaxing Yama is a kernel
                // policy change and does need root, so this is where a dialog
                // is warranted. The injector is told the scope is handled so
                // it never tries to sudo on its own.
                sendProgress('preparing', 'ptrace refused — requesting admin rights…');
                res = await withYamaRelaxed(() =>
                  run(`"${inj}" /tmp/libnebula_hook.so --yama-relaxed`, 30000),
                );
                // Show this attempt too: overwriting `res` silently threw
                // away the first attempt's diagnostics, which is exactly the
                // output needed when the two attempts fail differently.
                show(res, 'inject+root');
              }
            } else {
              sendProgress('log', 'nebula-inject helper not found — reinstall Nebula or run: cargo build --release');
            }
          } catch (e) {
            sendProgress('log', `inject error: ${e}`);
          }
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
    clearInterval(crashPoll);
    return { ok: true, injected: false, error: 'hook not detected within timeout' };
  } catch (err) {
    sendProgress('error', `Launch failed: ${err}`);
    return { ok: false, error: String(err) };
  } finally {
    try { clearInterval(crashPoll); } catch {}
  }
});

// ------------------------------------------------------------------ boot ---

async function getOverride() {
  const res = await run(`flatpak override --user --show ${APP_ID}`, 15000);
  return res.ok ? res.stdout : '';
}

// Harvest the hook's heartbeat + log from every Sober process root. The
// game's chroot has its own /tmp/.nebula/queue — the plain ~/.nebula path
// only covers processes that kept a real $HOME.
function harvestQueueFromRoots() {
  let status = '';
  let logChunk = '';
  try {
    const procs = findSoberProcessesSync();
    for (const proc of procs) {
      // Heartbeat
      if (!status) {
        try {
          status = fs.readFileSync(`/proc/${proc.pid}/root/tmp/.nebula/queue/status`, 'utf8').trim();
        } catch {}
      }
      // Log tail
      try {
        const data = fs.readFileSync(`/proc/${proc.pid}/root/tmp/.nebula/queue/log`, 'utf8');
        if (data) logChunk += (logChunk ? '\n' : '') + data;
      } catch {}
    }
  } catch {}
  return { status, logChunk };
}

// Synchronous process listing for the harvester (no await in fs walk).
function findSoberProcessesSync() {
  try {
    const out = [];
    for (const entry of fs.readdirSync('/proc')) {
      const pid = parseInt(entry, 10);
      if (isNaN(pid) || pid <= 0) continue;
      try {
        const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim();
        const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ');
        if (/sober/i.test(comm) || /org\.vinegarhq\.Sober|sober/i.test(cmd)) {
          out.push({ pid, comm, cmd });
        }
      } catch {}
    }
    return out;
  } catch {
    return [];
  }
}

async function getHookStatus() {
  const procs = await findSoberProcesses();
  if (procs.length === 0) return { state: 'idle', message: 'Sober not running' };

  // 1) Chroot/sandbox mirrors first (most authoritative for the game proc)
  const harvested = harvestQueueFromRoots();
  if (harvested.status === 'ATTACHED') {
    return { state: 'attached', message: 'Captured Luau VM — ready' };
  }
  if (harvested.status === 'FAILED') {
    return { state: 'err', message: 'Hook gave up — see console' };
  }
  if (harvested.status === 'WAITING') {
    return { state: 'waiting', message: 'Hook loaded — waiting for Luau VM' };
  }

  // 2) Plain ~/.nebula heartbeat (sandbox processes with a real HOME)
  try {
    const status = fs.readFileSync(path.join(QUEUE_DIR, 'status'), 'utf8').trim();
    if (status === 'ATTACHED') {
      return { state: 'attached', message: 'Captured Luau VM — ready' };
    }
    if (status === 'FAILED') {
      return { state: 'err', message: 'Hook gave up — see console' };
    }
    if (status === 'WAITING') {
      return { state: 'waiting', message: 'Hook loaded — waiting for Luau VM' };
    }
  } catch {}

  // 3) No heartbeat yet. If the maps show the .so loaded it may be in the
  // launcher process only — report it as a warm-up phase, not attached.
  for (const proc of procs) {
    if (procHasHook(proc.pid)) {
      return { state: 'waiting', message: 'Hook .so mapped — waiting for VM capture' };
    }
  }

  return { state: 'waiting', message: 'Sober running, hook not yet loaded' };
}

// Tail the hook's own log file(s): ~/.nebula/queue/log plus the /tmp/.nebula
// mirrors found inside every running Sober process root. The log can grow
// fast inside the game — cap how much we relay per tick and keep a ring
// buffer of recent lines so a flood can't wedge the renderer.
let lastLogPos = 0;
let mainLogInitialized = false;
const rootLogMarks = new Map(); // path -> last size
const MAX_LOG_LINES_PER_TICK = 40;
let marksInitialized = false;
setInterval(() => {
  const relay = (text) => {
    const lines = text.split('\n').filter((l) => l.trim());
    for (const line of lines.slice(-MAX_LOG_LINES_PER_TICK)) {
      sendProgress('hooklog', line);
    }
  };
  try {
    const data = fs.readFileSync(LOG_FILE, 'utf8');
    if (!mainLogInitialized) {
      // Skip stale content from previous sessions.
      lastLogPos = data.length;
      mainLogInitialized = true;
    } else if (data.length >= lastLogPos) {
      const chunk = data.slice(lastLogPos);
      lastLogPos = data.length;
      if (chunk.trim()) relay(chunk);
    } else {
      lastLogPos = 0; // log was rotated/truncated
    }
  } catch {}

  // Mirrors inside sandbox/chroot roots. On the first tick, mark existing
  // content as already-seen so stale logs from a previous session don't
  // replay into a fresh console.
  try {
    for (const proc of findSoberProcessesSync()) {
      const logPath = `/proc/${proc.pid}/root/tmp/.nebula/queue/log`;
      let data;
      try {
        data = fs.readFileSync(logPath, 'utf8');
      } catch { continue; }
      if (!marksInitialized) {
        rootLogMarks.set(logPath, data.length);
        continue;
      }
      const last = rootLogMarks.get(logPath) || 0;
      if (data.length >= last) {
        const chunk = data.slice(last);
        rootLogMarks.set(logPath, data.length);
        if (chunk.trim()) relay(chunk);
      } else {
        rootLogMarks.set(logPath, 0);
      }
    }
    marksInitialized = true;
    // Prune marks for dead processes
    if (rootLogMarks.size > 32) rootLogMarks.clear();
  } catch {}
}, 700);

// Survive unexpected async errors instead of taking the whole app down.
process.on('uncaughtException', (err) => {
  try { sendProgress('log', `Internal warning: ${err.message || err}`); } catch {}
});
process.on('unhandledRejection', (err) => {
  try { sendProgress('log', `Internal warning: ${err && err.message ? err.message : err}`); } catch {}
});

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
