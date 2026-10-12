// Nebula renderer — talks to the main process via the preload bridge.

const $ = (id) => document.getElementById(id);

const els = {
  hookPill: $('hook-pill'),
  hookPillLabel: $('hook-pill-label'),
  soberStatus: $('sober-status'),
  overrideStatus: $('override-status'),
  processCount: $('process-count'),
  hookStatus: $('hook-status'),
  btnLaunchInject: $('btn-launch-inject'),
  btnStopSober: $('btn-stop-sober'),
  launchProgress: $('launch-progress'),
  launchStage: $('launch-stage'),
  btnCheckSober: $('btn-check-sober'),
  btnInstallSober: $('btn-install-sober'),
  btnAttach: $('btn-attach'),
  btnExecute: $('btn-execute'),
  btnClear: $('btn-clear'),
  btnLoad: $('btn-load'),
  btnSave: $('btn-save'),
  fontSizeSelect: $('font-size-select'),
  cbAutoAttach: $('cb-auto-attach'),
  cbSafeMode: $('cb-safe-mode'),
  cbAllowPtrace: $('cb-allow-ptrace'),
  editor: $('script-editor'),
  editorStatus: $('editor-status'),
  editorStats: $('editor-stats'),
  console: $('console-output'),
  btnClearConsole: $('btn-clear-console'),
  btnSaveConsole: $('btn-save-console'),
  btnScrollConsole: $('btn-scroll-console'),
};

let state = {
  prefs: { autoAttach: true, fontSize: 13, safeMode: false, allowPtrace: false },
  procs: [],
  override: '',
  soberInstalled: false,
};

let scrollConsole = true;
let launchBusy = false;

// ---------------------------------------------------------------- helpers ---

function stamp() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false });
}

function log(text, kind = '') {
  const line = document.createElement('div');
  line.className = `log-line ${kind}`;
  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = stamp();
  line.appendChild(time);
  line.appendChild(document.createTextNode(text));
  els.console.appendChild(line);
  while (els.console.children.length > 500) els.console.removeChild(els.console.firstChild);
  if (scrollConsole) els.console.scrollTop = els.console.scrollHeight;
}

function setStatus(el, text, kind) {
  el.textContent = text;
  el.className = `status-indicator ${kind}`;
}

function setPill(kind, text) {
  els.hookPill.className = `status-pill ${kind}`;
  els.hookPillLabel.textContent = text;
}

function setStage(text, kind = '') {
  els.launchStage.textContent = text;
  els.launchStage.className = `launch-stage ${kind}`;
}

function setEditorStatus(text, kind = '') {
  els.editorStatus.textContent = text;
  els.editorStatus.className = `editor-status ${kind}`;
  if (kind) {
    clearTimeout(setEditorStatus._t);
    setEditorStatus._t = setTimeout(() => {
      els.editorStatus.className = 'editor-status';
    }, 2500);
  }
}

function updateStats() {
  const v = els.editor.value;
  els.editorStats.textContent =
    `${v ? v.split('\n').length : 0} lines · ${v.length} chars`;
}

// ------------------------------------------------------------------ state ---

const HOOK_KIND = {
  attached: 'ok',
  waiting: 'warn',
  idle: 'idle',
  err: 'err',
};

async function refresh() {
  const s = await window.nebula.getState();
  state = { ...state, ...s };

  if (state.soberInstalled) setStatus(els.soberStatus, 'Installed', 'ok');
  else setStatus(els.soberStatus, 'Not installed', 'idle');

  els.overrideStatus.textContent = state.override && state.override.includes('LD_PRELOAD')
    ? 'Applied' : 'None';

  els.processCount.textContent = String(state.procs.length);

  const hs = state.hookStatus || { state: 'idle', message: 'Idle' };
  const kind = HOOK_KIND[hs.state] || 'idle';
  setStatus(els.hookStatus, hs.message, kind);
  setPill(kind, hs.state === 'attached' ? 'Attached' : hs.state === 'waiting' ? 'Linking…' : 'Idle');

  els.cbAutoAttach.checked = !!state.prefs.autoAttach;
  els.cbSafeMode.checked = !!state.prefs.safeMode;
  els.cbAllowPtrace.checked = !!state.prefs.allowPtrace;
  els.fontSizeSelect.value = String(state.prefs.fontSize);
  els.editor.style.fontSize = `${state.prefs.fontSize}px`;
}

// Live progress from the main process during launch & inject.
window.nebula.onProgress(({ phase, message }) => {
  if (phase === 'hooklog') {
    // Genuine hook output (the hook's own log file from inside the game).
    log(`[hook] ${message}`);
    return;
  }
  if (phase === 'soberlog') {
    // Sober's own stderr, relayed. NOT the hook — keep the labels distinct so
    // "the hook is talking" is never confused with "Sober is talking".
    log(`[sober] ${message}`);
    return;
  }
  if (phase === 'log') {
    log(message);
    return;
  }
  if (phase === 'ok' || phase === 'err' || phase === 'warn') {
    log(message, phase);
  }
  setStage(message, phase === 'error' ? 'err' : phase === 'injected' || phase === 'installed' ? 'ok' : phase === 'timeout' ? 'warn' : '');
  switch (phase) {
    case 'preparing':
      els.launchProgress.className = 'progress-bar active indeterminate';
      break;
    case 'launching':
    case 'waiting':
      els.launchProgress.className = 'progress-bar active indeterminate';
      break;
    case 'injected':
    case 'installed':
      els.launchProgress.className = 'progress-bar active';
      els.launchProgress.style.width = '100%';
      break;
    case 'error':
      els.launchProgress.className = 'progress-bar';
      els.launchProgress.style.width = '0%';
      break;
    case 'idle':
      els.launchProgress.className = 'progress-bar';
      els.launchProgress.style.width = '0%';
      break;
  }
  if (message) log(message, phase === 'error' ? 'err' : phase === 'injected' ? 'ok' : '');
});

// --------------------------------------------------------------- actions ---

// THE button: one click → clean slate → override → launch → wait for hook.
els.btnLaunchInject.addEventListener('click', async () => {
  if (launchBusy) return;
  launchBusy = true;
  els.btnLaunchInject.disabled = true;
  els.btnLaunchInject.classList.add('busy');
  els.btnLaunchInject.querySelector('.launch-label').textContent = 'Injecting…';
  setStage('Starting…');
  try {
    const res = await window.nebula.launchAndInject();
    if (res.ok && res.injected) {
      setStage('Injected — ready to execute.', 'ok');
      log('Hook confirmed inside Sober. You can execute scripts now.', 'ok');
    } else if (res.ok) {
      setStage('Sober launched, hook not detected yet.', 'warn');
      log('Sober is running but the hook was not detected in time. It may still attach; watch the Hook status.', 'warn');
    } else {
      setStage(`Failed: ${res.error || 'unknown error'}`, 'err');
      log(`Launch & inject failed: ${res.error}`, 'err');
    }
  } catch (err) {
    setStage(`Error: ${err}`, 'err');
    log(`Launch error: ${err}`, 'err');
  } finally {
    launchBusy = false;
    els.btnLaunchInject.disabled = false;
    els.btnLaunchInject.classList.remove('busy');
    els.btnLaunchInject.querySelector('.launch-label').textContent = 'Launch & Inject';
    setTimeout(() => {
      els.launchProgress.className = 'progress-bar';
      els.launchProgress.style.width = '0%';
    }, 4000);
    refresh();
  }
});

els.btnStopSober.addEventListener('click', async () => {
  log('Stopping Sober…');
  await window.nebula.stopSober();
  log('Sober stopped.', 'ok');
  refresh();
});

els.btnCheckSober.addEventListener('click', async () => {
  log('Checking for Sober…');
  const ok = await window.nebula.checkSober();
  state.soberInstalled = ok;
  log(ok ? 'Sober is installed.' : 'Sober is not installed.', ok ? 'ok' : 'warn');
  refresh();
});

els.btnInstallSober.addEventListener('click', async () => {
  log('Installing Sober from Flathub… (this can take a while)');
  els.btnInstallSober.disabled = true;
  setStage('Installing Sober…');
  const res = await window.nebula.installSober();
  els.btnInstallSober.disabled = false;
  log(res.ok ? 'Sober installed.' : `Install failed: ${res.stderr || res.stdout}`, res.ok ? 'ok' : 'err');
  setStage(res.ok ? 'Sober installed.' : 'Install failed.', res.ok ? 'ok' : 'err');
  refresh();
});

// Manual override application (advanced / debugging).
els.btnAttach.addEventListener('click', async () => {
  log('Applying sandbox override…');
  els.btnAttach.disabled = true;
  try {
    const res = await window.nebula.attach();
    if (res.ok) {
      log('Override applied. Launch & Inject will reuse it.', 'ok');
    } else {
      log(`Override failed: ${res.error || res.stderr || res.stdout}`, 'err');
    }
  } catch (err) {
    log(`Override error: ${err}`, 'err');
  } finally {
    els.btnAttach.disabled = false;
    refresh();
  }
});

els.btnExecute.addEventListener('click', async () => {
  const code = els.editor.value;
  if (!code.trim()) {
    setEditorStatus('Nothing to execute', 'flash-err');
    return;
  }
  if (state.hookStatus && state.hookStatus.state !== 'attached') {
    log('Warning: hook not confirmed attached yet — script may not run.', 'warn');
  }
  setEditorStatus('Executing…');
  const res = await window.nebula.execute(code);
  log(`Queued ${res.file.split('/').pop()}`, 'ok');
  setEditorStatus(`Queued ${res.file.split('/').pop()}`, 'flash-ok');
});

els.btnClear.addEventListener('click', () => {
  els.editor.value = '';
  updateStats();
  setEditorStatus('Cleared');
  els.editor.focus();
});

// Real file open/save via Electron dialog instead of the old fake "Load".
els.btnLoad.addEventListener('click', async () => {
  const content = await window.nebula.openFile();
  if (content === null) return;
  els.editor.value = content;
  updateStats();
  setEditorStatus('Loaded file', 'flash-ok');
});

els.btnSave.addEventListener('click', async () => {
  const saved = await window.nebula.saveFile(els.editor.value);
  if (saved === null) return;
  setEditorStatus(saved ? 'Saved' : 'Save canceled', saved ? 'flash-ok' : '');
  if (saved) log('Script saved to disk.', 'ok');
});

els.fontSizeSelect.addEventListener('change', async () => {
  const fontSize = parseFloat(els.fontSizeSelect.value);
  els.editor.style.fontSize = `${fontSize}px`;
  state.prefs.fontSize = fontSize;
  await window.nebula.savePrefs(state.prefs);
});

els.cbAutoAttach.addEventListener('change', async () => {
  state.prefs.autoAttach = els.cbAutoAttach.checked;
  await window.nebula.savePrefs(state.prefs);
  log(`Auto-override ${state.prefs.autoAttach ? 'enabled' : 'disabled'}`);
});

els.cbSafeMode.addEventListener('change', async () => {
  state.prefs.safeMode = els.cbSafeMode.checked;
  await window.nebula.savePrefs(state.prefs);
  log(`Safe mode ${state.prefs.safeMode ? 'ON — launches Sober without the hook' : 'off'}`);
});

els.cbAllowPtrace.addEventListener('change', async () => {
  state.prefs.allowPtrace = els.cbAllowPtrace.checked;
  await window.nebula.savePrefs(state.prefs);
  if (state.prefs.allowPtrace) {
    log(
      'ptrace inject ENABLED — Sober treats being traced as hostile and will terminate. ' +
        'This has never delivered the hook here; use only to confirm that diagnosis.',
      'warn'
    );
  } else {
    log('ptrace inject disabled (safe)');
  }
});

els.btnClearConsole.addEventListener('click', () => {
  els.console.innerHTML = '';
});

els.btnSaveConsole.addEventListener('click', () => {
  const text = els.console.innerText;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `nebula-console-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
});

els.btnScrollConsole.addEventListener('click', () => {
  scrollConsole = !scrollConsole;
  els.btnScrollConsole.classList.toggle('active', scrollConsole);
});

// Editor niceties: Tab inserts spaces, live stats.
els.editor.addEventListener('keydown', (e) => {
  if (e.key === 'Tab') {
    e.preventDefault();
    const start = els.editor.selectionStart;
    const end = els.editor.selectionEnd;
    els.editor.setRangeText('  ', start, end, 'end');
  }
});
els.editor.addEventListener('input', updateStats);

// F5 to execute (Ctrl+Enter too)
document.addEventListener('keydown', (e) => {
  if (e.key === 'F5' || (e.key === 'Enter' && (e.ctrlKey || e.metaKey))) {
    e.preventDefault();
    els.btnExecute.click();
  }
});

// ------------------------------------------------------------------ boot ---

log('Nebula ready. Press Launch & Inject to hook Sober.');
updateStats();
refresh();
setInterval(refresh, 3000);
