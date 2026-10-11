// Nebula renderer â talks to the main process via the preload bridge.

const $ = (id) => document.getElementById(id);

const els = {
  soberStatus: $('sober-status'),
  overrideStatus: $('override-status'),
  processCount: $('process-count'),
  hookStatus: $('hook-status'),
  btnCheckSober: $('btn-check-sober'),
  btnInstallSober: $('btn-install-sober'),
  btnAttach: $('btn-attach'),
  btnLaunchSober: $('btn-launch-sober'),
  btnExecute: $('btn-execute'),
  btnClear: $('btn-clear'),
  btnLoad: $('btn-load'),
  btnSave: $('btn-save'),
  fontSizeSelect: $('font-size-select'),
  cbAutoAttach: $('cb-auto-attach'),
  editor: $('script-editor'),
  editorStatus: $('editor-status'),
  console: $('console-output'),
  btnClearConsole: $('btn-clear-console'),
  btnSaveConsole: $('btn-save-console'),
  btnScrollConsole: $('btn-scroll-console'),
};

let state = {
  prefs: { autoAttach: true, fontSize: 13.5 },
  procs: [],
  override: '',
  soberInstalled: false,
};

let scrollConsole = true;

// ---------------------------------------------------------------- helpers ---

function log(text, kind = '') {
  const line = document.createElement('div');
  line.className = `log-line ${kind}`;
  const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
  line.textContent = `[${time}] ${text}`;
  els.console.appendChild(line);
  if (scrollConsole) els.console.scrollTop = els.console.scrollHeight;
}

function setStatus(el, text, kind) {
  el.textContent = text;
  el.className = `status-indicator ${kind}`;
}

function setEditorStatus(text) {
  els.editorStatus.textContent = text;
}

// ------------------------------------------------------------------ state ---

async function refresh() {
  const s = await window.nebula.getState();
  state = { ...state, ...s };

  // Sober
  if (state.soberInstalled) setStatus(els.soberStatus, 'Installed', 'ok');
  else setStatus(els.soberStatus, 'Not installed', 'idle');

  // Override
  els.overrideStatus.textContent = state.override ? 'Applied' : 'None';

  // Processes
  els.processCount.textContent = String(state.procs.length);

  // Hook - use the actual hook status from the main process
  if (state.hookStatus) {
    const kind = state.hookStatus.state === 'attached' ? 'ok' 
               : state.hookStatus.state === 'waiting' ? 'warn' 
               : 'idle';
    setStatus(els.hookStatus, state.hookStatus.message, kind);
  } else {
    // Fallback to old logic
    if (state.procs.length > 0) setStatus(els.hookStatus, 'Attached', 'ok');
    else setStatus(els.hookStatus, 'Idle', 'idle');
  }

  // Prefs
  els.cbAutoAttach.checked = !!state.prefs.autoAttach;
  els.fontSizeSelect.value = String(state.prefs.fontSize);
  els.editor.style.fontSize = `${state.prefs.fontSize}px`;
}

// --------------------------------------------------------------- actions ---

els.btnCheckSober.addEventListener('click', async () => {
  log('Checking for Soberâ¦');
  const ok = await window.nebula.checkSober();
  state.soberInstalled = ok;
  log(ok ? 'Sober is installed.' : 'Sober is not installed.', ok ? 'ok' : 'warn');
  refresh();
});

els.btnInstallSober.addEventListener('click', async () => {
  log('Installing Sober from Flathubâ¦');
  els.btnInstallSober.disabled = true;
  const res = await window.nebula.installSober();
  els.btnInstallSober.disabled = false;
  log(res.ok ? 'Sober installed.' : `Install failed: ${res.stderr || res.stdout}`, res.ok ? 'ok' : 'err');
  refresh();
});

els.btnAttach.addEventListener('click', async () => {
  log('Attaching to Soberâ¦');
  els.btnAttach.disabled = true;
  els.btnAttach.textContent = 'Attaching…';
  
  try {
    const res = await window.nebula.attach();
    if (res.ok) {
      log('Attach complete. Launch Sober now.', 'ok');
      log('Tip: Completely quit Sober (including tray) before launching for best results.');
    } else {
      log(`Attach failed: ${res.stderr || res.stdout}`, 'err');
      log('Try running nebula-attach manually in a terminal for more details.', 'warn');
    }
  } catch (err) {
    log(`Attach error: ${err}`, 'err');
  } finally {
    els.btnAttach.disabled = false;
    els.btnAttach.textContent = 'Attach';
    refresh();
  }
});

els.btnLaunchSober.addEventListener('click', async () => {
  log('Launching Soberâ¦');
  const res = await window.nebula.launchSober();
  if (!res.ok) log(`Launch failed: ${res.stderr || res.stdout}`, 'err');
  refresh();
});

els.btnExecute.addEventListener('click', async () => {
  const code = els.editor.value;
  if (!code.trim()) {
    setEditorStatus('Nothing to execute');
    return;
  }
  setEditorStatus('Executingâ¦');
  const res = await window.nebula.execute(code);
  log(`Queued ${res.file}`, 'ok');
  setEditorStatus(`Queued ${res.file}`);
});

els.btnClear.addEventListener('click', () => {
  els.editor.value = '';
  setEditorStatus('Cleared');
  els.editor.focus();
});

els.btnSave.addEventListener('click', async () => {
  const code = els.editor.value;
  const res = await window.nebula.execute(code);
  log(`Saved to ${res.file}`, 'ok');
  setEditorStatus(`Saved ${res.file}`);
});

els.btnLoad.addEventListener('click', () => {
  els.editor.focus();
  setEditorStatus('Load: paste or drop a script');
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
  log(`Auto-attach ${state.prefs.autoAttach ? 'enabled' : 'disabled'}`);
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
  els.btnScrollConsole.textContent = `Scroll: ${scrollConsole ? 'ON' : 'OFF'}`;
});

// F5 to execute
document.addEventListener('keydown', (e) => {
  if (e.key === 'F5') {
    e.preventDefault();
    els.btnExecute.click();
  }
});

// ------------------------------------------------------------------ boot ---

log('Nebula ready.');
refresh();
setInterval(refresh, 3000);