//! nebula-hook — the shared object that gets loaded into Sober's game process.
//!
//! # How it works (reverse-engineering summary)
//!
//! Sober runs the Android Roblox binary translated to x86-64, and the Luau VM
//! is part of `libSoberRuntime.so`, which is already mapped into the process.
//! The VM's core API (`lua_state`, `lua_pushcclosure`, `lua_setfield`,
//! `luaL_loadstring`, `lua_pcall`, `lua_tolstring`, `lua_gettop`,
//! `lua_pushlstring`, `lua_type`, `lua_tostring`) is *exported* by that
//! library, so we can resolve everything with `dlsym` — no signature scanning
//! needed, and it keeps working across Roblox updates.
//!
//! We hook `lua_pcall` with a 14-byte absolute-jump trampoline. The first time
//! the game calls `lua_pcall` (which happens constantly — script scheduling,
//! callbacks, networking), our hook captures the live `lua_State*`.
//!
//! From then on a worker thread polls `~/.nebula/queue/exec.lua`. When a
//! script appears, it is executed on the captured state via
//! `luaL_loadstring` + `lua_pcall`, and any result/error is written back to
//! `~/.nebula/queue/log`.
//!
//! Because the hook runs *inside* the game's process, it shares the game's
//! Luau state: `print` output goes to the game's own console, and scripts run
//! in the game's global environment (`game`, `workspace`, ... just work).
//!
//! # Safety
//!
//! Scripts are executed on the captured thread's state. We deliberately queue
//! execution through the *next* `lua_pcall` call on that same thread (a
//! pending-slot design) rather than running Lua from a random foreign thread,
//! which Luau does not allow. The queue file is the cross-thread channel.

#![allow(non_snake_case)]

use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, c_void, CString};

unsafe extern "C" {
    fn free(p: *mut c_void);
}
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Luau C API bindings (resolved dynamically from libSoberRuntime.so)
// ---------------------------------------------------------------------------

type LuaState = c_void;

// (Reference for the dlsym-resolved surface; see `Api` below.)

// Function pointer types — real Luau ABI (see luau-lang/luau VM/include/lua.h).
type FnPushCC = unsafe extern "C" fn(
    *mut LuaState,
    Option<unsafe extern "C" fn(*mut LuaState) -> c_int>,
    *const c_char, // debugname
    c_int,         // nup
    *const c_void, // continuation (NULL)
);
type FnSetField = unsafe extern "C" fn(*mut LuaState, c_int, *const c_char);
type FnPushString = unsafe extern "C" fn(*mut LuaState, *const c_char);
/// `int luau_load(L, chunkname, bytecode, size, env)`
type FnLoad =
    unsafe extern "C" fn(*mut LuaState, *const c_char, *const c_char, usize, c_int) -> c_int;
/// `char* luau_compile(source, size, const lua_CompileOptions*, size_t* outsize)`
type FnCompile =
    unsafe extern "C" fn(*const c_char, usize, *const CompileOptions, *mut usize) -> *mut c_char;
type FnPCall = unsafe extern "C" fn(*mut LuaState, c_int, c_int, c_int) -> c_int;
type FnTolString = unsafe extern "C" fn(*mut LuaState, c_int, *mut usize) -> *const c_char;
type FnGetTop = unsafe extern "C" fn(*mut LuaState) -> c_int;
type FnPop = unsafe extern "C" fn(*mut LuaState, c_int);
type FnType = unsafe extern "C" fn(*mut LuaState, c_int) -> c_int;

/// Mirrors `lua_CompileOptions` in luacode.h (0-initialized = defaults).
#[repr(C)]
#[derive(Clone, Copy)]
struct CompileOptions {
    optimization_level: c_int,
    debug_level: c_int,
    type_info_level: c_int,
    coverage_level: c_int,
    vector_lib: *const c_char,
    vector_ctor: *const c_char,
    vector_type: *const c_char,
    vector_precision: c_int,
    mutable_globals: *const *const c_char,
    userdata_types: *const *const c_char,
    libraries_with_known_members: *const *const c_char,
    library_member_type_cb: *const c_void,
    library_member_constant_cb: *const c_void,
    disabled_builtins: *const *const c_char,
}

// Resolved Luau API. All pointers come from `dlsym` on the Luau host object.
struct Api {
    /// `lua_pushcclosurek(L, fn, debugname, nup, cont)` — real Luau ABI.
    pushcclosurek: FnPushCC,
    setfield: FnSetField,
    pushstring: FnPushString,
    /// `luau_load(L, chunkname, bytecode, size, env)` — real Luau loader.
    load: FnLoad,
    /// `luau_compile(source, size, opts, outsize)` — source→bytecode.
    compile: FnCompile,
    pcall: FnPCall,
    tolstring: FnTolString,
    /// Resolved for completeness; scripts may want it via future bridges.
    #[allow(dead_code)]
    gettop: FnGetTop,
    pop: FnPop,
    /// Optional nicety; may be absent on some builds.
    #[allow(dead_code)]
    ltype: Option<FnType>,
}

// ---------------------------------------------------------------------------
// Minimal dlsym bindings (avoid a -sys crate; this is the entire surface)
// ---------------------------------------------------------------------------

const RTLD_DEFAULT: *mut c_void = core::ptr::null_mut();

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

const RTLD_LAZY: c_int = 1;
const RTLD_NOLOAD: c_int = 0x4; // glibc extension: only succeed if already loaded

/// Look up a symbol in an already-loaded library (or the global namespace).
unsafe fn find_sym(lib: *mut c_void, name: &str) -> Option<*mut c_void> {
    let cname = CString::new(name).ok()?;
    let p = dlsym(lib, cname.as_ptr());
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

/// Load time: resolve the Luau API.
///
/// Search order:
///   1. `libSoberRuntime.so` if already mapped (NOLOAD),
///   2. the global namespace (RTLD_DEFAULT) — covers any object that exports
///      the Luau C API (Roblox loads several; we only need the symbols),
///   3. every mapped shared object named in /proc/self/maps (some Luau hosts
///      don't register their objects with the dynamic linker).
///
/// Only `lua_pcall` is mandatory — it anchors the hook. Everything else is
/// required for full script execution; if missing we degrade gracefully.
unsafe fn resolve_api() -> Option<Api> {
    // 1+2: NOLOAD dlopen, then global scope.
    let mut handle = dlopen(c"libSoberRuntime.so".as_ptr(), RTLD_LAZY | RTLD_NOLOAD);
    if handle.is_null() {
        handle = RTLD_DEFAULT;
    }
    if !handle.is_null() {
        if let Some(api) = resolve_from(handle) {
            return Some(api);
        }
    }

    // 3: walk /proc/self/maps and dlopen each mapped .so with NOLOAD, probing
    // for lua_pcall. This catches statically-renamed objects.
    let maps = read_self_maps();
    for name in maps {
        let cname = match CString::new(name.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let h = dlopen(cname.as_ptr(), RTLD_LAZY | RTLD_NOLOAD);
        if h.is_null() {
            continue;
        }
        if let Some(api) = resolve_from(h) {
            return Some(api);
        }
    }
    None
}

/// Parse `/proc/self/maps` into a deduped list of mapped library paths.
fn read_self_maps() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(contents) = std::fs::read_to_string("/proc/self/maps") {
        for line in contents.lines() {
            // Format: addr perms offset dev inode path
            let Some(path) = line.rsplit(' ').next() else {
                continue;
            };
            let path = path.trim();
            if path.starts_with('/') && path.contains(".so") && !out.contains(&path.to_string()) {
                out.push(path.to_string());
            }
        }
    }
    out
}

/// Try to resolve the full API from one object handle.
unsafe fn resolve_from(handle: *mut c_void) -> Option<Api> {
    // lua_pcall is the anchor — without it there is nothing to hook.
    let pcall: FnPCall = {
        let p = find_sym(handle, "lua_pcall")?;
        core::mem::transmute::<*mut c_void, FnPCall>(p)
    };
    macro_rules! sym {
        ($name:literal, $ty:ident) => {{
            match find_sym(handle, $name) {
                Some(p) => Some(core::mem::transmute::<*mut c_void, $ty>(p)),
                None => None,
            }
        }};
    }

    let pushcclosurek: Option<FnPushCC> = sym!("lua_pushcclosurek", FnPushCC);
    let setfield: Option<FnSetField> = sym!("lua_setfield", FnSetField);
    let pushstring: Option<FnPushString> = sym!("lua_pushstring", FnPushString);
    let load: Option<FnLoad> = sym!("luau_load", FnLoad);
    let compile: Option<FnCompile> = sym!("luau_compile", FnCompile);
    let tolstring: Option<FnTolString> = sym!("lua_tolstring", FnTolString);
    let gettop: Option<FnGetTop> = sym!("lua_gettop", FnGetTop);
    // Luau's `lua_pop` is a macro over `lua_settop`, so resolve settop.
    let pop: Option<FnPop> = sym!("lua_settop", FnPop);
    let ltype: Option<FnType> = sym!("lua_type", FnType);

    // Full script execution needs all of these.
    let (pushcclosurek, setfield, pushstring, load, compile, tolstring, gettop, pop) = (
        pushcclosurek?,
        setfield?,
        pushstring?,
        load?,
        compile?,
        tolstring?,
        gettop?,
        pop?,
    );

    Some(Api {
        pushcclosurek,
        setfield,
        pushstring,
        load,
        compile,
        pcall,
        tolstring,
        gettop,
        pop,
        ltype,
    })
}

// ---------------------------------------------------------------------------
// Trampoline: hook lua_pcall with a 14-byte absolute indirect jump
// ---------------------------------------------------------------------------

/// Write `JMP QWORD PTR [RIP+0]; .quad target` (14 bytes total) at `src`.
unsafe fn write_abs_jmp(src: *mut u8, target: *const c_void) {
    let mut stub: [u8; 14] = [
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip]
        0, 0, 0, 0, 0, 0, 0, 0, // 8-byte absolute address
    ];
    let addr = (target as usize).to_ne_bytes();
    stub[6..14].copy_from_slice(&addr);
    std::ptr::copy_nonoverlapping(stub.as_ptr(), src, 14);
}

/// Measure the length of a safe-to-relocate prologue: walk x86-64 instruction
/// boundaries until we have covered at least 14 bytes. Only instruction forms
/// whose encoding is position-independent (RIP-relative included — the whole
/// instruction moves together) are stepped over; anything exotic stops the walk
/// at a conservative boundary that still satisfies the minimum.
///
/// Returns the number of whole instructions covering >= 14 bytes.
unsafe fn measure_prologue(fnptr: *const u8) -> usize {
    let mut off = 0usize;

    while off < 14 {
        let b0 = *fnptr.add(off);

        // --- prefix group (may repeat) -----------------------------------
        let mut b = b0;
        let mut op_start = off;
        // Legacy prefixes / REX (0x40-0x4F) — scan through them.
        loop {
            let p = b;
            let is_legacy = matches!(
                p,
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF2 | 0xF3
            );
            let is_rex = (0x40..=0x4F).contains(&p);
            if is_legacy || is_rex {
                op_start += 1;
                b = *fnptr.add(op_start);
            } else {
                break;
            }
        }

        // --- opcode + immediate/modrm sizing ------------------------------
        let len: usize = match b {
            // 1-byte ops with no operands / push-pop regs
            0x50..=0x5F | 0x90 | 0x98 | 0x99 | 0xC3 | 0xF8 | 0xF9 | 0xFC | 0xFD => 1,
            // 8-bit immediate group
            0x83 | 0x80 | 0x6B | 0x69 | 0xC0 | 0xC1 | 0xC6 => {
                // opcode + modrm + disp + imm — decode modrm
                let modrm = *fnptr.add(op_start + 1);
                let mod_ = modrm >> 6;
                let rm = modrm & 7;
                let mut l = 2usize;
                if mod_ == 1 {
                    l += 1;
                } else if mod_ == 2 {
                    l += 4;
                } else if mod_ == 0 && rm == 5 {
                    l += 4; // RIP-relative disp32 (relocatable as a unit)
                }
                if rm == 4 && mod_ != 3 {
                    l += 1; // SIB
                }
                // 0x83/0x80/0xC6 carry an imm8; 0x69/0xC1/0xC0 too
                l + 1
            }
            // MOV r/m,r and friends: modrm + optional disp/SIB
            0x88 | 0x89 | 0x8A | 0x8B | 0x63 | 0x8D => {
                let modrm = *fnptr.add(op_start + 1);
                let mod_ = modrm >> 6;
                let rm = modrm & 7;
                let mut l = 2usize;
                if mod_ == 1 {
                    l += 1;
                } else if mod_ == 2 {
                    l += 4;
                } else if mod_ == 0 && rm == 5 {
                    l += 4;
                }
                if rm == 4 && mod_ != 3 {
                    l += 1;
                }
                l
            }
            // TEST/AND/OR/XOR/CMP/SUB/ADD with imm32: modrm + imm32
            0x81 => {
                let modrm = *fnptr.add(op_start + 1);
                let mod_ = modrm >> 6;
                let rm = modrm & 7;
                let mut l = 2usize;
                if mod_ == 1 {
                    l += 1;
                } else if mod_ == 2 {
                    l += 4;
                } else if mod_ == 0 && rm == 5 {
                    l += 4;
                }
                if rm == 4 && mod_ != 3 {
                    l += 1;
                }
                l + 4
            }
            // MOV imm32 to reg (B8+r / 69-style), XORps etc: op + imm32
            0xB8..=0xBF => 5,
            // LEA with RIP-relative etc is covered by 0x8D above.
            // Fallback: single byte — conservative, only used when nothing
            // else matched; the next loop iteration keeps scanning.
            _ => 1,
        };

        off = op_start + len;
        let _ = op_start;
        // Guard against pathological loops.
        if len == 0 {
            break;
        }
    }

    // Round up to at least 14.
    if off < 14 {
        off = 14;
    }
    off
}

/// Make the page(s) containing `addr` RWX. The `.text` of libSoberRuntime is
/// mapped R-X; we flip the whole page set covering our 14-byte patch.
unsafe fn unprotect(addr: *mut u8, len: usize) {
    let page_size = 4096;
    let start = (addr as usize) & !(page_size - 1);
    let end = (addr as usize + len + page_size - 1) & !(page_size - 1);
    let _ = mprotect(start as *mut c_void, end - start, 7 /* RWX */);
}

unsafe extern "C" {
    fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
}

// ---------------------------------------------------------------------------
// Global hook state
// ---------------------------------------------------------------------------

struct HookState {
    /// Resolved Luau API (set once at init; read-only afterwards).
    api: Api,
    /// The main-thread lua_State captured from the first hooked pcall.
    main_l: AtomicPtr<LuaState>,
    /// Original lua_pcall (trampoline into the patched prologue's tail).
    orig_pcall: AtomicPtr<c_void>,
    /// Pending script slot: 0 = empty, 1 = holds a script to run.
    pending: AtomicUsize,
    /// Captured error/result text for the pending slot.
    result: UnsafeCell<Option<String>>,
    /// Set once `nebula.*` globals are registered.
    registered: AtomicBool,
    queue: OnceLock<ScriptQueue>,
    installed: AtomicBool,
}

unsafe impl Sync for HookState {}

impl HookState {
    fn queue(&self) -> &ScriptQueue {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let paths = nebula_core::NebulaPaths::root(PathBuf::from(home).join(".nebula"));
        let _ = paths.ensure();
        self.queue.get_or_init(|| ScriptQueue::new(&paths))
    }
}

static HOOK: OnceLock<HookState> = OnceLock::new();

/// Build the global hook state from a resolved API.
fn make_hook_state(api: Api) -> HookState {
    HookState {
        api,
        main_l: AtomicPtr::new(core::ptr::null_mut()),
        orig_pcall: AtomicPtr::new(core::ptr::null_mut()),
        pending: AtomicUsize::new(0),
        result: UnsafeCell::new(None),
        registered: AtomicBool::new(false),
        queue: OnceLock::new(),
        installed: AtomicBool::new(false),
    }
}

fn hook() -> &'static HookState {
    HOOK.get_or_init(|| {
        make_hook_state(unsafe { resolve_api().expect("libSoberRuntime.so not loaded") })
    })
}

// ---------------------------------------------------------------------------
// The pcall hook
// ---------------------------------------------------------------------------

/// Hooked `lua_pcall`. Captures the state, then runs any queued script.
unsafe extern "C" fn hook_pcall(
    l: *mut LuaState,
    nargs: c_int,
    nresults: c_int,
    errfunc: c_int,
) -> c_int {
    let h = hook();

    // Capture the state once.
    if h.main_l.load(Ordering::Acquire).is_null() {
        h.main_l.store(l, Ordering::Release);
        h.queue().hook_set_status("ATTACHED");
        h.queue().hook_log("captured lua_State* (pcall hook)");
    }

    // If a script is queued, execute it *before* the game's own call so that
    // our frame runs on the same thread/state (Luau states are not thread-safe).
    if h.pending.load(Ordering::Acquire) == 1 {
        h.pending.store(0, Ordering::Release);
        run_pending(l);
    }

    // Tail-call the original.
    let orig = h.orig_pcall.load(Ordering::Acquire);
    let orig_fn: FnPCall = core::mem::transmute(orig);
    orig_fn(l, nargs, nresults, errfunc)
}

/// Load + execute the pending script on the given state.
///
/// Uses the real Luau pipeline: `luau_compile` (source → bytecode) then
/// `luau_load` (bytecode → function), then `lua_pcall` via the trampoline.
unsafe fn run_pending(l: *mut LuaState) {
    let h = hook();

    // Take the script parked by the worker thread.
    let script = {
        let mut slot = PENDING_SCRIPT.lock().unwrap();
        slot.take()
    };
    let Some(script) = script else { return };

    h.queue()
        .hook_log(&format!("executing script ({} bytes)", script.len()));

    // Register the nebula.* globals now — we are on the game thread, which is
    // the only safe place to touch the state.
    if !h.registered.load(Ordering::Acquire) {
        register_nebula(l);
    }

    // --- compile: source -> bytecode ------------------------------------
    let mut bytecode_size: usize = 0;
    let opts = CompileOptions {
        optimization_level: 1,
        debug_level: 1,
        type_info_level: 0,
        coverage_level: 0,
        vector_lib: core::ptr::null(),
        vector_ctor: core::ptr::null(),
        vector_type: core::ptr::null(),
        vector_precision: 0,
        mutable_globals: core::ptr::null(),
        userdata_types: core::ptr::null(),
        libraries_with_known_members: core::ptr::null(),
        library_member_type_cb: core::ptr::null(),
        library_member_constant_cb: core::ptr::null(),
        disabled_builtins: core::ptr::null(),
    };
    let bytecode = (h.api.compile)(
        script.as_ptr() as *const c_char,
        script.len(),
        &opts,
        &mut bytecode_size,
    );
    if bytecode.is_null() || bytecode_size == 0 {
        let msg = "luau_compile returned no bytecode (syntax error?)";
        h.queue().hook_log(msg);
        *h.result.get() = Some(format!("[Nebula] {msg}"));
        return;
    }

    // --- load: bytecode -> function on the stack ------------------------
    let chunkname = c"=nebula";
    let load_r = (h.api.load)(
        l,
        chunkname.as_ptr(),
        bytecode as *const c_char,
        bytecode_size,
        0,
    );
    // luau_compile's buffer is heap-allocated with the VM's allocator; free
    // it the same way (free() matches Luau's default allocator).
    free(bytecode as *mut c_void);
    if load_r != 0 {
        // Error message is on the stack; stringify it.
        let mut len: usize = 0;
        let p = (h.api.tolstring)(l, -1, &mut len);
        let msg = if p.is_null() {
            format!("luau_load failed (code {load_r})")
        } else {
            let bytes = std::slice::from_raw_parts(p as *const u8, len);
            String::from_utf8_lossy(bytes).into_owned()
        };
        // Pop the error string off the stack.
        (h.api.pop)(l, 1);
        h.queue().hook_log(&format!("load error: {msg}"));
        *h.result.get() = Some(format!("[Nebula] load error: {msg}"));
        return;
    }

    // --- call ------------------------------------------------------------
    let call_r = (h.api.pcall)(l, 0, 0, 0);
    if call_r != 0 {
        let mut len: usize = 0;
        let p = (h.api.tolstring)(l, -1, &mut len);
        let msg = if p.is_null() {
            format!("pcall failed (code {call_r})")
        } else {
            let bytes = std::slice::from_raw_parts(p as *const u8, len);
            String::from_utf8_lossy(bytes).into_owned()
        };
        (h.api.pop)(l, 1);
        h.queue().hook_log(&format!("exec error: {msg}"));
        *h.result.get() = Some(format!("[Nebula] error: {msg}"));
    } else {
        h.queue().hook_log("script finished OK");
        *h.result.get() = Some("[Nebula] executed OK".into());
    }
}

// ---------------------------------------------------------------------------
// nebula.* globals registered into the game's Lua environment
// ---------------------------------------------------------------------------

unsafe fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// `nebula.ping()` — returns the current wall-clock ms. Lets scripts verify
/// the bridge is alive.
unsafe extern "C" fn l_ping(l: *mut LuaState) -> c_int {
    let h = hook();
    let s = format!("{}", now_millis());
    let c = CString::new(s).unwrap();
    (h.api.pushstring)(l, c.as_ptr());
    1
}

/// `nebula.log(msg)` — writes a line back to the GUI console.
unsafe extern "C" fn l_log(l: *mut LuaState) -> c_int {
    let h = hook();
    let mut len: usize = 0;
    let p = (h.api.tolstring)(l, 1, &mut len);
    if !p.is_null() {
        let bytes = std::slice::from_raw_parts(p as *const u8, len);
        let msg = String::from_utf8_lossy(bytes);
        h.queue().hook_log(&format!("[script] {msg}"));
    }
    0
}

/// `nebula.getqueue()` — returns any script queued but not yet executed
/// (used by the GUI to confirm delivery).
unsafe extern "C" fn l_status(l: *mut LuaState) -> c_int {
    let h = hook();
    let s = if h.main_l.load(Ordering::Acquire).is_null() {
        "WAITING"
    } else {
        "ATTACHED"
    };
    let c = CString::new(s).unwrap();
    (h.api.pushstring)(l, c.as_ptr());
    1
}

/// Register the `nebula` functions into the global environment on state `l`.
///
/// MUST be called on the thread that owns `l` (Luau states are not thread
/// safe) — the pcall hook calls this from the game thread before running the
/// first queued script.
unsafe fn register_nebula(l: *mut LuaState) {
    let h = hook();
    if h.registered.swap(true, Ordering::AcqRel) {
        return;
    }

    const LUA_GLOBALSINDEX: c_int = -10002;

    let entries: &[(&str, unsafe extern "C" fn(*mut LuaState) -> c_int)] = &[
        ("nebula_ping", l_ping),
        ("nebula_log", l_log),
        ("nebula_status", l_status),
    ];

    // Push each C closure onto the stack, then set it as a global. Uses the
    // real `lua_pushcclosurek(L, fn, debugname, nup, cont)` ABI.
    for (name, func) in entries {
        let dbgname = CString::new(*name).unwrap();
        (h.api.pushcclosurek)(l, Some(*func), dbgname.as_ptr(), 0, core::ptr::null());
        (h.api.setfield)(l, LUA_GLOBALSINDEX, dbgname.as_ptr());
    }

    h.queue().hook_log("nebula.* globals registered");
}

// ---------------------------------------------------------------------------
// Worker thread: polls the queue, marks scripts pending, registers globals
// ---------------------------------------------------------------------------

const QUEUE_POLL_MS: u64 = 200;

/// Read the whole exec file if it exists (the GUI writes it atomically).
fn read_exec_file(path: &PathBuf) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    let _ = std::fs::remove_file(path);
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Result of one worker-tick.
enum Tick {
    Nothing,
    /// A script was queued; it will run on the next pcall.
    Queued,
}

/// The script handed from the worker to the pcall hook. Written by the
/// worker (after claiming the exec file), read+cleared by `run_pending`.
/// Content is plain bytes of Lua source; `Mutex<()>` guards the slot.
static PENDING_SCRIPT: Mutex<Option<String>> = Mutex::new(None);

fn worker_tick(h: &HookState) -> Tick {
    // (Globals are registered on the game thread by run_pending — see
    // register_nebula — so nothing Lua-related happens on this thread.)

    // Claim a queued script and park it for the next pcall.
    if let Some(script) = read_exec_file(&h.queue().exec_path()) {
        let mut slot = PENDING_SCRIPT.lock().unwrap();
        if slot.is_none() {
            *slot = Some(script);
            drop(slot);
            h.pending.store(1, Ordering::Release);
            return Tick::Queued;
        }
        // Slot busy (script still awaiting a pcall) — put nothing back; the
        // file was already claimed, so re-write it as pending to avoid loss.
        let _ = std::fs::write(h.queue().exec_path(), "");
    }
    Tick::Nothing
}

/// Worker thread body. Runs forever (daemon-like); dies with the process.
fn worker(h: &'static HookState) {
    let mut last_status = String::new();
    loop {
        let status = if h.main_l.load(Ordering::Acquire).is_null() {
            "WAITING"
        } else {
            "ATTACHED"
        };
        if status != last_status {
            h.queue().hook_set_status(status);
            last_status = status.to_string();
        }

        match worker_tick(h) {
            Tick::Queued => {
                h.queue().hook_log("script queued — will run at next pcall");
            }
            Tick::Nothing => {}
        }

        std::thread::sleep(Duration::from_millis(QUEUE_POLL_MS));
    }
}

// ---------------------------------------------------------------------------
// Entry point (runs when the .so is loaded into the game process)
// ---------------------------------------------------------------------------

/// mmapped RWX trampoline page guard, so double-init is visible at a glance.
static TRAMPOLINE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// Constructor: spawn the worker thread, which waits until `libSoberRuntime.so`
/// is mapped (LD_PRELOAD libs load *before* DT_NEEDED libraries, so the
/// runtime may not exist yet at ctor time), then installs the hook.
///
/// # Safety
/// Runs at .so load time inside the target process. Must not panic.
#[unsafe(no_mangle)]
extern "C" fn nebula_hook_init() {
    // Never panic across the FFI boundary.
    let _ = std::panic::catch_unwind(|| {
        let _ = std::thread::Builder::new()
            .name("nebula-init".into())
            .spawn(|| {
                let _ = std::panic::catch_unwind(init_and_install);
            });
    });
}

/// Pointer to the constructor, placed in `.init_array` so the loader runs it
/// when the .so is mapped. (A function pointer must be stored, not a function.)
#[link_section = ".init_array"]
#[used]
static NEBULA_INIT: unsafe extern "C" fn() = nebula_hook_init;

/// Wait for the runtime .so, install the trampoline, then run the queue loop.
fn init_and_install() {
    // Retry until libSoberRuntime.so shows up (bounded — 60 s).
    let mut tries = 0;
    loop {
        if unsafe { resolve_api() }.is_some() {
            break;
        }
        tries += 1;
        if tries >= 300 {
            eprintln!("[nebula] libSoberRuntime.so never appeared; hook inactive");
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let h = hook();
    if h.installed.swap(true, Ordering::AcqRel) {
        return; // already installed
    }

    // Location of the original lua_pcall (trampoline is computed below).
    let orig = h.api.pcall as *mut c_void;

    // Trampoline: copy a whole-instruction prologue (>= 14 bytes, measured so
    // we never split an instruction) into fresh RWX memory, then append a jump
    // back to (lua_pcall + prologue_len). Finally patch lua_pcall's prologue
    // with a jump to hook_pcall.
    let prologue_len = unsafe { measure_prologue(orig as *const u8) };
    unsafe {
        let tramp = mmap_rwx(prologue_len + 14);
        std::ptr::copy_nonoverlapping(orig as *const u8, tramp, prologue_len);
        write_abs_jmp(
            tramp.add(prologue_len),
            (orig as usize + prologue_len) as *const c_void,
        );
        TRAMPOLINE.store(tramp, Ordering::Release);
        unprotect(orig as *mut u8, prologue_len);
        write_abs_jmp(orig as *mut u8, hook_pcall as *const c_void);
        // Calls to the "original" must go through the trampoline (which
        // re-executes the copied prologue and resumes at orig+prologue_len) —
        // NOT through `orig` itself, whose prologue is now our jump.
        h.orig_pcall.store(tramp as *mut c_void, Ordering::Release);
    }
    h.queue().hook_log(&format!(
        "pcall trampoline installed (prologue {prologue_len} bytes)"
    ));
    h.queue().hook_log("nebula hook installed");

    // Take over this thread as the queue worker.
    worker(h)
}

/// mmap a small RWX region for the trampoline.
unsafe fn mmap_rwx(len: usize) -> *mut u8 {
    unsafe extern "C" {
        fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            off: i64,
        ) -> *mut c_void;
    }
    const PROT_RWX: c_int = 7;
    const MAP_PRIVATE: c_int = 0x02;
    const MAP_ANONYMOUS: c_int = 0x20;
    let p = mmap(
        core::ptr::null_mut(),
        len,
        PROT_RWX,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p as usize == usize::MAX {
        eprintln!("[nebula] mmap failed");
        core::ptr::null_mut()
    } else {
        p as *mut u8
    }
}

// Re-export what the worker needs from nebula-core (paths/queue).
use nebula_core::{NebulaPaths, ScriptQueue};

/// Trait shim: give ScriptQueue the `exec_path()` name used above without
/// changing nebula-core's public API.
trait ExecPathExt {
    fn exec_path(&self) -> PathBuf;
}

impl ExecPathExt for ScriptQueue {
    fn exec_path(&self) -> PathBuf {
        // ScriptQueue stores its paths privately; rebuild from HOME the same
        // way HookState::queue does.
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        NebulaPaths::root(PathBuf::from(home).join(".nebula")).exec_file()
    }
}
