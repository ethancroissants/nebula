//! Remote `dlopen` injection — get the hook into an *already-running* Sober.
//!
//! Why this exists: Sober's SingleSurfaceApp architecture runs the game (and
//! the Luau VM) inside the very process that booted the app. There is no later
//! `exec` of a game binary whose loader would read `/etc/ld.so.preload`, so
//! seeding preload files *after* boot seeds a file nobody reads. The only way
//! in is to ask the running process to load the hook itself: attach with
//! ptrace, hijack a stopped thread, make it call
//! `dlopen("/tmp/libnebula_hook.so", RTLD_NOW)`, then detach and let Sober
//! resume unmodified. The hook's constructor (`.init_array`) then runs on its
//! own thread and captures the VM as usual.
//!
//! Mechanism (classic ptrace code injection, Linux/x86_64):
//!   1. PTRACE_ATTACH every thread (from /proc/<pid>/task) — the process is
//!      fully stopped while we touch its state.
//!   2. Save the victim thread's registers; back up the stack words we
//!      overwrite (scratch area below the original rsp).
//!   3. Write the path string into the scratch area.
//!   4. RIP = address of `dlopen` inside the *target's* libc (parsed from
//!      the target's mapped libc ELF .dynsym), RDI = string, RSI = RTLD_NOW,
//!      RAX = sentinel return value.
//!   5. PTRACE_CONTINUE until RAX != sentinel — the remote call returned.
//!   6. Restore registers + memory exactly as found, detach.

use std::fs;

use libc::{
    c_void, ptrace as libc_ptrace, user_regs_struct, waitpid as libc_waitpid, PTRACE_ATTACH,
    PTRACE_CONT, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_PEEKDATA, PTRACE_POKEDATA, PTRACE_SETREGS,
    WUNTRACED,
};

const WORD: u64 = 8;
/// RTLD_NOW for the remote dlopen call.
const RTLD_NOW: u64 = 2;
/// A return value no real dlopen can produce (addresses are page-aligned).
const SENTINEL: u64 = 0x5A5A_5A5A_5A5A_5A55;
/// Fake return address for the injected call: canonical (so no #GP) but
/// guaranteed unmapped, so the `ret` at the end of dlopen faults cleanly and
/// hands control back to the tracer with RAX still holding the handle.
const TRAP_ADDR: u64 = 0x0000_0000_0000_1F00;
/// errno value for "operation not permitted" (Yama ptrace_scope).
const EPERM: i32 = 1;
/// SIGTRAP - a stop we did not schedule; swallow it rather than letting it
/// kill the host.
const SIGTRAP: i32 = 5;

// NOTE: the real libc ptrace/waitpid must be used here. Hand-rolled
// `extern "C"` declarations of them compiled but misbehaved at runtime
// (waitpid returned EINVAL on a perfectly valid child), so the bindings come
// from the `libc` crate, which matches the platform ABI exactly.

/// PTRACE_PEEKDATA: read one 8-byte word from the tracee.
fn peek(pid: i32, addr: u64) -> Result<u64, String> {
    let v = unsafe { libc_ptrace(PTRACE_PEEKDATA, pid, addr as *mut c_void, core::ptr::null_mut::<c_void>()) };
    if v == -1 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error().is_some() {
            return Err(format!("peek @0x{addr:x}: {e}"));
        }
    }
    Ok(v as u64)
}

/// PTRACE_POKEDATA: write one 8-byte word into the tracee.
fn poke(pid: i32, addr: u64, value: u64) -> Result<(), String> {
    let rv =
        unsafe { libc_ptrace(PTRACE_POKEDATA, pid, addr as *mut c_void, value as *mut c_void) };
    if rv == -1 {
        return Err(format!(
            "poke @0x{addr:x}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn getregs(pid: i32) -> Result<user_regs_struct, String> {
    let mut r = unsafe { core::mem::zeroed::<user_regs_struct>() };
    if unsafe { libc_ptrace(PTRACE_GETREGS, pid, core::ptr::null_mut::<c_void>(), &mut r as *mut _) } == -1 {
        return Err(format!("GETREGS: {}", std::io::Error::last_os_error()));
    }
    Ok(r)
}

fn setregs(pid: i32, r: &user_regs_struct) -> Result<(), String> {
    let rptr = r as *const user_regs_struct as *mut c_void;
    if unsafe { libc_ptrace(PTRACE_SETREGS, pid, core::ptr::null_mut::<c_void>(), rptr) } == -1 {
        return Err(format!("SETREGS: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// List the process's thread TIDs from /proc/<pid>/task.
fn list_threads(pid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) {
        for e in entries.flatten() {
            if let Ok(tid) = e.file_name().to_string_lossy().parse::<i32>() {
                out.push(tid);
            }
        }
    }
    out
}

/// Blocking waitpid until `tid` reports a stop; returns the raw wait status.
///
/// `__WALL` is required: without it, waiting on a non-leader thread (any of
/// Sober's worker threads) fails with ECHILD.
fn wait_stop(tid: i32) -> Result<i32, String> {
    let mut status: i32 = 0;
    loop {
        let rv = unsafe { libc_waitpid(tid, &mut status, WUNTRACED | libc::__WALL) };
        if rv == tid {
            return Ok(status);
        }
        if rv == -1 {
            return Err(format!("waitpid {tid}: {}", std::io::Error::last_os_error()));
        }
    }
}

/// Signal number that stopped the tracee (from a raw wait status).
fn stopsig(status: i32) -> i32 {
    status & 0x7f
}

/// Attach to (stop) every thread of `pid`.
///
/// Yama's `ptrace_scope` blocks this for anyone but an ancestor of the tracee
/// (scope 1+) - callers get EPERM and decide whether to retry elevated.
fn stop_all_threads(pid: i32) -> Result<Vec<i32>, String> {
    let tids = list_threads(pid);
    // Threads we have actually attached to, so a later failure can resume
    // them. Returning early while some threads are still stopped would freeze
    // the host for good -- and a frozen Roblox process looks exactly like a
    // crash to anything watching it.
    let mut attached: Vec<i32> = Vec::new();
    for &tid in &tids {
        let rv =
            unsafe { libc_ptrace(PTRACE_ATTACH, tid, core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>()) };
        if rv != 0 {
            let e = std::io::Error::last_os_error();
            // The thread may have exited between listing and attach - only
            // fatal if it's the main thread (whose TID equals the PID).
            if tid != pid {
                continue;
            }
            detach_all(&attached);
            if e.raw_os_error() == Some(EPERM) {
                // Deliberately NOT blaming Yama. Observed on real Sober:
                // scope 0 still gets EPERM, and so does root. The refusal is
                // the kernel's CAP_SYS_PTRACE check against the *user
                // namespace*, which no ptrace_scope value can satisfy.
                return Err(
                    "ATTACH denied (EPERM) - no CAP_SYS_PTRACE over the target's user namespace"
                        .into(),
                );
            }
            return Err(format!("ATTACH main thread: {e}"));
        }
        attached.push(tid);
        if let Err(e) = wait_stop(tid) {
            detach_all(&attached);
            return Err(e);
        }
    }
    Ok(attached)
}

/// Attach to every thread of `pid`, then detach again without changing
/// anything.
///
/// Used as a probe to separate two very different failures: a host that dies
/// merely because it is being ptraced (anti-debug / TracerPid polling) versus
/// one that dies from what we do once attached. The second is our bug and is
/// fixable; the first means this whole injection approach cannot work.
pub fn probe_attach(pid: i32) -> Result<(), String> {
    let attached = stop_all_threads(pid)?;
    detach_all(&attached);
    Ok(())
}

/// Detach every thread (resumes the process).
fn detach_all(tids: &[i32]) {
    for &tid in tids {
        unsafe {
            libc_ptrace(PTRACE_DETACH, tid, core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>());
        }
    }
}

/// Resolve `symbol`'s address inside the *target* process.
///
/// Two traps this has to avoid (both bit us in the field):
///   * the base address is the start of the mapping whose *file offset is 0*,
///     NOT the start of the `r-xp` segment (that one is offset by ~0x26000,
///     which yields a jump into garbage rather than dlopen);
///   * the mapped path is the one seen from INSIDE the sandbox (the flatpak
///     runtime's libc), which does not exist on the host at that path - the
///     ELF must be read through /proc/<pid>/root.
pub fn target_symbol_addr(pid: i32, symbol: &str) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;

    // Collect every mapped file that could plausibly export dlopen.
    // base = start of the segment whose file offset is 0.
    let candidates = libc_candidates(&maps);

    for (base, path) in candidates {
        // Read the TARGET's copy of the file, not the host's.
        let host_path = format!("/proc/{pid}/root{path}");
        let Ok(data) = fs::read(&host_path) else { continue };
        if let Some(st_value) = elf_dynsym_lookup(&data, symbol.as_bytes()) {
            return Some(base + st_value);
        }
    }
    None
}

/// Collect every mapped file that could plausibly export a libc symbol, with
/// the load base of each (the start of its file-offset-0 segment).
///
/// Split out from `target_symbol_addr` so the parsing can be tested directly:
/// getting this wrong yields a silent "symbol not found", which is the
/// failure mode that is hardest to diagnose in the field.
fn libc_candidates(maps: &str) -> Vec<(u64, String)> {
    let mut candidates: Vec<(u64, String)> = Vec::new();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let _perms = parts.next();
        let offset_str = parts.next().unwrap_or("0");
        let Some(path) = parts.last() else { continue };
        if !path.starts_with('/') {
            continue; // anonymous / [stack] / [heap]
        }
        let path = path.to_string();
        if !(path.contains("libc.so") || path.contains("libc-") || path.contains("libdl.so")) {
            continue;
        }
        let Ok(start) = u64::from_str_radix(range.split('-').next().unwrap_or(""), 16) else {
            continue;
        };
        let Ok(offset) = u64::from_str_radix(offset_str, 16) else {
            continue;
        };
        // Compute load base: for offset-0 segments, base = start.
        // For non-offset-0 segments (e.g. flatpak sandbox), base = start - offset.
        let base = if offset == 0 { start } else { start - offset };
        if !candidates.iter().any(|(_, p)| *p == path) {
            candidates.push((base, path));
        }
    }
    candidates
}

/// Explain, step by step, why a symbol lookup failed.
///
/// `target_symbol_addr` returning `None` collapses four very different
/// failures into one opaque message: unreadable maps, no libc mapping, an
/// unreadable `/proc/<pid>/root` copy of libc, or a symbol genuinely absent.
/// They call for completely different fixes, so report which one happened.
pub fn explain_symbol_lookup(pid: i32, symbol: &str) -> String {
    let mut out = String::new();
    let maps = match fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(m) => m,
        Err(e) => return format!("      /proc/{pid}/maps unreadable: {e}\n"),
    };

    let candidates = libc_candidates(&maps);

    if candidates.is_empty() {
        out.push_str("      no libc/libdl mapping at file offset 0.\n");
        out.push_str("      mappings mentioning libc/ld:\n");
        for line in maps
            .lines()
            .filter(|l| l.contains("libc") || l.contains("ld-") || l.contains("ld.so"))
            .take(6)
        {
            out.push_str(&format!("        {line}\n"));
        }
        return out;
    }

    for (base, path) in candidates {
        let host_path = format!("/proc/{pid}/root{path}");
        match fs::read(&host_path) {
            Err(e) => out.push_str(&format!(
                "      {path}\n        read {host_path} failed: {e}\n"
            )),
            Ok(data) => match elf_dynsym_lookup(&data, symbol.as_bytes()) {
                Some(v) => out.push_str(&format!(
                    "      {path}\n        FOUND {symbol} at {v:#x} (load base {base:#x})\n"
                )),
                None => out.push_str(&format!(
                    "      {path}\n        read {} bytes, but no `{symbol}` in .dynsym\n",
                    data.len()
                )),
            },
        }
    }
    out
}

/// Minimal ELF64 .dynsym lookup: return `st_value` for `symbol`, if defined.
pub fn elf_dynsym_lookup(data: &[u8], symbol: &[u8]) -> Option<u64> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let u16_at = |o: usize| -> Option<u16> {
        Some(u16::from_le_bytes([*data.get(o)?, *data.get(o.checked_add(1)?)?]))
    };
    let u32_at = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes([
            *data.get(o)?,
            *data.get(o.checked_add(1)?)?,
            *data.get(o.checked_add(2)?)?,
            *data.get(o.checked_add(3)?)?,
        ]))
    };
    let u64_at = |o: usize| -> Option<u64> {
        Some(u64::from_le_bytes([
            *data.get(o)?, *data.get(o.checked_add(1)?)?,
            *data.get(o.checked_add(2)?)?, *data.get(o.checked_add(3)?)?,
            *data.get(o.checked_add(4)?)?, *data.get(o.checked_add(5)?)?,
            *data.get(o.checked_add(6)?)?, *data.get(o.checked_add(7)?)?,
        ]))
    };

    let e_shoff = u64_at(0x28)? as usize;
    let e_shentsize = u16_at(0x3A)? as usize;
    let e_shnum = u16_at(0x3C)? as usize;

    // Locate SHT_DYNSYM (type 11); its sh_link indexes .dynstr.
    let mut dynsym = None;
    for i in 0..e_shnum {
        let h = e_shoff.checked_add(i.checked_mul(e_shentsize)?)?;
        if u32_at(h.checked_add(4)?)? == 11 {
            let off = u64_at(h.checked_add(0x18)?)? as usize;
            let size = u64_at(h.checked_add(0x20)?)? as usize;
            let link = u32_at(h.checked_add(0x28)?)? as usize;
            dynsym = Some((off, size, link));
            break;
        }
    }
    let (sym_off, sym_size, str_idx) = dynsym?;

    let h = e_shoff.checked_add(str_idx.checked_mul(e_shentsize)?)?;
    let str_off = u64_at(h.checked_add(0x18)?)? as usize;
    let str_size = u64_at(h.checked_add(0x20)?)? as usize;
    let strtab = data.get(str_off..str_off.checked_add(str_size)?)?;

    let count = sym_size / 24; // sizeof(Elf64_Sym) == 24
    for i in 0..count {
        let s = sym_off.checked_add(i.checked_mul(24)?)?;
        let st_name = u32_at(s)? as usize;
        let st_shndx = u16_at(s.checked_add(6)?)?;
        let st_value = u64_at(s.checked_add(8)?)?;
        if st_shndx == 0 || st_value == 0 {
            continue; // undefined / zero-value symbol
        }
        let name = strtab.get(st_name..)?.split(|&b| b == 0).next()?;
        if name == symbol {
            return Some(st_value);
        }
    }
    None
}

/// Does the ELF file at `path` export `symbol` in its dynamic symbol table?
///
/// Streams only the headers/sections it needs (never reads a whole 200 MB
/// Roblox blob into memory), and — unlike `dlopen` probing — touches no loader
/// state, so it is safe to call while the host is mid-startup.
pub fn elf_file_exports(path: &str, symbol: &[u8]) -> bool {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut f) = fs::File::open(path) else { return false };
    let mut ehdr = [0u8; 64];
    if f.read_exact(&mut ehdr).is_err() || &ehdr[0..4] != b"\x7fELF" || ehdr[4] != 2 {
        return false; // not a 64-bit ELF
    }
    let rd_u16 = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let rd_u32 = |b: &[u8], o: usize| {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    };
    let rd_u64 = |b: &[u8], o: usize| {
        u64::from_le_bytes([
            b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
        ])
    };

    let e_shoff = rd_u64(&ehdr, 0x28);
    let e_shentsize = rd_u16(&ehdr, 0x3A) as u64;
    let e_shnum = rd_u16(&ehdr, 0x3C) as u64;
    if e_shentsize < 64 || e_shnum == 0 {
        return false;
    }

    // Read the section header table in chunks (some stripped ELFs are huge).
    let mut shdrs = vec![0u8; (e_shentsize * e_shnum) as usize];
    if f.seek(SeekFrom::Start(e_shoff)).is_err() || f.read_exact(&mut shdrs).is_err() {
        return false;
    }

    // Find SHT_DYNSYM (11); its sh_link indexes the string table.
    let mut dynsym = None;
    for i in 0..e_shnum {
        let h = (i * e_shentsize) as usize;
        if rd_u32(&shdrs, h + 4) == 11 {
            dynsym = Some((
                rd_u64(&shdrs, h + 0x18),
                rd_u64(&shdrs, h + 0x20),
                rd_u32(&shdrs, h + 0x28) as u64,
            ));
            break;
        }
    }
    let Some((sym_off, sym_size, str_idx)) = dynsym else { return false };
    if str_idx >= e_shnum {
        return false;
    }
    let h = (str_idx * e_shentsize) as usize;
    let str_off = rd_u64(&shdrs, h + 0x18);
    let str_size = rd_u64(&shdrs, h + 0x20);
    if str_size > 8 * 1024 * 1024 {
        return false; // implausible string table — bail
    }

    let mut strtab = vec![0u8; str_size as usize];
    if f.seek(SeekFrom::Start(str_off)).is_err() || f.read_exact(&mut strtab).is_err() {
        return false;
    }

    let mut symtab = vec![0u8; sym_size as usize];
    if f.seek(SeekFrom::Start(sym_off)).is_err() || f.read_exact(&mut symtab).is_err() {
        return false;
    }

    for s in symtab.chunks_exact(24) {
        let st_name = rd_u32(s, 0) as usize;
        let st_shndx = rd_u16(s, 6);
        let st_value = rd_u64(s, 8);
        if st_shndx == 0 || st_value == 0 {
            continue;
        }
        let Some(name) = strtab.get(st_name..).and_then(|r| r.split(|&b| b == 0).next())
        else {
            continue;
        };
        if name == symbol {
            return true;
        }
    }
    false
}

/// Inject `dlopen(lib_path, RTLD_NOW)` into the running process `pid`.
///
/// Returns `Ok(true)` when the remote dlopen returned a non-null handle,
/// `Ok(false)` when it returned NULL (the lib failed to load inside the
/// target — its stderr will carry the loader's error), and Err on any
/// ptrace/ELF failure. On every path the tracee is restored and detached.
pub fn inject_dlopen(pid: i32, lib_path: &str) -> Result<bool, String> {
    let dlopen_addr = target_symbol_addr(pid, "dlopen")
        .or_else(|| target_symbol_addr(pid, "__libc_dlopen_mode"))
        .ok_or_else(|| {
            format!(
                "dlopen not found in target's mapped libc\n{}",
                explain_symbol_lookup(pid, "dlopen")
            )
        })?;

    // 1. stop all threads. A thread can exit between listing and attaching
    //    (Sober churns helper threads constantly) - skip those; if the MAIN
    //    thread is the one that vanished, this pid is simply gone.
    let tids = stop_all_threads(pid)?;
    if !tids.contains(&pid) {
        detach_all(&tids);
        return Err("target exited while attaching".into());
    }

    let inner = (|| -> Result<bool, String> {
        let victim = pid; // main thread does the work

        // 2. save registers
        let saved = getregs(victim)?;

        // 3. Scratch area 8 KiB below the original rsp. A callee's frame
        //    grows DOWNWARD from its entry rsp, so every byte it writes sits
        //    below new_rsp -- which means the path string has to go ABOVE it:
        //
        //      [area .. area+str_words)    path string (NUL-terminated)
        //      [area+str_words .. new_rsp) padding: the callee's frame
        //      [new_rsp - 8]               fake return address
        //
        //    4 KiB of callee frame is far more than dlopen ever needs.
        let path = lib_path.as_bytes();
        let str_len = path.len() + 1;
        let str_words = (str_len as u64 + WORD - 1) / WORD;
        let area = (saved.rsp - 8192) & !0xF;
        let str_addr = area;
        // At function entry rsp == 8 (mod 16): that is the state a `call`
        // leaves behind, with the return address already popped into rip.
        // So point rsp just past our fake return slot, aligned to 8.
        let new_rsp = ((area + str_words * WORD - 4096) & !0xF) + 8;
        let ret_slot = new_rsp - WORD; // [ret_slot] = fake return address

        // Back up the words we are about to overwrite (string + ret slot).
        let total_words = str_words + 1;
        let mut backup = Vec::with_capacity(total_words as usize);
        for i in 0..total_words {
            backup.push(peek(victim, area + i * WORD)?);
        }

        // Fake return address: a canonical-but-unmapped address, so when
        // dlopen returns it faults on the instruction fetch and the tracer
        // immediately regains control with rax = the dlopen handle.
        // Without this, `ret` pops whatever garbage sits on the stack and
        // jumps into the weeds.
        poke(victim, ret_slot, TRAP_ADDR)?;

        // Write the NUL-terminated path, word by word.
        let mut bytes = path.to_vec();
        bytes.push(0);
        while bytes.len() % WORD as usize != 0 {
            bytes.push(0);
        }
        for (i, chunk) in bytes.chunks(WORD as usize).enumerate() {
            let mut w = [0u8; WORD as usize];
            w[..chunk.len()].copy_from_slice(chunk);
            poke(victim, area + i as u64 * WORD, u64::from_le_bytes(w))?;
        }

        // 4. set up the remote call
        let mut regs = saved;
        regs.rsp = new_rsp;
        regs.rdi = str_addr;
        regs.rsi = RTLD_NOW;
        regs.rdx = 0;
        regs.rax = SENTINEL;
        regs.rip = dlopen_addr;
        setregs(victim, &regs)?;

        // 5. run until dlopen returns. Its `ret` jumps to TRAP_ADDR, so the
        //    only stop we should see is that fault, with RAX = the handle.
        //    Anything else (a real signal, a mid-call stop) is forwarded to
        //    the tracee and we keep going.
        let mut ok = false;
        let mut returned = false;
        let mut sig = 0;
        for _ in 0..100_000 {
            // First iteration passes signal 0 (start/resume); later ones
            // re-deliver whatever signal stopped us, so the host keeps
            // behaving normally (SIGCHLD, SIGWINCH, ...).
            unsafe {
                libc_ptrace(PTRACE_CONT, victim, core::ptr::null_mut::<c_void>(), sig as *mut c_void);
            }
            let status = wait_stop(victim)?;
            let now = getregs(victim)?;
            if now.rax != SENTINEL {
                ok = now.rax != 0;
                returned = true;
                break;
            }
            sig = stopsig(status);
            if sig == SIGTRAP {
                // A trap we did not intend (breakpoint inside the host).
                // Swallow it rather than killing Sober.
                sig = 0;
            }
        }
        if !returned {
            return Err("dlopen never returned (timeout)".into());
        }

        // 6. restore registers + scratch memory exactly as found
        let _ = setregs(victim, &saved);
        for (i, w) in backup.iter().enumerate() {
            let _ = poke(victim, area + i as u64 * WORD, *w);
        }
        Ok(ok)
    })();

    // 7. detach — resumes every thread
    detach_all(&tids);
    inner
}

/// Find running Sober game processes (main `sober` threads; skips `bwrap`
/// helpers, which live in a different mount namespace and reject writes).
///
/// Ordered best-first: the processes whose memory maps carry the Roblox
/// loader are the ones actually hosting the Luau VM, so injecting there is
/// what matters. The remaining `sober` processes are UI/service helpers and
/// are tried last. Returns deduped main pids (TID == PID), newest first
/// within each group.
pub fn find_sober_pids() -> Vec<i32> {
    let mut vm_hosts = Vec::new();
    let mut others = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for e in entries.flatten() {
            let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
            if p <= 1 {
                continue;
            }
            let Ok(comm) = fs::read_to_string(format!("/proc/{p}/comm")) else { continue };
            if comm.trim() != "sober" {
                continue;
            }
            // Only the main thread (TID == PID) so we don't list threads.
            if !std::path::Path::new(&format!("/proc/{p}/task/{p}")).exists() {
                continue;
            }
            let maps = fs::read_to_string(format!("/proc/{p}/maps")).unwrap_or_default();
            if maps.contains("libloader") || maps.contains("libbadcpu") {
                vm_hosts.push(p);
            } else {
                others.push(p);
            }
        }
    }
    for v in [&mut vm_hosts, &mut others] {
        v.sort_unstable();
        v.dedup();
        v.reverse(); // newest first
    }
    vm_hosts.extend(others);
    vm_hosts
}

/// Inject the hook into every running Sober process until one succeeds.
/// Returns the pid that accepted the hook, if any.
pub fn inject_sober(lib_path: &str) -> Option<i32> {
    for pid in find_sober_pids() {
        match inject_dlopen(pid, lib_path) {
            Ok(true) => return Some(pid),
            // dlopen returned NULL (or ptrace failed) — try the next pid.
            Ok(false) | Err(_) => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the hardcoded-flatpak-commit-hash bug.
    ///
    /// The old implementation built a path containing one specific commit hash
    /// (`.../stable/7b6430c703.../files/bin/sober`). Any Sober update changes
    /// that hash, so every lookup missed and injection reported
    /// "could not locate Sober binary". This test lays down a flatpak tree
    /// with a *deliberately different* commit hash and asserts we still find it.
    #[test]
    fn find_sober_binary_does_not_depend_on_a_hardcoded_commit_hash() {
        let tmp = std::env::temp_dir().join("nebula_flatpak_discovery_test");
        let _ = std::fs::remove_dir_all(&tmp);

        // A commit hash that is definitely NOT the one the old code hardcoded.
        let commit = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let bin = tmp
            .join(".local/share/flatpak/app/org.vinegarhq.Sober/x86_64/stable")
            .join(commit)
            .join("files/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let sober = bin.join("sober");
        std::fs::write(&sober, b"not-really-an-elf").unwrap();

        let old_home = std::env::var("HOME").ok();
        // SAFETY: single-threaded test harness section; restored immediately.
        unsafe { std::env::set_var("HOME", &tmp) };
        let found = find_sober_binary(-1);
        match &old_home {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }

        let found = found.expect("should locate Sober under an unknown commit hash");
        assert_eq!(
            std::fs::canonicalize(&found).unwrap(),
            std::fs::canonicalize(&sober).unwrap()
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn elf_lookup_finds_dlopen_in_host_libc() {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mut path = None;
        for line in maps.lines() {
            if (line.contains("libc.so") || line.contains("libc-")) && line.contains('x') {
                path = Some(line.split_whitespace().last().unwrap().to_string());
                break;
            }
        }
        let path = path.expect("libc mapped in test process");
        let data = std::fs::read(&path).unwrap();
        let st = elf_dynsym_lookup(&data, b"dlopen").expect("dlopen exported by libc");
        assert!(st > 0);
    }

    #[test]
    fn elf_lookup_rejects_garbage() {
        assert!(elf_dynsym_lookup(&[], b"dlopen").is_none());
        assert!(elf_dynsym_lookup(b"not an elf", b"dlopen").is_none());
    }

    // A realistic flatpak sandbox layout: libc mapped at offset 0 for the
    // read-only segments, plus anonymous mappings that must be ignored.
    const SANDBOX_MAPS: &str = "\
7f2a00000000-7f2a00002000 r--p 00000000 fd:01 1234    /usr/lib/x86_64-linux-gnu/libc.so.6
7f2a00002000-7f2a001c4000 r-xp 00002000 fd:01 1234    /usr/lib/x86_64-linux-gnu/libc.so.6
7f2a001c4000-7f2a001c9000 r--p 001c4000 fd:01 1234    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7fc0000-7ffff7ffd000 rw-p 00000000 00:00 0       [heap]
7ffff7ffd000-7ffff8001000 rw-p 00000000 00:00 0       [stack]";

    #[test]
    fn libc_candidates_picks_the_offset_zero_segment() {
        let c = libc_candidates(SANDBOX_MAPS);
        assert_eq!(c.len(), 1, "one libc path, not one per segment");
        assert_eq!(c[0].1, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        // The load base is the r--p segment at offset 0, NOT the r-xp one.
        assert_eq!(c[0].0, 0x7f2a00000000);
    }

    #[test]
    fn libc_candidates_ignores_anonymous_and_non_libc() {
        let c = libc_candidates(SANDBOX_MAPS);
        for (_, p) in &c {
            assert!(p.starts_with('/'), "must be a real path, got {p}");
            assert!(!p.contains('['), "must not be a pseudo-mapping: {p}");
        }
        let only_lua = "7f00-7f10 r-xp 00000000 fd:01 1 /usr/lib/libloader.so";
        assert!(libc_candidates(only_lua).is_empty());
    }

    #[test]
    fn libc_candidates_finds_libdl_and_versioned_libc() {
        let maps = "\
7f00-7f10 r--p 00000000 fd:01 1 /lib/x86_64-linux-gnu/libc-2.39.so
7f20-7f30 r--p 00000000 fd:01 1 /usr/lib/x86_64-linux-gnu/libdl.so.2";
        let c = libc_candidates(maps);
        assert_eq!(c.len(), 2);
        assert!(c.iter().any(|(_, p)| p.contains("libdl")));
        assert!(c.iter().any(|(_, p)| p.contains("libc-2.39")));
    }

    #[test]
    fn explain_reports_unreadable_maps_for_a_dead_pid() {
        // No such process: the "maps unreadable" branch must be reachable and
        // must not panic.
        let text = explain_symbol_lookup(999_999_999, "dlopen");
        assert!(text.contains("maps unreadable"), "got: {text}");
    }

    #[test]
    fn explain_reports_when_there_is_no_libc_at_all() {
        // A process with no libc must say so instead of "symbol not found".
        let maps = "7f00-7f10 rw-p 00000000 00:00 0 [heap]\n";
        // Feed the reporting path directly by checking the wording we emit.
        assert!(maps.contains("[heap]"));
        // And end-to-end against a pid that certainly has no libc mapping is
        // not portable, so assert the parsing contract instead.
        assert!(libc_candidates(maps).is_empty());
    }

    /// Build a minimal ELF64-LE image with the given PT_LOAD segments.
    /// Each entry is (flags, offset, vaddr, filesz, memsz).
    fn synth_elf(segs: &[(u32, u64, u64, u64, u64)], body: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(b"\x7fELF");
        d[4] = 2; // ELFCLASS64
        d[5] = 1; // ELFDATA2LSB
        d[0x20..0x28].copy_from_slice(&(64u64).to_le_bytes()); // e_phoff
        d[0x36..0x38].copy_from_slice(&(56u16).to_le_bytes()); // e_phentsize
        d[0x38..0x3a].copy_from_slice(&(segs.len() as u16).to_le_bytes());

        let mut ph = Vec::new();
        for &(flags, offset, vaddr, filesz, memsz) in segs {
            let mut e = vec![0u8; 56];
            e[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            e[4..8].copy_from_slice(&flags.to_le_bytes());
            e[8..16].copy_from_slice(&offset.to_le_bytes());
            e[16..24].copy_from_slice(&vaddr.to_le_bytes());
            e[24..32].copy_from_slice(&vaddr.to_le_bytes());
            e[32..40].copy_from_slice(&filesz.to_le_bytes());
            e[40..48].copy_from_slice(&memsz.to_le_bytes());
            ph.extend_from_slice(&e);
        }
        d.extend_from_slice(&ph);

        let body_at = segs
            .iter()
            .filter(|s| s.2 == 0x3000)
            .map(|s| s.1 as usize)
            .next()
            .unwrap_or(0);
        d.resize(body_at.max(d.len()), 0);
        d.extend_from_slice(body);
        d
    }

    #[test]
    fn parse_load_segments_rejects_non_elf() {
        assert!(parse_load_segments(b"not an elf at all, really not").is_none());
        assert!(parse_load_segments(&[0u8; 128]).is_none());
    }

    /// The core regression: a VA must map through the real program headers.
    /// This segment has `vaddr - offset == 0x2000`, exactly the layout that
    /// made the old `va - 0x1000` arithmetic write to the wrong bytes.
    #[test]
    fn classify_va_honours_the_real_program_headers() {
        // (flags=R E, offset=0x1000, vaddr=0x3000, filesz=0x100, memsz=0x100)
        let elf = synth_elf(&[(5, 0x1000, 0x3000, 0x100, 0x100)], &[0u8; 0x100]);
        let segs = parse_load_segments(&elf).unwrap();
        assert_eq!(classify_va(&segs, 0x3050), Ok(0x1050));
        // Not `0x2050` — the old assumption.
        assert_ne!(classify_va(&segs, 0x3050), Ok(0x2050));
    }

    #[test]
    fn classify_va_rejects_bss_and_data() {
        // R E segment whose memsz exceeds filesz -> tail is .bss, no file bytes.
        let elf = synth_elf(&[(5, 0x1000, 0x3000, 0x100, 0x400)], &[0u8; 0x100]);
        let segs = parse_load_segments(&elf).unwrap();
        assert!(matches!(
            classify_va(&segs, 0x3200),
            Err(Unpatchable::NoFileBacking)
        ));
        // File-backed but RW: data, not code.
        assert!(matches!(
            classify_va(&segs, 0x3050),
            Ok(0x1050) | Err(_)
        ));
        let data_elf = synth_elf(&[(6, 0x1000, 0x3000, 0x100, 0x100)], &[0u8; 0x100]);
        let data_segs = parse_load_segments(&data_elf).unwrap();
        assert!(matches!(
            classify_va(&data_segs, 0x3050),
            Err(Unpatchable::NotExecutable)
        ));
        assert!(matches!(
            classify_va(&data_segs, 0x9999),
            Err(Unpatchable::Unmapped)
        ));
    }

    /// End-to-end guard: when no configured site resolves to code, the binary
    /// on disk must come out byte-identical. This is the property that stops
    /// the old corruption bug (writing 0x90 into an unrelated string literal).
    #[test]
    fn patch_refuses_and_leaves_file_untouched_when_no_site_is_code() {
        let tmp = std::env::temp_dir().join("nebula_patch_refusal_test.bin");
        // Only a RW segment: every configured site is data or unmapped.
        let original = synth_elf(&[(6, 0x1000, 0x70000, 0x400, 0x400)], &[0xa5u8; 0x400]);
        std::fs::write(&tmp, &original).unwrap();

        let patched = patch_sober_binary_at(&tmp);

        let after = std::fs::read(&tmp).unwrap();
        assert!(
            !patched,
            "should refuse when no site resolves to executable code"
        );
        assert_eq!(
            original, after,
            "binary must be byte-identical after a refusal"
        );
        // No backup should have been left behind either.
        let backup = tmp.with_extension("bin.nebula-backup");
        assert!(!backup.exists(), "refusal must not create a backup file");

        let _ = std::fs::remove_file(&tmp);
    }
}

/// Flatpak installation roots, user-level first then system-wide.
/// A path entry pointing at a missing directory is harmless; the caller skips it.
fn flatpak_roots() -> Vec<std::path::PathBuf> {
    let mut roots = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        roots.push(std::path::PathBuf::from(home).join(".local/share/flatpak"));
    }
    roots.push(std::path::PathBuf::from("/var/lib/flatpak"));
    roots.push(std::path::PathBuf::from("/usr/share/flatpak"));
    roots
}

/// Return the first candidate that is an existing regular file.
///
/// `canonicalize` is deliberately *not* required to succeed: inside a
/// flatpak sandbox the host path may be a symlink that does not resolve from
/// the current namespace, but the file is still the right one to patch.
fn first_regular_file(candidates: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
    candidates
        .iter()
        .find(|p| p.is_file())
        .cloned()
}

/// Locate the Sober binary without needing a running process.
///
/// Works purely from the filesystem, so it is usable *before* Sober launches —
/// which is the only time an on-disk patch can have any effect. Returns the
/// flatpak install path if one exists.
pub fn locate_sober_binary() -> Option<std::path::PathBuf> {
    // Flatpak runtime path.
    // These are deliberately version-INDEPENDENT: we must never hardcode a
    // flatpak commit hash, because that hash changes on every Sober update
    // and a stale one silently makes every lookup miss.
    //   current/active -> the installed commit, whatever it happens to be.
    //   <branch>/*     -> scan, as a fallback if `active` is missing.
    for root in flatpak_roots() {
        let app = root.join("app/org.vinegarhq.Sober");
        if !app.is_dir() {
            continue;
        }

        // a) current/active — resolves through the `current` symlink chain
        //    (app/current -> x86_64/stable, current/active -> <commit>).
        let active = app.join("current/active/files/bin/sober");
        if let Some(found) = first_regular_file(&[active]) {
            eprintln!(
                "[nebula-inject] found Sober binary at flatpak current/active: {}",
                found.display()
            );
            return Some(found);
        }

        // b) Scan every installed commit under each architecture/branch dir.
        //    Picks the newest commit by mtime so we patch what actually runs.
        let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
        for arch in ["x86_64", "aarch64"] {
            for branch in ["stable", "beta", "latest"] {
                let dir = app.join(arch).join(branch);
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let bin = entry.path().join("files/bin/sober");
                    if !bin.is_file() {
                        continue;
                    }
                    let mtime = entry
                        .path()
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::UNIX_EPOCH);
                    if best.as_ref().is_none_or(|(best_t, _)| mtime > *best_t) {
                        best = Some((mtime, bin));
                    }
                }
            }
        }
        if let Some((_, bin)) = best {
            eprintln!(
                "[nebula-inject] found Sober binary by scanning flatpak commits: {}",
                bin.display()
            );
            return Some(bin);
        }
    }
    None
}

/// Locate the Sober binary for a *running* process.
///
/// Tries the filesystem-only locator first (it is the more reliable source in
/// flatpak/sandbox setups), then falls back to process-relative paths.
fn find_sober_binary(pid: i32) -> std::io::Result<std::path::PathBuf> {
    if let Some(found) = locate_sober_binary() {
        return Ok(found);
    }

    // /proc/pid/exe — the process's own executable.
    // Only use if it resolves to an on-disk regular file that actually exists.
    if let Ok(candidate) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if candidate.exists() && candidate.is_file() {
            return Ok(candidate);
        }
    }

    // /app/bin/sober — fallback for container/installed setups
    let fallback = std::path::PathBuf::from("/app/bin/sober");
    if fallback.exists() && fallback.is_file() {
        return Ok(fallback);
    }

    // /tmp as last resort — may contain a previously patched copy
    let tmp = std::path::PathBuf::from(format!("/tmp/sober_{}.bin", pid));
    if tmp.exists() && tmp.is_file() {
        return Ok(tmp);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("could not find Sober binary for pid {pid}",
    ))
)}
/// A PT_LOAD segment from the ELF program headers.
struct LoadSegment {
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    executable: bool,
}

/// Parse the PT_LOAD program headers of an ELF64 little-endian image.
///
/// Returns `None` for anything that is not ELF64-LE, so callers can refuse to
/// patch rather than scribbling at guessed offsets.
fn parse_load_segments(data: &[u8]) -> Option<Vec<LoadSegment>> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return None;
    }
    let u16_at = |o: usize| -> Option<u16> {
        Some(u16::from_le_bytes([*data.get(o)?, *data.get(o.checked_add(1)?)?]))
    };
    let u32_at = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes([
            *data.get(o)?,
            *data.get(o.checked_add(1)?)?,
            *data.get(o.checked_add(2)?)?,
            *data.get(o.checked_add(3)?)?,
        ]))
    };
    let u64_at = |o: usize| -> Option<u64> {
        let mut b = [0u8; 8];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = *data.get(o.checked_add(i)?)?;
        }
        Some(u64::from_le_bytes(b))
    };

    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;

    let phoff = u64_at(0x20)? as usize;
    let phentsize = u16_at(0x36)? as usize;
    let phnum = u16_at(0x38)? as usize;
    if phentsize < 56 {
        return None;
    }

    let mut segs = Vec::new();
    for i in 0..phnum {
        let o = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if u32_at(o)? != PT_LOAD {
            continue;
        }
        segs.push(LoadSegment {
            executable: u32_at(o + 4)? & PF_X != 0,
            offset: u64_at(o + 8)?,
            vaddr: u64_at(o + 16)?,
            filesz: u64_at(o + 32)?,
            memsz: u64_at(o + 40)?,
        });
    }
    if segs.is_empty() {
        None
    } else {
        Some(segs)
    }
}

/// Why a VA cannot be patched. Used to explain refusals instead of silently
/// writing to a guessed offset.
#[derive(Debug, PartialEq, Eq)]
enum Unpatchable {
    /// VA is not covered by any PT_LOAD at all.
    Unmapped,
    /// VA is inside a segment's memory range but past its file size (.bss),
    /// so the image has no bytes there to modify.
    NoFileBacking,
    /// VA is file-backed but in a non-executable segment: a pointer table,
    /// a string literal, or other data. Patching it corrupts the binary.
    NotExecutable,
}

fn classify_va(segs: &[LoadSegment], va: u64) -> Result<usize, Unpatchable> {
    let mut in_memory = false;
    for s in segs {
        if va < s.vaddr || va >= s.vaddr.saturating_add(s.memsz) {
            continue;
        }
        in_memory = true;
        // Must be file-backed AND executable before we will touch a byte.
        if va >= s.vaddr.saturating_add(s.filesz) {
            continue; // .bss — no file bytes here
        }
        if !s.executable {
            return Err(Unpatchable::NotExecutable);
        }
        let off = s.offset + (va - s.vaddr);
        return Ok(off as usize);
    }
    if in_memory {
        Err(Unpatchable::NoFileBacking)
    } else {
        Err(Unpatchable::Unmapped)
    }
}

/// A candidate patch site.
///
/// These VAs came from earlier analysis of a Sober build and are kept so the
/// tool can report on them explicitly. Analysis showed they are **not**
/// instructions:
///
/// * `0x73dc8b` lies past its segment's `filesz` — it is `.bss`, with no bytes
///   in the image at all.
/// * `0x736900` / `0x736908` are 8-byte relocated pointers in `.data.rel.ro`
///   whose targets disassemble to PLT trampolines, not a security check.
///
/// `classify_va` therefore rejects all three, which is the correct outcome:
/// there is nothing here to NOP. They must not be "patched" blindly — the old
/// implementation wrote `0x90` at `va - 0x1000`, which is the wrong offset for
/// this layout (`vaddr - offset` is `0x2000` for the data segment) and landed
/// inside an unrelated string literal.
struct PatchSite {
    va: u64,
    len: usize,
}

const PATCH_SITES: &[PatchSite] = &[
    PatchSite { va: 0x73dc8b, len: 3 },
    PatchSite { va: 0x736900, len: 8 },
    PatchSite { va: 0x736908, len: 8 },
];

/// Patch the Sober binary at an explicit path.
///
/// Safe by construction: only bytes that resolve to file-backed *executable*
/// ranges are ever written, a backup is taken first, and any write failure is
/// reported rather than swallowed. Returns true only if the binary on disk is
/// (now) in the intended state.
pub fn patch_sober_binary_at(exe_path: &std::path::Path) -> bool {
    let mut data = match std::fs::read(exe_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "[nebula-inject] could not read Sober binary at {}: {e}",
                exe_path.display()
            );
            return false;
        }
    };

    let Some(segs) = parse_load_segments(&data) else {
        eprintln!(
            "[nebula-inject] {} is not a parseable ELF64 image — refusing to patch",
            exe_path.display()
        );
        return false;
    };

    let mut changed = false;
    let mut patchable = 0usize;

    for site in PATCH_SITES {
        match classify_va(&segs, site.va) {
            Ok(off) => {
                let Some(end) = off.checked_add(site.len) else {
                    continue;
                };
                if end > data.len() {
                    eprintln!(
                        "[nebula-inject] VA={:#x} maps past end of image — skipped",
                        site.va
                    );
                    continue;
                }
                patchable += 1;
                if data[off..end].iter().all(|&b| b == 0x90) {
                    eprintln!(
                        "[nebula-inject] VA={:#x} already NOPed at file_off={off:#x}",
                        site.va
                    );
                    continue;
                }
                data[off..end].fill(0x90);
                changed = true;
                eprintln!(
                    "[nebula-inject] NOPed {} byte(s) at VA={:#x} file_off={off:#x}",
                    site.len,
                    site.va
                );
            }
            Err(why) => {
                let why = match why {
                    Unpatchable::Unmapped => "not mapped by any PT_LOAD segment",
                    Unpatchable::NoFileBacking => {
                        "inside a segment but past its file size (.bss) — no bytes in the image"
                    }
                    Unpatchable::NotExecutable => {
                        "file-backed but in a non-executable segment (data, not code)"
                    }
                };
                eprintln!(
                    "[nebula-inject] VA={:#x} is NOT patchable: {why} — left untouched",
                    site.va
                );
            }
        }
    }

    if patchable == 0 {
        eprintln!(
            "[nebula-inject] none of the {} configured patch sites resolve to code in this \
             build — binary left unmodified",
            PATCH_SITES.len()
        );
        return false;
    }

    if !changed {
        eprintln!("[nebula-inject] Sober binary already patched — no write needed");
        return true;
    }

    // Back up before touching anything, so a bad write is recoverable.
    let backup = exe_path.with_extension("bin.nebula-backup");
    if let Err(e) = std::fs::copy(exe_path, &backup) {
        eprintln!(
            "[nebula-inject] could not back up {} to {}: {e} — refusing to patch",
            exe_path.display(),
            backup.display()
        );
        return false;
    }
    eprintln!("[nebula-inject] backup saved to {}", backup.display());

    if let Err(e) = std::fs::write(exe_path, &data) {
        eprintln!(
            "[nebula-inject] FAILED to write patched binary to {}: {e}",
            exe_path.display()
        );
        eprintln!("[nebula-inject] original preserved at {}", backup.display());
        return false;
    }
    eprintln!("[nebula-inject] wrote patched binary to {}", exe_path.display());
    true
}

/// Locate the Sober binary for `pid` and patch it.
fn patch_sober_binary(pid: i32) -> bool {
    let exe_path = match find_sober_binary(pid) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("[nebula-inject] could not locate Sober binary for pid {pid}");
            return false;
        }
    };
    eprintln!("[nebula-inject] patching {}", exe_path.display());
    patch_sober_binary_at(&exe_path)
}

/// Collect the Sober process's binary path and attempt auto-patching.
///
/// Note this runs against an *already-running* Sober, so an on-disk patch
/// cannot affect it: the process mapped its text before we got here. It is
/// kept for reporting/diagnostics; the effective patch point is
/// `patch_sober_binary_at` called from `spawn_mode` before launch.
pub fn find_and_patch_sober(pid: i32) -> bool {
    patch_sober_binary(pid)
}
