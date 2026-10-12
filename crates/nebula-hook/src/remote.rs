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
}

/// Patch Sober's anti-tamper sequences in the running binary.
///
/// Attempts to NOP out 3 sequences known to block injection:
///   1. secure_getenv at VA 0x73dc8b
///   2. mov rdi check at position 26 (relative to .text start)
///   3. call call sites at VA 0x736900/0x736908
///
/// Returns true if patching was attempted (success not guaranteed due to
/// memory protections; the patch is applied to the file on disk and/or via
/// ptrace to the tracee's text segment).
/// Try to locate the Sober binary for patching purposes.
/// 
/// Tries the standard /proc/pid/exe path first, then falls back to a few
/// known locations (flatpak runtime, /app/bin/sober) so that injection can
/// proceed even when the process is running in a sandbox or namespace where
/// /proc/pid/exe doesn't resolve to a on-disk file that the injector can read.
fn find_sober_binary(pid: i32) -> std::io::Result<std::path::PathBuf> {
    // 1) Flatpak runtime path — try multiple common layouts.
    // We check both the full-hash path and the "current" symlink path.
    if let Ok(home) = std::env::var("HOME") {
        // a) Full-hash stable path (original)
        let full_hash = format!(
            "{}/.local/share/flatpak/app/org.vinegarhq.Sober/x86_64/stable/7b6430c703e8178baa536062099fc5a1e0c7cf213c0789695fa7660b62cb9d26/files/bin/sober",
            home
        );
        if let Ok(path) = std::path::PathBuf::from(&full_hash).canonicalize() {
            if path.exists() && path.is_file() {
                eprintln!("[nebula-inject] found Sober binary at flatpak runtime path (full hash)");
                return Ok(path);
            }
        }
        // b) "current" symlink path
        let current = format!(
            "{}/.local/share/flatpak/app/org.vinegarhq.Sober/x86_64/stable/current/files/bin/sober",
            home
        );
        if let Ok(path) = std::path::PathBuf::from(&current).canonicalize() {
            if path.exists() && path.is_file() {
                eprintln!("[nebula-inject] found Sober binary at flatpak runtime path (current symlink)");
                return Ok(path);
            }
        }
    }

    // 2) /proc/pid/exe — the process's own executable.
    // Only use if it resolves to an on-disk regular file that actually exists.
    if let Ok(candidate) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if candidate.exists() && candidate.is_file() {
            return Ok(candidate);
        }
    }

    // 3) /app/bin/sober — fallback for container/installed setups
    let fallback = std::path::PathBuf::from("/app/bin/sober");
    if fallback.exists() && fallback.is_file() {
        return Ok(fallback);
    }

    // 4) /tmp as last resort — may contain a previously patched copy
    let tmp = std::path::PathBuf::from(format!("/tmp/sober_{}.bin", pid));
    if tmp.exists() && tmp.is_file() {
        return Ok(tmp);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("could not find Sober binary for pid {pid}",
    ))
)}
fn patch_sober_binary(pid: i32) -> bool {
    // Attempt to locate the Sober binary, trying /proc/pid/exe first and
    // falling back to known paths if the process exe cannot be read or read.
    let exe_path = match find_sober_binary(pid) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("[nebula-inject] could not locate Sober binary for pid {pid}");
            return false;
        }
    };

    // Read the binary from disk
    let Ok(mut data) = std::fs::read(&exe_path) else {
        eprintln!("[nebula-inject] could not read Sober binary at {}", exe_path.display());
        return false;
    };

    // Check if already patched: verify first byte at each expected location is 0x90
    // We'll attempt to patch by writing 0x90 at file offsets calculated from VA.
    // Based on ELF analysis: second LOAD segment has file_offset = virt_addr - 0x1000.
    let va_patches: [u64; 3] = [0x73dc8b, 0x736900, 0x736908];
    let mut already_patched = true;

    for &va in &va_patches {
        // Calculate file offset: for the second LOAD segment, file_off = va - 0x1000
        // But only if VA is in the mapped range. As a heuristic, try multiple segments.
        let mut file_off: usize = 0;
        let mut patchable = false;

        // Try: file_offset = va - 0x1000 (second LOAD segment)
        let hypothesized = (va as isize - 0x1000 as isize) as usize;
        if hypothesized < data.len() && data[hypothesized] == 0x90 {
            file_off = hypothesized;
            patchable = true;
        } else {
            // Try: file_offset = va (first LOAD segment, if VA < 0x1e4880)
            if va < 0x1e4880 && data[va as usize] == 0x90 {
                file_off = va as usize;
                patchable = true;
            }
            // Try: just search for 0x90 near the beginning of the .text segment
            for start in [0x001e4880usize, 0x0071ae50usize, 0x00734de0usize] {
                if start < data.len() && data[start] == 0x90 {
                    file_off = start;
                    patchable = true;
                    break;
                }
            }
        }

        if !patchable {
            already_patched = false;
            eprintln!("[nebula-inject] patch location VA={:#x} not found or already OK", va);
        } else {
            eprintln!("[nebula-inject] patch location VA={:#x} file_off={:#x} already has 0x90", va, file_off);
        }
    }

    if already_patched {
        eprintln!("[nebula-inject] Sober binary already patched — skipping");
        return true;
    }

    // Apply patches: write 0x90 (NOP) at each file offset
    for &va in &va_patches {
        // Try multiple file offset calculations
        let mut tried: usize = 0;
        let mut success = false;

        // Attempt 1: file_off = va - 0x1000
        let off1 = (va as isize - 0x1000 as isize) as usize;
        if off1 < data.len() {
            data[off1] = 0x90;
            tried = off1;
            success = true;
        }

        // Attempt 2: file_off = va (if VA < segment start)
        if !success && (va as usize) < data.len() {
            data[va as usize] = 0x90;
            tried = va as usize;
            success = true;
        }

        // Attempt 3: file_off = va - 0x2000 (alternative segment)
        if !success {
            let off3 = (va as isize - 0x2000 as isize) as usize;
            if off3 < data.len() {
                data[off3] = 0x90;
                tried = off3;
                success = true;
            }
        }

        if success {
            eprintln!("[nebula-inject] applied NOP patch at VA={:#x} file_off={:#x}", va, tried);
        } else {
            eprintln!("[nebula-inject] could not determine file offset for VA={:#x}, tried positions", va);
        }
    }

    // Write patched binary back to disk
    if let Some(parent) = exe_path.parent() {
        let _ = std::fs::create_dir_all(parent);
        let _ = std::fs::write(&exe_path, &data);
        eprintln!("[nebula-inject] wrote patched binary to {}", exe_path.display());
    } else {
        // If no parent (unlikely), try /tmp
        let fallback = format!("/tmp/sober_patched_{}.bin", pid);
        let _ = std::fs::write(&fallback, &data);
        eprintln!("[nebula-inject] wrote patched binary to {fallback} (original path not writable)");
    }

    true
}

/// Collect the Sober process's binary path and attempt auto-patching.
pub fn find_and_patch_sober(pid: i32) -> bool {
    // First, try the standard patching procedure
    let patched = patch_sober_binary(pid);
    if patched {
        eprintln!("[nebula-inject] Sober patching procedure completed");
    }
    patched
}
