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
        wait_stop(tid)?;
    }
    Ok(tids)
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
    let mut candidates: Vec<(u64, String)> = Vec::new();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let _perms = parts.next();
        let offset = parts.next().unwrap_or("0");
        let Some(path) = parts.last() else { continue };
        if !path.starts_with('/') {
            continue;
        }
        let path = path.to_string();
        let is_libc = path.contains("libc.so") || path.contains("libc-");
        let is_libdl = path.contains("libdl.so");
        if !(is_libc || is_libdl) {
            continue;
        }
        if offset != "00000000" {
            continue; // only the first (offset-0) segment carries the base
        }
        let Ok(start) = u64::from_str_radix(range.split('-').next().unwrap_or(""), 16) else {
            continue;
        };
        if !candidates.iter().any(|(_, p)| *p == path) {
            candidates.push((start, path));
        }
    }

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
        .ok_or("dlopen not found in target's mapped libc")?;

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
}
