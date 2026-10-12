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

type CInt = i32;

const WORD: u64 = 8;
/// RTLD_NOW for the remote dlopen call.
const RTLD_NOW: u64 = 2;
/// A return value no real dlopen can produce (addresses are page-aligned).
const SENTINEL: u64 = 0x5A5A_5A5A_5A5A_5A55;

extern "C" {
    fn ptrace(request: CInt, pid: i32, addr: *mut core::ffi::c_void, data: *mut core::ffi::c_void) -> i64;
    fn waitpid(pid: i32, status: *mut CInt, options: CInt) -> i32;
    fn __errno_location() -> *mut CInt;
}

const PTRACE_ATTACH: CInt = 16;
const PTRACE_DETACH: CInt = 17;
const PTRACE_GETREGS: CInt = 12;
const PTRACE_SETREGS: CInt = 13;
const PTRACE_CONT: CInt = 7;
const WUNTRACED: CInt = 0x0000_0004;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserRegs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
}

fn errno() -> CInt {
    unsafe { *__errno_location() }
}

/// PTRACE_PEEKDATA: read one 8-byte word from the tracee.
fn peek(pid: i32, addr: u64) -> Result<u64, String> {
    let saved = errno();
    unsafe { *__errno_location() = 0 };
    let v = unsafe { ptrace(2 /* PTRACE_PEEKDATA */, pid, addr as *mut _, core::ptr::null_mut()) };
    let e = errno();
    unsafe { *__errno_location() = saved };
    if v == -1 && e != 0 {
        return Err(format!("peek @0x{addr:x}: errno {e}"));
    }
    Ok(v as u64)
}

/// PTRACE_POKEDATA: write one 8-byte word into the tracee.
fn poke(pid: i32, addr: u64, value: u64) -> Result<(), String> {
    let rv = unsafe { ptrace(5 /* PTRACE_POKEDATA */, pid, addr as *mut _, value as *mut _) };
    if rv == -1 {
        return Err(format!("poke @0x{addr:x}: errno {}", errno()));
    }
    Ok(())
}

fn getregs(pid: i32) -> Result<UserRegs, String> {
    let mut r = UserRegs {
        r15: 0, r14: 0, r13: 0, r12: 0, rbp: 0, rbx: 0, r11: 0, r10: 0,
        r9: 0, r8: 0, rax: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, orig_rax: 0,
        rip: 0, cs: 0, eflags: 0, rsp: 0, ss: 0,
    };
    if unsafe {
        ptrace(
            PTRACE_GETREGS,
            pid,
            core::ptr::null_mut(),
            &mut r as *mut UserRegs as *mut _,
        )
    } == -1
    {
        return Err(format!("GETREGS: errno {}", errno()));
    }
    Ok(r)
}

fn setregs(pid: i32, r: &UserRegs) -> Result<(), String> {
    if unsafe {
        ptrace(
            PTRACE_SETREGS,
            pid,
            core::ptr::null_mut(),
            r as *const UserRegs as *mut _,
        )
    } == -1
    {
        return Err(format!("SETREGS: errno {}", errno()));
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

/// Blocking waitpid until `tid` reports a stop.
fn wait_stop(tid: i32) -> Result<(), String> {
    let mut status: CInt = 0;
    loop {
        let rv = unsafe { waitpid(tid, &mut status, WUNTRACED) };
        if rv == tid {
            return Ok(());
        }
        if rv == -1 {
            return Err(format!("waitpid {tid}: errno {}", errno()));
        }
    }
}

/// Attach to (stop) every thread of `pid`.
fn stop_all_threads(pid: i32) -> Result<Vec<i32>, String> {
    let tids = list_threads(pid);
    for &tid in &tids {
        let rv = unsafe { ptrace(PTRACE_ATTACH, tid, core::ptr::null_mut(), core::ptr::null_mut()) };
        if rv != 0 {
            // The thread may have exited between listing and attach — only
            // fatal if it's the main thread (whose TID equals the PID).
            if tid != pid {
                continue;
            }
            return Err(format!("ATTACH main thread: errno {}", errno()));
        }
        wait_stop(tid)?;
    }
    Ok(tids)
}

/// Detach every thread (resumes the process).
fn detach_all(tids: &[i32]) {
    for &tid in tids {
        unsafe {
            ptrace(PTRACE_DETACH, tid, core::ptr::null_mut(), core::ptr::null_mut());
        }
    }
}

/// Resolve `symbol`'s address inside the *target* process: find its mapped
/// libc, parse that ELF's .dynsym, return `base + st_value`.
pub fn target_symbol_addr(pid: i32, symbol: &str) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut base = None;
    let mut path = None;
    for line in maps.lines() {
        if !(line.contains("libc.so") || line.contains("libc-")) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next()?;
        if !perms.contains('x') {
            continue;
        }
        let p = parts.last()?.to_string();
        if !p.starts_with('/') {
            continue;
        }
        base = u64::from_str_radix(range.split('-').next()?, 16).ok();
        path = Some(p);
        break;
    }
    let base = base?;
    let path = path?;
    let data = fs::read(&path).ok()?;
    let st_value = elf_dynsym_lookup(&data, symbol.as_bytes())?;
    // For shared objects st_value is a virtual address relative to the load
    // base (first PT_LOAD maps at `base` in /proc/<pid>/maps).
    Some(base + st_value)
}

/// Minimal ELF64 .dynsym lookup: return `st_value` for `symbol`, if defined.
pub fn elf_dynsym_lookup(data: &[u8], symbol: &[u8]) -> Option<u64> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let u16_at = |o: usize| -> Option<u16> {
        Some(u16::from_le_bytes([
            *data.get(o)?, *data.get(o.checked_add(1)?)?,
        ]))
    };
    let u32_at = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes([
            *data.get(o)?, *data.get(o.checked_add(1)?)?,
            *data.get(o.checked_add(2)?)?, *data.get(o.checked_add(3)?)?,
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

/// Inject `dlopen(lib_path, RTLD_NOW)` into the running process `pid`.
///
/// Returns `Ok(true)` when the remote dlopen returned a non-null handle,
/// `Ok(false)` when it returned NULL (the lib failed to load inside the
/// target — its stderr will carry the loader's error), and Err on any
/// ptrace/ELF failure. On every path the tracee is restored and detached.
pub fn inject_dlopen(pid: i32, lib_path: &str) -> Result<bool, String> {
    let dlopen_addr =
        target_symbol_addr(pid, "dlopen").ok_or("dlopen not found in target's mapped libc")?;

    // 1. stop all threads
    let tids = stop_all_threads(pid)?;

    let inner = (|| -> Result<bool, String> {
        let victim = pid; // main thread does the work

        // 2. save registers
        let saved = getregs(victim)?;

        // 3. scratch area: 2 KiB below the current rsp, 16-byte aligned.
        //    Layout: [area .. area+str) = path string (16-byte aligned),
        //            rsp = area + align_up(str, 16) — the call's own frame
        //            grows DOWN from rsp, away from the string, so dlopen
        //            can never clobber the path while it runs.
        let path = lib_path.as_bytes();
        let str_len = path.len() + 1;
        let str_words = (str_len as u64 + WORD - 1) / WORD;
        let area = (saved.rsp - 2048) & !0xF;
        let str_addr = area;
        let new_rsp = area + str_words * WORD;

        // Back up the words we're about to overwrite.
        let mut backup = Vec::with_capacity(str_words as usize);
        for i in 0..str_words {
            backup.push(peek(victim, area + i * WORD)?);
        }

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

        // 5. run until the sentinel is replaced by the real return value
        let mut ok = false;
        let mut returned = false;
        for _ in 0..20_000 {
            unsafe {
                ptrace(PTRACE_CONT, victim, core::ptr::null_mut(), core::ptr::null_mut());
            }
            wait_stop(victim)?;
            let now = getregs(victim)?;
            if now.rax != SENTINEL {
                ok = now.rax != 0;
                returned = true;
                break;
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
/// Returns deduped main pids (TID == PID), newest first.
pub fn find_sober_pids() -> Vec<i32> {
    let mut out = Vec::new();
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
            out.push(p);
        }
    }
    out.sort_unstable();
    out.dedup();
    out.reverse(); // newest first — most likely the game process
    out
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
