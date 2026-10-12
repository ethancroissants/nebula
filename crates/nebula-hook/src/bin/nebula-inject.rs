//! nebula-inject — push the hook into an already-running Sober.
//!
//! Sober's SingleSurfaceApp runs the game (and its Luau VM) inside the process
//! that booted the app; `ld.so.preload` seeding after boot never applies to it
//! because the loader only reads that file at process start. This tool asks
//! the running process to load the hook itself: ptrace-attach, hijack one
//! stopped thread, make it `dlopen("/tmp/libnebula_hook.so", RTLD_NOW)`,
//! restore everything, detach. The hook's constructor then captures the VM.
//!
//! Usage: nebula-inject <pid> <path-to-libnebula_hook.so>
//!   <pid>    target process (omit to auto-detect the running Sober)
//!   <lib>    path as seen FROM INSIDE the sandbox, e.g. /tmp/libnebula_hook.so
//!
//! Exit codes: 0 = injected (dlopen returned a handle), 1 = tried but no
//! process accepted it, 2 = usage error. Progress on stdout, details on stderr.

use std::env;
use std::process::{Command, ExitCode};

use nebula_hook::remote;

/// Test/utility mode: `--spawn <lib> <program> [args...]` launches the program
/// as our OWN child and injects into it.
///
/// This exists because ptrace_scope=1 only permits tracing descendants — so a
/// self-spawned target is the one case we can always attach to, which makes it
/// the right harness for exercising the injection mechanics without Sober.
fn spawn_mode(lib: &str, argv: &[String], attach_only: bool) -> ExitCode {
    let Some(prog) = argv.first() else {
        eprintln!("usage: nebula-inject --spawn <lib> <program> [args...]");
        return ExitCode::from(2);
    };
    let mut child = Command::new(prog);
    child.args(&argv[1..]);
    child.env_remove("LD_PRELOAD");

    // Patch BEFORE the process exists.
    //
    // A running process has already mapped its text segment, so rewriting the
    // binary on disk afterwards cannot change the code executing in its
    // address space — patching after launch is a guaranteed no-op. Doing it
    // here is the only point where an on-disk patch can take effect.
    //
    // Best-effort: a refusal here is reported and the spawn still proceeds,
    // because the caller may be aiming at an arbitrary program rather than
    // Sober, and failing to spawn would be worse than an unpatched launch.
    match remote::locate_sober_binary() {
        Some(bin) => {
            eprintln!(
                "[nebula-inject] pre-launch: patching {}",
                bin.display()
            );
            if !remote::patch_sober_binary_at(&bin) {
                eprintln!(
                    "[nebula-inject] pre-launch: no patch applied (see reasons above) — \
                     continuing unpatched"
                );
            }
        }
        None => {
            eprintln!(
                "[nebula-inject] pre-launch: no Sober binary found to patch — \
                 continuing without patching"
            );
        }
    }

    let Ok(mut child) = child.spawn() else {
        eprintln!("[nebula-inject] could not spawn {prog}");
        return ExitCode::from(1);
    };
    let pid = child.id() as i32;
    println!("[nebula-inject] spawned {prog} as pid {pid}");

    // Give the target a moment to map libc and reach its main loop.
    std::thread::sleep(std::time::Duration::from_millis(1200));

    let result: Result<bool, String> = if attach_only {
        remote::probe_attach(pid).map(|_| true)
    } else {
        remote::inject_dlopen(pid, lib)
    };

    // In probe mode nothing was loaded, so there is no heartbeat to wait for.
    let mut flag = String::new();
    if !attach_only {
        // The hook's constructor spawns a thread that settles (1.5 s) before
        // it writes its first heartbeat, so give it room before reaping.
        for _ in 0..40 {
            flag = read_flag();
            if flag != "(none)" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        println!("[nebula-inject] hook heartbeat after inject: {flag}");
    }

    // Leave the child in a known state and reap it.
    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(true) if attach_only => {
            println!("[nebula-inject] probe OK on pid {pid} — ptrace alone is survivable");
            ExitCode::SUCCESS
        }
        Ok(true) => {
            println!("[nebula-inject] injected into pid {pid} — hook .so loaded");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("[nebula-inject] pid {pid}: dlopen returned NULL");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("[nebula-inject] pid {pid}: {e}");
            ExitCode::from(1)
        }
    }
}

/// The hook's constructor writes a status heartbeat; read it so the spawn
/// harness can assert the constructor actually ran inside the child.
fn read_flag() -> String {
    let home = env::var("HOME").unwrap_or_default();
    for p in [
        format!("{home}/.nebula/queue/status"),
        "/tmp/.nebula/queue/status".to_string(),
    ] {
        if let Ok(s) = std::fs::read_to_string(&p) {
            if !s.trim().is_empty() {
                return s.trim().to_string();
            }
        }
    }
    "(none)".into()
}

/// Attach to every thread and detach again, loading nothing.
///
/// Answers the question that matters when the host vanishes mid-injection:
/// did merely *being traced* kill it, or did our dlopen trampoline? Those
/// need completely different responses, and right now they look identical
/// from the outside — both present as "Sober closed by itself".
fn probe_into(pids: &[i32]) -> ExitCode {
    for pid in pids {
        println!("[nebula-inject] probing pid {pid} (attach + detach, nothing else)…");
        match remote::probe_attach(*pid) {
            Ok(()) => {
                println!("[nebula-inject] probe OK on pid {pid} — ptrace alone is survivable");
                return ExitCode::SUCCESS;
            }
            Err(e) => eprintln!("[nebula-inject] probe failed on pid {pid}: {e}"),
        }
    }
    eprintln!("[nebula-inject] no pid accepted a plain attach/detach probe");
    ExitCode::from(1)
}

/// Try each pid in turn; success on the first that accepts the hook.
///
/// Returns the exit code plus a flag saying whether *every* attempt was
/// refused with EPERM (i.e. the capability check is the only thing in the way).
fn inject_into(pids: &[i32], lib: &str) -> (ExitCode, bool) {
    let mut saw_eperm = false;
    let mut saw_other = false;
    for pid in pids {
        println!("[nebula-inject] attempting pid {pid}…");
        match remote::inject_dlopen(*pid, lib) {
            Ok(true) => {
                println!("[nebula-inject] injected into pid {pid} - hook .so loaded");
                return (ExitCode::SUCCESS, false);
            }
            Ok(false) => {
                eprintln!("[nebula-inject] pid {pid}: dlopen returned NULL (loader rejected the .so)");
                saw_other = true;
            }
            Err(e) => {
                eprintln!("[nebula-inject] pid {pid}: {e}");
                if e.contains("EPERM") {
                    saw_eperm = true;
                } else {
                    saw_other = true;
                }
            }
        }
    }
    (ExitCode::from(1), saw_eperm && !saw_other)
}

/// Current value of kernel.yama.ptrace_scope, if Yama is present.
fn yama_scope() -> Option<u32> {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Temporarily set kernel.yama.ptrace_scope. This is the one step where
/// elevating is correct: it changes a kernel policy, it does not trace.
fn set_yama_scope(value: u32) -> bool {
    Command::new("sudo")
        .arg("-n")
        .arg("sh")
        .arg("-c")
        .arg(format!("echo {value} > /proc/sys/kernel/yama/ptrace_scope"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// --- user namespaces -----------------------------------------------------
//
// Sober is a Flatpak app: bwrap puts it in a child user namespace owned by
// the launching user. Attaching from the parent namespace is refused, and
// that refusal is NOT Yama: it is the kernel's CAP_SYS_PTRACE check, which
// asks "are you capable *in the tracee's user namespace*". Relaxing
// ptrace_scope to 0 does not answer that question, which is exactly what we
// observed -- scope 0, still EPERM.
//
// Becoming a member of that namespace does answer it. So: join the target's
// user namespace, map ourselves to root inside it, and attach from there.

fn userns_link(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/ns/user"))
        .ok()
        .map(|p| p.display().to_string())
}

fn command_on_path(cmd: &str) -> bool {
    let path = env::var("PATH").unwrap_or_default();
    path.split(':').any(|dir| {
        if dir.is_empty() {
            return false;
        }
        std::fs::metadata(format!("{dir}/{cmd}")).is_ok()
    })
}

fn status_field(pid: i32, field: &str) -> String {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return "(unreadable)".into();
    };
    status
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_else(|| "(absent)".into())
}

/// Everything we can cheaply learn about why an attach was refused. Printed
/// on failure so the next run settles the question instead of guessing at it.
fn diagnostics(pid: i32) -> String {
    let ours = userns_link(std::process::id() as i32).unwrap_or_else(|| "(unknown)".into());
    let theirs = userns_link(pid).unwrap_or_else(|| "(unreadable)".into());
    let same_ns = ours == theirs;
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).is_ok();
    let tracer = status_field(pid, "TracerPid");
    let tracer_pid = tracer.split_whitespace().next().unwrap_or("?");

    let mut out = format!(
        "  diagnostics for pid {pid}:\n\
         \x20   yama ptrace_scope : {}\n\
         \x20   our user namespace : {ours}\n\
         \x20   target user ns    : {theirs}{}\n\
         \x20   target Uid/Gid    : {} / {}\n\
         \x20   TracerPid         : {tracer}\n\
         \x20   /proc/pid/maps    : {}\n\
         \x20   nsenter available : {}",
        yama_scope()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "(absent)".into()),
        if same_ns { "  [SAME NAMESPACE]" } else { "  [DIFFERENT]" },
        status_field(pid, "Uid"),
        status_field(pid, "Gid"),
        if maps { "readable" } else { "NOT readable" },
        if command_on_path("nsenter") { "yes" } else { "no" },
    );
    if tracer_pid != "0" {
        out.push_str("\n  !! someone is ALREADY tracing this process");
    }
    out
}

/// Re-run ourselves inside `pid`'s user namespace. Returns Some(true) only if
/// the nested run actually injected.
fn reexec_in_target_userns(pid: i32, lib: &str, explicit_pid: Option<i32>) -> Option<bool> {
    if !command_on_path("nsenter") {
        eprintln!("[nebula-inject] nsenter not installed — cannot join the target's user namespace");
        return None;
    }
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[nebula-inject] cannot locate self for namespace re-exec: {e}");
            return None;
        }
    };

    // Being uid 0 *inside* the namespace is what grants a full capability set
    // there (a process with euid 0 in a userns holds every capability in it).
    // nsenter has no --map-root-user — that is unshare's spelling — so
    // --setuid/--setgid is the equivalent. The second variant just joins and
    // keeps our credentials, for sandboxes that do not map uid 0.
    let variants: [&[&str]; 2] = [
        &["--setuid=0", "--setgid=0"],
        &["--preserve-credentials"],
    ];

    for (n, flags) in variants.iter().enumerate() {
        let mut cmd = Command::new("nsenter");
        cmd.arg("--user")
            .arg("--target")
            .arg(pid.to_string());
        for f in *flags {
            cmd.arg(f);
        }
        cmd.arg(&exe).arg("--in-userns");
        if let Some(p) = explicit_pid {
            cmd.arg(p.to_string());
        }
        cmd.arg(lib);
        if n == 0 {
            eprintln!("[nebula-inject] joining pid {pid}'s user namespace and retrying from inside…");
        } else {
            eprintln!("[nebula-inject] retrying without remapping uid…");
        }
        match cmd.status() {
            Ok(st) if st.success() => return Some(true),
            Ok(_) => continue,
            Err(e) => {
                eprintln!("[nebula-inject] nsenter failed to start: {e}");
                return None;
            }
        }
    }
    Some(false)
}

fn main() -> ExitCode {
    // --yama-relaxed: the caller (the GUI) has already relaxed Yama and will
    // restore it, so never escalate from in here. Nebula's front-end is the
    // process that can actually show a password dialog; a sudo prompt fired
    // from this child would land on a terminal nobody is watching.
    // NB: --attach-only is filtered out of the positional args too, so in
    // `--spawn` mode it can appear after the program without being handed
    // to that program as an argument.
    let argv: Vec<String> = env::args()
        .skip(1)
        .filter(|a| a != "--yama-relaxed" && a != "--attach-only")
        .collect();
    let attach_only = env::args().any(|a| a == "--attach-only");
    let yama_relaxed = env::args().any(|a| a == "--yama-relaxed");
    // Set when we re-exec'd ourselves inside the target's user namespace.
    // Guards against recursing: from in there we are already the right
    // context, so a second EPERM is a real answer, not a reason to re-join.
    let in_userns = env::args().any(|a| a == "--in-userns");
    if in_userns {
        eprintln!("[nebula-inject] running inside the target's user namespace");
    }
    if argv.first().map(|s| s == "--spawn").unwrap_or(false) {
        if argv.len() < 3 {
            eprintln!("usage: nebula-inject --spawn <lib> <program> [args...]");
            return ExitCode::from(2);
        }
        return spawn_mode(&argv[1], &argv[2..], attach_only);
    }

    let mut args = argv.into_iter();
    let first = match args.next() {
        Some(a) if !a.is_empty() => a,
        _ => {
            eprintln!("usage: nebula-inject [pid] <path-to-libnebula_hook.so>");
            eprintln!("       nebula-inject --spawn <lib> <program> [args...]");
            return ExitCode::from(2);
        }
    };

    // One argument = the library (auto-detect Sober). Two = pid + library,
    // which is what the test harness uses to aim at a stand-in process.
    let (explicit_pid, lib) = match args.next() {
        Some(second) => (first.parse::<i32>().ok(), second),
        None => (None, first),
    };
    if lib.is_empty() {
        eprintln!("usage: nebula-inject [pid] <path-to-libnebula_hook.so>");
        return ExitCode::from(2);
    }

    let pids: Vec<i32> = match explicit_pid {
        Some(p) => vec![p],
        None => remote::find_sober_pids(),
    };
    if pids.is_empty() {
        eprintln!("[nebula-inject] no running sober process found");
        return ExitCode::from(1);
    }

    // Auto-patch the Sober binary if it isn't already patched.
    // This NOPs out 3 anti-tamper sequences that would block injection.
    for pid in &pids {
        eprintln!("[nebula-inject] attempting to auto-patch Sober binary for pid {pid}...");
        let patched = remote::find_and_patch_sober(*pid);
        if patched {
            eprintln!("[nebula-inject] Sober binary patched successfully");
        } else {
            eprintln!("[nebula-inject] could not patch Sober binary (may already be patched or unwritable)");
        }
    }

    if attach_only {
        return probe_into(&pids);
    }
    // First pass as-is. If every pid is refused with EPERM, relax Yama and
    // try again (see below).
    let (code, denied) = inject_into(&pids, &lib);
    if code == ExitCode::SUCCESS {
        return ExitCode::SUCCESS;
    }

    if denied && in_userns {
        // We are already inside the namespace and still refused — so it is
        // not the namespace, and not Yama. Dump everything we can see.
        for pid in &pids {
            eprintln!("{}", diagnostics(*pid));
        }
        eprintln!(
            "[nebula-inject] refused even from inside the target's user namespace.\n\
             \x20             This is the honest failure: the kernel is denying ptrace for a\n\
             \x20             reason we cannot talk our way out of (a tracer already attached,\n\
             \x20             or an LSM). The diagnostics above say which."
        );
        return ExitCode::from(1);
    }

    if denied {
        // Try from inside the target's user namespace first: that is the
        // fix for a plain Flatpak sandbox, and it needs no privileges at all.
        let target = *pids.first().unwrap_or(&0);
        let attempted = if target > 0 {
            reexec_in_target_userns(target, &lib, explicit_pid)
        } else {
            None
        };
        // Report what we could learn either way — this is the run that tells
        // us whether the namespace was the actual blocker.
        for pid in &pids {
            eprintln!("{}", diagnostics(*pid));
        }
        match attempted {
            Some(true) => return ExitCode::SUCCESS,
            Some(false) => return ExitCode::from(1),
            None => { /* fall through to the older paths */ }
        }
    }

    if denied && yama_relaxed {
        eprintln!(
            "[nebula-inject] still EPERM even though the GUI reported ptrace_scope relaxed.\n\
             \x20             If you have already given Nebula admin rights, check the value:\n\
             \x20             cat /proc/sys/kernel/yama/ptrace_scope"
        );
        return ExitCode::from(1);
    }

    // Every attempt was refused by Yama's ptrace_scope.
    //
    // Elevation does NOT help here, and that is the subtle part: Sober runs in
    // a user namespace created by *your own* account, so your uid owns that
    // namespace and holds full capabilities inside it — while sudo (uid 0)
    // does not. Root gets EPERM as well, and could not read /proc/<pid>/root
    // to find the sandbox's libc anyway. So: relax Yama with sudo (the one
    // step that genuinely needs root — it's a kernel policy change, not a
    // trace), inject as ourselves, then put the knob straight back.
    if denied {
        let Some(previous) = yama_scope() else {
            eprintln!("[nebula-inject] ptrace denied; /proc/sys/kernel/yama/ptrace_scope unreadable");
            return ExitCode::from(1);
        };
        if previous != 0 {
            println!(
                "[nebula-inject] ptrace denied - relaxing yama ptrace_scope {previous} -> 0 (sudo)..."
            );
            if !set_yama_scope(0) {
                eprintln!(
                    "[nebula-inject] could not relax ptrace_scope. Run manually:\n\
                     \x20             sudo sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'\n\
                     \x20             (and switch it back to 1 afterwards)"
                );
                return ExitCode::from(1);
            }
            let (result, _) = inject_into(&pids, &lib);
            // Restore immediately whatever happened: this is a security
            // setting and we only relaxed it for the duration of the call.
            let restored = set_yama_scope(previous);
            println!(
                "[nebula-inject] yama ptrace_scope restored to {previous}{}",
                if restored { "" } else { " (FAILED - restore it manually!)" }
            );
            return result;
        }
    }
    ExitCode::from(1)
}
