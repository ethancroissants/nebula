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
fn spawn_mode(lib: &str, argv: &[String]) -> ExitCode {
    let Some(prog) = argv.first() else {
        eprintln!("usage: nebula-inject --spawn <lib> <program> [args...]");
        return ExitCode::from(2);
    };
    let mut child = Command::new(prog);
    child.args(&argv[1..]);
    child.env_remove("LD_PRELOAD");
    let Ok(mut child) = child.spawn() else {
        eprintln!("[nebula-inject] could not spawn {prog}");
        return ExitCode::from(1);
    };
    let pid = child.id() as i32;
    println!("[nebula-inject] spawned {prog} as pid {pid}");

    // Give the target a moment to map libc and reach its main loop.
    std::thread::sleep(std::time::Duration::from_millis(1200));

    let result = remote::inject_dlopen(pid, lib);

    // The hook's constructor spawns a thread that settles (1.5 s) before it
    // writes its first heartbeat, so give it room before reaping the child.
    let mut flag = String::new();
    for _ in 0..40 {
        flag = read_flag();
        if flag != "(none)" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    println!("[nebula-inject] hook heartbeat after inject: {flag}");

    // Leave the child in a known state and reap it.
    let _ = child.kill();
    let _ = child.wait();

    match result {
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

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.first().map(|s| s == "--spawn").unwrap_or(false) {
        if argv.len() < 3 {
            eprintln!("usage: nebula-inject --spawn <lib> <program> [args...]");
            return ExitCode::from(2);
        }
        return spawn_mode(&argv[1], &argv[2..]);
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
    let mut denied = false;
    for pid in &pids {
        println!("[nebula-inject] attempting pid {pid}…");
        match remote::inject_dlopen(*pid, &lib) {
            Ok(true) => {
                println!("[nebula-inject] injected into pid {pid} — hook .so loaded");
                return ExitCode::SUCCESS;
            }
            Ok(false) => {
                eprintln!("[nebula-inject] pid {pid}: dlopen returned NULL (loader rejected the .so)");
            }
            Err(e) => {
                eprintln!("[nebula-inject] pid {pid}: {e}");
                if e.contains("EPERM") {
                    denied = true;
                }
            }
        }
    }

    // Every attempt was refused by Yama's ptrace_scope. Root bypasses it
    // (CAP_SYS_PTRACE), so re-run ourselves elevated exactly once — the
    // tracee is left untouched by the failed attempts, so this is safe.
    if denied && !env::var("NEBULA_INJECT_ELEVATED").is_ok() {
        let exe = match env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[nebula-inject] cannot locate self for elevation: {e}");
                return ExitCode::from(1);
            }
        };
        let mut cmd = Command::new("sudo");
        cmd.arg("-n");
        cmd.env("NEBULA_INJECT_ELEVATED", "1");
        cmd.arg(&exe);
        if let Some(p) = explicit_pid {
            cmd.arg(p.to_string());
        }
        cmd.arg(&lib);
        println!("[nebula-inject] ptrace denied — retrying with sudo (CAP_SYS_PTRACE)…");
        match cmd.status() {
            Ok(st) if st.success() => return ExitCode::SUCCESS,
            Ok(_) => {
                eprintln!(
                    "[nebula-inject] elevated retry failed. Either allow passwordless sudo, or run:\n\
                     \x20              sudo sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'\n\
                     \x20              (and switch it back to 1 afterwards)"
                );
            }
            Err(e) => eprintln!("[nebula-inject] could not spawn sudo: {e}"),
        }
    }
    ExitCode::from(1)
}
