//! nebula-inject — push the hook into an already-running Sober.
//!
//! Sober's SingleSurfaceApp runs the game (and its Luau VM) inside the process
//! that booted the app; `ld.so.preload` seeding after boot never applies to it
//! because the loader only reads that file at process start. This tool asks
//! the running process to load the hook itself: ptrace-attach, hijack one
//! stopped thread, make it `dlopen("/tmp/libnebula_hook.so", RTLD_NOW)`,
//! restore everything, detach. The hook's constructor then captures the VM.
//!
//! Usage: nebula-inject <path-to-libnebula_hook.so>
//!   (path as seen FROM INSIDE the Sober sandbox, i.e. /tmp/libnebula_hook.so)
//!
//! Exit codes: 0 = injected (dlopen returned a handle), 1 = tried but no
//! process accepted it, 2 = usage error. Progress on stdout, details on stderr.

use std::process::ExitCode;

use nebula_hook::remote;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let lib = match args.next() {
        Some(l) if !l.is_empty() => l,
        _ => {
            eprintln!("usage: nebula-inject <path-to-libnebula_hook.so>");
            return ExitCode::from(2);
        }
    };

    let pids = remote::find_sober_pids();
    if pids.is_empty() {
        eprintln!("[nebula-inject] no running sober process found");
        return ExitCode::from(1);
    }
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
            }
        }
    }
    ExitCode::from(1)
}
