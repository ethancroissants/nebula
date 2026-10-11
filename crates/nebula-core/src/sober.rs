//! Sober-specific knowledge: config paths, flatpak interactions, and the
//! "one file" sandbox override that lets the hook see the queue.
//!
//! Reverse-engineering notes (from community RE of the closed-source Sober):
//!
//! * Sober is installed as the Flatpak `org.vinegarhq.Sober`.
//! * `sober` (Rust runtime) spawns the translated Roblox binary and loads
//!   `libbadcpu.so` into it. Extra shared objects can be loaded the same way
//!   by exporting `LD_PRELOAD` through `flatpak override --env=...`.
//! * The Flatpak sandbox blocks `$HOME` by default; `flatpak override
//!   --filesystem=PATH:ro` pokes exactly one hole. Nebula opens a hole for
//!   its queue directory only — not the whole home dir.
//! * Inside the game process, the Luau VM lives in `libSoberRuntime.so`,
//!   whose exported `lua_*` symbols are resolvable with `dlsym` at runtime.

use std::process::Command;

use crate::Result;

/// The Sober flatpak app id.
pub const FLATPAK_APP_ID: &str = "org.vinegarhq.Sober";

/// `true` when the `flatpak` command exists.
pub fn have_flatpak() -> bool {
    Command::new("flatpak")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `true` when Sober is installed (system *or* user flatpak).
pub fn sober_installed() -> bool {
    Command::new("flatpak")
        .args(["info", FLATPAK_APP_ID])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Command::new("flatpak")
            .args(["info", "--user", FLATPAK_APP_ID])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

/// Run `flatpak override --user ...` for Sober with the given args.
fn override_user(args: &[&str]) -> Result<()> {
    let out = Command::new("flatpak")
        .args(["override", "--user", FLATPAK_APP_ID])
        .args(args)
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(crate::Error::Process(format!(
            "flatpak override failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Remove every previous Nebula override so we start from a clean slate.
pub fn reset_overrides() -> Result<()> {
    override_user(&["--reset"])
}

/// Grant Sober access to one path. `rw` controls the `:ro` suffix.
pub fn grant_filesystem(path: &str, rw: bool) -> Result<()> {
    let perm = if rw { "rw" } else { "ro" };
    override_user(&[&format!("--filesystem={path}:{perm}")])
}

/// Export an env var into the Sober sandbox (used for `LD_PRELOAD`).
pub fn set_env(key: &str, value: &str) -> Result<()> {
    override_user(&[&format!("--env={key}={value}")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_is_sober() {
        assert_eq!(FLATPAK_APP_ID, "org.vinegarhq.Sober");
    }
}
