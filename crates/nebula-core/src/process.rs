//! Locates the Sober / Roblox processes by reading `/proc`.
//!
//! Sober's process tree looks like this at runtime:
//!
//! ```text
//! flatpak (org.vinegarhq.Sober)
//!  └─ sober_services        # GTK login/launcher UI
//!  └─ sober                 # the runtime (Rust) — spawns the game process
//!      └─ RobloxPlayerBeta  # the translated Android game binary
//! ```
//!
//! Process names may be truncated to 15 chars in `comm` (e.g. `RobloxPlayerBe`),
//! so we match on prefixes against both `comm` and the full `cmdline`.

use std::fs;
use std::path::PathBuf;

use crate::Result;

/// A discovered Sober-related process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoberProcess {
    pub pid: i32,
    /// Process name from `/proc/<pid>/comm` (may be truncated).
    pub name: String,
    /// Full command line from `/proc/<pid>/cmdline` (NUL-separated).
    pub cmdline: String,
}

impl SoberProcess {
    /// `true` if this process is (almost certainly) the one running Luau —
    /// i.e. the translated Roblox player.
    pub fn is_roblox(&self) -> bool {
        let n = self.name.to_lowercase();
        n.starts_with("robloxplayerbe") || self.cmdline.to_lowercase().contains("robloxplayerbeta")
    }

    /// `true` for the Sober runtime binary itself.
    pub fn is_sober_runtime(&self) -> bool {
        self.name == "sober"
    }
}

fn read_nonl(path: &PathBuf) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end().to_string())
}

fn read_cmdline(pid: i32) -> String {
    let p = PathBuf::from(format!("/proc/{pid}/cmdline"));
    let raw = fs::read(&p).unwrap_or_default();
    String::from_utf8_lossy(&raw)
        .replace('\0', " ")
        .trim()
        .to_string()
}

/// Scan `/proc` for Sober-related processes.
pub fn scan() -> Result<Vec<SoberProcess>> {
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        let Ok(pid) = fname.parse::<i32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }

        let Some(comm) = read_nonl(&entry.path().join("comm")) else {
            continue; // process vanished or not ours to read
        };

        // Interesting names: sober, sober_services, RobloxPlayerBeta (or truncated)
        let interesting = comm.starts_with("sober")
            || comm.starts_with("RobloxPlayerBe")
            || comm.starts_with("robloxplayerbe");
        if !interesting {
            continue;
        }

        out.push(SoberProcess {
            pid,
            name: comm,
            cmdline: read_cmdline(pid),
        });
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

/// Pick the best attach candidate: prefer the Roblox player, then the runtime.
pub fn pick_target(procs: &[SoberProcess]) -> Option<&SoberProcess> {
    procs
        .iter()
        .find(|p| p.is_roblox())
        .or_else(|| procs.iter().find(|p| p.is_sober_runtime()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_roblox_matches_truncated_names() {
        let p = SoberProcess {
            pid: 1234,
            name: "RobloxPlayerBe".into(),
            cmdline: "/app/bin/RobloxPlayerBeta".into(),
        };
        assert!(p.is_roblox());
        assert!(!p.is_sober_runtime());
    }

    #[test]
    fn is_sober_runtime() {
        let p = SoberProcess {
            pid: 100,
            name: "sober".into(),
            cmdline: "sober".into(),
        };
        assert!(p.is_sober_runtime());
        assert!(!p.is_roblox());
    }

    #[test]
    fn pick_prefers_roblox() {
        let sober = SoberProcess {
            pid: 1,
            name: "sober".into(),
            cmdline: String::new(),
        };
        let roblox = SoberProcess {
            pid: 2,
            name: "RobloxPlayerBe".into(),
            cmdline: String::new(),
        };
        assert_eq!(pick_target(&[sober.clone(), roblox.clone()]), Some(&roblox));
        assert_eq!(pick_target(&[sober.clone()]), Some(&sober));
    }
}
