//! Filesystem locations used by Nebula at runtime.
//!
//! | File                        | Purpose                                          |
//! |-----------------------------|--------------------------------------------------|
//! | `~/.nebula/queue/exec.lua`  | script dropped here gets executed by the hook    |
//! | `~/.nebula/queue/log`       | log lines written by the hook                    |
//! | `~/.nebula/queue/status`    | `ATTACHED` / `WAITING` heartbeat from the hook   |
//! | `~/.nebula/scripts/`        | saved scripts (GUI "Save" button)                |
//! | `~/.nebula/libnebula.so`    | the hook library (copied here on first attach)   |
//!
//! NOTE: the queue directory lives *outside* the Flatpak sandbox in `$HOME`,
//! and the injector grants Sober read/write access to exactly that one file
//! (plus the log) — the sandbox never sees the rest of `$HOME`.

use std::fs;
use std::path::PathBuf;

/// All runtime paths Nebula cares about.
#[derive(Debug, Clone)]
pub struct NebulaPaths {
    /// Root: `~/.nebula`
    pub root: PathBuf,
}

impl NebulaPaths {
    /// Use `$HOME/.nebula`.
    pub fn default_home() -> crate::Result<Self> {
        let home =
            std::env::var_os("HOME").ok_or_else(|| crate::Error::Io("HOME not set".into()))?;
        Ok(Self::root(PathBuf::from(home).join(".nebula")))
    }

    /// Use an explicit root (used by tests).
    pub fn root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn queue_dir(&self) -> PathBuf {
        self.root.join("queue")
    }

    /// The script file the hook polls. Written atomically by the GUI.
    pub fn exec_file(&self) -> PathBuf {
        self.queue_dir().join("exec.lua")
    }

    /// The hook's log file (read by the GUI console).
    pub fn log_file(&self) -> PathBuf {
        self.queue_dir().join("log")
    }

    /// The hook's heartbeat file: `ATTACHED` or `WAITING`.
    pub fn status_file(&self) -> PathBuf {
        self.queue_dir().join("status")
    }

    /// Where saved scripts live.
    pub fn scripts_dir(&self) -> PathBuf {
        self.root.join("scripts")
    }

    /// Where the deployed hook library lives.
    pub fn hook_so(&self) -> PathBuf {
        self.root.join("libnebula_hook.so")
    }

    /// Create every directory Nebula needs. Idempotent.
    pub fn ensure(&self) -> crate::Result<()> {
        fs::create_dir_all(self.queue_dir())?;
        fs::create_dir_all(self.scripts_dir())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_consistent() {
        let p = NebulaPaths::root(PathBuf::from("/tmp/nebula-test"));
        assert_eq!(
            p.exec_file(),
            PathBuf::from("/tmp/nebula-test/queue/exec.lua")
        );
        assert_eq!(
            p.hook_so(),
            PathBuf::from("/tmp/nebula-test/libnebula_hook.so")
        );
    }
}
