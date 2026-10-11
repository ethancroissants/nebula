//! The script transport queue.
//!
//! The GUI never touches process memory. It writes the script to
//! `~/.nebula/queue/exec.lua` atomically (temp file + rename), and the injected
//! hook — polling every 200 ms inside the game — picks it up, deletes it, and
//! executes it in the live Luau VM.
//!
//! The same file channel carries an append-only log back to the GUI, so the
//! console pane shows `[Nebula]` lines straight from inside the game.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::{NebulaPaths, Result};

/// Handle to the queue directory.
#[derive(Debug, Clone)]
pub struct ScriptQueue {
    exec: PathBuf,
    log: PathBuf,
    status: PathBuf,
}

impl ScriptQueue {
    pub fn new(paths: &NebulaPaths) -> Self {
        Self {
            exec: paths.exec_file(),
            log: paths.log_file(),
            status: paths.status_file(),
        }
    }

    /// Queue a script for execution. Atomic: the hook never sees a partial file.
    pub fn push(&self, script: &str) -> Result<()> {
        let dir = self
            .exec
            .parent()
            .ok_or_else(|| crate::Error::Io("exec file has no parent".into()))?;
        let tmp = dir.join(format!(".exec-{}.tmp", std::process::id()));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(script.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.exec)?;
        Ok(())
    }

    /// Read (and clear) pending log lines written by the hook.
    pub fn drain_log(&self) -> Result<Vec<String>> {
        let mut s = String::new();
        if self.log.exists() {
            File::open(&self.log)?.read_to_string(&mut s)?;
        }
        Ok(s.lines().map(|l| l.to_string()).collect())
    }

    /// Read the hook's status heartbeat: `ATTACHED`, `WAITING`, or none.
    pub fn status(&self) -> Option<String> {
        fs::read_to_string(&self.status)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Called by the hook side (see nebula-hook): claim the pending script.
    /// Returns `None` when there is nothing queued.
    pub fn take_pending(&self) -> Option<String> {
        if !self.exec.exists() {
            return None;
        }
        let mut s = String::new();
        {
            let mut f = File::open(&self.exec).ok()?;
            f.read_to_string(&mut s).ok()?;
        }
        let _ = fs::remove_file(&self.exec);
        if s.is_empty() {
            return None;
        }
        Some(s)
    }

    /// Hook side: append a line to the shared log.
    pub fn hook_log(&self, line: &str) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.log) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Hook side: write the status heartbeat.
    pub fn hook_set_status(&self, status: &str) {
        let _ = fs::write(&self.status, status);
    }

    /// Test helper: does the exec file exist?
    #[cfg(test)]
    pub fn pending_exists(&self) -> bool {
        self.exec.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_paths() -> NebulaPaths {
        let dir = std::env::temp_dir().join(format!("nebula-test-{}", std::process::id()));
        NebulaPaths::root(dir)
    }

    #[test]
    fn push_take_roundtrip() {
        let paths = tmp_paths();
        paths.ensure().unwrap();
        let q = ScriptQueue::new(&paths);
        assert!(q.take_pending().is_none());
        q.push("print('hi')").unwrap();
        assert!(q.pending_exists());
        assert_eq!(q.take_pending().as_deref(), Some("print('hi')"));
        assert!(q.take_pending().is_none());
    }

    #[test]
    fn log_drain() {
        let paths = tmp_paths();
        paths.ensure().unwrap();
        let q = ScriptQueue::new(&paths);
        q.hook_log("line one");
        q.hook_log("line two");
        assert_eq!(
            q.drain_log().unwrap(),
            vec!["line one".to_string(), "line two".to_string()]
        );
    }

    #[test]
    fn status_roundtrip() {
        let paths = tmp_paths();
        paths.ensure().unwrap();
        let q = ScriptQueue::new(&paths);
        assert_eq!(q.status(), None);
        q.hook_set_status("ATTACHED");
        assert_eq!(q.status().as_deref(), Some("ATTACHED"));
    }
}
