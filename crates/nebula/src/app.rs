//! The main application state + egui draw loop.

use std::path::PathBuf;
use std::time::Duration;

use eframe::egui;

use nebula_core::{NebulaPaths, ScriptQueue, SoberProcess};

use crate::theme;

/// Persisted user preferences.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Prefs {
    auto_attach: bool,
    font_size: f32,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            auto_attach: true,
            font_size: 13.5,
        }
    }
}

/// What the UI shows as attach state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachState {
    /// Hook file is ready; waiting for the game to start.
    Waiting,
    /// Hook confirmed the game is running.
    Attached,
    /// Flatpak override applied, but no hook heartbeat yet.
    HookReady,
    /// Nothing set up yet.
    Idle,
}

pub struct NebulaApp {
    paths: NebulaPaths,
    queue: ScriptQueue,
    prefs: Prefs,
    prefs_path: PathBuf,

    code: String,
    console: String,
    error: Option<String>,

    procs: Vec<SoberProcess>,
    status: AttachState,
    log_offset: u64,
    poll_timer: Duration,
}

impl NebulaApp {
    pub fn new() -> Self {
        let paths = NebulaPaths::default_home()
            .unwrap_or_else(|_| NebulaPaths::root(PathBuf::from("/tmp/nebula-fallback")));
        let _ = paths.ensure();
        let queue = ScriptQueue::new(&paths);

        let prefs_path = paths.root.join("prefs.json");
        let prefs = std::fs::read(&prefs_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();

        Self {
            paths,
            queue,
            prefs,
            prefs_path,
            code: String::new(),
            console: String::new(),
            error: None,
            procs: Vec::new(),
            status: AttachState::Idle,
            log_offset: 0,
            poll_timer: Duration::ZERO,
        }
    }

    /// Persist prefs (called whenever they change).
    fn save_prefs(&self) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.prefs) {
            let _ = std::fs::write(&self.prefs_path, bytes);
        }
    }

    /// Poll Sober processes and the hook heartbeat; refresh attach state.
    fn poll(&mut self) {
        self.procs = nebula_core::process::scan().unwrap_or_default();
        self.status = self.compute_status();
    }

    fn compute_status(&self) -> AttachState {
        let heartbeat = self.queue.status();
        let has_procs = self
            .procs
            .iter()
            .any(|p| p.is_roblox() || p.is_sober_runtime());

        match heartbeat.as_deref() {
            Some("ATTACHED") => AttachState::Attached,
            Some("WAITING") => AttachState::HookReady,
            _ if has_procs => AttachState::Waiting,
            _ => AttachState::Idle,
        }
    }

    /// Apply the Flatpak override that loads the hook into Sober.
    fn attach(&mut self) {
        // Deploy the hook .so next to the queue (from our own executable dir,
        // or a system location when installed via package).
        let hook_src = self
            .hook_source()
            .unwrap_or_else(|| PathBuf::from("libnebula_hook.so"));

        let _ = nebula_core::sober::reset_overrides();
        let _ =
            nebula_core::sober::grant_filesystem(&self.paths.queue_dir().to_string_lossy(), true);
        let preload = format!("{}:ro", hook_src.to_string_lossy());
        let result = nebula_core::sober::set_env("LD_PRELOAD", &preload);

        match result {
            Ok(()) => {
                self.status = AttachState::HookReady;
                self.console
                    .push_str("[Nebula] Hook deployed. Launch (or restart) Sober now.\n");
            }
            Err(e) => {
                self.error = Some(format!("attach failed: {e}"));
            }
        }
    }

    /// Where to copy the hook .so from: next to our executable.
    fn hook_source(&self) -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        let candidate = dir.join("libnebula_hook.so");
        candidate.exists().then_some(candidate)
    }

    /// Push the editor's script into the queue.
    fn execute(&mut self) {
        if self.code.trim().is_empty() {
            return;
        }
        match self.queue.push(&self.code) {
            Ok(()) => {
                self.console
                    .push_str(&format!("[Nebula] queued {} bytes\n", self.code.len()));
                self.code.clear();
            }
            Err(e) => self.error = Some(format!("queue write failed: {e}")),
        }
    }

    /// Pull any new hook log lines into the console.
    fn drain_log(&mut self) {
        if let Ok(lines) = self.queue.drain_log() {
            let skip = self.log_offset as usize;
            if lines.len() > skip {
                for line in &lines[skip..] {
                    self.console.push_str(line);
                    self.console.push('\n');
                }
            }
            self.log_offset = lines.len() as u64;
        }
    }
}

impl eframe::App for NebulaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll at ~4 Hz; keep UI responsive.
        self.poll_timer += Duration::from_millis(16);
        if self.poll_timer >= Duration::from_millis(250) {
            self.poll_timer = Duration::ZERO;
            self.poll();
            self.drain_log();
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(theme::BG_BASE)
                    .inner_margin(0.0),
            )
            .show(ctx, |ui| {
                self.draw_header(ui);
                self.draw_body(ctx, ui);
            });
    }
}

impl NebulaApp {
    fn draw_header(&mut self, ui: &mut egui::Ui) {
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 64.0), egui::Sense::hover());
        theme::gradient_rect(ui, rect);

        ui.painter().text(
            rect.left_center() + egui::vec2(20.0, 0.0),
            egui::Align2::LEFT_CENTER,
            "✦ Nebula",
            egui::FontId::proportional(22.0),
            egui::Color32::WHITE,
        );
        ui.painter().text(
            rect.right_center() - egui::vec2(20.0, 0.0),
            egui::Align2::RIGHT_CENTER,
            self.status_label(),
            egui::FontId::proportional(13.0),
            egui::Color32::WHITE.linear_multiply(0.85),
        );
    }

    fn status_label(&self) -> &'static str {
        match self.status {
            AttachState::Attached => "● attached",
            AttachState::HookReady => "◐ hook ready — launch Sober",
            AttachState::Waiting => "○ waiting for Roblox…",
            AttachState::Idle => "○ not attached",
        }
    }

    fn draw_body(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing = egui::vec2(10.0, 10.0);

        ui.horizontal(|ui| {
            if theme::ghost_button(ui, "Attach to Sober") {
                self.attach();
                self.save_prefs();
            }
            if theme::ghost_button(ui, "Execute (F5)") {
                self.execute();
            }
            if theme::ghost_button(ui, "Clear") {
                self.code.clear();
                self.console.clear();
                self.log_offset = 0;
            }
            if theme::ghost_button(ui, "Open…") {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Lua", &["lua", "txt"])
                    .pick_file()
                {
                    match std::fs::read_to_string(&path) {
                        Ok(s) => self.code = s,
                        Err(e) => self.error = Some(e.to_string()),
                    }
                }
            }
            if theme::ghost_button(ui, "Save") {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Lua", &["lua"])
                    .set_file_name("script.lua")
                    .save_file()
                {
                    if let Err(e) = std::fs::write(&path, &self.code) {
                        self.error = Some(e.to_string());
                    }
                }
            }
        });

        // Editor pane.
        theme::panel_frame().show(ui, |ui| {
            ui.set_min_height(240.0);
            ui.add_sized(
                [ui.available_width(), 240.0],
                egui::TextEdit::multiline(&mut self.code)
                    .code_editor()
                    .font(egui::FontSelection::FontId(egui::FontId::monospace(
                        self.prefs.font_size,
                    ))),
            );
        });

        // Console pane.
        ui.separator();
        theme::panel_frame().show(ui, |ui| {
            ui.set_min_height(160.0);
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(egui::Label::new(
                    egui::RichText::new(&self.console).monospace().size(12.0),
                ));
            });
        });

        // Errors toast.
        if let Some(err) = &self.error {
            ui.colored_label(
                egui::Color32::from_rgb(0xFF, 0x6B, 0x7B),
                format!("⚠ {err}"),
            );
        }

        // Execute on Ctrl+Enter or F5.
        ctx.input(|i| {
            if i.key_pressed(egui::Key::F5) || (i.key_pressed(egui::Key::Enter) && i.modifiers.ctrl)
            {
                self.execute();
            }
        });
    }
}
