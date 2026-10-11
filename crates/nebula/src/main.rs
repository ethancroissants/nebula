//! Nebula — sleek script executor for Sober.
//!
//! Entry point: boot eframe with the dark "nebula" visual style and run the
//! app loop until the window closes.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod theme;

use eframe::egui;

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([720.0, 520.0])
            .with_title("Nebula — for Sober")
            .with_icon(theme::icon()),
        ..Default::default()
    };

    eframe::run_native(
        "Nebula",
        options,
        Box::new(|cc| {
            theme::install(cc);
            Ok(Box::new(app::NebulaApp::new()))
        }),
    )
    .expect("failed to start Nebula GUI");
}
