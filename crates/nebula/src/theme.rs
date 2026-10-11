//! Nebula's visual identity: deep-space dark theme, indigo/violet accent,
//! rounded panels, custom fonts.

use eframe::egui;

/// The accent gradient endpoints, used for buttons and the title glow.
pub const ACCENT_A: egui::Color32 = egui::Color32::from_rgb(0x7C, 0x5C, 0xFF); // indigo
pub const ACCENT_B: egui::Color32 = egui::Color32::from_rgb(0xC0, 0x6B, 0xFF); // violet

/// Base surfaces (backgrounds), dark space-blue ramp.
pub const BG_BASE: egui::Color32 = egui::Color32::from_rgb(0x0D, 0x0E, 0x1A);
pub const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(0x15, 0x17, 0x28);
pub const BG_ELEV: egui::Color32 = egui::Color32::from_rgb(0x1C, 0x1F, 0x35);

/// Build the global egui style: dark, rounded, indigo accents.
pub fn install(cc: &eframe::CreationContext<'_>) {
    let fonts = egui::FontDefinitions::default();
    // (Nebula ships with egui's default fonts; a custom display font can be
    // added later via include_bytes! here.)

    cc.egui_ctx.set_fonts(fonts);

    let mut style = (*cc.egui_ctx.style()).clone();
    let s = &mut style;

    s.visuals = egui::Visuals::dark();
    s.visuals.window_fill = BG_PANEL;
    s.visuals.panel_fill = BG_BASE;
    s.visuals.extreme_bg_color = BG_ELEV; // editor / input backgrounds
    s.visuals.faint_bg_color = egui::Color32::from_rgb(0x19, 0x1B, 0x2E);

    s.visuals.widgets.noninteractive.bg_fill = BG_PANEL;
    s.visuals.widgets.noninteractive.fg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0xD8, 0xDC, 0xF0));

    s.visuals.widgets.inactive.bg_fill = BG_ELEV;
    s.visuals.widgets.inactive.fg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0xB0, 0xB6, 0xD8));

    s.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x2A, 0x2E, 0x52);
    s.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.2_f32, egui::Color32::WHITE);

    s.visuals.widgets.active.bg_fill = ACCENT_A;
    s.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.2_f32, egui::Color32::WHITE);

    s.visuals.selection.bg_fill = ACCENT_A.linear_multiply(0.55);
    s.visuals.selection.stroke = egui::Stroke::new(1.0_f32, ACCENT_B);

    // Round everything a little more than stock.
    for w in [
        &mut s.visuals.widgets.noninteractive,
        &mut s.visuals.widgets.inactive,
        &mut s.visuals.widgets.hovered,
        &mut s.visuals.widgets.active,
    ] {
        w.corner_radius = egui::CornerRadius::same(8);
    }

    s.visuals.override_text_color = Some(egui::Color32::from_rgb(0xE6, 0xE8, 0xF4));
    s.visuals.hyperlink_color = ACCENT_B;

    s.spacing.item_spacing = egui::vec2(8.0, 8.0);
    s.spacing.button_padding = egui::vec2(12.0, 6.0);

    cc.egui_ctx.set_style(style);
}

/// A vertical gradient mesh for the header band.
pub fn gradient_rect(ui: &egui::Ui, rect: egui::Rect) {
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.left_top(), ACCENT_A);
    mesh.colored_vertex(rect.right_top(), ACCENT_B);
    mesh.colored_vertex(rect.right_bottom(), ACCENT_B.linear_multiply(0.4));
    mesh.colored_vertex(rect.left_bottom(), ACCENT_A.linear_multiply(0.4));
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    ui.painter().add(egui::Shape::mesh(mesh));
}

/// Simple rounded panel with subtle border.
pub fn panel_frame() -> egui::Frame {
    egui::Frame::default()
        .fill(BG_PANEL)
        .corner_radius(egui::CornerRadius::same(12))
        .inner_margin(egui::Margin::same(12))
        .stroke(egui::Stroke::new(
            1.0_f32,
            egui::Color32::from_rgb(0x27, 0x2B, 0x48),
        ))
}

/// A big rounded "primary" button with the accent gradient.
#[allow(dead_code)] // part of the theme toolkit; used by future panels
pub fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), egui::Sense::click());

    let mut fill = ACCENT_A;
    if ui.ui_contains_pointer() && enabled {
        fill = ACCENT_B;
    }
    if !enabled {
        fill = egui::Color32::from_rgb(0x30, 0x33, 0x50);
    }

    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(10), fill);
    ui.painter().rect_stroke(
        rect,
        egui::CornerRadius::same(10),
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x50, 0x54, 0x80)),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::proportional(15.0),
        if enabled {
            egui::Color32::WHITE
        } else {
            egui::Color32::from_rgb(0x88, 0x8C, 0xA8)
        },
    );

    enabled && resp.clicked()
}

/// A small ghost (outline) button.
pub fn ghost_button(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(label)
        .small()
        .fill(BG_ELEV)
        .stroke(egui::Stroke::new(
            1.0_f32,
            egui::Color32::from_rgb(0x3A, 0x3F, 0x66),
        ))
        .corner_radius(egui::CornerRadius::same(8));
    ui.add(button).clicked()
}

/// Window icon: a simple star-in-circle rendered to an RGBA buffer.
pub fn icon() -> egui::IconData {
    const S: usize = 64;
    let mut rgba = vec![0u8; S * S * 4];

    let cx = (S as f32 - 1.0) / 2.0;
    let cy = cx;
    let r_outer = 28.0;
    let r_inner = 11.0;

    for y in 0..S {
        for x in 0..S {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let dist = (dx * dx + dy * dy).sqrt();

            // Ring: outer circle band.
            let on_ring = (dist - (r_outer - 4.0)).abs() < 2.2;

            // Four-point star (diamond rotated 45°, hollow center).
            let star = |sx: f32, sy: f32, k: f32| -> bool {
                let d = (sx.abs() + sy.abs()) / k;
                (0.35..=1.0).contains(&d) && d <= 1.0
            };

            let in_star = star(dx, dy, r_inner * 2.0);

            if on_ring || in_star {
                let idx = (y * S + x) * 4;
                let (r, g, b) = (0x9Eu8, 0x7Bu8, 0xFFu8);
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 255;
            }
        }
    }

    egui::IconData {
        width: S as u32,
        height: S as u32,
        rgba,
    }
}
