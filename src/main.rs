#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ui;

use eframe::egui;

fn main() -> eframe::Result {
    let initial = std::env::args().nth(1);
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/tlspect.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title(format!("TLSpect - X.509 Certificate Inspector ({})", env!("CARGO_PKG_VERSION")))
        .with_inner_size([1160.0, 780.0])
        .with_min_inner_size([800.0, 520.0]);
    if let Some(icon) = icon {
        viewport = viewport.with_icon(icon);
    }
    eframe::run_native(
        "TLSpect",
        eframe::NativeOptions { viewport, ..Default::default() },
        Box::new(move |cc| Ok(Box::new(app::TlspectApp::new(cc, initial)))),
    )
}
