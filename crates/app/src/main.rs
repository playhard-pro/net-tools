//! net-tools desktop application entry point.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[macro_use]
extern crate rust_i18n;

mod app;
mod config_store;
mod fonts;
mod tabs;
mod ui;

use eframe::egui;

// i18n: load all locale files under locales/ at compile time (must be invoked at the crate root).
i18n!("../../locales", fallback = "en");

fn main() -> eframe::Result {
    // Logging.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Restore the previously selected language.
    if let Some(cfg) = config_store::load() {
        rust_i18n::set_locale(&cfg.language);
    }

    // tokio runtime: probe tasks run here while the UI runs on the main thread.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let handle = rt.handle().clone();
    let _keep_alive = rt;

    // Runtime window icon, also used by the taskbar / dock while running.
    // The icon embedded in the executable (Windows) and packaged installers is
    // configured separately in `build.rs` and `packager.toml`.
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/icon.png"))
        .expect("bundled icon.png is not a valid PNG");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([888.0, 800.0])
            .with_min_inner_size([800.0, 560.0])
            .with_title("net-tools")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "net-tools",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, handle.clone())))),
    )
}
