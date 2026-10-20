//! net-tools desktop application entry point.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[macro_use]
extern crate rust_i18n;

mod app;
mod config_store;
mod fonts;
mod latency_stats;
mod speedtest_worker;
mod tabs;
mod ui;

use eframe::egui;

// i18n: load all locale files under locales/ at compile time (must be invoked at the crate root).
i18n!("../../locales", fallback = "en");

/// Prefer Xwayland inside WSLg.
///
/// The WSLg Wayland compositor uses a software GL path and can terminate while
/// an OpenGL window is being resized. WSLg always provides Xwayland as well, so
/// the X11 backend is the safer choice there. Other Wayland sessions keep their
/// native backend.
#[cfg(target_os = "linux")]
fn prefer_x11_on_wslg() {
    if std::path::Path::new("/mnt/wslg").exists() && std::env::var_os("DISPLAY").is_some() {
        std::env::remove_var("WAYLAND_DISPLAY");
    }
}

#[cfg(not(target_os = "linux"))]
fn prefer_x11_on_wslg() {}

fn main() -> eframe::Result {
    // The speed test runs iperf3 in a hidden child process of this same
    // executable so that its live JSON event stream can be consumed by the UI.
    if speedtest_worker::is_worker_invocation() {
        std::process::exit(speedtest_worker::run_worker());
    }

    // An elevated helper only writes the system clock and exits without opening
    // the UI. Normal launches fall through to the application below.
    if let Some(code) = net_tools_core::system_time::handle_elevation_request() {
        std::process::exit(code);
    }

    // Privileged TCP MTR / Path MTU runs in an elevated copy of this process.
    if let Some(code) = net_tools_core::elevation::handle_helper_request() {
        std::process::exit(code);
    }

    prefer_x11_on_wslg();

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
            .with_inner_size([1100.0, 800.0])
            .with_min_inner_size([960.0, 560.0])
            .with_title("net-tools")
            .with_icon(icon),
        // Center the window on the primary monitor at startup so the position
        // is deterministic instead of being chosen by the window manager.
        // Note: not supported on Wayland, where the compositor decides placement.
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "net-tools",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, handle.clone())))),
    )
}
