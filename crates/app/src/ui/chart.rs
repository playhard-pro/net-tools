//! Latency line chart (based on egui_plot).

use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use rust_i18n::t;

/// Render a `(x, y)` series as a line chart. `points` is `(seq, rtt_ms)`.
pub fn latency_chart(ui: &mut egui::Ui, points: &[[f64; 2]], height: f32) {
    let data: Vec<[f64; 2]> = points.to_vec();
    let y_max = points.iter().map(|p| p[1]).fold(1.0_f64, f64::max).max(1.0);

    Plot::new("latency_plot")
        .height(height)
        .show_x(true)
        .show_y(true)
        .include_y(0.0)
        .include_y(y_max)
        .y_axis_label(t!("common.rtt_ms"))
        .show(ui, |plot_ui| {
            plot_ui.line(
                Line::new("rtt", PlotPoints::from(data))
                    .color(egui::Color32::from_rgb(0, 180, 255)),
            );
        });
}
