//! Latency line chart (based on egui_plot).

use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use rust_i18n::t;

use super::theme::Palette;

/// Render a `(x, y)` series as a line chart. `points` is `(seq, rtt_ms)`.
pub fn latency_chart(ui: &mut egui::Ui, points: &[[f64; 2]], height: f32) {
    let data: Vec<[f64; 2]> = points.to_vec();
    let y_max = points.iter().map(|p| p[1]).fold(1.0_f64, f64::max).max(1.0);
    let line_color = Palette::from_ui(ui).chart_primary;

    Plot::new("latency_plot")
        .height(height)
        .show_x(true)
        .show_y(true)
        .include_y(0.0)
        .include_y(y_max)
        .y_axis_label(t!("common.rtt_ms"))
        .show(ui, |plot_ui| {
            plot_ui.line(Line::new("rtt", PlotPoints::from(data)).color(line_color));
        });
}

/// Render download and upload throughput samples as separate lines.
///
/// `id` keeps the plot state independent from other charts in the application.
pub fn throughput_chart(
    ui: &mut egui::Ui,
    id: &str,
    samples: &[net_tools_core::model::SpeedSample],
    height: f32,
) {
    use net_tools_core::model::SpeedPhase;

    let collect = |phase: SpeedPhase| -> Vec<[f64; 2]> {
        samples
            .iter()
            .filter(|sample| sample.phase == phase)
            .map(|sample| [sample.elapsed_s, sample.mbps])
            .collect()
    };
    let download = collect(SpeedPhase::Download);
    let upload = collect(SpeedPhase::Upload);
    let y_max = download
        .iter()
        .chain(upload.iter())
        .map(|point| point[1])
        .fold(1.0_f64, f64::max)
        .max(1.0);
    let palette = Palette::from_ui(ui);

    Plot::new(id)
        .height(height)
        .show_x(true)
        .show_y(true)
        .include_y(0.0)
        .include_y(y_max)
        .x_axis_label(t!("speedtest.elapsed_s"))
        .y_axis_label(t!("speedtest.mbps"))
        .legend(egui_plot::Legend::default())
        .show(ui, |plot_ui| {
            if !download.is_empty() {
                plot_ui.line(
                    Line::new("Download", PlotPoints::from(download)).color(palette.chart_primary),
                );
            }
            if !upload.is_empty() {
                plot_ui.line(
                    Line::new("Upload", PlotPoints::from(upload)).color(palette.chart_secondary),
                );
            }
        });
}
