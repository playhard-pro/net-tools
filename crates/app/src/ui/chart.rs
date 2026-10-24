//! Latency charts: line chart and RTT histogram (based on egui_plot).

use eframe::egui;
use egui_plot::{Bar, BarChart, Line, Plot, PlotPoints};
use rust_i18n::t;

use net_tools_core::model::{WifiChannelUsage, WifiSignalSample};

use super::theme::Palette;

/// One bucket of a latency histogram.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HistogramBin {
    /// Inclusive lower RTT bound in milliseconds.
    pub lower_ms: f64,
    /// Upper RTT bound in milliseconds, exclusive except for the last bucket.
    pub upper_ms: f64,
    /// Number of samples that fall into this bucket.
    pub count: u64,
}

/// Split `values` into equal-width buckets covering their full range.
///
/// An empty input produces no buckets. When every value is identical, a single
/// bucket is returned so the caller can still render the sample count.
pub fn histogram_bins(values: &[f64], bins: usize) -> Vec<HistogramBin> {
    if values.is_empty() || bins == 0 {
        return Vec::new();
    }

    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if max <= min {
        return vec![HistogramBin {
            lower_ms: min,
            upper_ms: max,
            count: values.len() as u64,
        }];
    }

    let width = (max - min) / bins as f64;
    let mut counts = vec![0_u64; bins];
    for &value in values {
        // Values at the upper edge belong to the last bucket.
        let index = (((value - min) / width).floor() as usize).min(bins - 1);
        counts[index] += 1;
    }

    counts
        .into_iter()
        .enumerate()
        .map(|(index, count)| {
            let lower_ms = min + index as f64 * width;
            // Keep the final bucket aligned with the exact maximum.
            let upper_ms = if index + 1 == bins {
                max
            } else {
                min + (index + 1) as f64 * width
            };
            HistogramBin {
                lower_ms,
                upper_ms,
                count,
            }
        })
        .collect()
}

/// Render a latency histogram with the sample count on the vertical axis.
///
/// `id` keeps the plot state independent between tabs, while the axis labels
/// let callers describe the metric being summarized.
pub fn histogram_chart(
    ui: &mut egui::Ui,
    id: &str,
    bins: &[HistogramBin],
    height: f32,
    x_label: &str,
    y_label: &str,
) {
    if bins.is_empty() {
        return;
    }

    let color = Palette::from_ui(ui).chart_primary;
    let max_count = bins.iter().map(|bin| bin.count).max().unwrap_or(1).max(1) as f64;
    let bars: Vec<Bar> = bins
        .iter()
        .map(|bin| {
            let midpoint = (bin.lower_ms + bin.upper_ms) / 2.0;
            let width = (bin.upper_ms - bin.lower_ms).max(f64::EPSILON);
            Bar::new(midpoint, bin.count as f64)
                .width(width * 0.9)
                .name(format!(
                    "{:.1}–{:.1} ms: {}",
                    bin.lower_ms, bin.upper_ms, bin.count
                ))
        })
        .collect();

    Plot::new(id)
        .height(height)
        .show_x(true)
        .show_y(true)
        .include_y(0.0)
        .include_y(max_count)
        .x_axis_label(x_label)
        .y_axis_label(y_label)
        .show(ui, |plot_ui| {
            plot_ui.bar_chart(BarChart::new("samples", bars).color(color));
        });
}

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
    let width = ui.available_width().max(1.0);

    Plot::new(id)
        .width(width)
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

/// Render receive and transmit rate samples as two lines on one compact chart.
///
/// Both series share the axes so their relative magnitude stays visible. The
/// caller supplies the unit label because the same widget is used for byte and
/// packet rates.
pub fn network_rate_chart(
    ui: &mut egui::Ui,
    id: &str,
    rx: &[[f64; 2]],
    tx: &[[f64; 2]],
    height: f32,
    y_label: &str,
) {
    let y_max = rx
        .iter()
        .chain(tx.iter())
        .map(|point| point[1])
        .fold(1.0_f64, f64::max)
        .max(1.0);
    let palette = Palette::from_ui(ui);
    let width = ui.available_width().max(1.0);

    Plot::new(id)
        .width(width)
        .height(height)
        .show_x(true)
        .show_y(true)
        .include_y(0.0)
        .include_y(y_max)
        .x_axis_label(t!("overview.elapsed_s"))
        .y_axis_label(y_label)
        .legend(egui_plot::Legend::default())
        .show(ui, |plot_ui| {
            if !rx.is_empty() {
                plot_ui.line(
                    Line::new("RX", PlotPoints::from(rx.to_vec())).color(palette.chart_primary),
                );
            }
            if !tx.is_empty() {
                plot_ui.line(
                    Line::new("TX", PlotPoints::from(tx.to_vec())).color(palette.chart_secondary),
                );
            }
        });
}

/// Render the current-link RSSI history as a line chart.
pub fn wifi_signal_chart(ui: &mut egui::Ui, id: &str, samples: &[WifiSignalSample], height: f32) {
    let points = samples
        .iter()
        .filter_map(|sample| {
            sample
                .signal_dbm
                .map(|signal| [sample.elapsed_s, signal as f64])
        })
        .collect::<Vec<_>>();
    if points.is_empty() {
        return;
    }
    let min = points
        .iter()
        .map(|point| point[1])
        .fold(f64::INFINITY, f64::min);
    let max = points
        .iter()
        .map(|point| point[1])
        .fold(f64::NEG_INFINITY, f64::max);
    let color = Palette::from_ui(ui).chart_primary;
    let width = ui.available_width().max(1.0);

    Plot::new(id)
        .width(width)
        .height(height)
        .show_x(true)
        .show_y(true)
        .include_y(min)
        .include_y(max)
        .x_axis_label(t!("overview.elapsed_s"))
        .y_axis_label(t!("wifi.signal_dbm"))
        .show(ui, |plot_ui| {
            plot_ui.line(Line::new("RSSI", PlotPoints::from(points)).color(color));
        });
}

/// Render channel occupancy as bars for one band.
pub fn wifi_channel_chart(ui: &mut egui::Ui, id: &str, usage: &[WifiChannelUsage], height: f32) {
    if usage.is_empty() {
        return;
    }
    let color = Palette::from_ui(ui).chart_primary;
    let bars = usage
        .iter()
        .map(|entry| {
            let label = format!(
                "{} ch {}: {} AP, {:.0}%",
                entry.band.label(),
                entry.channel,
                entry.access_points,
                entry.occupancy
            );
            Bar::new(entry.channel as f64, entry.occupancy)
                .width(0.75)
                .name(label)
        })
        .collect::<Vec<_>>();
    let width = ui.available_width().max(1.0);

    Plot::new(id)
        .width(width)
        .height(height)
        .show_x(true)
        .show_y(true)
        .include_y(0.0)
        .include_y(100.0)
        .x_axis_label(t!("wifi.channel"))
        .y_axis_label(t!("wifi.occupancy"))
        .show(ui, |plot_ui| {
            plot_ui.bar_chart(BarChart::new("channels", bars).color(color));
        });
}

/// Render one bar per resolver, using the average latency as the value.
///
/// The table next to the chart carries the resolver names; the bar names are
/// still set so hovering a bar reveals the full label.
pub fn resolver_latency_chart(ui: &mut egui::Ui, id: &str, values: &[(String, f64)], height: f32) {
    if values.is_empty() {
        return;
    }
    let color = Palette::from_ui(ui).chart_primary;
    let bars: Vec<Bar> = values
        .iter()
        .enumerate()
        .map(|(index, (label, value))| {
            Bar::new(index as f64, *value)
                .width(0.7)
                .name(format!("{label}: {value:.1} ms"))
        })
        .collect();
    let max = values
        .iter()
        .map(|(_, value)| *value)
        .fold(1.0_f64, f64::max);
    Plot::new(id)
        .height(height)
        .show_x(false)
        .show_y(true)
        .include_y(0.0)
        .include_y(max)
        .y_axis_label(t!("common.rtt_ms"))
        .show(ui, |plot_ui| {
            plot_ui.bar_chart(BarChart::new("resolvers", bars).color(color));
        });
}

#[cfg(test)]
mod tests {
    use super::histogram_bins;

    #[test]
    fn histogram_assigns_every_value_to_a_bucket() {
        let bins = histogram_bins(&[1.0, 1.0, 2.0, 2.0, 3.0], 2);
        assert_eq!(bins.len(), 2);
        assert_eq!(bins.iter().map(|bin| bin.count).sum::<u64>(), 5);
        // Values on an internal bucket boundary belong to the upper bucket.
        assert_eq!(bins[0].count, 2);
        assert_eq!(bins[1].count, 3);
        assert!((bins[0].lower_ms - 1.0).abs() < f64::EPSILON);
        assert!((bins[1].upper_ms - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn histogram_handles_identical_and_empty_values() {
        let bins = histogram_bins(&[4.0, 4.0], 5);
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0].count, 2);
        assert!(histogram_bins(&[], 5).is_empty());
    }
}
