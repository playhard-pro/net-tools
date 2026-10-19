//! Ping tab: continuous ICMP / UDP probing.

use eframe::egui;
use net_tools_core::config::{InputHistory, PingSettings};
use net_tools_core::control::TaskController;
use net_tools_core::model::{ProbeEvent, ProbeMode, ProbeSample};
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use crate::latency_stats::LatencyStats;
use crate::ui::common::{error_banner, info_line, privilege_note, state_badge};
use crate::ui::history_input;
use crate::ui::result_table::table_fixed_rows;
use crate::ui::settings;

/// Upper bound on the records kept for the table, chart and exports.
const MAX_SAMPLES: usize = 1000;
/// Number of data rows visible before the table starts scrolling.
const VISIBLE_ROWS: usize = 10;
/// Number of buckets used by the RTT histogram.
const HISTOGRAM_BINS: usize = 20;
/// History bucket for the target input.
const TARGET_HISTORY_KEY: &str = "ping.target";

pub struct PingTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub samples: Vec<ProbeSample>,
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    pub stats: LatencyStats,
    pub jitter_ms: f64,
    pub last_ms: Option<f64>,
    pub chart: Vec<[f64; 2]>,
    pub histogram: Vec<crate::ui::chart::HistogramBin>,
    pub info: Vec<String>,
    pub error: Option<(String, Option<String>)>,
}

impl Default for PingTab {
    fn default() -> Self {
        Self::new()
    }
}

impl PingTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            samples: Vec::new(),
            sent: 0,
            received: 0,
            lost: 0,
            stats: LatencyStats::default(),
            jitter_ms: 0.0,
            last_ms: None,
            chart: Vec::new(),
            histogram: Vec::new(),
            info: Vec::new(),
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.samples.clear();
        self.sent = 0;
        self.received = 0;
        self.lost = 0;
        self.stats = LatencyStats::default();
        self.jitter_ms = 0.0;
        self.last_ms = None;
        self.chart.clear();
        self.histogram.clear();
        self.info.clear();
        self.error = None;
    }

    pub fn start(&mut self, s: &PingSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.restart(s, rt);
    }

    /// Stop the current task (if any) and start a fresh one. Used by the target
    /// input to restart on Enter without waiting for a manual stop.
    pub fn restart(&mut self, s: &PingSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            match settings.mode {
                net_tools_core::model::ProbeMode::Icmp => {
                    net_tools_core::net::icmp::run_ping_icmp(&handle, &settings).await
                }
                net_tools_core::model::ProbeMode::Udp => {
                    net_tools_core::net::udp::run_ping_udp(&handle, &settings).await
                }
            }
        });
    }

    pub fn drain(&mut self) {
        let mut latency_added = false;
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::Latency(sample) => {
                    self.sent += 1;
                    self.received += 1;
                    if let Some(last) = self.last_ms {
                        self.jitter_ms = (self.jitter_ms + (sample.rtt_ms - last).abs()) / 2.0;
                    }
                    self.last_ms = Some(sample.rtt_ms);
                    latency_added = true;
                    self.chart.push([sample.seq as f64, sample.rtt_ms]);
                    if self.chart.len() > MAX_SAMPLES {
                        self.chart.remove(0);
                    }
                    // Newest first: insert at the front and drop the oldest
                    // records once the cap is reached.
                    self.samples.insert(0, sample);
                    self.samples.truncate(MAX_SAMPLES);
                }
                ProbeEvent::Timeout { seq } => {
                    self.sent += 1;
                    self.lost += 1;
                    self.chart.push([seq as f64, 0.0]);
                    if self.chart.len() > MAX_SAMPLES {
                        self.chart.remove(0);
                    }
                }
                ProbeEvent::Info(msg) => {
                    self.info.push(msg);
                    if self.info.len() > 50 {
                        self.info.remove(0);
                    }
                }
                ProbeEvent::Error { message, hint } => {
                    self.error = Some((message, hint));
                }
                _ => {}
            }
        }

        if latency_added {
            self.recompute_stats();
        }
    }

    /// Recompute derived statistics after the retained sample window changes.
    fn recompute_stats(&mut self) {
        self.stats = LatencyStats::from_values(self.samples.iter().map(|sample| sample.rtt_ms));
        let rtts: Vec<f64> = self.samples.iter().map(|sample| sample.rtt_ms).collect();
        self.histogram = crate::ui::chart::histogram_bins(&rtts, HISTOGRAM_BINS);
    }

    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            self.lost as f64 / self.sent as f64 * 100.0
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut PingSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        privilege: &PrivilegeStatus,
        settings_expanded: bool,
    ) -> bool {
        self.drain();
        if self.ctrl.is_active() {
            // Keep repainting while a task runs so results and the auto-sized
            // table columns stay up to date.
            ui.ctx().request_repaint();
        }

        let (submit, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            egui::Grid::new("ping_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("common.mode"));
                    settings::probe_mode_selector(ui, &mut s.mode);
                    ui.end_row();
                });
            if s.mode == net_tools_core::model::ProbeMode::Udp {
                egui::Grid::new("ping_udp")
                    .num_columns(2)
                    .spacing([12.0, 10.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.udp_port"));
                        ui.add(egui::DragValue::new(&mut s.udp_port).range(1..=65_535));
                        ui.end_row();
                    });
            }
            let submit = settings::common_probe(ui, &mut s.common, history, TARGET_HISTORY_KEY);

            // ICMP ping needs an ICMP socket. On Linux that is normally
            // available unprivileged, so this only shows on restricted hosts.
            if s.mode == ProbeMode::Icmp {
                privilege_note(ui, privilege.icmp, privilege, &t!("privilege.needs_icmp"));
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                self.control_row(ui, s, history, rt);
                state_badge(ui, self.ctrl.state);
            });
            ui.label(format!(
                "{} / {} ({}%)",
                self.received,
                self.sent,
                self.loss_pct() as u32
            ));

            if let Some((msg, hint)) = &self.error {
                error_banner(ui, msg, hint.as_deref());
            }
            for line in self.info.iter().rev().take(5) {
                info_line(ui, line);
            }
            submit
        });

        if submit == Some(true) {
            history_input::record_fields(history, &[(TARGET_HISTORY_KEY, &s.common.target)]);
            self.restart(s, rt);
        }

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);

            // Statistics.
            let format_ms = |value: Option<f64>| {
                value.map_or_else(|| "-".to_string(), |ms| format!("{ms:.1} ms"))
            };
            ui.horizontal_wrapped(|ui| {
                ui.label(t!("ping.stats.min", v = format_ms(self.stats.min_ms)));
                ui.label(t!("ping.stats.avg", v = format_ms(self.stats.avg_ms)));
                ui.label(t!("ping.stats.max", v = format_ms(self.stats.max_ms)));
                ui.label(t!("ping.stats.stdev", v = format_ms(self.stats.stdev_ms)));
                ui.label(t!(
                    "ping.stats.jitter",
                    v = format!("{:.1} ms", self.jitter_ms)
                ));
                ui.label(t!("ping.stats.p50", v = format_ms(self.stats.p50_ms)));
                ui.label(t!("ping.stats.p95", v = format_ms(self.stats.p95_ms)));
                ui.label(t!("ping.stats.p99", v = format_ms(self.stats.p99_ms)));
            });

            // Table: newest record first, kept to a fixed number of visible rows.
            let headers = [
                t!("common.time"),
                t!("common.rtt_ms"),
                t!("common.ttl"),
                t!("common.from"),
                t!("common.size"),
            ];
            table_fixed_rows(ui, &headers, self.samples.len(), VISIBLE_ROWS, |i, row| {
                let sample = &self.samples[i];
                row.col(|ui| {
                    ui.label(&sample.time);
                });
                row.col(|ui| {
                    ui.label(format!("{:.2}", sample.rtt_ms));
                });
                row.col(|ui| {
                    ui.label(sample.ttl.map_or("-".into(), |v| v.to_string()));
                });
                row.col(|ui| {
                    ui.label(&sample.from);
                });
                row.col(|ui| {
                    ui.label(format!("{} B", sample.size));
                });
            });

            // Chart sits below the table, with a little breathing room.
            if !self.chart.is_empty() {
                ui.add_space(12.0);
                crate::ui::chart::latency_chart(ui, &self.chart, 180.0);
            }

            if !self.histogram.is_empty() {
                ui.add_space(12.0);
                ui.label(egui::RichText::new(t!("ping.histogram.title")).strong());
                crate::ui::chart::histogram_chart(
                    ui,
                    "ping_latency_histogram",
                    &self.histogram,
                    160.0,
                    &t!("ping.histogram.rtt_ms"),
                    &t!("ping.histogram.samples"),
                );
            }
        });

        expanded
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match crate::ui::common::result_toolbar(ui) {
            crate::ui::common::ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            crate::ui::common::ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("ping", "csv", &self.to_csv())
            }
            crate::ui::common::ToolbarAction::ExportJson => {
                crate::ui::export::save_file("ping", "json", &self.to_json())
            }
            crate::ui::common::ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("ping", "html", &self.to_html())
            }
            crate::ui::common::ToolbarAction::Clear => self.reset(),
            crate::ui::common::ToolbarAction::None => {}
        }
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        s: &PingSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            net_tools_core::control::TaskState::Idle
            | net_tools_core::control::TaskState::Finished => {
                if ui.button(t!("common.start")).clicked() {
                    history_input::record_fields(
                        history,
                        &[(TARGET_HISTORY_KEY, &s.common.target)],
                    );
                    self.start(s, rt);
                }
            }
            net_tools_core::control::TaskState::Running => {
                if ui.button(t!("common.pause")).clicked() {
                    self.ctrl.pause();
                }
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            }
            net_tools_core::control::TaskState::Paused => {
                if ui.button(t!("common.resume")).clicked() {
                    self.ctrl.resume();
                }
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            }
            net_tools_core::control::TaskState::Stopping => {
                ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
            }
        }
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from("time,seq,rtt_ms,ttl,from,size\n");
        for s in &self.samples {
            out.push_str(&format!(
                "{},{},{:.2},{},{},{}\n",
                crate::ui::export::csv_field(&s.time),
                s.seq,
                s.rtt_ms,
                s.ttl.map_or("-".into(), |v| v.to_string()),
                s.from,
                s.size
            ));
        }
        out
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.samples).unwrap_or_default()
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}
