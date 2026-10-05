//! Ping tab: continuous ICMP / UDP probing.

use eframe::egui;
use net_tools_core::config::PingSettings;
use net_tools_core::control::TaskController;
use net_tools_core::model::{ProbeEvent, ProbeSample};
use rust_i18n::t;

use crate::ui::common::{error_banner, info_line, state_badge};
use crate::ui::result_table::table;
use crate::ui::settings;

const MAX_SAMPLES: usize = 500;

pub struct PingTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub samples: Vec<ProbeSample>,
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub total_ms: f64,
    pub jitter_ms: f64,
    pub last_ms: Option<f64>,
    pub chart: Vec<[f64; 2]>,
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
            min_ms: None,
            max_ms: None,
            total_ms: 0.0,
            jitter_ms: 0.0,
            last_ms: None,
            chart: Vec::new(),
            info: Vec::new(),
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.samples.clear();
        self.sent = 0;
        self.received = 0;
        self.lost = 0;
        self.min_ms = None;
        self.max_ms = None;
        self.total_ms = 0.0;
        self.jitter_ms = 0.0;
        self.last_ms = None;
        self.chart.clear();
        self.info.clear();
        self.error = None;
    }

    pub fn start(&mut self, s: &PingSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
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
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::Latency(sample) => {
                    self.sent += 1;
                    self.received += 1;
                    if let Some(last) = self.last_ms {
                        self.jitter_ms = (self.jitter_ms + (sample.rtt_ms - last).abs()) / 2.0;
                    }
                    self.last_ms = Some(sample.rtt_ms);
                    self.total_ms += sample.rtt_ms;
                    self.min_ms = Some(self.min_ms.map_or(sample.rtt_ms, |m| m.min(sample.rtt_ms)));
                    self.max_ms = Some(self.max_ms.map_or(sample.rtt_ms, |m| m.max(sample.rtt_ms)));
                    self.chart.push([sample.seq as f64, sample.rtt_ms]);
                    if self.chart.len() > MAX_SAMPLES {
                        self.chart.remove(0);
                    }
                    self.samples.push(sample);
                    if self.samples.len() > MAX_SAMPLES {
                        self.samples.remove(0);
                    }
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
    }

    pub fn avg_ms(&self) -> Option<f64> {
        if self.received == 0 {
            None
        } else {
            Some(self.total_ms / self.received as f64)
        }
    }

    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            self.lost as f64 / self.sent as f64 * 100.0
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, s: &mut PingSettings, rt: &tokio::runtime::Handle) {
        self.drain();
        if self.ctrl.is_active() {
            // Keep repainting while a task runs so results and the auto-sized
            // table columns stay up to date.
            ui.ctx().request_repaint();
        }

        // Settings.
        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("ping_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.mode"));
                        settings::probe_mode_selector(ui, &mut s.mode);
                        ui.end_row();
                    });
                if s.mode == net_tools_core::model::ProbeMode::Udp {
                    egui::Grid::new("ping_udp")
                        .num_columns(2)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            ui.label(t!("common.udp_port"));
                            ui.add(egui::DragValue::new(&mut s.udp_port).range(1..=65_535));
                            ui.end_row();
                        });
                }
                settings::common_probe(ui, &mut s.common);
            });

        // Control buttons and state.
        ui.horizontal(|ui| {
            self.control_row(ui, s, rt);
            state_badge(ui, self.ctrl.state);
            ui.label(format!(
                "{} / {} ({}%)",
                self.received,
                self.sent,
                self.loss_pct() as u32
            ));
        });

        // Result toolbar: placed directly under the controls, above every
        // result-related widget, so it can never be pushed down.
        self.toolbar(ui);

        if let Some((msg, hint)) = &self.error {
            error_banner(ui, msg, hint.as_deref());
        }
        for line in self.info.iter().rev().take(5) {
            info_line(ui, line);
        }

        ui.separator();

        // Statistics.
        ui.horizontal_wrapped(|ui| {
            ui.label(t!(
                "ping.stats.min",
                v = self.min_ms.map_or("-".into(), |v| format!("{:.1} ms", v))
            ));
            ui.label(t!(
                "ping.stats.avg",
                v = self.avg_ms().map_or("-".into(), |v| format!("{:.1} ms", v))
            ));
            ui.label(t!(
                "ping.stats.max",
                v = self.max_ms.map_or("-".into(), |v| format!("{:.1} ms", v))
            ));
            ui.label(t!(
                "ping.stats.jitter",
                v = format!("{:.1} ms", self.jitter_ms)
            ));
        });

        // Chart.
        if !self.chart.is_empty() {
            crate::ui::chart::latency_chart(ui, &self.chart, 180.0);
        }

        // Table.
        let headers = [
            t!("common.seq"),
            t!("common.rtt_ms"),
            t!("common.ttl"),
            t!("common.from"),
            t!("common.size"),
        ];
        table(ui, &headers, self.samples.len(), |i, row| {
            let sample = &self.samples[i];
            row.col(|ui| {
                ui.label(sample.seq.to_string());
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

    fn control_row(&mut self, ui: &mut egui::Ui, s: &PingSettings, rt: &tokio::runtime::Handle) {
        match self.ctrl.state {
            net_tools_core::control::TaskState::Idle
            | net_tools_core::control::TaskState::Finished => {
                if ui.button(t!("common.start")).clicked() {
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
        let mut out = String::from("seq,rtt_ms,ttl,from,size\n");
        for s in &self.samples {
            out.push_str(&format!(
                "{},{:.2},{},{},{}\n",
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
