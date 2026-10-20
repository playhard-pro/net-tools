//! Ping tab: continuous ICMP / UDP probing.

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{InputHistory, PingSettings};
use net_tools_core::control::TaskController;
use net_tools_core::model::{PmtuResult, PmtuStep, ProbeEvent, ProbeMode, ProbeSample};
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use crate::latency_stats::LatencyStats;
use crate::ui::common::{error_banner, info_line, privilege_note, state_badge};
use crate::ui::history_input;
use crate::ui::result_table::table_fixed_rows_with_columns;
use crate::ui::settings;

/// Upper bound on the records kept for the table, chart and exports.
const MAX_SAMPLES: usize = 1000;
/// Number of data rows visible before the table starts scrolling.
const VISIBLE_ROWS: usize = 10;
/// Number of buckets used by the RTT histogram.
const HISTOGRAM_BINS: usize = 20;
/// History bucket for the target input.
const TARGET_HISTORY_KEY: &str = "ping.target";
/// History bucket for the TCP port input.
const TCP_PORT_HISTORY_KEY: &str = "ping.tcp_port";

pub struct PingTab {
    pub ctrl: TaskController<ProbeEvent>,
    /// Independent task controller for Path MTU discovery, so it does not
    /// interfere with the continuous ping.
    pub mtu_ctrl: TaskController<ProbeEvent>,
    pub mtu_steps: Vec<PmtuStep>,
    pub mtu_result: Option<PmtuResult>,
    pub mtu_error: Option<(String, Option<String>)>,
    /// Path MTU settings waiting for the user to confirm the UAC explanation.
    pending_elevated_pmtu: Option<PingSettings>,
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
            mtu_ctrl: TaskController::new(),
            mtu_steps: Vec::new(),
            mtu_result: None,
            mtu_error: None,
            pending_elevated_pmtu: None,
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
                net_tools_core::model::ProbeMode::Tcp => {
                    net_tools_core::net::tcp::run_ping_tcp(&handle, &settings).await
                }
            }
        });
    }

    /// Start Path MTU discovery independently from the continuous ping.
    pub fn start_mtu(&mut self, s: &PingSettings, rt: &tokio::runtime::Handle) {
        if self.mtu_ctrl.is_active() {
            return;
        }
        self.reset_mtu();
        let settings = s.clone();
        self.mtu_ctrl.start(rt, move |handle| async move {
            net_tools_core::net::pmtu::run_pmtu(&handle, &settings).await;
        });
    }

    /// Start Path MTU immediately, or explain the upcoming UAC prompt first.
    fn request_start_mtu(
        &mut self,
        s: &PingSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        self.record_inputs(history, s);
        if cfg!(windows)
            && !net_tools_core::elevation::in_helper_process()
            && !net_tools_core::elevation::is_elevated()
        {
            self.pending_elevated_pmtu = Some(s.clone());
        } else {
            self.start_mtu(s, rt);
        }
    }

    /// Explain why Path MTU needs administrator rights before the core probe
    /// opens the UAC prompt.
    fn pmtu_elevation_dialog(&mut self, ctx: &egui::Context, rt: &tokio::runtime::Handle) {
        let Some(settings) = self.pending_elevated_pmtu.clone() else {
            return;
        };
        let mut proceed = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::new("pmtu_elevation_confirm")).show(ctx, |ui| {
            ui.set_width(460.0);
            ui.heading(t!("common.elevation_title"));
            ui.add_space(4.0);
            ui.label(t!("pmtu.elevation_reason"));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(t!("common.continue")).clicked() {
                    proceed = true;
                }
                if ui.button(t!("common.cancel")).clicked() {
                    cancel = true;
                }
            });
        });
        if proceed {
            self.pending_elevated_pmtu = None;
            self.start_mtu(&settings, rt);
        } else if cancel || modal.should_close() {
            self.pending_elevated_pmtu = None;
        }
    }

    /// Drop the previous Path MTU result before a new search.
    pub fn reset_mtu(&mut self) {
        self.mtu_steps.clear();
        self.mtu_result = None;
        self.mtu_error = None;
    }

    fn drain_mtu(&mut self) {
        for ev in self.mtu_ctrl.drain() {
            match ev {
                ProbeEvent::PmtuStep(step) => self.mtu_steps.push(step),
                ProbeEvent::Pmtu(result) => self.mtu_result = Some(result),
                ProbeEvent::Info(msg) => {
                    self.info.push(msg);
                    if self.info.len() > 50 {
                        self.info.remove(0);
                    }
                }
                ProbeEvent::Error { message, hint } => self.mtu_error = Some((message, hint)),
                _ => {}
            }
        }
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
        self.drain_mtu();
        if self.ctrl.is_active() || self.mtu_ctrl.is_active() {
            // Keep repainting while a task runs so results and the auto-sized
            // table columns stay up to date.
            ui.ctx().request_repaint();
        }

        let mut start_mtu = false;
        let mut stop_mtu = false;
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
            if s.mode == net_tools_core::model::ProbeMode::Tcp {
                egui::Grid::new("ping_tcp")
                    .num_columns(2)
                    .spacing([12.0, 10.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.port"));
                        settings::tcp_port_input(
                            ui,
                            TCP_PORT_HISTORY_KEY,
                            &mut s.tcp_port,
                            history,
                        );
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

            ui.separator();
            ui.heading(t!("pmtu.title"));
            ui.label(t!("pmtu.hint"));
            egui::Grid::new("ping_pmtu_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("pmtu.min_mtu"));
                    ui.add(
                        egui::DragValue::new(&mut s.pmtu.min_mtu)
                            .range(68..=65_535)
                            .suffix(" B"),
                    );
                    ui.end_row();

                    ui.label(t!("pmtu.max_mtu"));
                    ui.add(
                        egui::DragValue::new(&mut s.pmtu.max_mtu)
                            .range(68..=65_535)
                            .suffix(" B"),
                    );
                    ui.end_row();

                    ui.label(t!("pmtu.attempts"));
                    ui.add(egui::DragValue::new(&mut s.pmtu.attempts).range(1..=5));
                    ui.end_row();
                });
            ui.horizontal(|ui| {
                match self.mtu_ctrl.state {
                    net_tools_core::control::TaskState::Idle
                    | net_tools_core::control::TaskState::Finished => {
                        if ui.button(t!("pmtu.discover")).clicked() {
                            start_mtu = true;
                        }
                    }
                    net_tools_core::control::TaskState::Running
                    | net_tools_core::control::TaskState::Paused => {
                        if ui.button(t!("common.stop")).clicked() {
                            stop_mtu = true;
                        }
                    }
                    net_tools_core::control::TaskState::Stopping => {
                        ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
                    }
                }
                state_badge(ui, self.mtu_ctrl.state);
            });
            if let Some((msg, hint)) = &self.mtu_error {
                error_banner(ui, msg, hint.as_deref());
            }
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

        if start_mtu {
            self.request_start_mtu(s, history, rt);
        }
        if stop_mtu {
            self.mtu_ctrl.stop();
        }
        self.pmtu_elevation_dialog(ui.ctx(), rt);
        if submit == Some(true) {
            self.record_inputs(history, s);
            self.restart(s, rt);
        }

        crate::ui::layout::results_panel(ui, |ui| {
            if self.mtu_result.is_some() || !self.mtu_steps.is_empty() || self.mtu_error.is_some() {
                self.mtu_results(ui);
                ui.add_space(12.0);
                ui.separator();
            }
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
            // Measure the timestamp with the same monospace font used by the
            // cells, so the column always fits the full value regardless of the
            // platform font. The source column consumes the remaining width and
            // the numeric columns stay compact.
            let columns = [
                Column::exact(Self::ping_time_width(ui, &self.samples)),
                Column::exact(80.0),
                Column::exact(52.0),
                Column::remainder().at_least(120.0),
                Column::exact(84.0),
            ];
            table_fixed_rows_with_columns(
                ui,
                &headers,
                self.samples.len(),
                VISIBLE_ROWS,
                columns,
                |i, row| {
                    let sample = &self.samples[i];
                    row.col(|ui| {
                        ui.monospace(&sample.time).on_hover_text(&sample.time);
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{:.2}", sample.rtt_ms));
                    });
                    row.col(|ui| {
                        ui.monospace(sample.ttl.map_or("-".into(), |v| v.to_string()));
                    });
                    row.col(|ui| {
                        ui.monospace(&sample.from).on_hover_text(&sample.from);
                    });
                    row.col(|ui| {
                        // TCP connect probes do not carry an ICMP payload.
                        if s.mode == ProbeMode::Tcp {
                            ui.monospace("-");
                        } else {
                            ui.monospace(format!("{} B", sample.size));
                        }
                    });
                },
            );

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

    /// Width needed to show a complete ping timestamp in the monospace font.
    fn ping_time_width(ui: &egui::Ui, samples: &[ProbeSample]) -> f32 {
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let fallback = "0000-00-00 00:00:00.000";
        let text = samples
            .first()
            .map_or(fallback, |sample| sample.time.as_str());
        let width = ui.ctx().fonts_mut(|fonts| {
            fonts
                .layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::WHITE)
                .size()
                .x
        });
        (width + 16.0).max(140.0)
    }

    /// Path MTU result area: summary, search steps and its own export actions.
    fn mtu_results(&mut self, ui: &mut egui::Ui) {
        let result = self.mtu_result.clone();
        ui.heading(t!("pmtu.title"));
        if let Some(result) = &result {
            if let Some(mtu) = result.path_mtu {
                ui.label(
                    egui::RichText::new(t!(
                        "pmtu.summary",
                        mtu = mtu,
                        payload = result.payload_bytes.unwrap_or(0),
                        overhead = result.overhead
                    ))
                    .strong(),
                );
            }
            if let Some(error) = &result.error {
                error_banner(ui, error, None);
            }
            ui.label(t!(
                "pmtu.range",
                min = result.min_mtu,
                max = result.max_mtu,
                ip = result.ip
            ));
        }

        ui.horizontal(|ui| {
            if ui.small_button(t!("common.copy_all")).clicked() {
                ui.ctx().copy_text(self.mtu_to_csv());
            }
            if ui.small_button("CSV").clicked() {
                crate::ui::export::save_file("pmtu", "csv", &self.mtu_to_csv());
            }
            if ui.small_button(t!("common.clear")).clicked() {
                self.reset_mtu();
            }
        });

        if !self.mtu_steps.is_empty() {
            let headers = [
                t!("pmtu.step_mtu"),
                t!("pmtu.step_payload"),
                t!("pmtu.step_outcome"),
                t!("common.from"),
                t!("common.rtt_ms"),
                t!("pmtu.step_detail"),
            ];
            // The detail text can be long. Use fixed, proportional columns and
            // truncation so the header and cells stay aligned instead of the
            // table widening or squeezing the numeric columns.
            let spacing = ui.spacing().item_spacing.x * (headers.len().saturating_sub(1)) as f32;
            let table_width =
                (ui.available_width() - ui.spacing().scroll.allocated_width() - spacing).max(1.0);
            let columns = [
                Column::exact(table_width * 0.10),
                Column::exact(table_width * 0.11),
                Column::exact(table_width * 0.13),
                Column::exact(table_width * 0.22),
                Column::exact(table_width * 0.12),
                Column::exact(table_width * 0.32),
            ];
            table_fixed_rows_with_columns(
                ui,
                &headers,
                self.mtu_steps.len(),
                6,
                columns,
                |i, row| {
                    let step = &self.mtu_steps[i];
                    row.col(|ui| {
                        ui.monospace(step.mtu.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(step.payload_bytes.to_string());
                    });
                    row.col(|ui| {
                        ui.label(step.outcome.label());
                    });
                    row.col(|ui| {
                        let responder = step.responder.as_deref().unwrap_or("-");
                        ui.monospace(responder).on_hover_text(responder);
                    });
                    row.col(|ui| {
                        ui.monospace(step.rtt_ms.map_or("-".into(), |v| format!("{v:.2}")));
                    });
                    row.col(|ui| {
                        let detail = step.detail.as_deref().unwrap_or("-");
                        ui.label(detail).on_hover_text(detail);
                    });
                },
            );
        }
    }

    fn mtu_to_csv(&self) -> String {
        let mut out = String::from("mtu,payload,outcome,responder,rtt_ms,detail\n");
        for step in &self.mtu_steps {
            out.push_str(&format!(
                "{},{},{},{},{},{}\n",
                step.mtu,
                step.payload_bytes,
                step.outcome.label(),
                crate::ui::export::csv_field(step.responder.as_deref().unwrap_or("-")),
                step.rtt_ms.map_or("-".into(), |v| format!("{v:.2}")),
                crate::ui::export::csv_field(step.detail.as_deref().unwrap_or("-")),
            ));
        }
        out
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

    /// Remember the target and, in TCP mode, the destination port.
    fn record_inputs(&self, history: &mut InputHistory, s: &PingSettings) {
        let port = s.tcp_port.to_string();
        let mut fields = vec![(TARGET_HISTORY_KEY, s.common.target.as_str())];
        if s.mode == ProbeMode::Tcp {
            fields.push((TCP_PORT_HISTORY_KEY, port.as_str()));
        }
        history_input::record_fields(history, &fields);
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
                    self.record_inputs(history, s);
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
