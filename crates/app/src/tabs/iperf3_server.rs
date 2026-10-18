//! Built-in iperf3 server tab.
//!
//! The actual server runs in the same hidden worker process used by the client
//! tool, so the GUI can receive its JSON event stream without printing raw
//! protocol output to the terminal.

use std::time::Duration;

use eframe::egui;
use net_tools_core::config::{InputHistory, Iperf3ServerSettings};
use net_tools_core::control::TaskController;
use net_tools_core::model::{Iperf3ServerProgress, Iperf3ServerResult, ProbeEvent};
use rust_i18n::t;

use crate::speedtest_worker;
use crate::tabs::speedtest::metric_card;
use crate::ui::common::{error_banner, info_line, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::table_fixed_rows;

/// History bucket for the bind address.
const BIND_HISTORY_KEY: &str = "iperf3_server.bind";

/// Maximum number of tests kept in the session history.
const HISTORY_LIMIT: usize = 100;

/// Visible history rows before the table scrolls.
const VISIBLE_ROWS: usize = 6;

/// Repaint cadence while the server is listening.
const REPAINT: Duration = Duration::from_millis(250);

/// State of the server tab.
pub struct Iperf3ServerTab {
    ctrl: TaskController<ProbeEvent>,
    results: Vec<Iperf3ServerResult>,
    progress: Option<Iperf3ServerProgress>,
    logs: Vec<String>,
    error: Option<(String, Option<String>)>,
    /// Bindable local addresses, refreshed on demand.
    local_ips: Vec<String>,
}

impl Default for Iperf3ServerTab {
    fn default() -> Self {
        Self::new()
    }
}

impl Iperf3ServerTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            results: Vec::new(),
            progress: None,
            logs: Vec::new(),
            error: None,
            local_ips: net_tools_core::net::iperf3::local_ip_addresses(),
        }
    }

    /// Stop the listener when another top-level tab is selected. Completed
    /// results stay available in the session history.
    pub fn clear_on_hide(&mut self) {
        if self.ctrl.is_active() {
            self.ctrl.stop();
        }
        let _ = self.ctrl.drain();
        self.logs.clear();
        self.progress = None;
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut Iperf3ServerSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        self.drain();
        if self.ctrl.is_active() {
            ui.ctx().request_repaint_after(REPAINT);
        }

        let mut submit = false;
        let mut refresh_ips = false;
        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("iperf3_server_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("server.bind_address"));
                        ui.horizontal(|ui| {
                            let all_interfaces = t!("server.all_interfaces").to_string();
                            let mut presets: Vec<(&str, &str)> =
                                vec![(all_interfaces.as_str(), "")];
                            presets
                                .extend(self.local_ips.iter().map(|ip| (ip.as_str(), ip.as_str())));
                            if history_input::singleline_with_labeled_presets(
                                ui,
                                BIND_HISTORY_KEY,
                                &presets,
                                &mut settings.bind_address,
                                history,
                                300.0,
                            ) {
                                submit = true;
                            }
                            if ui.button(t!("server.refresh_ips")).clicked() {
                                refresh_ips = true;
                            }
                        });
                        ui.end_row();

                        ui.label(t!("server.port"));
                        ui.add(egui::DragValue::new(&mut settings.port).range(1..=65_535));
                        ui.end_row();

                        ui.label(t!("server.one_off"));
                        ui.checkbox(&mut settings.one_off, "");
                        ui.end_row();

                        ui.label(t!("server.max_duration"));
                        ui.add(
                            egui::DragValue::new(&mut settings.max_duration_s)
                                .range(0..=86_400)
                                .suffix(" s"),
                        );
                        ui.end_row();

                        ui.label(t!("server.bitrate_limit"));
                        let mut limit = settings.bitrate_limit_bps as f64 / 1_000_000.0;
                        if ui
                            .add(
                                egui::DragValue::new(&mut limit)
                                    .range(0.0..=1_000_000.0)
                                    .suffix(" Mbps"),
                            )
                            .changed()
                        {
                            settings.bitrate_limit_bps = (limit * 1_000_000.0).round() as u64;
                        }
                        ui.end_row();
                    });
                ui.weak(t!("server.hint"));
            });
        if refresh_ips {
            self.local_ips = net_tools_core::net::iperf3::local_ip_addresses();
        }
        if submit && !self.ctrl.is_active() {
            self.start(settings, history, rt);
        }

        ui.horizontal(|ui| {
            if self.ctrl.is_active() {
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            } else if ui.button(t!("common.start")).clicked() {
                self.start(settings, history, rt);
            }
            state_badge(ui, self.ctrl.state);
            if self.ctrl.is_active() {
                ui.spinner();
                ui.weak(t!(
                    "server.listening_on",
                    addr = format!(
                        "{}:{}",
                        if settings.bind_address.trim().is_empty() {
                            "0.0.0.0"
                        } else {
                            settings.bind_address.trim()
                        },
                        settings.port
                    )
                ));
            }
        });

        if let Some((message, hint)) = &self.error {
            error_banner(ui, message, hint.as_deref());
        }
        for line in self.logs.iter().rev().take(5) {
            info_line(ui, line);
        }

        if let Some(progress) = &self.progress {
            self.live_metrics(ui, progress);
        }

        ui.separator();
        self.toolbar(ui);
        if self.results.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(32.0);
                ui.weak(t!("server.empty"));
            });
            return;
        }
        self.results_table(ui);
    }

    fn start(
        &mut self,
        settings: &Iperf3ServerSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        if self.ctrl.is_active() {
            return;
        }
        self.error = None;
        history_input::record_fields(history, &[(BIND_HISTORY_KEY, &settings.bind_address)]);
        self.logs.clear();
        let settings = settings.clone();
        self.ctrl.start(rt, move |handle| async move {
            speedtest_worker::run_iperf3_server(&handle, &settings).await;
        });
    }

    fn drain(&mut self) {
        for event in self.ctrl.drain() {
            match event {
                ProbeEvent::Iperf3ServerResult(result) => {
                    self.progress = None;
                    self.results.insert(0, result);
                    self.results.truncate(HISTORY_LIMIT);
                }
                ProbeEvent::Iperf3ServerProgress(progress) => {
                    self.progress = Some(progress);
                }
                ProbeEvent::Info(message) => {
                    self.logs.push(message);
                    self.logs.truncate(50);
                }
                ProbeEvent::Error { message, hint } => {
                    self.progress = None;
                    self.error = Some((message, hint));
                }
                ProbeEvent::Finished => self.progress = None,
                _ => {}
            }
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("iperf3-server", "csv", &self.to_csv())
            }
            ToolbarAction::ExportJson => {
                crate::ui::export::save_file("iperf3-server", "json", &self.to_json())
            }
            ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("iperf3-server", "html", &self.to_html())
            }
            ToolbarAction::Clear => {
                self.results.clear();
                self.progress = None;
                self.logs.clear();
                self.error = None;
            }
            ToolbarAction::None => {}
        }
    }

    /// Live metrics of the test currently being served.
    fn live_metrics(&self, ui: &mut egui::Ui, progress: &Iperf3ServerProgress) {
        ui.add_space(4.0);
        ui.columns(4, |columns| {
            metric_card(
                &mut columns[0],
                t!("server.current"),
                &format!("{:.1} Mbps", progress.current_mbps),
            );
            metric_card(&mut columns[1], t!("server.client"), &progress.peer);
            if progress.protocol == "UDP" {
                metric_card(
                    &mut columns[2],
                    t!("speedtest.lost"),
                    &progress.lost_percent.map_or_else(
                        || t!("speedtest.not_available").to_string(),
                        |v| format!("{v:.2} %"),
                    ),
                );
            } else {
                metric_card(
                    &mut columns[2],
                    t!("speedtest.retransmits"),
                    &progress.retransmits.map_or_else(
                        || t!("speedtest.not_available").to_string(),
                        |v| v.to_string(),
                    ),
                );
            }
            metric_card(
                &mut columns[3],
                t!("speedtest.jitter"),
                &progress.jitter_ms.map_or_else(
                    || t!("speedtest.not_available").to_string(),
                    |v| format!("{v:.2} ms"),
                ),
            );
        });
        let ratio = if progress.total_s > 0.0 {
            (progress.elapsed_s / progress.total_s).clamp(0.0, 1.0) as f32
        } else {
            0.0
        };
        ui.add(egui::ProgressBar::new(ratio).text(format!(
            "{} · {} · {:.1}s / {:.1}s",
            progress.protocol, progress.direction, progress.elapsed_s, progress.total_s
        )));
    }

    fn results_table(&self, ui: &mut egui::Ui) {
        let headers = [
            t!("common.time"),
            t!("server.client"),
            t!("speedtest.protocol"),
            t!("speedtest.direction"),
            t!("speedtest.duration_s"),
            t!("server.sent"),
            t!("server.received"),
            t!("speedtest.retransmits"),
            t!("speedtest.jitter"),
            t!("speedtest.lost"),
        ];
        table_fixed_rows(
            ui,
            &headers,
            self.results.len(),
            VISIBLE_ROWS,
            |index, row| {
                let result = &self.results[index];
                row.col(|ui| {
                    ui.label(&result.time);
                });
                row.col(|ui| {
                    ui.label(&result.peer);
                });
                row.col(|ui| {
                    ui.label(&result.protocol);
                });
                row.col(|ui| {
                    ui.label(&result.direction);
                });
                row.col(|ui| {
                    ui.label(format!("{:.1}", result.duration_s));
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .sent_mbps
                            .map_or("-".into(), |value| format!("{value:.1}")),
                    );
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .received_mbps
                            .map_or("-".into(), |value| format!("{value:.1}")),
                    );
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .retransmits
                            .map_or("-".into(), |value| value.to_string()),
                    );
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .jitter_ms
                            .map_or("-".into(), |value| format!("{value:.2}")),
                    );
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .lost_percent
                            .map_or("-".into(), |value| format!("{value:.2}")),
                    );
                });
            },
        );
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "time,client,protocol,direction,duration_s,sent_mbps,received_mbps,retransmits,jitter_ms,lost_percent\n",
        );
        for result in &self.results {
            out.push_str(&format!(
                "{},{},{},{},{:.1},{},{},{},{},{}\n",
                crate::ui::export::csv_field(&result.time),
                crate::ui::export::csv_field(&result.peer),
                crate::ui::export::csv_field(&result.protocol),
                crate::ui::export::csv_field(&result.direction),
                result.duration_s,
                result
                    .sent_mbps
                    .map_or("-".into(), |value| format!("{value:.2}")),
                result
                    .received_mbps
                    .map_or("-".into(), |value| format!("{value:.2}")),
                result
                    .retransmits
                    .map_or("-".into(), |value| value.to_string()),
                result
                    .jitter_ms
                    .map_or("-".into(), |value| format!("{value:.2}")),
                result
                    .lost_percent
                    .map_or("-".into(), |value| format!("{value:.2}")),
            ));
        }
        out
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.results).unwrap_or_default()
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}
