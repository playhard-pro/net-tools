//! MTR tab: hop-by-hop routing over ICMP / UDP.

use eframe::egui;
use net_tools_core::config::{InputHistory, MtrSettings};
use net_tools_core::control::TaskController;
use net_tools_core::model::{HopStats, ProbeEvent, ProbeMode};
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use crate::ui::common::{error_banner, info_line, state_badge};
use crate::ui::history_input;
use crate::ui::result_table::table;
use crate::ui::settings;

/// History bucket for the target input.
const TARGET_HISTORY_KEY: &str = "mtr.target";
/// History bucket for the TCP port input.
const TCP_PORT_HISTORY_KEY: &str = "mtr.tcp_port";

pub struct MtrTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub hops: Vec<HopStats>,
    pub info: Vec<String>,
    pub error: Option<(String, Option<String>)>,
    /// Settings waiting for the user to confirm the explanation before UAC.
    pending_elevated_start: Option<MtrSettings>,
}

impl Default for MtrTab {
    fn default() -> Self {
        Self::new()
    }
}

impl MtrTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            hops: Vec::new(),
            info: Vec::new(),
            error: None,
            pending_elevated_start: None,
        }
    }

    pub fn reset(&mut self) {
        self.hops.clear();
        self.info.clear();
        self.error = None;
    }

    pub fn start(&mut self, s: &MtrSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.restart(s, rt);
    }

    /// Stop the current task (if any) and start a fresh one. Used by the target
    /// input to restart on Enter without waiting for a manual stop.
    pub fn restart(&mut self, s: &MtrSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            net_tools_core::net::mtr::run_mtr(&handle, &settings).await;
        });
    }

    pub fn drain(&mut self) {
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::Hop(hop) => {
                    // A reached hop ends the path: drop anything the first,
                    // fully concurrent round may have discovered beyond it.
                    if hop.reached {
                        self.hops.retain(|h| h.hop <= hop.hop);
                    }
                    if let Some(existing) = self.hops.iter_mut().find(|h| h.hop == hop.hop) {
                        *existing = hop;
                    } else {
                        self.hops.push(hop);
                        self.hops.sort_by_key(|h| h.hop);
                    }
                }
                ProbeEvent::Info(msg) => {
                    self.info.push(msg);
                    if self.info.len() > 50 {
                        self.info.remove(0);
                    }
                }
                ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut MtrSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        _privilege: &PrivilegeStatus,
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
            egui::Grid::new("mtr_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("common.mode"));
                    settings::probe_mode_selector(ui, &mut s.mode);
                    ui.end_row();

                    ui.label(t!("common.max_hops"));
                    ui.add(egui::DragValue::new(&mut s.max_hops).range(1..=64));
                    ui.end_row();

                    if s.mode == net_tools_core::model::ProbeMode::Udp {
                        ui.label(t!("common.udp_port"));
                        ui.add(egui::DragValue::new(&mut s.udp_port).range(1..=65_535));
                        ui.end_row();
                    }
                    if s.mode == ProbeMode::Tcp {
                        ui.label(t!("common.port"));
                        settings::tcp_port_input(
                            ui,
                            TCP_PORT_HISTORY_KEY,
                            &mut s.tcp_port,
                            history,
                        );
                        ui.end_row();
                    }
                });
            let submit = settings::common_probe(ui, &mut s.common, history, TARGET_HISTORY_KEY);

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                self.control_row(ui, s, history, rt);
                state_badge(ui, self.ctrl.state);
            });

            if let Some((msg, hint)) = &self.error {
                error_banner(ui, msg, hint.as_deref());
            }
            for line in self.info.iter().rev().take(5) {
                info_line(ui, line);
            }
            submit
        });

        if submit == Some(true) {
            self.request_start(s, history, rt);
        }
        self.elevation_dialog(ui.ctx(), rt);

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);

            let headers = [
                t!("mtr.hop"),
                t!("mtr.addr"),
                t!("mtr.reverse"),
                t!("mtr.loss"),
                t!("mtr.count"),
                t!("mtr.last_ms"),
                t!("mtr.avg_ms"),
                t!("mtr.best_ms"),
                t!("mtr.worst_ms"),
                t!("mtr.stdev_ms"),
            ];
            table(ui, &headers, self.hops.len(), |i, row| {
                let h = &self.hops[i];
                row.col(|ui| {
                    ui.label(h.hop.to_string());
                });
                row.col(|ui| {
                    ui.label(h.addr_text());
                });
                row.col(|ui| {
                    ui.label(h.reverse_text());
                });
                row.col(|ui| {
                    ui.label(format!("{:.1}%", h.loss_ratio() * 100.0));
                });
                row.col(|ui| {
                    ui.label(format!("{}/{}/{}", h.sent, h.success_count(), h.lost));
                });
                row.col(|ui| {
                    ui.label(h.last_ms.map_or("-".into(), |v| format!("{:.2}", v)));
                });
                row.col(|ui| {
                    ui.label(h.avg_ms.map_or("-".into(), |v| format!("{:.2}", v)));
                });
                row.col(|ui| {
                    ui.label(h.best_ms.map_or("-".into(), |v| format!("{:.2}", v)));
                });
                row.col(|ui| {
                    ui.label(h.worst_ms.map_or("-".into(), |v| format!("{:.2}", v)));
                });
                row.col(|ui| {
                    ui.label(h.stdev_ms.map_or("-".into(), |v| format!("{:.2}", v)));
                });
            });
        });

        expanded
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match crate::ui::common::result_toolbar(ui) {
            crate::ui::common::ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            crate::ui::common::ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("mtr", "csv", &self.to_csv())
            }
            crate::ui::common::ToolbarAction::ExportJson => {
                crate::ui::export::save_file("mtr", "json", &self.to_json())
            }
            crate::ui::common::ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("mtr", "html", &self.to_html())
            }
            crate::ui::common::ToolbarAction::Clear => self.reset(),
            crate::ui::common::ToolbarAction::None => {}
        }
    }

    /// Whether starting this mode should explain the upcoming UAC prompt first.
    fn needs_elevation_confirmation(s: &MtrSettings) -> bool {
        cfg!(windows)
            && !net_tools_core::elevation::in_helper_process()
            && !net_tools_core::elevation::is_elevated()
            && matches!(s.mode, ProbeMode::Udp | ProbeMode::Tcp)
    }

    /// Start immediately, or show the explanation dialog before the core probe
    /// requests UAC.
    fn request_start(
        &mut self,
        s: &MtrSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        self.record_inputs(history, s);
        if Self::needs_elevation_confirmation(s) {
            self.pending_elevated_start = Some(s.clone());
        } else {
            self.start(s, rt);
        }
    }

    /// Explain why administrator rights are needed before the core probe opens
    /// the UAC prompt.
    fn elevation_dialog(&mut self, ctx: &egui::Context, rt: &tokio::runtime::Handle) {
        let Some(settings) = self.pending_elevated_start.clone() else {
            return;
        };
        let mut proceed = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::new("mtr_elevation_confirm")).show(ctx, |ui| {
            ui.set_width(460.0);
            ui.heading(t!("common.elevation_title"));
            ui.add_space(4.0);
            ui.label(t!("mtr.elevation_reason"));
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
            self.pending_elevated_start = None;
            self.start(&settings, rt);
        } else if cancel || modal.should_close() {
            self.pending_elevated_start = None;
        }
    }

    /// Remember the target and, in TCP mode, the destination port.
    fn record_inputs(&self, history: &mut InputHistory, s: &MtrSettings) {
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
        s: &MtrSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            net_tools_core::control::TaskState::Idle
            | net_tools_core::control::TaskState::Finished => {
                if ui.button(t!("common.start")).clicked() {
                    self.request_start(s, history, rt);
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
        let mut out =
            String::from("hop,addr,reverse,loss,sent,success,lost,last,avg,best,worst,stdev\n");
        for h in &self.hops {
            out.push_str(&format!(
                "{},{},{},{:.1}%,{},{},{},{},{},{},{},{}\n",
                h.hop,
                crate::ui::export::csv_field(&h.addr_text()),
                crate::ui::export::csv_field(&h.reverse_text()),
                h.loss_ratio() * 100.0,
                h.sent,
                h.success_count(),
                h.lost,
                h.last_ms.map_or("-".into(), |v| format!("{:.2}", v)),
                h.avg_ms.map_or("-".into(), |v| format!("{:.2}", v)),
                h.best_ms.map_or("-".into(), |v| format!("{:.2}", v)),
                h.worst_ms.map_or("-".into(), |v| format!("{:.2}", v)),
                h.stdev_ms.map_or("-".into(), |v| format!("{:.2}", v)),
            ));
        }
        out
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.hops).unwrap_or_default()
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}
