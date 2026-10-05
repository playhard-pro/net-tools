//! Port scan tab: TCP connect / SYN / UDP with banner grabbing.

use eframe::egui;
use net_tools_core::config::PortScanSettings;
use net_tools_core::control::TaskController;
use net_tools_core::model::{PortResult, PortState, ProbeEvent, ScanProgress};
use rust_i18n::t;

use crate::ui::common::{error_banner, info_line, state_badge};
use crate::ui::result_table::table;
use crate::ui::settings;

pub struct PortScanTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub results: Vec<PortResult>,
    pub progress: Option<ScanProgress>,
    pub info: Vec<String>,
    pub error: Option<(String, Option<String>)>,
}

impl Default for PortScanTab {
    fn default() -> Self {
        Self::new()
    }
}

impl PortScanTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            results: Vec::new(),
            progress: None,
            info: Vec::new(),
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.results.clear();
        self.progress = None;
        self.info.clear();
        self.error = None;
    }

    pub fn start(&mut self, s: &PortScanSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.reset();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| {
            net_tools_core::net::portscan::run_scan(handle, settings)
        });
    }

    pub fn drain(&mut self) {
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::Port(p) => self.results.push(p),
                ProbeEvent::ScanProgress(p) => self.progress = Some(p),
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

    pub fn ui(&mut self, ui: &mut egui::Ui, s: &mut PortScanSettings, rt: &tokio::runtime::Handle) {
        self.drain();
        if self.ctrl.is_active() {
            // Keep repainting while a task runs so results and the auto-sized
            // table columns stay up to date.
            ui.ctx().request_repaint();
        }

        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("portscan_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.targets"));
                        ui.add(egui::TextEdit::singleline(&mut s.targets).desired_width(240.0));
                        ui.end_row();

                        ui.label(t!("common.preset"));
                        settings::port_preset_selector(ui, &mut s.preset);
                        ui.end_row();

                        ui.label(t!("common.ports"));
                        ui.add(egui::TextEdit::singleline(&mut s.ports).desired_width(240.0));
                        ui.end_row();

                        ui.label(t!("common.mode"));
                        settings::scan_mode_selector(ui, &mut s.mode);
                        ui.end_row();

                        ui.label(t!("common.ip_version"));
                        settings::ip_version_selector(ui, &mut s.ip_version);
                        ui.end_row();

                        ui.label(t!("common.concurrency"));
                        ui.add(egui::DragValue::new(&mut s.concurrency).range(1..=4096));
                        ui.end_row();

                        ui.label(t!("common.timeout_ms"));
                        ui.add(
                            egui::DragValue::new(&mut s.timeout_ms)
                                .range(10..=120_000)
                                .suffix(" ms"),
                        );
                        ui.end_row();

                        ui.label(t!("common.grab_banner"));
                        ui.checkbox(&mut s.grab_banner, "");
                        ui.end_row();

                        ui.label(t!("common.reverse_dns"));
                        ui.checkbox(&mut s.reverse_dns, "");
                        ui.end_row();
                    });
            });

        ui.horizontal(|ui| {
            self.control_row(ui, s, rt);
            state_badge(ui, self.ctrl.state);
            if let Some(p) = &self.progress {
                ui.label(format!("{} / {} ({})", p.scanned, p.total, p.open));
            }
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

        let headers = [
            t!("common.host"),
            t!("common.port"),
            t!("common.protocol"),
            t!("common.state"),
            t!("common.service"),
            t!("common.banner"),
        ];
        table(ui, &headers, self.results.len(), |i, row| {
            let r = &self.results[i];
            row.col(|ui| {
                ui.label(&r.host);
            });
            row.col(|ui| {
                ui.label(r.port.to_string());
            });
            row.col(|ui| {
                ui.label(r.protocol.label());
            });
            row.col(|ui| {
                let color = match r.state {
                    PortState::Open => egui::Color32::from_rgb(0, 200, 0),
                    PortState::Closed => egui::Color32::GRAY,
                    PortState::Filtered => egui::Color32::from_rgb(230, 160, 0),
                    PortState::OpenOrFiltered => egui::Color32::from_rgb(230, 160, 0),
                };
                ui.colored_label(color, r.state.label());
            });
            row.col(|ui| {
                ui.label(r.service.clone().unwrap_or_else(|| "-".into()));
            });
            row.col(|ui| {
                let banner = r
                    .banner
                    .clone()
                    .unwrap_or_else(|| "-".into())
                    .replace(['\r', '\n'], " ");
                ui.label(banner);
            });
        });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match crate::ui::common::result_toolbar(ui) {
            crate::ui::common::ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            crate::ui::common::ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("port-scan", "csv", &self.to_csv())
            }
            crate::ui::common::ToolbarAction::ExportJson => {
                crate::ui::export::save_file("port-scan", "json", &self.to_json())
            }
            crate::ui::common::ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("port-scan", "html", &self.to_html())
            }
            crate::ui::common::ToolbarAction::Clear => self.reset(),
            crate::ui::common::ToolbarAction::None => {}
        }
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        s: &PortScanSettings,
        rt: &tokio::runtime::Handle,
    ) {
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
        let mut out = String::from("host,port,protocol,state,service,banner\n");
        for r in &self.results {
            out.push_str(&format!(
                "{},{},{},{},{},{}\n",
                r.host,
                r.port,
                r.protocol.label(),
                r.state.label(),
                r.service.clone().unwrap_or_else(|| "-".into()),
                r.banner
                    .clone()
                    .unwrap_or_default()
                    .replace(['\r', '\n'], " "),
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
