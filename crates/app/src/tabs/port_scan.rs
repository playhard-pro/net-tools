//! Port scan tab: TCP connect / SYN / UDP with banner grabbing.

use eframe::egui;
use net_tools_core::config::{InputHistory, PortScanSettings};
use net_tools_core::control::TaskController;
use net_tools_core::model::{PortResult, PortState, ProbeEvent, ScanMode, ScanProgress};
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use crate::ui::common::{error_banner, info_line, privilege_note, state_badge};
use crate::ui::history_input;
use crate::ui::result_table::table;
use crate::ui::settings;
use crate::ui::theme::Palette;

/// History buckets for the editable inputs.
const TARGETS_HISTORY_KEY: &str = "portscan.targets";
const PORTS_HISTORY_KEY: &str = "portscan.ports";

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
        self.restart(s, rt);
    }

    /// Stop the current task (if any) and start a fresh one. Used by the target
    /// input to restart on Enter without waiting for a manual stop.
    pub fn restart(&mut self, s: &PortScanSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| {
            net_tools_core::net::portscan::run_scan(handle, settings)
        });
    }

    pub fn drain(&mut self) {
        let mut added = false;
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::Port(p) => {
                    self.results.push(p);
                    added = true;
                }
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
        // Workers report completions concurrently, so keep the table in a
        // stable host/port order without changing the scan itself.
        if added {
            sort_results(&mut self.results);
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut PortScanSettings,
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
            let mut submit = false;
            egui::Grid::new("portscan_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("common.targets"));
                    if history_input::singleline(
                        ui,
                        TARGETS_HISTORY_KEY,
                        &mut s.targets,
                        history,
                        160.0,
                    ) {
                        submit = true;
                    }
                    ui.end_row();

                    ui.label(t!("common.preset"));
                    settings::port_preset_selector(ui, &mut s.preset);
                    ui.end_row();

                    ui.label(t!("common.ports"));
                    history_input::singleline(ui, PORTS_HISTORY_KEY, &mut s.ports, history, 160.0);
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

            // SYN scanning needs a raw socket and is Linux-only, so only
            // warn there.
            if s.mode == ScanMode::Syn && cfg!(target_os = "linux") {
                privilege_note(ui, privilege.raw, privilege, &t!("privilege.needs_raw_syn"));
            }

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
            history_input::record_fields(
                history,
                &[
                    (TARGETS_HISTORY_KEY, &s.targets),
                    (PORTS_HISTORY_KEY, &s.ports),
                ],
            );
            self.restart(s, rt);
        }

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);
            self.progress_ui(ui);

            let palette = Palette::from_ui(ui);
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
                        PortState::Open => palette.state_running,
                        PortState::Closed => palette.state_idle,
                        PortState::Filtered | PortState::OpenOrFiltered => palette.state_paused,
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
        });

        expanded
    }

    /// Show overall scan progress, remaining probes and the open-port count.
    fn progress_ui(&self, ui: &mut egui::Ui) {
        let Some(progress) = &self.progress else {
            return;
        };
        let fraction = if progress.total == 0 {
            0.0
        } else {
            progress.scanned as f32 / progress.total as f32
        };
        let remaining = progress.total.saturating_sub(progress.scanned);
        let palette = Palette::from_ui(ui);
        egui::Frame::new()
            .fill(palette.card_bg)
            .corner_radius(4.0)
            .inner_margin(egui::Margin::symmetric(8, 6))
            .show(ui, |ui| {
                ui.add(
                    egui::ProgressBar::new(fraction)
                        .desired_width(ui.available_width())
                        .show_percentage(),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(format!(
                        "{}: {} / {}",
                        t!("portscan.scanned"),
                        progress.scanned,
                        progress.total
                    ));
                    ui.separator();
                    ui.monospace(format!("{}: {}", t!("portscan.remaining"), remaining));
                    ui.separator();
                    ui.monospace(format!("{}: {}", t!("portscan.open"), progress.open));
                });
            });
        ui.add_space(8.0);
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
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            net_tools_core::control::TaskState::Idle
            | net_tools_core::control::TaskState::Finished => {
                if ui.button(t!("common.start")).clicked() {
                    history_input::record_fields(
                        history,
                        &[
                            (TARGETS_HISTORY_KEY, &s.targets),
                            (PORTS_HISTORY_KEY, &s.ports),
                        ],
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

/// Sort scan rows for display. Hosts stay grouped, and ports are ascending
/// within each host regardless of worker completion order.
fn sort_results(results: &mut [PortResult]) {
    results.sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_tools_core::model::PortProtocol;

    fn result(host: &str, port: u16) -> PortResult {
        PortResult {
            host: host.into(),
            port,
            protocol: PortProtocol::Tcp,
            state: PortState::Open,
            banner: None,
            service: None,
        }
    }

    #[test]
    fn results_sort_by_host_then_port() {
        let mut results = vec![
            result("b", 443),
            result("a", 80),
            result("a", 22),
            result("b", 22),
        ];
        sort_results(&mut results);
        let keys: Vec<(&str, u16)> = results.iter().map(|r| (r.host.as_str(), r.port)).collect();
        assert_eq!(keys, vec![("a", 22), ("a", 80), ("b", 22), ("b", 443)]);
    }
}
