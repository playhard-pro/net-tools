//! LAN discovery tab: neighbor table, ICMP sweep and name/service lookup.

use std::collections::BTreeMap;
use std::net::IpAddr;

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{InputHistory, LanDiscoverySettings};
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{LanDevice, LanScanProgress, ProbeEvent};
use rust_i18n::t;

use crate::ui::common::{error_banner, info_line, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::{cell_with_tooltip, table_with_columns};
use crate::ui::theme::Palette;

const TARGETS_HISTORY_KEY: &str = "lan_discovery.targets";

pub struct LanDiscoveryTab {
    pub ctrl: TaskController<ProbeEvent>,
    devices: BTreeMap<IpAddr, LanDevice>,
    progress: Option<LanScanProgress>,
    info: Vec<String>,
    error: Option<(String, Option<String>)>,
}

impl Default for LanDiscoveryTab {
    fn default() -> Self {
        Self::new()
    }
}

impl LanDiscoveryTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            devices: BTreeMap::new(),
            progress: None,
            info: Vec::new(),
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.devices.clear();
        self.progress = None;
        self.info.clear();
        self.error = None;
    }

    /// Stop a running scan when another tab is selected. Completed results stay
    /// available for the next visit.
    pub fn clear_on_hide(&mut self) {
        if self.ctrl.is_active() {
            self.ctrl.stop();
        }
    }

    fn start(&mut self, settings: &LanDiscoverySettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.reset();
        let settings = settings.clone();
        self.ctrl.start(rt, move |handle| {
            net_tools_core::net::lan_discovery::run_scan(handle, settings)
        });
    }

    fn drain(&mut self) {
        for event in self.ctrl.drain() {
            match event {
                ProbeEvent::LanDevice(device) => {
                    self.devices.insert(device.ip, device);
                }
                ProbeEvent::LanProgress(progress) => self.progress = Some(progress),
                ProbeEvent::Info(message) => {
                    self.info.push(localized_info(&message));
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
        settings: &mut LanDiscoverySettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        self.drain();
        if self.ctrl.is_active() {
            ui.ctx().request_repaint();
        }

        let local_subnets = net_tools_core::net::lan_discovery::local_subnets();
        let (submit, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            let mut submit = false;
            egui::Grid::new("lan_discovery_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("common.targets"));
                    let presets = local_subnet_presets(&local_subnets);
                    let preset_refs = presets
                        .iter()
                        .map(|(label, value)| (label.as_str(), value.as_str()))
                        .collect::<Vec<_>>();
                    if history_input::singleline_with_labeled_presets(
                        ui,
                        TARGETS_HISTORY_KEY,
                        &preset_refs,
                        &mut settings.targets,
                        history,
                        160.0,
                    ) {
                        submit = true;
                    }
                    ui.end_row();

                    ui.label("");
                    ui.weak(t!("lan_discovery.target_hint"));
                    ui.end_row();

                    ui.label(t!("common.timeout_ms"));
                    ui.add(
                        egui::DragValue::new(&mut settings.timeout_ms)
                            .range(100..=30_000)
                            .suffix(" ms"),
                    );
                    ui.end_row();

                    ui.label(t!("common.concurrency"));
                    ui.add(egui::DragValue::new(&mut settings.concurrency).range(1..=1024));
                    ui.end_row();

                    ui.label(t!("lan_discovery.icmp_scan"));
                    ui.checkbox(&mut settings.icmp_scan, "");
                    ui.end_row();

                    ui.label(t!("common.reverse_dns"));
                    ui.checkbox(&mut settings.reverse_dns, "");
                    ui.end_row();

                    ui.label(t!("lan_discovery.mdns"));
                    ui.checkbox(&mut settings.mdns, "");
                    ui.end_row();

                    ui.label(t!("lan_discovery.ssdp"));
                    ui.checkbox(&mut settings.ssdp, "");
                    ui.end_row();

                    ui.label(t!("lan_discovery.netbios"));
                    ui.checkbox(&mut settings.netbios, "");
                    ui.end_row();

                    ui.label(t!("lan_discovery.online_mac"));
                    ui.checkbox(&mut settings.allow_online_mac, "");
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                self.control_row(ui, settings, history, rt);
                state_badge(ui, self.ctrl.state);
            });
            if let Some((message, hint)) = &self.error {
                error_banner(ui, message, hint.as_deref());
            }
            for line in self.info.iter().rev().take(5) {
                info_line(ui, line);
            }
            submit
        });

        if submit == Some(true) {
            history_input::record_fields(history, &[(TARGETS_HISTORY_KEY, &settings.targets)]);
            self.start(settings, rt);
        }

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);
            self.progress_ui(ui);
            if self.devices.is_empty() {
                ui.weak(t!("lan_discovery.empty"));
                return;
            }

            let headers = [
                t!("lan_discovery.ip"),
                t!("lan_discovery.mac"),
                t!("lan_discovery.vendor"),
                t!("lan_discovery.hostname"),
                t!("lan_discovery.name_source"),
                t!("lan_discovery.services"),
            ];
            let rows = self.devices.values().collect::<Vec<_>>();
            let columns = [
                Column::auto().at_least(100.0).at_most(140.0),
                Column::auto().at_least(110.0).at_most(150.0),
                Column::auto().at_least(90.0).at_most(180.0),
                Column::auto().at_least(110.0).at_most(200.0),
                Column::auto().at_least(70.0).at_most(90.0),
                Column::remainder(),
            ];
            table_with_columns(ui, &headers, rows.len(), columns, |index, row| {
                let device = rows[index];
                row.col(|ui| {
                    ui.label(device.ip.to_string());
                });
                row.col(|ui| {
                    let text = device.mac.as_deref().unwrap_or("-");
                    cell_with_tooltip(ui, text, text);
                });
                row.col(|ui| {
                    let text = device.vendor.as_deref().unwrap_or("-");
                    cell_with_tooltip(ui, text, text);
                });
                row.col(|ui| {
                    let text = device.hostname.as_deref().unwrap_or("-");
                    cell_with_tooltip(ui, text, text);
                });
                row.col(|ui| {
                    ui.label(
                        device
                            .hostname_source
                            .map(|source| source.label())
                            .unwrap_or("-"),
                    );
                });
                row.col(|ui| {
                    let summary = device.service_summary();
                    let text = if summary.is_empty() {
                        "-".to_string()
                    } else {
                        summary
                    };
                    cell_with_tooltip(ui, &text, &text);
                });
            });
        });

        expanded
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        settings: &LanDiscoverySettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            TaskState::Idle | TaskState::Finished => {
                if ui.button(t!("common.start")).clicked() {
                    history_input::record_fields(
                        history,
                        &[(TARGETS_HISTORY_KEY, &settings.targets)],
                    );
                    self.start(settings, rt);
                }
            }
            TaskState::Running | TaskState::Paused => {
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            }
            TaskState::Stopping => {
                ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
            }
        }
    }

    fn progress_ui(&self, ui: &mut egui::Ui) {
        let Some(progress) = &self.progress else {
            return;
        };
        let fraction = if progress.total == 0 {
            0.0
        } else {
            progress.scanned as f32 / progress.total as f32
        };
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
                        t!("lan_discovery.scanned"),
                        progress.scanned,
                        progress.total
                    ));
                    ui.separator();
                    ui.monospace(format!("{}: {}", t!("lan_discovery.found"), progress.found));
                });
            });
        ui.add_space(8.0);
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("lan-discovery", "csv", &self.to_csv())
            }
            ToolbarAction::ExportJson => {
                crate::ui::export::save_file("lan-discovery", "json", &self.to_json())
            }
            ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("lan-discovery", "html", &self.to_html())
            }
            ToolbarAction::Clear => self.reset(),
            ToolbarAction::None => {}
        }
    }

    fn rows(&self) -> Vec<&LanDevice> {
        self.devices.values().collect()
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "ip,mac,vendor,vendor_source,hostname,name_source,netbios_name,netbios_workgroup,mdns_services,upnp_name,upnp_manufacturer,upnp_model,upnp_device_type,rtt_ms,sources\n",
        );
        for device in self.rows() {
            let values = [
                device.ip.to_string(),
                device.mac.clone().unwrap_or_default(),
                device.vendor.clone().unwrap_or_default(),
                device
                    .vendor_source
                    .map(|source| source.label().to_string())
                    .unwrap_or_default(),
                device.hostname.clone().unwrap_or_default(),
                device
                    .hostname_source
                    .map(|source| source.label().to_string())
                    .unwrap_or_default(),
                device.netbios_name.clone().unwrap_or_default(),
                device.netbios_workgroup.clone().unwrap_or_default(),
                device.mdns_services.join(";"),
                device.upnp_name.clone().unwrap_or_default(),
                device.upnp_manufacturer.clone().unwrap_or_default(),
                device.upnp_model.clone().unwrap_or_default(),
                device.upnp_device_type.clone().unwrap_or_default(),
                device
                    .rtt_ms
                    .map_or_else(String::new, |value| format!("{value:.2}")),
                device
                    .sources
                    .iter()
                    .map(|source| source.label())
                    .collect::<Vec<_>>()
                    .join(";"),
            ];
            out.push_str(
                &values
                    .iter()
                    .map(|value| crate::ui::export::csv_field(value))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            out.push('\n');
        }
        out
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.rows()).unwrap_or_default()
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}

/// Translate the structured progress messages emitted by the core scan task.
/// Core messages stay language-neutral; the UI owns their presentation.
fn localized_info(message: &str) -> String {
    if message == "IPv6 targets use passive neighbor discovery only" {
        return t!("lan_discovery.info_ipv6_passive").to_string();
    }
    if message
        == "no neighbor entries matched the IPv6 target; showing all private neighbor entries"
    {
        return t!("lan_discovery.info_ipv6_fallback").to_string();
    }
    if let Some(count) = labeled_count(message, "SSDP/UPnP: ", " device(s)") {
        return t!("lan_discovery.info_ssdp", count = count).to_string();
    }
    if let Some(count) = labeled_count(message, "mDNS: ", " device(s)") {
        return t!("lan_discovery.info_mdns", count = count).to_string();
    }
    if let Some(count) = labeled_count(message, "neighbor table: ", " device(s)") {
        return t!("lan_discovery.info_neighbor_table", count = count).to_string();
    }
    if let Some(count) = labeled_count(message, "ICMP scanning ", " host(s)") {
        return t!("lan_discovery.info_icmp_scan", count = count).to_string();
    }
    if let Some(count) = labeled_count(
        message,
        "neighbor table added ",
        " device(s) after the sweep",
    ) {
        return t!("lan_discovery.info_neighbor_added", count = count).to_string();
    }
    if let Some(targets) = message.strip_prefix("targets: ") {
        return t!("lan_discovery.info_targets", targets = targets).to_string();
    }
    message.to_string()
}

fn labeled_count(message: &str, prefix: &str, suffix: &str) -> Option<u64> {
    message
        .strip_prefix(prefix)?
        .strip_suffix(suffix)?
        .trim()
        .parse()
        .ok()
}

/// Build labeled presets for the target field. The history drop-down renders
/// these next to the remembered values, matching the DNS server selector.
fn local_subnet_presets(subnets: &[net_tools_core::model::LocalSubnet]) -> Vec<(String, String)> {
    let mut presets = vec![(t!("lan_discovery.target_auto").to_string(), String::new())];
    presets.extend(subnets.iter().map(|subnet| {
        let label = if subnet.cidr.contains(':') {
            format!(
                "{} · {} · {}",
                subnet.interface,
                subnet.address,
                t!("lan_discovery.ipv6_passive")
            )
        } else {
            format!("{} · {}", subnet.interface, subnet.address)
        };
        (label, subnet.cidr.clone())
    }));
    presets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(ip: &str) -> LanDevice {
        LanDevice::new(ip.parse().unwrap())
    }

    #[test]
    fn csv_contains_header_and_rows() {
        let mut tab = LanDiscoveryTab::new();
        tab.devices
            .insert("192.168.1.1".parse().unwrap(), device("192.168.1.1"));
        let csv = tab.to_csv();
        assert!(csv.starts_with("ip,mac,"));
        assert!(csv.contains("192.168.1.1"));
    }

    #[test]
    fn clear_on_hide_only_stops_active_work() {
        let mut tab = LanDiscoveryTab::new();
        tab.clear_on_hide();
        assert_eq!(tab.ctrl.state, TaskState::Idle);
    }

    #[test]
    fn default_tab_renders_without_panic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut tab = LanDiscoveryTab::new();
        let mut settings = LanDiscoverySettings::default();
        let mut history = InputHistory::default();
        let ctx = egui::Context::default();
        for _ in 0..4 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(1200.0, 800.0),
                )),
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                let _ = tab.ui(ui, &mut settings, &mut history, runtime.handle(), true);
            })
            .textures_delta
            .clear();
        }
    }
}
