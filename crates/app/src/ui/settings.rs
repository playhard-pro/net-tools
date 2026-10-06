//! Settings panel: reusable widgets for common probe settings.

use eframe::egui;
use net_tools_core::config::{CommonProbe, InputHistory};
use net_tools_core::model::{IpVersion, PortPreset, ProbeMode, ScanMode};
use rust_i18n::t;

use super::history_input;

/// Render the common settings shared by ping and mtr. Returns `true` when the
/// target input received an Enter key press, so the caller can restart the task
/// with the new target.
///
/// `key` identifies the target field's history bucket.
pub fn common_probe(
    ui: &mut egui::Ui,
    c: &mut CommonProbe,
    history: &mut InputHistory,
    key: &str,
) -> bool {
    let mut submit = false;
    egui::Grid::new("common_probe_grid")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label(t!("common.target"));
            if history_input::singleline(ui, key, &mut c.target, history, 240.0) {
                submit = true;
            }
            ui.end_row();

            ui.label(t!("common.ip_version"));
            ip_version_selector(ui, &mut c.ip_version);
            ui.end_row();

            ui.label(t!("common.timeout_ms"));
            ui.add(
                egui::DragValue::new(&mut c.timeout_ms)
                    .range(10..=120_000)
                    .suffix(" ms"),
            );
            ui.end_row();

            ui.label(t!("common.interval_ms"));
            ui.add(
                egui::DragValue::new(&mut c.interval_ms)
                    .range(10..=60_000)
                    .suffix(" ms"),
            );
            ui.end_row();

            ui.label(t!("common.packet_size"));
            ui.add(
                egui::DragValue::new(&mut c.packet_size)
                    .range(0..=65_000)
                    .suffix(" B"),
            );
            ui.end_row();

            ui.label(t!("common.reverse_dns"));
            ui.checkbox(&mut c.reverse_dns, "");
            ui.end_row();
        });
    submit
}

/// IP version dropdown.
pub fn ip_version_selector(ui: &mut egui::Ui, v: &mut IpVersion) {
    egui::ComboBox::from_id_salt("ip_version")
        .selected_text(v.label())
        .show_ui(ui, |ui| {
            for x in [IpVersion::Auto, IpVersion::V4, IpVersion::V6] {
                ui.selectable_value(v, x, x.label());
            }
        });
}

/// Probe mode (ICMP / UDP) dropdown.
pub fn probe_mode_selector(ui: &mut egui::Ui, m: &mut ProbeMode) {
    egui::ComboBox::from_id_salt("probe_mode")
        .selected_text(m.label())
        .show_ui(ui, |ui| {
            for x in [ProbeMode::Icmp, ProbeMode::Udp] {
                ui.selectable_value(m, x, x.label());
            }
        });
}

/// Scan mode dropdown.
pub fn scan_mode_selector(ui: &mut egui::Ui, m: &mut ScanMode) {
    egui::ComboBox::from_id_salt("scan_mode")
        .selected_text(m.label())
        .show_ui(ui, |ui| {
            for x in [ScanMode::TcpConnect, ScanMode::Syn, ScanMode::Udp] {
                ui.selectable_value(m, x, x.label());
            }
        });
}

/// Port preset dropdown.
pub fn port_preset_selector(ui: &mut egui::Ui, p: &mut PortPreset) {
    egui::ComboBox::from_id_salt("port_preset")
        .selected_text(p.label())
        .show_ui(ui, |ui| {
            for x in [
                PortPreset::Custom,
                PortPreset::Top100,
                PortPreset::Top1000,
                PortPreset::All,
            ] {
                ui.selectable_value(p, x, x.label());
            }
        });
}
