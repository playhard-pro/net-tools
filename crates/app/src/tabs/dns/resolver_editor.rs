//! Shared resolver list editor used by propagation and benchmark sub-tools.

use eframe::egui;
use net_tools_core::model::DnsProtocol;
use net_tools_core::net::dns_tool::presets_for;
use rust_i18n::t;

/// Draw the preset toggles and the custom resolver input.
pub(super) fn ui(
    ui: &mut egui::Ui,
    protocol: DnsProtocol,
    selected: &mut Vec<String>,
    custom: &mut String,
) {
    let presets = presets_for(protocol);
    // Drop ids that are unavailable for the current transport.
    selected.retain(|id| presets.iter().any(|preset| preset.id == id));

    ui.horizontal_wrapped(|ui| {
        if ui.small_button(t!("dns.resolvers.select_all")).clicked() {
            *selected = presets.iter().map(|preset| preset.id.to_string()).collect();
        }
        if ui.small_button(t!("dns.resolvers.select_none")).clicked() {
            selected.clear();
        }
    });
    ui.vertical(|ui| {
        for preset in presets {
            let mut checked = selected.iter().any(|id| id == preset.id);
            if ui.checkbox(&mut checked, preset.label).changed() {
                if checked {
                    selected.push(preset.id.to_string());
                } else {
                    selected.retain(|id| id != preset.id);
                }
            }
        }
    });
    ui.add_space(4.0);
    ui.label(t!("dns.resolvers.custom"));
    // Keep the editor inside the settings panel. An infinite desired width
    // makes egui measure against the whole window and overflow the divider.
    let width = (ui.available_width() - 4.0).max(120.0);
    ui.add(
        egui::TextEdit::multiline(custom)
            .desired_rows(3)
            .desired_width(width)
            .hint_text(t!("dns.resolvers.custom_hint")),
    );
}
