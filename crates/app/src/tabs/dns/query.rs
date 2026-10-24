//! DNS query sub-tool: single recursive query or iterative trace.

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{DnsSettings, InputHistory};
use net_tools_core::control::TaskState;
use net_tools_core::model::{DnsDnssecStatus, DnsProtocol, DnsQueryResult};
use net_tools_core::net::dns_tool::COMMON_RECORD_TYPES;
use rust_i18n::t;

use super::{protocol_selector, DnsTab};
use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::{cell_with_tooltip, table_fixed_rows_with_columns};
use crate::ui::theme::Palette;

const TARGET_HISTORY_KEY: &str = "dns.target";
const SERVER_HISTORY_KEY: &str = "dns.server";

/// Render the query sub-tool.
pub(super) fn ui(
    tab: &mut DnsTab,
    ui: &mut egui::Ui,
    s: &mut DnsSettings,
    history: &mut InputHistory,
    rt: &tokio::runtime::Handle,
    settings_expanded: bool,
) -> bool {
    // Migrate the legacy force-TCP switch to the protocol selector once, so
    // users can switch back to UDP afterwards.
    if s.force_tcp {
        s.protocol = DnsProtocol::Tcp;
        s.force_tcp = false;
    }
    let (submit, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
        ui.heading(t!("common.settings"));
        let mut submit = false;
        egui::Grid::new("dns_query_settings")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label(t!("common.target"));
                if history_input::singleline(ui, TARGET_HISTORY_KEY, &mut s.target, history, 160.0)
                {
                    submit = true;
                }
                ui.end_row();

                ui.label(t!("dns.record_type"));
                record_type_input(ui, &mut s.record_type);
                ui.end_row();

                ui.label(t!("dns.protocol"));
                protocol_selector(ui, &mut s.protocol);
                if matches!(s.protocol, DnsProtocol::Dot | DnsProtocol::Doh) {
                    s.trace = false;
                }
                ui.end_row();

                ui.label(t!("dns.server"));
                let presets = server_presets(s.protocol);
                if history_input::singleline_with_labeled_presets(
                    ui,
                    SERVER_HISTORY_KEY,
                    &presets,
                    &mut s.server,
                    history,
                    140.0,
                ) {
                    submit = true;
                }
                ui.end_row();

                ui.label(t!("common.timeout_ms"));
                ui.add(
                    egui::DragValue::new(&mut s.timeout_ms)
                        .range(100..=120_000)
                        .suffix(" ms"),
                );
                ui.end_row();

                ui.label(t!("dns.dnssec"));
                ui.checkbox(&mut s.dnssec, "");
                ui.end_row();

                ui.label(t!("dns.trace_mode"));
                ui.add_enabled_ui(
                    !matches!(s.protocol, DnsProtocol::Dot | DnsProtocol::Doh),
                    |ui| {
                        ui.checkbox(&mut s.trace, "");
                    },
                );
                ui.end_row();
            });
        ui.weak(t!("dns.server_hint"));
        if s.trace {
            ui.weak(t!("dns.trace_protocol_hint"));
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            control_row(tab, ui, s, history, rt);
            state_badge(ui, tab.query_ctrl.state);
        });

        if let Some((msg, hint)) = &tab.error {
            error_banner(ui, msg, hint.as_deref());
        }
        submit
    });

    if submit == Some(true) {
        record_inputs(s, history);
        restart(tab, s, rt);
    }

    crate::ui::layout::results_panel(ui, |ui| {
        toolbar(tab, ui);
        if let Some(result) = &tab.query_result {
            summary(ui, result);
            ui.add_space(6.0);
            answer_table(ui, result);
        } else if tab.output.is_empty() && !tab.query_ctrl.is_active() {
            ui.weak(t!("dns.empty_query"));
        }

        // The raw response is part of a normal query as well as an iterative
        // trace. Prefer the structured result's text and fall back to the
        // streamed trace output.
        let raw_text = tab
            .query_result
            .as_ref()
            .map(|result| result.raw.as_str())
            .filter(|text| !text.is_empty())
            .unwrap_or(tab.output.as_str());
        if !raw_text.is_empty() {
            ui.add_space(8.0);
            egui::CollapsingHeader::new(t!("dns.raw_output"))
                .default_open(true)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("dns_raw_output")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            let mut text = raw_text;
                            ui.add(
                                egui::TextEdit::multiline(&mut text)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(18),
                            );
                        });
                });
        }

        if let Some(result) = &tab.query_result {
            ui.add_space(6.0);
            dnssec_details(ui, result);
        }
    });

    expanded
}

fn control_row(
    tab: &mut DnsTab,
    ui: &mut egui::Ui,
    s: &DnsSettings,
    history: &mut InputHistory,
    rt: &tokio::runtime::Handle,
) {
    match tab.query_ctrl.state {
        TaskState::Idle | TaskState::Finished => {
            let label = if s.trace {
                t!("dns.trace")
            } else {
                t!("dns.query")
            };
            if ui.button(label).clicked() {
                record_inputs(s, history);
                start(tab, s, rt);
            }
        }
        TaskState::Running => {
            if ui.button(t!("common.stop")).clicked() {
                tab.query_ctrl.stop();
            }
        }
        TaskState::Paused => {
            if ui.button(t!("common.resume")).clicked() {
                tab.query_ctrl.resume();
            }
            if ui.button(t!("common.stop")).clicked() {
                tab.query_ctrl.stop();
            }
        }
        TaskState::Stopping => {
            ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
        }
    }
}

fn start(tab: &mut DnsTab, s: &DnsSettings, rt: &tokio::runtime::Handle) {
    if tab.query_ctrl.is_active() {
        return;
    }
    restart(tab, s, rt);
}

fn restart(tab: &mut DnsTab, s: &DnsSettings, rt: &tokio::runtime::Handle) {
    tab.query_result = None;
    tab.output.clear();
    tab.error = None;
    let settings = s.clone();
    tab.query_ctrl.start(rt, move |handle| async move {
        if settings.trace {
            net_tools_core::net::dns_tool::run_trace(&handle, &settings).await;
        } else {
            net_tools_core::net::dns_tool::run_query(&handle, &settings).await;
        }
    });
}

fn record_inputs(s: &DnsSettings, history: &mut InputHistory) {
    history_input::record_fields(
        history,
        &[
            (TARGET_HISTORY_KEY, &s.target),
            (SERVER_HISTORY_KEY, &s.server),
        ],
    );
}

/// Server presets for the selected transport, with the system resolver first
/// for plain DNS.
pub(super) fn server_presets(protocol: DnsProtocol) -> Vec<(&'static str, &'static str)> {
    let mut presets = Vec::new();
    if matches!(protocol, DnsProtocol::Udp | DnsProtocol::Tcp) {
        presets.push(("System resolver", ""));
    }
    for preset in net_tools_core::net::dns_tool::presets_for(protocol) {
        presets.push((preset.label, preset.endpoint));
    }
    presets
}

/// Editable record-type input whose drop-down lists the common record types.
pub(super) fn record_type_input(ui: &mut egui::Ui, value: &mut String) {
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(value).desired_width(90.0));
        ui.push_id("dns_record_type", |ui| {
            let button = crate::ui::common::dropdown_button(ui, &t!("dns.common_types"));
            egui::Popup::from_toggle_button_response(&button)
                .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                .width(120.0)
                .show(|ui| {
                    for &rtype in COMMON_RECORD_TYPES {
                        let selected = value.eq_ignore_ascii_case(rtype);
                        if ui.selectable_label(selected, rtype).clicked() {
                            *value = rtype.to_string();
                            ui.close();
                        }
                    }
                });
        });
    });
}

fn toolbar(tab: &mut DnsTab, ui: &mut egui::Ui) {
    match result_toolbar(ui) {
        ToolbarAction::Copy => ui.ctx().copy_text(tab.to_csv()),
        ToolbarAction::ExportCsv => crate::ui::export::save_file("dns-query", "csv", &tab.to_csv()),
        ToolbarAction::ExportJson => {
            crate::ui::export::save_file("dns-query", "json", &tab.to_json())
        }
        ToolbarAction::ExportHtml => {
            crate::ui::export::save_file("dns-query", "html", &tab.to_html())
        }
        ToolbarAction::Clear => {
            tab.query_result = None;
            tab.output.clear();
            tab.error = None;
        }
        ToolbarAction::None => {}
    }
}

fn summary(ui: &mut egui::Ui, result: &DnsQueryResult) {
    let palette = Palette::from_ui(ui);
    let dnssec_color = match result.dnssec.status {
        DnsDnssecStatus::Secure => palette.success_text,
        DnsDnssecStatus::Bogus => palette.error_text,
        DnsDnssecStatus::Insecure | DnsDnssecStatus::Indeterminate => palette.warning_text,
        _ => ui.visuals().weak_text_color(),
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(t!(
            "dns.summary.status",
            status = result.response_code.clone()
        ));
        ui.label(t!("dns.summary.time", time = result.elapsed_ms));
        ui.label(t!("dns.summary.server", server = result.server.clone()));
        ui.label(t!(
            "dns.summary.transport",
            transport = result.transport.clone()
        ));
        ui.colored_label(
            dnssec_color,
            format!("DNSSEC: {}", result.dnssec.status.label()),
        );
        if result.dnssec.ad {
            ui.label("AD");
        }
    });
    if let Some(error) = &result.error {
        error_banner(ui, error, None);
    }
}

fn answer_table(ui: &mut egui::Ui, result: &DnsQueryResult) {
    if result.answers.is_empty() {
        ui.weak(t!("dns.no_answers"));
        return;
    }
    const VISIBLE_ANSWER_ROWS: usize = 10;
    table_fixed_rows_with_columns(
        ui,
        &[
            t!("dns.columns.name").to_string(),
            t!("dns.columns.ttl").to_string(),
            t!("dns.columns.type").to_string(),
            t!("dns.columns.value").to_string(),
        ],
        result.answers.len(),
        VISIBLE_ANSWER_ROWS,
        [
            Column::auto().at_least(140.0).at_most(260.0),
            Column::exact(64.0),
            Column::exact(84.0),
            Column::remainder().at_least(160.0),
        ],
        |index, row| {
            let record = &result.answers[index];
            row.col(|ui| {
                cell_with_tooltip(ui, &record.name, &record.name);
            });
            row.col(|ui| {
                ui.label(record.ttl.to_string());
            });
            row.col(|ui| {
                ui.label(&record.record_type);
            });
            row.col(|ui| {
                cell_with_tooltip(ui, &record.value, &record.value);
            });
        },
    );
}

fn dnssec_details(ui: &mut egui::Ui, result: &DnsQueryResult) {
    if matches!(result.dnssec.status, DnsDnssecStatus::Disabled) {
        return;
    }
    egui::CollapsingHeader::new(t!("dns.dnssec_details"))
        .default_open(result.dnssec.status == DnsDnssecStatus::Bogus)
        .show(ui, |ui| {
            egui::Grid::new("dns_dnssec_grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(t!("dns.dnssec_status"));
                    ui.label(result.dnssec.status.label());
                    ui.end_row();
                    ui.label(t!("dns.dnssec_ad"));
                    ui.label(if result.dnssec.ad { "yes" } else { "no" });
                    ui.end_row();
                    ui.label(t!("dns.dnssec_rrsig"));
                    ui.label(result.dnssec.rrsig_count.to_string());
                    ui.end_row();
                    ui.label(t!("dns.dnssec_nsec"));
                    ui.label(result.dnssec.nsec_count.to_string());
                    ui.end_row();
                    ui.label(t!("dns.dnssec_ds"));
                    ui.label(if result.dnssec.ds_present {
                        "yes"
                    } else {
                        "no"
                    });
                    ui.end_row();
                    ui.label(t!("dns.dnssec_dnskey"));
                    ui.label(if result.dnssec.dnskey_present {
                        "yes"
                    } else {
                        "no"
                    });
                    ui.end_row();
                });
            if let Some(error) = &result.dnssec.error {
                error_banner(ui, error, None);
            }
            for step in &result.dnssec.chain {
                ui.label(format!(
                    "{}: key {} / {} / DS {} / DNSKEY {} / {}",
                    step.zone,
                    step.key_tag.unwrap_or_default(),
                    step.algorithm.clone().unwrap_or_default(),
                    if step.ds_present { "yes" } else { "no" },
                    if step.dnskey_present { "yes" } else { "no" },
                    if step.secure { "secure" } else { "not secure" }
                ));
            }
        });
}

impl DnsTab {
    /// CSV export for the current query result.
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "target,record_type,server,protocol,response_code,elapsed_ms,name,ttl,type,value\n",
        );
        if let Some(result) = &self.query_result {
            if result.answers.is_empty() {
                out.push_str(&format!(
                    "{},{},{},{},{},{},,,,\n",
                    crate::ui::export::csv_field(&result.target),
                    crate::ui::export::csv_field(&result.record_type),
                    crate::ui::export::csv_field(&result.server),
                    result.protocol.label(),
                    crate::ui::export::csv_field(&result.response_code),
                    result.elapsed_ms,
                ));
            }
            for record in &result.answers {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{}\n",
                    crate::ui::export::csv_field(&result.target),
                    crate::ui::export::csv_field(&result.record_type),
                    crate::ui::export::csv_field(&result.server),
                    result.protocol.label(),
                    crate::ui::export::csv_field(&result.response_code),
                    result.elapsed_ms,
                    crate::ui::export::csv_field(&record.name),
                    record.ttl,
                    crate::ui::export::csv_field(&record.record_type),
                    crate::ui::export::csv_field(&record.value),
                ));
            }
        }
        out
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.query_result).unwrap_or_else(|_| "{}".into())
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}
