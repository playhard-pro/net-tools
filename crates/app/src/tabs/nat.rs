//! NAT tab: STUN-based NAT type and behavior discovery.

use std::time::Duration;

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{InputHistory, NatSettings};
use net_tools_core::control::TaskController;
use net_tools_core::model::{
    NatBindingResult, NatFilteringBehavior, NatMappingBehavior, NatResult, NatStep, NatStepKind,
    NatTestMode, NatType, ProbeEvent,
};
use rust_i18n::t;

use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::export::{csv_field, save_file};
use crate::ui::history_input;
use crate::ui::result_table::{cell_with_tooltip, table_fixed_rows_with_columns};
use crate::ui::settings::ip_version_selector;
use crate::ui::theme::Palette;

/// History bucket for the STUN server field.
const SERVER_HISTORY_KEY: &str = "nat.server";

/// History bucket for the optional local bind address.
const LOCAL_BIND_HISTORY_KEY: &str = "nat.local_bind";

/// Number of step rows visible before the log scrolls. The results area has
/// spare vertical room below the table, so keep enough rows visible to avoid
/// scrolling for a typical run.
const VISIBLE_STEP_ROWS: usize = 12;

/// Width reserved for the step name column so localized labels stay readable.
const STEP_NAME_WIDTH: f32 = 112.0;

/// Width reserved for the RTT column; it only holds a number and a unit.
const STEP_RTT_WIDTH: f32 = 84.0;

/// Relative widths of the remaining step table columns. Endpoint columns get
/// the largest share, but are still clipped to this table; the full value is
/// available through a tooltip.
const STEP_COLUMN_WEIGHTS: [f32; 5] = [0.18, 0.10, 0.28, 0.28, 0.16];

/// Repaint cadence while a discovery run is active.
const LIVE_REPAINT: Duration = Duration::from_millis(200);

/// Servers offered in the drop-down. Public servers can be offline or may not
/// support the CHANGE-REQUEST extension required by the discovery procedures.
pub const PRESET_SERVERS: &[&str] = &[
    "stun.fitauto.ru",
    "stun.m-online.net",
    "stun.mixvoip.com",
    "stun.voipgate.com",
    "stun.t-online.de",
    "stun.srce.hr",
    "stun.aa.net.uk",
    "stun.syncthing.net",
];

pub struct NatTab {
    pub ctrl: TaskController<ProbeEvent>,
    /// Last completed result. It stays available when switching tabs.
    pub result: Option<NatResult>,
    /// Steps of the current or most recent run, used for live progress.
    pub steps: Vec<NatStep>,
    pub error: Option<(String, Option<String>)>,
    /// Whether this tab is currently visible; events arriving while hidden are
    /// discarded so they cannot leak into the next visit.
    visible: bool,
}

impl Default for NatTab {
    fn default() -> Self {
        Self::new()
    }
}

impl NatTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            result: None,
            steps: Vec::new(),
            error: None,
            visible: false,
        }
    }

    pub fn reset(&mut self) {
        self.result = None;
        self.steps.clear();
        self.error = None;
    }

    /// Start a fresh run, replacing any previous result.
    pub fn restart(&mut self, settings: &NatSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        let settings = settings.clone();
        self.ctrl.start(rt, move |handle| async move {
            net_tools_core::net::stun::run_query(&handle, &settings).await;
        });
    }

    pub fn drain(&mut self) {
        for event in self.ctrl.drain() {
            if !self.visible {
                continue;
            }
            match event {
                ProbeEvent::NatStep(step) => self.steps.push(step),
                ProbeEvent::Nat(result) => {
                    self.steps = result.steps.clone();
                    self.result = Some(result);
                    self.error = None;
                }
                ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    /// Stop an in-flight run when another tab is selected. A completed result
    /// remains available; unfinished step progress is dropped.
    pub fn clear_on_hide(&mut self) {
        self.visible = false;
        if self.ctrl.is_active() {
            self.ctrl.stop();
        }
        let _ = self.ctrl.drain();
        self.error = None;
        if let Some(result) = &self.result {
            self.steps = result.steps.clone();
        } else {
            self.steps.clear();
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut NatSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        self.drain();
        self.visible = true;
        if self.ctrl.is_active() {
            ui.ctx().request_repaint_after(LIVE_REPAINT);
        }

        let (outcome, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            let mut submit = false;

            egui::Grid::new("nat_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("nat.mode"));
                    egui::ComboBox::from_id_salt("nat_mode")
                        .selected_text(settings.mode.label())
                        .show_ui(ui, |ui| {
                            for mode in [NatTestMode::Rfc5780, NatTestMode::Rfc3489] {
                                ui.selectable_value(&mut settings.mode, mode, mode.label());
                            }
                        });
                    ui.end_row();

                    ui.label(t!("common.ip_version"));
                    ip_version_selector(ui, &mut settings.ip_version);
                    ui.end_row();

                    ui.label(t!("nat.server"));
                    if history_input::singleline_with_presets(
                        ui,
                        SERVER_HISTORY_KEY,
                        PRESET_SERVERS,
                        &mut settings.server,
                        history,
                        160.0,
                    ) {
                        submit = true;
                    }
                    ui.end_row();

                    ui.label(t!("common.timeout_ms"));
                    ui.add(
                        egui::DragValue::new(&mut settings.timeout_ms)
                            .range(100..=120_000)
                            .suffix(" ms"),
                    );
                    ui.end_row();

                    ui.label(t!("nat.retries"));
                    ui.add(egui::DragValue::new(&mut settings.retries).range(0..=10));
                    ui.end_row();
                });

            ui.add_space(4.0);
            ui.weak(t!("nat.server_hint"));
            if settings.mode == NatTestMode::Rfc3489 {
                ui.add_space(4.0);
                let color = Palette::from_ui(ui).warning_text;
                ui.colored_label(color, t!("nat.rfc3489_warning"));
            }

            ui.add_space(4.0);
            egui::CollapsingHeader::new(t!("common.advanced"))
                .default_open(false)
                .show(ui, |ui| {
                    egui::Grid::new("nat_advanced")
                        .num_columns(2)
                        .spacing([12.0, 10.0])
                        .show(ui, |ui| {
                            ui.label(t!("nat.local_bind"));
                            history_input::singleline(
                                ui,
                                LOCAL_BIND_HISTORY_KEY,
                                &mut settings.local_bind,
                                history,
                                160.0,
                            );
                            ui.end_row();
                        });
                    ui.weak(t!("nat.local_bind_hint"));
                });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                self.control_row(ui, settings, history, rt);
                state_badge(ui, self.ctrl.state);
            });

            if let Some((message, hint)) = &self.error {
                error_banner(ui, message, hint.as_deref());
            }

            submit
        });
        let submit = outcome.unwrap_or(false);

        if submit {
            self.record_settings(settings, history);
            self.restart(settings, rt);
        }

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);
            egui::ScrollArea::vertical()
                .id_salt("nat_results_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    self.result_ui(ui);
                });
        });

        expanded
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        settings: &NatSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        if self.ctrl.is_active() {
            if ui.button(t!("common.stop")).clicked() {
                self.ctrl.stop();
            }
            ui.spinner();
            ui.weak(t!("nat.testing"));
        } else if ui.button(t!("common.start")).clicked() {
            self.record_settings(settings, history);
            self.restart(settings, rt);
        }
    }

    fn record_settings(&self, settings: &NatSettings, history: &mut InputHistory) {
        let server = settings.server.trim();
        if !PRESET_SERVERS.contains(&server) {
            history.record(SERVER_HISTORY_KEY, server);
        }
        if !settings.local_bind.trim().is_empty() {
            history.record(LOCAL_BIND_HISTORY_KEY, settings.local_bind.trim());
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => ui.ctx().copy_text(self.summary_text()),
            ToolbarAction::ExportCsv => {
                save_file("nat-result", "csv", &self.to_csv());
            }
            ToolbarAction::ExportJson => {
                if let Some(result) = &self.result {
                    if let Ok(json) = serde_json::to_string_pretty(result) {
                        save_file("nat-result", "json", &json);
                    }
                }
            }
            ToolbarAction::ExportHtml => {
                let html = crate::ui::export::csv_to_html(&self.to_csv());
                save_file("nat-result", "html", &html);
            }
            ToolbarAction::Clear => self.reset(),
            ToolbarAction::None => {}
        }
    }

    fn result_ui(&self, ui: &mut egui::Ui) {
        if self.result.is_none() && self.steps.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(48.0);
                ui.weak(t!("nat.empty"));
            });
            return;
        }

        if let Some(result) = &self.result {
            ui.add_space(8.0);
            self.type_card(ui, result);
            ui.add_space(10.0);
            metrics_ui(ui, result);
            ui.add_space(10.0);
            explanation_ui(ui, result);
        } else {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak(t!("nat.testing"));
            });
        }

        ui.add_space(12.0);
        ui.heading(t!("nat.steps"));
        if self.steps.is_empty() {
            ui.weak(t!("nat.no_steps"));
            return;
        }
        let rows = self.steps.len().min(VISIBLE_STEP_ROWS);
        let headers = [
            t!("nat.step").to_string(),
            t!("nat.target").to_string(),
            t!("nat.change").to_string(),
            t!("nat.response_from").to_string(),
            t!("nat.mapped").to_string(),
            t!("nat.outcome").to_string(),
            t!("common.rtt_ms").to_string(),
        ];
        // TableBuilder adds the inter-column spacing on top of the column
        // widths, so reserve it here to keep the right edge inside the panel.
        let spacing = ui.spacing().item_spacing.x * (headers.len().saturating_sub(1)) as f32;
        let table_width =
            (ui.available_width() - ui.spacing().scroll.allocated_width() - spacing).max(1.0);
        let flexible = (table_width - STEP_NAME_WIDTH - STEP_RTT_WIDTH).max(1.0);
        let columns = [
            Column::exact(STEP_NAME_WIDTH),
            Column::exact(flexible * STEP_COLUMN_WEIGHTS[0]),
            Column::exact(flexible * STEP_COLUMN_WEIGHTS[1]),
            Column::exact(flexible * STEP_COLUMN_WEIGHTS[2]),
            Column::exact(flexible * STEP_COLUMN_WEIGHTS[3]),
            Column::exact(flexible * STEP_COLUMN_WEIGHTS[4]),
            Column::exact(STEP_RTT_WIDTH),
        ];
        table_fixed_rows_with_columns(
            ui,
            &headers,
            self.steps.len(),
            rows,
            columns,
            |index, row| {
                let step = &self.steps[index];
                row.col(|ui| {
                    let text = step_label(step.kind);
                    cell_with_tooltip(ui, &text, &text);
                });
                row.col(|ui| {
                    cell_with_tooltip(
                        ui,
                        egui::RichText::new(&step.target).monospace(),
                        &step.target,
                    );
                });
                row.col(|ui| {
                    let text = change_label(step.change_ip, step.change_port);
                    cell_with_tooltip(ui, &text, &text);
                });
                row.col(|ui| {
                    let text = step.response_from.as_deref().unwrap_or("-");
                    cell_with_tooltip(ui, egui::RichText::new(text).monospace(), text);
                });
                row.col(|ui| {
                    let text = step.mapped_endpoint.as_deref().unwrap_or("-");
                    cell_with_tooltip(ui, egui::RichText::new(text).monospace(), text);
                });
                row.col(|ui| {
                    let text = outcome_label(&step.outcome);
                    cell_with_tooltip(ui, &text, &text);
                });
                row.col(|ui| {
                    ui.monospace(
                        step.rtt_ms
                            .map(|rtt| format!("{rtt:.1} ms"))
                            .unwrap_or_else(|| "-".into()),
                    );
                });
            },
        );
    }

    fn type_card(&self, ui: &mut egui::Ui, result: &NatResult) {
        let palette = Palette::from_ui(ui);
        let (label_key, color) = nat_type_style(result.nat_type, &palette);
        egui::Frame::new()
            .fill(palette.card_bg)
            .corner_radius(8.0)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new(t!("nat.type"))
                            .small()
                            .color(palette.card_text),
                    );
                    ui.label(
                        egui::RichText::new(t!(label_key))
                            .size(26.0)
                            .strong()
                            .color(color),
                    );
                });
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(format!("{}  ·  {}", result.mode.label(), result.server))
                        .small()
                        .color(palette.card_text),
                );
            });
    }

    fn summary_text(&self) -> String {
        let Some(result) = &self.result else {
            return String::new();
        };
        format!(
            "NAT type: {}\nMode: {}\nServer: {}\nBinding: {}\nMapping: {}\nFiltering: {}\nLocal: {}\nPublic: {}\nOther: {}\nElapsed: {} ms",
            nat_type_label(result.nat_type),
            result.mode.label(),
            result.server,
            binding_label(result.binding),
            mapping_label(result.mapping),
            filtering_label(result.filtering),
            result.local_endpoint,
            result.public_endpoint.as_deref().unwrap_or("-"),
            result.other_endpoint.as_deref().unwrap_or("-"),
            result.elapsed_ms
        )
    }

    fn to_csv(&self) -> String {
        let mut csv = String::from(
            "step,kind,target,change_ip,change_port,responded,response_from,mapped_endpoint,changed_endpoint,rtt_ms,outcome\n",
        );
        for step in &self.steps {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{}\n",
                step.index,
                csv_field(&format!("{:?}", step.kind)),
                csv_field(&step.target),
                step.change_ip,
                step.change_port,
                step.responded,
                csv_field(step.response_from.as_deref().unwrap_or("")),
                csv_field(step.mapped_endpoint.as_deref().unwrap_or("")),
                csv_field(step.changed_endpoint.as_deref().unwrap_or("")),
                step.rtt_ms
                    .map(|rtt| format!("{rtt:.3}"))
                    .unwrap_or_default(),
                csv_field(&step.outcome),
            ));
        }
        csv
    }
}

fn nat_type_style(nat_type: NatType, palette: &Palette) -> (&'static str, egui::Color32) {
    match nat_type {
        NatType::OpenInternet => ("nat.type_open_internet", palette.success_text),
        NatType::FullCone => ("nat.type_full_cone", palette.success_text),
        NatType::RestrictedCone => ("nat.type_restricted", palette.info_text),
        NatType::PortRestrictedCone => ("nat.type_port_restricted", palette.info_text),
        NatType::SymmetricUdpFirewall => ("nat.type_firewall", palette.warning_text),
        NatType::Symmetric => ("nat.type_symmetric", palette.warning_text),
        NatType::UdpBlocked => ("nat.type_udp_blocked", palette.error_text),
        NatType::UnsupportedServer => ("nat.type_unsupported", palette.error_text),
        NatType::Unknown => ("nat.type_unknown", palette.warning_text),
    }
}

fn nat_type_label(nat_type: NatType) -> &'static str {
    match nat_type {
        NatType::OpenInternet => "open internet",
        NatType::FullCone => "full cone",
        NatType::RestrictedCone => "restricted cone",
        NatType::PortRestrictedCone => "port restricted cone",
        NatType::SymmetricUdpFirewall => "symmetric UDP firewall",
        NatType::Symmetric => "symmetric",
        NatType::UdpBlocked => "UDP blocked",
        NatType::UnsupportedServer => "unsupported server",
        NatType::Unknown => "unknown",
    }
}

fn binding_label(binding: NatBindingResult) -> &'static str {
    match binding {
        NatBindingResult::Success => "success",
        NatBindingResult::UnsupportedServer => "unsupported server",
        NatBindingResult::Failed => "failed",
        NatBindingResult::Unknown => "unknown",
    }
}

fn mapping_label(mapping: NatMappingBehavior) -> &'static str {
    match mapping {
        NatMappingBehavior::Direct => "direct",
        NatMappingBehavior::EndpointIndependent => "endpoint-independent",
        NatMappingBehavior::AddressDependent => "address-dependent",
        NatMappingBehavior::AddressAndPortDependent => "address and port-dependent",
        NatMappingBehavior::UnsupportedServer => "unsupported server",
        NatMappingBehavior::Failed => "failed",
        NatMappingBehavior::Unknown => "unknown",
    }
}

fn filtering_label(filtering: NatFilteringBehavior) -> &'static str {
    match filtering {
        NatFilteringBehavior::EndpointIndependent => "endpoint-independent",
        NatFilteringBehavior::AddressDependent => "address-dependent",
        NatFilteringBehavior::AddressAndPortDependent => "address and port-dependent",
        NatFilteringBehavior::UnsupportedServer => "unsupported server",
        NatFilteringBehavior::Unknown => "unknown",
    }
}

fn binding_key(binding: NatBindingResult) -> &'static str {
    match binding {
        NatBindingResult::Success => "nat.binding_success",
        NatBindingResult::UnsupportedServer => "nat.binding_unsupported",
        NatBindingResult::Failed => "nat.binding_failed",
        NatBindingResult::Unknown => "nat.binding_unknown",
    }
}

fn mapping_key(mapping: NatMappingBehavior) -> &'static str {
    match mapping {
        NatMappingBehavior::Direct => "nat.mapping_direct",
        NatMappingBehavior::EndpointIndependent => "nat.mapping_endpoint_independent",
        NatMappingBehavior::AddressDependent => "nat.mapping_address_dependent",
        NatMappingBehavior::AddressAndPortDependent => "nat.mapping_address_port_dependent",
        NatMappingBehavior::UnsupportedServer => "nat.mapping_unsupported",
        NatMappingBehavior::Failed => "nat.mapping_failed",
        NatMappingBehavior::Unknown => "nat.mapping_unknown",
    }
}

fn filtering_key(filtering: NatFilteringBehavior) -> &'static str {
    match filtering {
        NatFilteringBehavior::EndpointIndependent => "nat.filtering_endpoint_independent",
        NatFilteringBehavior::AddressDependent => "nat.filtering_address_dependent",
        NatFilteringBehavior::AddressAndPortDependent => "nat.filtering_address_port_dependent",
        NatFilteringBehavior::UnsupportedServer => "nat.filtering_unsupported",
        NatFilteringBehavior::Unknown => "nat.filtering_unknown",
    }
}

fn metrics_ui(ui: &mut egui::Ui, result: &NatResult) {
    egui::Grid::new("nat_metrics")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label(t!("nat.binding"));
            ui.label(t!(binding_key(result.binding)));
            ui.end_row();

            ui.label(t!("nat.mapping"));
            ui.label(t!(mapping_key(result.mapping)));
            ui.end_row();

            ui.label(t!("nat.filtering"));
            ui.label(t!(filtering_key(result.filtering)));
            ui.end_row();

            ui.label(t!("nat.local_endpoint"));
            ui.monospace(&result.local_endpoint);
            ui.end_row();

            ui.label(t!("nat.public_endpoint"));
            ui.monospace(result.public_endpoint.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label(t!("nat.other_endpoint"));
            ui.monospace(result.other_endpoint.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label(t!("nat.elapsed"));
            ui.monospace(format!("{} ms", result.elapsed_ms));
            ui.end_row();
        });

    if let Some(warning) = &result.warning {
        let palette = Palette::from_ui(ui);
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(palette.warning_bg)
            .corner_radius(4.0)
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.colored_label(palette.warning_text, warning_label(warning));
            });
    }
}

fn warning_label(warning: &str) -> String {
    let key = match warning {
        "alternate-endpoint" => "nat.warn_alternate_endpoint",
        "source-change" => "nat.warn_source_change",
        "no-mapped" => "nat.warn_no_mapped",
        "ignored-source-change" => "nat.warn_ignored_source",
        "ignored-port-change" => "nat.warn_ignored_port",
        _ => return warning.to_string(),
    };
    t!(key).to_string()
}

fn explanation_ui(ui: &mut egui::Ui, result: &NatResult) {
    let (what, advice) = explanation_keys(result.nat_type);
    let palette = Palette::from_ui(ui);
    ui.add_space(2.0);
    ui.heading(t!("nat.explanation"));
    egui::Frame::new()
        .fill(palette.card_bg)
        .corner_radius(6.0)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(t!(what)).color(palette.card_text));
            ui.add_space(4.0);
            ui.label(egui::RichText::new(t!(advice)).color(palette.card_text));
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(t!("nat.cgnat_note"))
                    .small()
                    .color(palette.card_text),
            );
        });
}

fn explanation_keys(nat_type: NatType) -> (&'static str, &'static str) {
    match nat_type {
        NatType::OpenInternet => ("nat.explain_open_what", "nat.explain_open_advice"),
        NatType::FullCone => ("nat.explain_full_what", "nat.explain_full_advice"),
        NatType::RestrictedCone => (
            "nat.explain_restricted_what",
            "nat.explain_restricted_advice",
        ),
        NatType::PortRestrictedCone => (
            "nat.explain_port_restricted_what",
            "nat.explain_port_restricted_advice",
        ),
        NatType::SymmetricUdpFirewall => {
            ("nat.explain_firewall_what", "nat.explain_firewall_advice")
        }
        NatType::Symmetric => ("nat.explain_symmetric_what", "nat.explain_symmetric_advice"),
        NatType::UdpBlocked => ("nat.explain_blocked_what", "nat.explain_blocked_advice"),
        NatType::UnsupportedServer => (
            "nat.explain_unsupported_what",
            "nat.explain_unsupported_advice",
        ),
        NatType::Unknown => ("nat.explain_unknown_what", "nat.explain_unknown_advice"),
    }
}

fn step_label(kind: NatStepKind) -> String {
    let key = match kind {
        NatStepKind::Binding => "nat.step_binding",
        NatStepKind::FilteringTest2 => "nat.step_filtering_2",
        NatStepKind::FilteringTest3 => "nat.step_filtering_3",
        NatStepKind::MappingTest2 => "nat.step_mapping_2",
        NatStepKind::MappingTest3 => "nat.step_mapping_3",
        NatStepKind::Rfc3489Test1 => "nat.step_classic_1",
        NatStepKind::Rfc3489Test2 => "nat.step_classic_2",
        NatStepKind::Rfc3489Test1Second => "nat.step_classic_1_second",
        NatStepKind::Rfc3489Test3 => "nat.step_classic_3",
    };
    t!(key).to_string()
}

fn change_label(change_ip: bool, change_port: bool) -> String {
    match (change_ip, change_port) {
        (true, true) => t!("nat.change_ip_port").to_string(),
        (true, false) => t!("nat.change_ip").to_string(),
        (false, true) => t!("nat.change_port").to_string(),
        (false, false) => "-".into(),
    }
}

fn outcome_label(outcome: &str) -> String {
    let key = match outcome {
        "no-response" => "nat.outcome_no_response",
        "mapped" => "nat.outcome_mapped",
        "unsupported-server" => "nat.outcome_unsupported",
        "responded" => "nat.outcome_responded",
        "mapping-changed" => "nat.outcome_mapping_changed",
        "mapping-unchanged" => "nat.outcome_mapping_unchanged",
        "alternate-endpoint-response" => "nat.outcome_alternate_endpoint",
        "alternate-port-response" => "nat.outcome_alternate_port",
        "no-alternate-port-response" => "nat.outcome_no_alternate_port",
        "unexpected-source" => "nat.outcome_unexpected_source",
        "no-mapped-address" => "nat.outcome_no_mapped",
        "mapping-changed-again" => "nat.outcome_mapping_changed_again",
        _ => return outcome.to_string(),
    };
    t!(key).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explanation_keys_cover_every_type() {
        for nat_type in [
            NatType::Unknown,
            NatType::UnsupportedServer,
            NatType::UdpBlocked,
            NatType::OpenInternet,
            NatType::SymmetricUdpFirewall,
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::PortRestrictedCone,
            NatType::Symmetric,
        ] {
            let (what, advice) = explanation_keys(nat_type);
            assert!(!what.is_empty());
            assert!(!advice.is_empty());
        }
    }

    #[test]
    fn change_label_uses_dash_when_nothing_changes() {
        assert_eq!(change_label(false, false), "-");
        assert!(!change_label(true, true).is_empty());
    }
}
