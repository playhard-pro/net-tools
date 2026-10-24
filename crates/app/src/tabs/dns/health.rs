//! Domain health check sub-tool.

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{DomainHealthSettings, InputHistory};
use net_tools_core::control::TaskState;
use net_tools_core::model::{DnsDnssecStatus, DomainHealthReport, HealthSeverity};
use rust_i18n::t;

use super::DnsTab;
use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::table_fixed_rows_with_columns;
use crate::ui::theme::Palette;

const DOMAIN_HISTORY_KEY: &str = "dns.health.domain";
const SERVER_HISTORY_KEY: &str = "dns.health.server";

pub(super) fn ui(
    tab: &mut DnsTab,
    ui: &mut egui::Ui,
    s: &mut DomainHealthSettings,
    history: &mut InputHistory,
    rt: &tokio::runtime::Handle,
    settings_expanded: bool,
) -> bool {
    let (submit, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
        ui.heading(t!("common.settings"));
        let mut submit = false;
        egui::Grid::new("dns_health_settings")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label(t!("dns.health.domain"));
                if history_input::singleline(ui, DOMAIN_HISTORY_KEY, &mut s.domain, history, 160.0)
                {
                    submit = true;
                }
                ui.end_row();
                ui.label(t!("dns.protocol"));
                super::protocol_selector(ui, &mut s.protocol);
                ui.end_row();
                ui.label(t!("dns.server"));
                let presets = super::query::server_presets(s.protocol);
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
                ui.label(t!("dns.health.dkim_selectors"));
                ui.add(
                    egui::TextEdit::singleline(&mut s.dkim_selectors)
                        .desired_width(160.0)
                        .hint_text(t!("dns.health.selectors_hint")),
                );
                ui.end_row();
                ui.label(t!("common.timeout_ms"));
                ui.add(
                    egui::DragValue::new(&mut s.timeout_ms)
                        .range(100..=120_000)
                        .suffix(" ms"),
                );
                ui.end_row();
                ui.label(t!("common.concurrency"));
                ui.add(egui::DragValue::new(&mut s.concurrency).range(1..=4));
                ui.end_row();
            });
        ui.add_space(6.0);
        ui.label(egui::RichText::new(t!("dns.health.checks")).strong());
        egui::Grid::new("dns_health_checks")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                check(ui, &mut s.check_mx, "dns.health.check_mx");
                check(ui, &mut s.check_spf, "dns.health.check_spf");
                check(ui, &mut s.check_dkim, "dns.health.check_dkim");
                check(ui, &mut s.check_dmarc, "dns.health.check_dmarc");
                check(ui, &mut s.check_ptr, "dns.health.check_ptr");
                check(ui, &mut s.check_caa, "dns.health.check_caa");
                check(ui, &mut s.check_ns_soa, "dns.health.check_ns_soa");
                check(ui, &mut s.check_dnssec, "dns.health.check_dnssec");
            });
        ui.weak(t!("dns.health.hint"));

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            match tab.health_ctrl.state {
                TaskState::Idle | TaskState::Finished => {
                    if ui.button(t!("common.start")).clicked() {
                        history_input::record_fields(
                            history,
                            &[
                                (DOMAIN_HISTORY_KEY, &s.domain),
                                (SERVER_HISTORY_KEY, &s.server),
                            ],
                        );
                        start(tab, s, rt);
                    }
                }
                TaskState::Running => {
                    if ui.button(t!("common.stop")).clicked() {
                        tab.health_ctrl.stop();
                    }
                }
                TaskState::Paused => {
                    if ui.button(t!("common.resume")).clicked() {
                        tab.health_ctrl.resume();
                    }
                    if ui.button(t!("common.stop")).clicked() {
                        tab.health_ctrl.stop();
                    }
                }
                TaskState::Stopping => {
                    ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
                }
            }
            state_badge(ui, tab.health_ctrl.state);
        });
        if let Some((message, hint)) = &tab.error {
            error_banner(ui, message, hint.as_deref());
        }
        submit
    });

    if submit == Some(true) {
        start(tab, s, rt);
    }

    crate::ui::layout::results_panel(ui, |ui| {
        toolbar(tab, ui);
        if let Some(report) = tab.health.clone() {
            summary(ui, &report);
            ui.add_space(6.0);
            categories(ui, &report);
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(t!("dns.health.details_count", count = report.issues.len()))
                    .strong(),
            );
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .id_salt("dns_health_issues")
                .auto_shrink([false, false])
                .show(ui, |ui| issues(ui, &report));
        } else if !tab.health_ctrl.is_active() {
            ui.weak(t!("dns.empty_health"));
        }
    });
    expanded
}

fn check(ui: &mut egui::Ui, value: &mut bool, label: &str) {
    ui.label(t!(label));
    ui.checkbox(value, "");
    ui.end_row();
}

fn start(tab: &mut DnsTab, s: &DomainHealthSettings, rt: &tokio::runtime::Handle) {
    if tab.health_ctrl.is_active() {
        tab.health_ctrl.stop();
    }
    tab.error = None;
    tab.health = None;
    tab.progress = None;
    let settings = s.clone();
    tab.health_ctrl.start(rt, move |handle| async move {
        net_tools_core::net::dns_tool::run_health(&handle, &settings).await;
    });
}

fn toolbar(tab: &mut DnsTab, ui: &mut egui::Ui) {
    match result_toolbar(ui) {
        ToolbarAction::Copy => ui.ctx().copy_text(tab.health_csv()),
        ToolbarAction::ExportCsv => {
            crate::ui::export::save_file("dns-health", "csv", &tab.health_csv())
        }
        ToolbarAction::ExportJson => {
            crate::ui::export::save_file("dns-health", "json", &tab.health_json())
        }
        ToolbarAction::ExportHtml => {
            crate::ui::export::save_file("dns-health", "html", &tab.health_html())
        }
        ToolbarAction::Clear => {
            tab.health = None;
            tab.error = None;
        }
        ToolbarAction::None => {}
    }
}

fn summary(ui: &mut egui::Ui, report: &DomainHealthReport) {
    let palette = Palette::from_ui(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label(t!(
            "dns.health.summary",
            domain = report.domain.clone(),
            time = report.elapsed_ms
        ));
        ui.colored_label(
            severity_color(&palette, report.severity),
            t!(
                "dns.health.severity",
                severity = severity_label(report.severity)
            ),
        );
        if let Some(dnssec) = &report.dnssec {
            ui.label(format!("DNSSEC: {}", dnssec.status.label()));
        }
    });
}

fn categories(ui: &mut egui::Ui, report: &DomainHealthReport) {
    let palette = Palette::from_ui(ui);
    // Keep the summary table compact so the detailed findings below remain
    // visible instead of being pushed out of the results panel.
    let visible_rows = report.categories.len().clamp(1, 8);
    table_fixed_rows_with_columns(
        ui,
        &[
            t!("dns.health.columns.category").to_string(),
            t!("dns.health.columns.status").to_string(),
            t!("dns.health.columns.summary").to_string(),
        ],
        report.categories.len(),
        visible_rows,
        [
            Column::auto().at_least(100.0).at_most(160.0),
            Column::exact(90.0),
            Column::remainder().at_least(160.0),
        ],
        |index, row| {
            let category = &report.categories[index];
            row.col(|ui| {
                ui.label(category_label(&category.category));
            });
            row.col(|ui| {
                ui.colored_label(
                    severity_color(&palette, category.severity),
                    severity_label(category.severity),
                );
            });
            row.col(|ui| {
                ui.label(&category.summary);
            });
        },
    );
}

fn issues(ui: &mut egui::Ui, report: &DomainHealthReport) {
    if report.issues.is_empty() {
        ui.weak(t!("dns.health.no_findings"));
        return;
    }
    let palette = Palette::from_ui(ui);
    for finding in &report.issues {
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                severity_color(&palette, finding.severity),
                format!("[{}]", severity_label(finding.severity)),
            );
            ui.label(egui::RichText::new(category_label(&finding.category)).strong());
            ui.label(&finding.title);
        });
        if !finding.detail.is_empty() {
            ui.label(&finding.detail);
        }
        if let Some(advice) = &finding.advice {
            ui.weak(advice);
        }
        for evidence in &finding.evidence {
            ui.label(egui::RichText::new(evidence).monospace());
        }
        ui.add_space(4.0);
        ui.separator();
    }
}

fn severity_label(severity: HealthSeverity) -> &'static str {
    match severity {
        HealthSeverity::Error => "error",
        HealthSeverity::Warning => "warning",
        HealthSeverity::Ok => "ok",
        HealthSeverity::Info => "info",
    }
}

fn severity_color(palette: &Palette, severity: HealthSeverity) -> egui::Color32 {
    match severity {
        HealthSeverity::Error => palette.error_text,
        HealthSeverity::Warning => palette.warning_text,
        HealthSeverity::Ok => palette.success_text,
        HealthSeverity::Info => palette.info_text,
    }
}

fn category_label(category: &str) -> String {
    match category {
        "mx" => t!("dns.health.category.mx").to_string(),
        "spf" => t!("dns.health.category.spf").to_string(),
        "dkim" => t!("dns.health.category.dkim").to_string(),
        "dmarc" => t!("dns.health.category.dmarc").to_string(),
        "ptr" => t!("dns.health.category.ptr").to_string(),
        "caa" => t!("dns.health.category.caa").to_string(),
        "ns_soa" => t!("dns.health.category.ns_soa").to_string(),
        "dnssec" => t!("dns.health.category.dnssec").to_string(),
        other => other.to_string(),
    }
}

impl DnsTab {
    pub fn health_csv(&self) -> String {
        let mut out = String::from("domain,severity,category,title,detail,evidence,advice\n");
        if let Some(report) = &self.health {
            for issue in &report.issues {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    crate::ui::export::csv_field(&report.domain),
                    severity_label(issue.severity),
                    crate::ui::export::csv_field(&issue.category),
                    crate::ui::export::csv_field(&issue.title),
                    crate::ui::export::csv_field(&issue.detail),
                    crate::ui::export::csv_field(&issue.evidence.join("; ")),
                    crate::ui::export::csv_field(issue.advice.as_deref().unwrap_or_default()),
                ));
            }
        }
        out
    }

    pub fn health_json(&self) -> String {
        serde_json::to_string_pretty(&self.health).unwrap_or_else(|_| "{}".into())
    }

    pub fn health_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.health_csv())
    }
}

// Keep the import used even when DNSSEC is disabled; the report type is part of
// the exported JSON shape.
#[allow(dead_code)]
fn _dnssec_status_label(status: DnsDnssecStatus) -> &'static str {
    status.label()
}
