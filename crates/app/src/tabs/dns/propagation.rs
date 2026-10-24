//! DNS propagation comparison sub-tool.

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{DnsPropagationSettings, InputHistory};
use net_tools_core::control::TaskState;
use net_tools_core::model::DnsPropagationReport;
use rust_i18n::t;

use super::{protocol_selector, resolver_editor, DnsTab};
use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::{cell_with_tooltip, table_selectable_with_columns};
use crate::ui::theme::Palette;

const TARGET_HISTORY_KEY: &str = "dns.propagation.target";
const VISIBLE_ROWS: usize = 10;

pub(super) fn ui(
    tab: &mut DnsTab,
    ui: &mut egui::Ui,
    s: &mut DnsPropagationSettings,
    history: &mut InputHistory,
    rt: &tokio::runtime::Handle,
    settings_expanded: bool,
) -> bool {
    let (submit, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
        ui.heading(t!("common.settings"));
        let mut submit = false;
        egui::Grid::new("dns_propagation_settings")
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
                super::query::record_type_input(ui, &mut s.record_type);
                ui.end_row();
                ui.label(t!("dns.protocol"));
                protocol_selector(ui, &mut s.protocol);
                ui.end_row();
                ui.label(t!("common.timeout_ms"));
                ui.add(
                    egui::DragValue::new(&mut s.timeout_ms)
                        .range(100..=120_000)
                        .suffix(" ms"),
                );
                ui.end_row();
                ui.label(t!("common.concurrency"));
                ui.add(egui::DragValue::new(&mut s.concurrency).range(1..=8));
                ui.end_row();
            });
        ui.add_space(6.0);
        ui.label(egui::RichText::new(t!("dns.resolvers.title")).strong());
        resolver_editor::ui(ui, s.protocol, &mut s.resolvers, &mut s.custom);

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            match tab.propagation_ctrl.state {
                TaskState::Idle | TaskState::Finished => {
                    if ui.button(t!("common.start")).clicked() {
                        history_input::record_fields(history, &[(TARGET_HISTORY_KEY, &s.target)]);
                        start(tab, s, rt);
                    }
                }
                TaskState::Running => {
                    if ui.button(t!("common.stop")).clicked() {
                        tab.propagation_ctrl.stop();
                    }
                }
                TaskState::Paused => {
                    if ui.button(t!("common.resume")).clicked() {
                        tab.propagation_ctrl.resume();
                    }
                    if ui.button(t!("common.stop")).clicked() {
                        tab.propagation_ctrl.stop();
                    }
                }
                TaskState::Stopping => {
                    ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
                }
            }
            state_badge(ui, tab.propagation_ctrl.state);
        });
        if let Some(progress) = &tab.progress {
            ui.weak(t!(
                "dns.progress",
                done = progress.done,
                total = progress.total,
                current = progress.current.clone()
            ));
        }
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
        if let Some(report) = tab.propagation.clone() {
            summary(ui, &report);
            ui.add_space(6.0);
            table(tab, ui, &report);
            if let Some(result) = tab
                .propagation_selected
                .and_then(|index| report.results.get(index))
            {
                ui.add_space(8.0);
                detail(ui, result);
            }
        } else if !tab.propagation_ctrl.is_active() {
            ui.weak(t!("dns.empty_propagation"));
        }
    });
    expanded
}

fn start(tab: &mut DnsTab, s: &DnsPropagationSettings, rt: &tokio::runtime::Handle) {
    if tab.propagation_ctrl.is_active() {
        tab.propagation_ctrl.stop();
    }
    tab.error = None;
    tab.propagation = None;
    tab.propagation_selected = None;
    tab.progress = None;
    let settings = s.clone();
    tab.propagation_ctrl.start(rt, move |handle| async move {
        net_tools_core::net::dns_tool::run_propagation(&handle, &settings).await;
    });
}

fn toolbar(tab: &mut DnsTab, ui: &mut egui::Ui) {
    match result_toolbar(ui) {
        ToolbarAction::Copy => ui.ctx().copy_text(tab.propagation_csv()),
        ToolbarAction::ExportCsv => {
            crate::ui::export::save_file("dns-propagation", "csv", &tab.propagation_csv())
        }
        ToolbarAction::ExportJson => {
            crate::ui::export::save_file("dns-propagation", "json", &tab.propagation_json())
        }
        ToolbarAction::ExportHtml => {
            crate::ui::export::save_file("dns-propagation", "html", &tab.propagation_html())
        }
        ToolbarAction::Clear => {
            tab.propagation = None;
            tab.propagation_selected = None;
            tab.error = None;
            tab.progress = None;
        }
        ToolbarAction::None => {}
    }
}

fn summary(ui: &mut egui::Ui, report: &DnsPropagationReport) {
    ui.horizontal_wrapped(|ui| {
        ui.label(t!(
            "dns.propagation.summary.consistent",
            consistent = report.consistent,
            total = report.total
        ));
        ui.label(t!(
            "dns.propagation.summary.groups",
            count = report.groups.len()
        ));
        if report.failed > 0 {
            let palette = Palette::from_ui(ui);
            ui.colored_label(
                palette.error_text,
                t!("dns.propagation.summary.failed", count = report.failed),
            );
        }
    });
}

fn table(tab: &mut DnsTab, ui: &mut egui::Ui, report: &DnsPropagationReport) {
    let palette = Palette::from_ui(ui);
    let consensus = report.groups.first().map(|group| group.key.as_str());
    let headers = [
        t!("dns.propagation.columns.resolver").to_string(),
        t!("dns.propagation.columns.status").to_string(),
        t!("dns.propagation.columns.answers").to_string(),
        t!("dns.propagation.columns.ttl").to_string(),
        t!("dns.propagation.columns.time").to_string(),
        t!("dns.propagation.columns.dnssec").to_string(),
    ];
    let columns = [
        Column::auto().at_least(120.0).at_most(220.0).clip(true),
        Column::auto().at_least(70.0).at_most(120.0).clip(true),
        Column::remainder().at_least(200.0),
        Column::exact(64.0),
        Column::exact(72.0),
        Column::auto().at_least(80.0).at_most(120.0).clip(true),
    ];
    let clicked = table_selectable_with_columns(
        ui,
        &headers,
        report.results.len(),
        VISIBLE_ROWS,
        tab.propagation_selected,
        columns,
        |index, row| {
            let result = &report.results[index];
            let differs = result.error.is_none()
                && consensus.is_some()
                && Some(result.answer_key().as_str()) != consensus;
            row.col(|ui| {
                let text = &result.resolver.label;
                if differs {
                    ui.colored_label(palette.warning_text, text);
                } else {
                    cell_with_tooltip(ui, text, &result.resolver.endpoint);
                }
            });
            row.col(|ui| match &result.error {
                Some(error) => {
                    ui.colored_label(palette.error_text, t!("dns.propagation.error"))
                        .on_hover_text(error);
                }
                None => {
                    ui.label(result.response_code.clone().unwrap_or_default());
                }
            });
            row.col(|ui| {
                let text = if result.answers.is_empty() {
                    "-".to_string()
                } else {
                    result.answers.join("; ")
                };
                cell_with_tooltip(ui, &text, &text);
            });
            row.col(|ui| {
                ui.label(
                    result
                        .avg_ttl
                        .map(|ttl| ttl.to_string())
                        .unwrap_or_else(|| "-".into()),
                );
            });
            row.col(|ui| {
                ui.label(format!("{} ms", result.elapsed_ms));
            });
            row.col(|ui| {
                ui.label(if result.ad { "AD" } else { "-" });
            });
        },
    );
    if let Some(index) = clicked {
        tab.propagation_selected = Some(index);
    }
}

fn detail(ui: &mut egui::Ui, result: &net_tools_core::model::DnsResolverResult) {
    ui.separator();
    egui::Grid::new("dns_propagation_detail")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label(t!("dns.propagation.columns.resolver"));
            ui.label(&result.resolver.label);
            ui.end_row();
            ui.label(t!("dns.server"));
            ui.label(&result.resolver.endpoint);
            ui.end_row();
            ui.label(t!("dns.protocol"));
            ui.label(result.resolver.protocol.label());
            ui.end_row();
        });
    if let Some(error) = &result.error {
        error_banner(ui, error, None);
    } else {
        for answer in &result.answers {
            ui.label(egui::RichText::new(answer).monospace());
        }
    }
}

impl DnsTab {
    pub fn propagation_csv(&self) -> String {
        let mut out =
            String::from("resolver,endpoint,protocol,status,answers,ttl,time_ms,ad,error\n");
        if let Some(report) = &self.propagation {
            for result in &report.results {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    crate::ui::export::csv_field(&result.resolver.label),
                    crate::ui::export::csv_field(&result.resolver.endpoint),
                    result.resolver.protocol.label(),
                    crate::ui::export::csv_field(
                        result.response_code.as_deref().unwrap_or_default()
                    ),
                    crate::ui::export::csv_field(&result.answers.join("; ")),
                    result
                        .avg_ttl
                        .map(|ttl| ttl.to_string())
                        .unwrap_or_default(),
                    result.elapsed_ms,
                    result.ad,
                    crate::ui::export::csv_field(result.error.as_deref().unwrap_or_default()),
                ));
            }
        }
        out
    }

    pub fn propagation_json(&self) -> String {
        serde_json::to_string_pretty(&self.propagation).unwrap_or_else(|_| "{}".into())
    }

    pub fn propagation_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.propagation_csv())
    }
}
