//! Resolver latency benchmark sub-tool.

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{DnsBenchmarkSettings, InputHistory};
use net_tools_core::control::TaskState;
use net_tools_core::model::DnsBenchmarkReport;
use rust_i18n::t;

use super::{protocol_selector, resolver_editor, DnsTab};
use crate::ui::chart::resolver_latency_chart;
use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::{cell_with_tooltip, table_selectable_with_columns};
use crate::ui::theme::Palette;

const TARGET_HISTORY_KEY: &str = "dns.benchmark.target";
const VISIBLE_ROWS: usize = 10;

pub(super) fn ui(
    tab: &mut DnsTab,
    ui: &mut egui::Ui,
    s: &mut DnsBenchmarkSettings,
    history: &mut InputHistory,
    rt: &tokio::runtime::Handle,
    settings_expanded: bool,
) -> bool {
    let (submit, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
        ui.heading(t!("common.settings"));
        let mut submit = false;
        egui::Grid::new("dns_benchmark_settings")
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
                ui.label(t!("dns.benchmark.samples"));
                ui.add(egui::DragValue::new(&mut s.samples).range(1..=20));
                ui.end_row();
                ui.label(t!("dns.benchmark.interval"));
                ui.add(
                    egui::DragValue::new(&mut s.interval_ms)
                        .range(100..=5000)
                        .suffix(" ms"),
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
        ui.label(egui::RichText::new(t!("dns.resolvers.title")).strong());
        resolver_editor::ui(ui, s.protocol, &mut s.resolvers, &mut s.custom);
        ui.weak(t!("dns.benchmark.hint"));

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            match tab.benchmark_ctrl.state {
                TaskState::Idle | TaskState::Finished => {
                    if ui.button(t!("common.start")).clicked() {
                        history_input::record_fields(history, &[(TARGET_HISTORY_KEY, &s.target)]);
                        start(tab, s, rt);
                    }
                }
                TaskState::Running => {
                    if ui.button(t!("common.stop")).clicked() {
                        tab.benchmark_ctrl.stop();
                    }
                }
                TaskState::Paused => {
                    if ui.button(t!("common.resume")).clicked() {
                        tab.benchmark_ctrl.resume();
                    }
                    if ui.button(t!("common.stop")).clicked() {
                        tab.benchmark_ctrl.stop();
                    }
                }
                TaskState::Stopping => {
                    ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
                }
            }
            state_badge(ui, tab.benchmark_ctrl.state);
        });
        progress_ui(ui, tab.progress.as_ref());
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
        progress_ui(ui, tab.progress.as_ref());
        if let Some(report) = tab.benchmark.clone() {
            summary(ui, &report);
            ui.add_space(6.0);
            table(tab, ui, &report);
            let chart_values: Vec<(String, f64)> = report
                .rows
                .iter()
                .filter(|row| row.success > 0)
                .map(|row| (row.resolver.label.clone(), row.avg_ms))
                .collect();
            if !chart_values.is_empty() {
                ui.add_space(8.0);
                resolver_latency_chart(ui, "dns_benchmark_chart", &chart_values, 180.0);
            }
            if let Some(row) = tab
                .benchmark_selected
                .and_then(|index| report.rows.get(index))
            {
                ui.add_space(8.0);
                detail(ui, row);
            }
        } else if !tab.benchmark_ctrl.is_active() {
            ui.weak(t!("dns.empty_benchmark"));
        }
    });
    expanded
}

fn start(tab: &mut DnsTab, s: &DnsBenchmarkSettings, rt: &tokio::runtime::Handle) {
    if tab.benchmark_ctrl.is_active() {
        tab.benchmark_ctrl.stop();
    }
    tab.error = None;
    tab.benchmark = None;
    tab.benchmark_selected = None;
    tab.progress = None;
    let settings = s.clone();
    tab.benchmark_ctrl.start(rt, move |handle| async move {
        net_tools_core::net::dns_tool::run_benchmark(&handle, &settings).await;
    });
}

fn toolbar(tab: &mut DnsTab, ui: &mut egui::Ui) {
    match result_toolbar(ui) {
        ToolbarAction::Copy => ui.ctx().copy_text(tab.benchmark_csv()),
        ToolbarAction::ExportCsv => {
            crate::ui::export::save_file("dns-benchmark", "csv", &tab.benchmark_csv())
        }
        ToolbarAction::ExportJson => {
            crate::ui::export::save_file("dns-benchmark", "json", &tab.benchmark_json())
        }
        ToolbarAction::ExportHtml => {
            crate::ui::export::save_file("dns-benchmark", "html", &tab.benchmark_html())
        }
        ToolbarAction::Clear => {
            tab.benchmark = None;
            tab.benchmark_selected = None;
            tab.error = None;
            tab.progress = None;
        }
        ToolbarAction::None => {}
    }
}

/// Draw the shared benchmark progress bar and its counter.
fn progress_ui(ui: &mut egui::Ui, progress: Option<&net_tools_core::model::DnsRunProgress>) {
    let Some(progress) = progress else {
        return;
    };
    let fraction = if progress.total == 0 {
        0.0
    } else {
        progress.done as f32 / progress.total as f32
    };
    ui.add(
        egui::ProgressBar::new(fraction)
            .desired_width(ui.available_width())
            .show_percentage(),
    );
    ui.weak(t!(
        "dns.progress",
        done = progress.done,
        total = progress.total,
        current = progress.current.clone()
    ));
    ui.add_space(4.0);
}

fn summary(ui: &mut egui::Ui, report: &DnsBenchmarkReport) {
    ui.horizontal_wrapped(|ui| {
        ui.label(t!(
            "dns.benchmark.summary",
            target = report.target.clone(),
            samples = report.samples,
            count = report.rows.len()
        ));
        if let Some(best) = report.rows.first() {
            ui.label(t!(
                "dns.benchmark.best",
                resolver = best.resolver.label.clone(),
                avg = format!("{:.1}", best.avg_ms)
            ));
        }
    });
}

fn table(tab: &mut DnsTab, ui: &mut egui::Ui, report: &DnsBenchmarkReport) {
    let palette = Palette::from_ui(ui);
    let headers = [
        t!("dns.propagation.columns.resolver").to_string(),
        t!("dns.benchmark.columns.success").to_string(),
        t!("dns.benchmark.columns.fail").to_string(),
        t!("dns.benchmark.columns.avg").to_string(),
        "P50".to_string(),
        "P95".to_string(),
        t!("dns.benchmark.columns.min").to_string(),
        t!("dns.benchmark.columns.max").to_string(),
        t!("dns.benchmark.columns.stddev").to_string(),
        "TTL".to_string(),
    ];
    let columns = [
        Column::auto().at_least(120.0).at_most(220.0).clip(true),
        Column::exact(60.0),
        Column::exact(54.0),
        Column::exact(70.0),
        Column::exact(64.0),
        Column::exact(64.0),
        Column::exact(64.0),
        Column::exact(64.0),
        Column::exact(64.0),
        Column::exact(64.0),
    ];
    let clicked = table_selectable_with_columns(
        ui,
        &headers,
        report.rows.len(),
        VISIBLE_ROWS,
        tab.benchmark_selected,
        columns,
        |index, row| {
            let item = &report.rows[index];
            row.col(|ui| {
                if item.error.is_some() {
                    ui.colored_label(palette.error_text, &item.resolver.label);
                } else {
                    cell_with_tooltip(ui, &item.resolver.label, &item.resolver.endpoint);
                }
            });
            row.col(|ui| {
                ui.label(item.success.to_string());
            });
            row.col(|ui| {
                if item.failure > 0 {
                    ui.colored_label(palette.warning_text, item.failure.to_string());
                } else {
                    ui.label("0");
                }
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", item.avg_ms));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", item.p50_ms));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", item.p95_ms));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", item.min_ms));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", item.max_ms));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", item.stddev_ms));
            });
            row.col(|ui| {
                ui.label(
                    item.avg_ttl
                        .map(|ttl| format!("{ttl:.0}"))
                        .unwrap_or_else(|| "-".into()),
                );
            });
        },
    );
    if let Some(index) = clicked {
        tab.benchmark_selected = Some(index);
    }
}

fn detail(ui: &mut egui::Ui, row: &net_tools_core::model::DnsBenchmarkRow) {
    ui.separator();
    egui::Grid::new("dns_benchmark_detail")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label(t!("dns.propagation.columns.resolver"));
            ui.label(&row.resolver.label);
            ui.end_row();
            ui.label(t!("dns.server"));
            ui.label(&row.resolver.endpoint);
            ui.end_row();
            ui.label(t!("dns.protocol"));
            ui.label(row.resolver.protocol.label());
            ui.end_row();
        });
    if let Some(error) = &row.error {
        error_banner(ui, error, None);
    }
}

impl DnsTab {
    pub fn benchmark_csv(&self) -> String {
        let mut out = String::from(
            "resolver,endpoint,protocol,success,failure,min_ms,avg_ms,p50_ms,p95_ms,max_ms,stddev_ms,avg_ttl,error\n",
        );
        if let Some(report) = &self.benchmark {
            for row in &report.rows {
                out.push_str(&format!(
                    "{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{}\n",
                    crate::ui::export::csv_field(&row.resolver.label),
                    crate::ui::export::csv_field(&row.resolver.endpoint),
                    row.resolver.protocol.label(),
                    row.success,
                    row.failure,
                    row.min_ms,
                    row.avg_ms,
                    row.p50_ms,
                    row.p95_ms,
                    row.max_ms,
                    row.stddev_ms,
                    row.avg_ttl
                        .map(|ttl| format!("{ttl:.1}"))
                        .unwrap_or_default(),
                    crate::ui::export::csv_field(row.error.as_deref().unwrap_or_default()),
                ));
            }
        }
        out
    }

    pub fn benchmark_json(&self) -> String {
        serde_json::to_string_pretty(&self.benchmark).unwrap_or_else(|_| "{}".into())
    }

    pub fn benchmark_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.benchmark_csv())
    }
}
