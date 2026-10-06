//! Lookup tab: query a domain or IP address through RDAP and render the JSON
//! response as a tree that is fully expanded by default.

use eframe::egui;
use net_tools_core::config::{InputHistory, LookupSettings};
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{LookupResult, ProbeEvent};
use net_tools_core::net::ip_insight::flatten_json;
use rust_i18n::t;

use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;

/// History bucket for the target input.
const TARGET_HISTORY_KEY: &str = "lookup.target";
/// Color used for object keys and container labels.
const KEY_COLOR: egui::Color32 = egui::Color32::from_rgb(120, 180, 255);
/// Color used for string values.
const STRING_COLOR: egui::Color32 = egui::Color32::from_rgb(140, 220, 140);
/// Color used for numeric values.
const NUMBER_COLOR: egui::Color32 = egui::Color32::from_rgb(230, 180, 120);
/// Color used for boolean values.
const BOOL_COLOR: egui::Color32 = egui::Color32::from_rgb(200, 150, 230);
/// Color used for `null`.
const NULL_COLOR: egui::Color32 = egui::Color32::GRAY;

pub struct LookupTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub result: Option<LookupResult>,
    pub error: Option<(String, Option<String>)>,
    /// Bumped for every query so the tree's collapse state starts fresh.
    query_id: u64,
}

impl Default for LookupTab {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            result: None,
            error: None,
            query_id: 0,
        }
    }

    pub fn reset(&mut self) {
        self.result = None;
        self.error = None;
    }

    pub fn start(&mut self, s: &LookupSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.restart(s, rt);
    }

    /// Stop any running query and start a fresh one, so pressing Enter in the
    /// target input re-queries without an explicit stop.
    pub fn restart(&mut self, s: &LookupSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        // A new query id forces the tree to be rebuilt with all nodes expanded.
        self.query_id = self.query_id.wrapping_add(1);
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            net_tools_core::net::rdap::run_lookup(&handle, &settings).await;
        });
    }

    pub fn drain(&mut self) {
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::Lookup(r) => self.result = Some(r),
                ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut LookupSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        self.drain();
        if self.ctrl.is_active() {
            // Keep repainting while the request is in flight.
            ui.ctx().request_repaint();
        }

        let mut submit = false;
        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("lookup_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.target"));
                        if history_input::singleline(
                            ui,
                            "lookup.target",
                            &mut s.target,
                            history,
                            320.0,
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
                    });
            });
        if submit {
            history_input::record_fields(history, &[(TARGET_HISTORY_KEY, &s.target)]);
            self.restart(s, rt);
        }

        ui.horizontal(|ui| {
            self.control_row(ui, s, history, rt);
            state_badge(ui, self.ctrl.state);
        });

        if let Some((msg, hint)) = &self.error {
            error_banner(ui, msg, hint.as_deref());
        }

        ui.separator();

        self.toolbar(ui);
        self.result_ui(ui);
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        s: &LookupSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            TaskState::Idle | TaskState::Finished => {
                if ui.button(t!("lookup.query")).clicked() {
                    history_input::record_fields(history, &[(TARGET_HISTORY_KEY, &s.target)]);
                    self.start(s, rt);
                }
            }
            TaskState::Running => {
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            }
            TaskState::Paused => {
                if ui.button(t!("common.resume")).clicked() {
                    self.ctrl.resume();
                }
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            }
            TaskState::Stopping => {
                ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
            }
        }
    }

    /// Render the metadata line and the JSON tree of the latest result.
    fn result_ui(&self, ui: &mut egui::Ui) {
        let Some(result) = &self.result else {
            return;
        };

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(&result.target)
                    .heading()
                    .color(KEY_COLOR),
            );
            ui.label(t!("lookup.kind", kind = &result.kind));
            if let Some(status) = result.status {
                ui.label(t!("ip_insight.http_status", code = status));
            }
            if result.elapsed_ms > 0.0 {
                ui.label(t!(
                    "ip_insight.elapsed",
                    ms = format!("{:.0}", result.elapsed_ms)
                ));
            }
        });
        // Explain why the shown target differs from what the user entered.
        if !result.original_target.is_empty() && result.original_target != result.target {
            ui.colored_label(
                egui::Color32::from_rgb(230, 180, 120),
                t!("lookup.fallback", original = &result.original_target),
            );
        }
        if !result.url.is_empty() {
            ui.label(egui::RichText::new(&result.url).weak().small());
        }

        if result.status == Some(404) && result.data.is_none() && result.error.is_none() {
            ui.colored_label(
                egui::Color32::from_rgb(230, 180, 120),
                t!("lookup.not_found"),
            );
        }
        if let Some(error) = &result.error {
            ui.colored_label(egui::Color32::from_rgb(255, 130, 130), error);
        }
        if let Some(raw) = &result.raw {
            ui.label(egui::RichText::new(raw).monospace());
        }

        if let Some(data) = &result.data {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    json_tree(ui, &format!("lookup-{}", self.query_id), "", data, true);
                });
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => {
                if let Some(result) = &self.result {
                    ui.ctx().copy_text(result_json(result));
                }
            }
            ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("lookup", "csv", &self.to_csv())
            }
            ToolbarAction::ExportJson => {
                crate::ui::export::save_file("lookup", "json", &self.to_json())
            }
            ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("lookup", "html", &self.to_html())
            }
            ToolbarAction::Clear => self.reset(),
            ToolbarAction::None => {}
        }
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from("key,value\n");
        if let Some(result) = &self.result {
            if let Some(data) = &result.data {
                for (key, value) in flatten_json(data) {
                    out.push_str(&format!(
                        "{},{}\n",
                        crate::ui::export::csv_field(&key),
                        crate::ui::export::csv_field(&value),
                    ));
                }
            } else if let Some(error) = &result.error {
                out.push_str(&format!("error,{}\n", crate::ui::export::csv_field(error)));
            }
        }
        out
    }

    pub fn to_json(&self) -> String {
        match &self.result {
            Some(result) => serde_json::to_string_pretty(result).unwrap_or_default(),
            None => String::new(),
        }
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}

/// Pretty printed RDAP document, used for the copy action.
fn result_json(result: &LookupResult) -> String {
    match &result.data {
        Some(data) => serde_json::to_string_pretty(data).unwrap_or_default(),
        None => result.raw.clone().unwrap_or_default(),
    }
}

/// Recursively render a JSON value. Containers become collapsible headers, all
/// expanded according to `default_open`; scalars become `key: value` rows.
fn json_tree(
    ui: &mut egui::Ui,
    path: &str,
    label: &str,
    value: &serde_json::Value,
    default_open: bool,
) {
    match value {
        serde_json::Value::Object(map) => {
            let hint = format!("{{{}}}", map.len());
            container_node(ui, path, label, &hint, default_open, |ui| {
                for (key, child) in map {
                    json_tree(ui, &format!("{path}/{key}"), key, child, default_open);
                }
            });
        }
        serde_json::Value::Array(items) => {
            let hint = format!("[{}]", items.len());
            container_node(ui, path, label, &hint, default_open, |ui| {
                array_items(ui, path, items, default_open);
            });
        }
        _ => scalar_row(ui, label, value),
    }
}

/// Render the elements of an array directly, without an intermediate `[i]`
/// node: object fields are pulled up to the array level and scalar elements are
/// shown as bare values (the array header already names the field). Consecutive
/// structured elements are separated so their fields stay visually distinct.
fn array_items(ui: &mut egui::Ui, path: &str, items: &[serde_json::Value], default_open: bool) {
    for (index, child) in items.iter().enumerate() {
        if index > 0 && (child.is_object() || child.is_array()) {
            ui.separator();
        }
        match child {
            serde_json::Value::Object(map) => {
                for (key, grand) in map {
                    json_tree(
                        ui,
                        &format!("{path}/{index}/{key}"),
                        key,
                        grand,
                        default_open,
                    );
                }
            }
            // A nested array is flattened one more level.
            serde_json::Value::Array(nested) => {
                array_items(ui, &format!("{path}/{index}"), nested, default_open);
            }
            // The array header already names the field, so scalar elements are
            // shown without repeating the label.
            _ => scalar_row(ui, "", child),
        }
    }
}

/// Render a collapsible container with a preformatted `{n}` / `[n]` hint.
fn container_node(
    ui: &mut egui::Ui,
    path: &str,
    label: &str,
    hint: &str,
    default_open: bool,
    body: impl FnOnce(&mut egui::Ui),
) {
    let id = ui.make_persistent_id(format!("{path}#node"));
    let state = egui::collapsing_header::CollapsingState::load_with_default_open(
        ui.ctx(),
        id,
        default_open,
    );
    state
        .show_header(ui, |ui| {
            let text = if label.is_empty() {
                hint.to_string()
            } else {
                format!("{label}  {hint}")
            };
            ui.label(egui::RichText::new(text).strong().color(KEY_COLOR));
        })
        .body(|ui| body(ui));
}

/// Render a leaf node as `key: value` with a type dependent color. When the
/// label is empty (for example an array of scalars at the document root) only
/// the value is shown.
fn scalar_row(ui: &mut egui::Ui, label: &str, value: &serde_json::Value) {
    let (text, color) = match value {
        serde_json::Value::String(s) => (format!("\"{s}\""), STRING_COLOR),
        serde_json::Value::Number(n) => (n.to_string(), NUMBER_COLOR),
        serde_json::Value::Bool(b) => (b.to_string(), BOOL_COLOR),
        serde_json::Value::Null => ("null".to_string(), NULL_COLOR),
        // Objects and arrays are handled by `json_tree`, so this is unreachable.
        other => (other.to_string(), NULL_COLOR),
    };
    ui.horizontal(|ui| {
        if !label.is_empty() {
            ui.label(egui::RichText::new(format!("{label}:")).color(KEY_COLOR));
        }
        ui.label(egui::RichText::new(text).monospace().color(color));
    });
}
