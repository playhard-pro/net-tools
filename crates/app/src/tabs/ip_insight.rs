//! IP insight tab: query a target IP against several online APIs and render
//! each provider's JSON response as its own key/value table.

use eframe::egui;
use net_tools_core::config::IpInsightSettings;
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{IpInsightResult, ProbeEvent};
use net_tools_core::net::ip_insight::{flatten_json, IP_API_PROVIDERS};
use rust_i18n::t;

use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::result_table::key_value_table;

pub struct IpInsightTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub results: Vec<IpInsightResult>,
    pub error: Option<(String, Option<String>)>,
}

impl Default for IpInsightTab {
    fn default() -> Self {
        Self::new()
    }
}

impl IpInsightTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            results: Vec::new(),
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.results.clear();
        self.error = None;
    }

    pub fn start(&mut self, s: &IpInsightSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.restart(s, rt);
    }

    /// Stop the current query (if any) and start a fresh one, so pressing Enter
    /// in the target input re-queries without an explicit stop.
    pub fn restart(&mut self, s: &IpInsightSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        // Pre-create one slot per provider so table order stays stable while
        // the responses arrive out of order.
        self.results = IP_API_PROVIDERS
            .iter()
            .map(|p| IpInsightResult::pending(p.name))
            .collect();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            net_tools_core::net::ip_insight::run_ip_insight(&handle, &settings).await;
        });
    }

    pub fn drain(&mut self) {
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::IpInsight(r) => {
                    if let Some(slot) = self.results.iter_mut().find(|x| x.provider == r.provider) {
                        *slot = r;
                    } else {
                        self.results.push(r);
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
        s: &mut IpInsightSettings,
        rt: &tokio::runtime::Handle,
    ) {
        self.drain();
        if self.ctrl.is_active() {
            // Keep repainting while a query runs so results appear as they land.
            ui.ctx().request_repaint();
        }

        let mut submit = false;
        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("ip_insight_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.target"));
                        let target =
                            ui.add(egui::TextEdit::singleline(&mut s.target).desired_width(240.0));
                        if target.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
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
            self.restart(s, rt);
        }

        ui.horizontal(|ui| {
            self.control_row(ui, s, rt);
            state_badge(ui, self.ctrl.state);
        });

        if let Some((msg, hint)) = &self.error {
            error_banner(ui, msg, hint.as_deref());
        }

        ui.separator();

        // Result toolbar lives below the divider, together with the results it
        // acts on.
        self.toolbar(ui);
        self.results_ui(ui);
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        s: &IpInsightSettings,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            TaskState::Idle | TaskState::Finished => {
                if ui.button(t!("ip_insight.query")).clicked() {
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

    /// Render one heading + table per provider, separated by dividers.
    fn results_ui(&self, ui: &mut egui::Ui) {
        if self.results.is_empty() {
            return;
        }
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (index, result) in self.results.iter().enumerate() {
                    if index > 0 {
                        ui.separator();
                    }
                    provider_ui(ui, result);
                }
            });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("ip-insight", "csv", &self.to_csv())
            }
            ToolbarAction::ExportJson => {
                crate::ui::export::save_file("ip-insight", "json", &self.to_json())
            }
            ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("ip-insight", "html", &self.to_html())
            }
            ToolbarAction::Clear => self.reset(),
            ToolbarAction::None => {}
        }
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from("provider,key,value\n");
        for result in &self.results {
            if let Some(data) = &result.data {
                for (key, value) in flatten_json(data) {
                    out.push_str(&format!(
                        "{},{},{}\n",
                        crate::ui::export::csv_field(&result.provider),
                        crate::ui::export::csv_field(&key),
                        crate::ui::export::csv_field(&value),
                    ));
                }
            } else if let Some(error) = &result.error {
                out.push_str(&format!(
                    "{},{},{}\n",
                    crate::ui::export::csv_field(&result.provider),
                    crate::ui::export::csv_field("error"),
                    crate::ui::export::csv_field(error),
                ));
            }
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

/// Draw a single provider's heading, status line and key/value table.
fn provider_ui(ui: &mut egui::Ui, result: &IpInsightResult) {
    ui.horizontal(|ui| {
        ui.heading(&result.provider);
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

    if let Some(error) = &result.error {
        ui.colored_label(egui::Color32::from_rgb(255, 130, 130), error);
    }
    if let Some(data) = &result.data {
        let rows = flatten_json(data);
        key_value_table(
            ui,
            (&result.provider, "kv"),
            &t!("ip_insight.key"),
            &t!("ip_insight.value"),
            &rows,
        );
    } else if result.is_pending() {
        ui.label(t!("ip_insight.pending"));
    }
    if let Some(raw) = &result.raw {
        ui.label(egui::RichText::new(raw).monospace());
    }
    if !result.url.is_empty() {
        ui.label(egui::RichText::new(&result.url).weak().small());
    }
}
