//! DNS tab: dig-like single query and iterative trace.

use eframe::egui;
use net_tools_core::config::{DnsSettings, InputHistory};
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::ProbeEvent;
use net_tools_core::net::dns_tool::COMMON_RECORD_TYPES;
use rust_i18n::t;

use crate::ui::common::{error_banner, state_badge};
use crate::ui::history_input;

/// History buckets for the editable inputs. The record type uses a fixed list
/// of common types instead of a history, so it has no bucket.
const TARGET_HISTORY_KEY: &str = "dns.target";
const SERVER_HISTORY_KEY: &str = "dns.server";

pub struct DnsTab {
    pub ctrl: TaskController<ProbeEvent>,
    /// Text produced by the latest query or trace.
    pub output: String,
    pub error: Option<(String, Option<String>)>,
}

impl Default for DnsTab {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            output: String::new(),
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.output.clear();
        self.error = None;
    }

    pub fn start(&mut self, s: &DnsSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.restart(s, rt);
    }

    /// Stop any running task and start a fresh one, so pressing Enter runs the
    /// query again without an explicit stop.
    pub fn restart(&mut self, s: &DnsSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            if settings.trace {
                net_tools_core::net::dns_tool::run_trace(&handle, &settings).await;
            } else {
                net_tools_core::net::dns_tool::run_query(&handle, &settings).await;
            }
        });
    }

    pub fn drain(&mut self) {
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::DnsText(text) => self.output.push_str(&text),
                ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut DnsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        self.drain();
        if self.ctrl.is_active() {
            // Keep repainting while the query is in flight.
            ui.ctx().request_repaint();
        }

        let mut submit = false;
        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("dns_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.target"));
                        if history_input::singleline(
                            ui,
                            TARGET_HISTORY_KEY,
                            &mut s.target,
                            history,
                            320.0,
                        ) {
                            submit = true;
                        }
                        ui.end_row();

                        ui.label(t!("dns.record_type"));
                        record_type_input(ui, &mut s.record_type);
                        ui.end_row();

                        ui.label(t!("dns.server"));
                        ui.horizontal(|ui| {
                            if history_input::singleline(
                                ui,
                                SERVER_HISTORY_KEY,
                                &mut s.server,
                                history,
                                220.0,
                            ) {
                                submit = true;
                            }
                            // Format hint, e.g. "8.8.8.8:53".
                            ui.weak(t!("dns.server_hint"));
                        });
                        ui.end_row();

                        ui.label(t!("common.timeout_ms"));
                        ui.add(
                            egui::DragValue::new(&mut s.timeout_ms)
                                .range(100..=120_000)
                                .suffix(" ms"),
                        );
                        ui.end_row();

                        ui.label(t!("dns.force_tcp"));
                        ui.checkbox(&mut s.force_tcp, "");
                        ui.end_row();

                        ui.label(t!("dns.trace_mode"));
                        ui.checkbox(&mut s.trace, "");
                        ui.end_row();
                    });
            });
        if submit {
            record_inputs(s, history);
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
        self.output_ui(ui);
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        s: &DnsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            TaskState::Idle | TaskState::Finished => {
                let label = if s.trace {
                    t!("dns.trace")
                } else {
                    t!("dns.query")
                };
                if ui.button(label).clicked() {
                    record_inputs(s, history);
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

    /// Read-only text view with a copy and a clear button.
    fn output_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(t!("dns.output"));
            if ui.small_button(t!("common.copy_all")).clicked() {
                ui.ctx().copy_text(self.output.clone());
            }
            if ui.small_button(t!("common.clear")).clicked() {
                self.output.clear();
            }
        });
        // Wrap the text view in a scroll area: the output of a full trace is
        // much taller than the window and must stay reachable.
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.output)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(24),
                );
            });
    }
}

/// Remember the current input values when a task is started.
fn record_inputs(s: &DnsSettings, history: &mut InputHistory) {
    history_input::record_fields(
        history,
        &[
            (TARGET_HISTORY_KEY, &s.target),
            (SERVER_HISTORY_KEY, &s.server),
        ],
    );
}

/// Editable record-type input whose drop-down lists the common record types.
fn record_type_input(ui: &mut egui::Ui, value: &mut String) {
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(value).desired_width(90.0));
        ui.push_id("dns_record_type", |ui| {
            let button = ui.button("▼").on_hover_text(t!("dns.common_types"));
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
