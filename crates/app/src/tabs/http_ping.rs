//! HTTP Ping tab: multiple methods with per-stage timing.

use eframe::egui;
use net_tools_core::config::HttpSettings;
use net_tools_core::control::TaskController;
use net_tools_core::model::{HttpResult, ProbeEvent};
use rust_i18n::t;

use crate::ui::common::{error_banner, info_line, state_badge};
use crate::ui::result_table::table;
use crate::ui::settings;

const MAX_RESULTS: usize = 500;

pub struct HttpPingTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub results: Vec<HttpResult>,
    pub chart: Vec<[f64; 2]>,
    pub info: Vec<String>,
    pub error: Option<(String, Option<String>)>,
}

impl Default for HttpPingTab {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpPingTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            results: Vec::new(),
            chart: Vec::new(),
            info: Vec::new(),
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.results.clear();
        self.chart.clear();
        self.info.clear();
        self.error = None;
    }

    pub fn start(&mut self, s: &HttpSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.reset();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            net_tools_core::net::http::run_http(&handle, &settings).await;
        });
    }

    pub fn drain(&mut self) {
        for ev in self.ctrl.drain() {
            match ev {
                ProbeEvent::Http(r) => {
                    self.chart.push([r.seq as f64, r.total_ms]);
                    if self.chart.len() > MAX_RESULTS {
                        self.chart.remove(0);
                    }
                    self.results.push(r);
                    if self.results.len() > MAX_RESULTS {
                        self.results.remove(0);
                    }
                }
                ProbeEvent::Info(msg) => {
                    self.info.push(msg);
                    if self.info.len() > 50 {
                        self.info.remove(0);
                    }
                }
                ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, s: &mut HttpSettings, rt: &tokio::runtime::Handle) {
        self.drain();
        if self.ctrl.is_active() {
            // Keep repainting while a task runs so results and the auto-sized
            // table columns stay up to date.
            ui.ctx().request_repaint();
        }

        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("http_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("http.url"));
                        ui.add(egui::TextEdit::singleline(&mut s.target).desired_width(320.0));
                        ui.end_row();

                        ui.label(t!("http.method"));
                        method_selector(ui, &mut s.method);
                        ui.end_row();

                        ui.label(t!("common.ip_version"));
                        settings::ip_version_selector(ui, &mut s.ip_version);
                        ui.end_row();

                        ui.label(t!("common.timeout_ms"));
                        ui.add(
                            egui::DragValue::new(&mut s.timeout_ms)
                                .range(10..=120_000)
                                .suffix(" ms"),
                        );
                        ui.end_row();

                        ui.label(t!("common.interval_ms"));
                        ui.add(
                            egui::DragValue::new(&mut s.interval_ms)
                                .range(10..=60_000)
                                .suffix(" ms"),
                        );
                        ui.end_row();

                        ui.label(t!("http.follow_redirects"));
                        ui.checkbox(&mut s.follow_redirects, "");
                        ui.end_row();

                        ui.label(t!("http.verify_tls"));
                        ui.checkbox(&mut s.verify_tls, "");
                        ui.end_row();

                        ui.label(t!("http.expect_status"));
                        let mut status_text =
                            s.expect_status.map(|v| v.to_string()).unwrap_or_default();
                        ui.add(egui::TextEdit::singleline(&mut status_text).desired_width(60.0));
                        s.expect_status = status_text.trim().parse::<u16>().ok();
                        ui.end_row();

                        ui.label(t!("http.expect_keyword"));
                        let mut kw = s.expect_keyword.clone().unwrap_or_default();
                        ui.add(egui::TextEdit::singleline(&mut kw).desired_width(160.0));
                        s.expect_keyword = if kw.trim().is_empty() { None } else { Some(kw) };
                        ui.end_row();

                        ui.label(t!("http.headers"));
                        ui.add(
                            egui::TextEdit::multiline(&mut s.headers)
                                .desired_rows(2)
                                .desired_width(320.0),
                        );
                        ui.end_row();

                        ui.label(t!("http.body"));
                        ui.add(
                            egui::TextEdit::multiline(&mut s.body)
                                .desired_rows(2)
                                .desired_width(320.0),
                        );
                        ui.end_row();

                        ui.label(t!("common.reverse_dns"));
                        ui.checkbox(&mut s.reverse_dns, "");
                        ui.end_row();
                    });
            });

        ui.horizontal(|ui| {
            self.control_row(ui, s, rt);
            state_badge(ui, self.ctrl.state);
        });

        // Result toolbar: placed directly under the controls, above every
        // result-related widget, so it can never be pushed down.
        self.toolbar(ui);

        if let Some((msg, hint)) = &self.error {
            error_banner(ui, msg, hint.as_deref());
        }
        for line in self.info.iter().rev().take(5) {
            info_line(ui, line);
        }

        ui.separator();

        if !self.chart.is_empty() {
            crate::ui::chart::latency_chart(ui, &self.chart, 150.0);
        }

        let headers = [
            t!("common.seq"),
            t!("http.method"),
            t!("http.status"),
            t!("http.dns_ms"),
            t!("http.connect_ms"),
            t!("http.tls_ms"),
            t!("http.ttfb_ms"),
            t!("http.total_ms"),
            t!("http.body_bytes"),
            t!("http.ok"),
        ];
        table(ui, &headers, self.results.len(), |i, row| {
            let r = &self.results[i];
            row.col(|ui| {
                ui.label(r.seq.to_string());
            });
            row.col(|ui| {
                ui.label(&r.method);
            });
            row.col(|ui| {
                ui.label(r.status.map_or("-".into(), |v| v.to_string()));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", r.dns_ms));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", r.connect_ms));
            });
            row.col(|ui| {
                ui.label(r.tls_ms.map_or("-".into(), |v| format!("{:.1}", v)));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", r.ttfb_ms));
            });
            row.col(|ui| {
                ui.label(format!("{:.1}", r.total_ms));
            });
            row.col(|ui| {
                ui.label(r.body_bytes.to_string());
            });
            row.col(|ui| {
                ui.label(if r.ok { "✓" } else { "✗" });
            });
        });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match crate::ui::common::result_toolbar(ui) {
            crate::ui::common::ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            crate::ui::common::ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("http-ping", "csv", &self.to_csv())
            }
            crate::ui::common::ToolbarAction::ExportJson => {
                crate::ui::export::save_file("http-ping", "json", &self.to_json())
            }
            crate::ui::common::ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("http-ping", "html", &self.to_html())
            }
            crate::ui::common::ToolbarAction::Clear => self.reset(),
            crate::ui::common::ToolbarAction::None => {}
        }
    }

    fn control_row(&mut self, ui: &mut egui::Ui, s: &HttpSettings, rt: &tokio::runtime::Handle) {
        match self.ctrl.state {
            net_tools_core::control::TaskState::Idle
            | net_tools_core::control::TaskState::Finished => {
                if ui.button(t!("common.start")).clicked() {
                    self.start(s, rt);
                }
            }
            net_tools_core::control::TaskState::Running => {
                if ui.button(t!("common.pause")).clicked() {
                    self.ctrl.pause();
                }
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            }
            net_tools_core::control::TaskState::Paused => {
                if ui.button(t!("common.resume")).clicked() {
                    self.ctrl.resume();
                }
                if ui.button(t!("common.stop")).clicked() {
                    self.ctrl.stop();
                }
            }
            net_tools_core::control::TaskState::Stopping => {
                ui.add_enabled(false, egui::Button::new(t!("state.stopping")));
            }
        }
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "seq,method,status,dns_ms,connect_ms,tls_ms,ttfb_ms,total_ms,body_bytes,ok,error\n",
        );
        for r in &self.results {
            out.push_str(&format!(
                "{},{},{},{:.1},{:.1},{},{:.1},{:.1},{},{},{}\n",
                r.seq,
                r.method,
                r.status.map_or("-".into(), |v| v.to_string()),
                r.dns_ms,
                r.connect_ms,
                r.tls_ms.map_or("-".into(), |v| format!("{:.1}", v)),
                r.ttfb_ms,
                r.total_ms,
                r.body_bytes,
                if r.ok { "ok" } else { "fail" },
                r.error.clone().unwrap_or_default(),
            ));
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

fn method_selector(ui: &mut egui::Ui, method: &mut String) {
    let methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"];
    egui::ComboBox::from_id_salt("http_method")
        .selected_text(method.as_str())
        .show_ui(ui, |ui| {
            for m in methods {
                ui.selectable_value(method, m.to_string(), m);
            }
        });
}
