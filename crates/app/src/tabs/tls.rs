//! TLS tab: certificate, protocol, revocation, HSTS, CT and CAA checks.

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::{InputHistory, TlsSettings};
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{
    CaaCheck, CtCheck, HstsCheck, ProbeEvent, RevocationCheck, RevocationStatus, TlsCertInfo,
    TlsHealth, TlsProgress, TlsResult,
};
use net_tools_core::net::tls::{self, TlsTarget};
use rust_i18n::t;

use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::table_selectable_with_columns;
use crate::ui::settings;
use crate::ui::theme::Palette;

/// History bucket for the multi-line target input.
const TARGETS_HISTORY_KEY: &str = "tls.targets";
/// Number of rows visible in the result table.
const VISIBLE_ROWS: usize = 8;

pub struct TlsTab {
    pub ctrl: TaskController<ProbeEvent>,
    /// Parsed targets in input order; the rows stay visible while checks run.
    entries: Vec<TlsTarget>,
    /// Results indexed by the target index. `None` means still pending.
    results: Vec<Option<TlsResult>>,
    pub progress: Option<TlsProgress>,
    pub selected: Option<usize>,
    pub error: Option<(String, Option<String>)>,
}

impl Default for TlsTab {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            entries: Vec::new(),
            results: Vec::new(),
            progress: None,
            selected: None,
            error: None,
        }
    }

    pub fn reset(&mut self) {
        self.entries.clear();
        self.results.clear();
        self.progress = None;
        self.selected = None;
        self.error = None;
    }

    /// Start a fresh batch, replacing the current rows and results.
    pub fn restart(&mut self, s: &TlsSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        self.entries = tls::parse_targets(&s.targets, s.port);
        self.results = vec![None; self.entries.len()];
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            tls::run_check(&handle, &settings).await;
        });
    }

    /// Stop a running batch when another tab is selected and drop its rows.
    pub fn clear_on_hide(&mut self) {
        if self.ctrl.is_active() {
            self.ctrl.stop();
        }
        let _ = self.ctrl.drain();
        self.reset();
    }

    pub fn drain(&mut self) {
        for event in self.ctrl.drain() {
            match event {
                ProbeEvent::Tls(result) => {
                    let result = *result;
                    let index = result.index;
                    if self.results.len() <= index {
                        self.results.resize(index + 1, None);
                    }
                    if self.entries.len() <= index {
                        self.entries.resize_with(index + 1, || TlsTarget {
                            target: result.target.clone(),
                            host: result.host.clone(),
                            port: result.port,
                        });
                    }
                    self.results[index] = Some(result);
                    if self.selected.is_none() {
                        self.selected = Some(0);
                    }
                }
                ProbeEvent::TlsProgress(progress) => self.progress = Some(progress),
                ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut TlsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        self.drain();
        if self.ctrl.is_active() {
            ui.ctx().request_repaint();
        }

        let (_, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            egui::Grid::new("tls_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("common.targets"));
                    history_input::multiline(
                        ui,
                        TARGETS_HISTORY_KEY,
                        &mut s.targets,
                        history,
                        180.0,
                        3,
                    );
                    ui.end_row();

                    ui.label(t!("common.port"));
                    ui.add(egui::DragValue::new(&mut s.port).range(1..=65535));
                    ui.end_row();

                    ui.label(t!("common.ip_version"));
                    settings::ip_version_selector(ui, &mut s.ip_version);
                    ui.end_row();

                    ui.label(t!("common.timeout_ms"));
                    ui.add(
                        egui::DragValue::new(&mut s.timeout_ms)
                            .range(100..=120_000)
                            .suffix(" ms"),
                    );
                    ui.end_row();

                    ui.label(t!("common.concurrency"));
                    ui.add(egui::DragValue::new(&mut s.concurrency).range(1..=10));
                    ui.end_row();

                    ui.label(t!("tls.warn_days"));
                    ui.add(egui::DragValue::new(&mut s.warn_days).range(1..=3650));
                    ui.end_row();

                    ui.label(t!("tls.probe_versions"));
                    ui.checkbox(&mut s.probe_versions, "");
                    ui.end_row();

                    ui.label(t!("tls.probe_alpn"));
                    ui.checkbox(&mut s.probe_alpn, "");
                    ui.end_row();
                });

            ui.add_space(8.0);
            ui.label(egui::RichText::new(t!("tls.security_checks")).strong());
            egui::Grid::new("tls_security_settings")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label(t!("tls.check_revocation"));
                    ui.checkbox(&mut s.check_revocation, "");
                    ui.end_row();
                    ui.label(t!("tls.check_hsts"));
                    ui.checkbox(&mut s.check_hsts, "");
                    ui.end_row();
                    ui.label(t!("tls.check_ct"));
                    ui.checkbox(&mut s.check_ct, "");
                    ui.end_row();
                    ui.label(t!("tls.check_caa"));
                    ui.checkbox(&mut s.check_caa, "");
                    ui.end_row();
                });
            ui.weak(t!("tls.security_hint"));
            ui.weak(t!("tls.target_hint"));

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                self.control_row(ui, s, history, rt);
                state_badge(ui, self.ctrl.state);
            });

            if let Some((message, hint)) = &self.error {
                error_banner(ui, message, hint.as_deref());
            }
        });

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);
            self.summary_ui(ui);
            self.table_ui(ui, s.warn_days);
            if let Some(result) = self
                .selected
                .and_then(|index| self.results.get(index))
                .and_then(Option::as_ref)
            {
                ui.add_space(10.0);
                egui::ScrollArea::vertical()
                    .id_salt("tls_detail_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.detail_ui(ui, result, s));
            }
        });

        expanded
    }

    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        s: &TlsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match self.ctrl.state {
            TaskState::Idle | TaskState::Finished => {
                if ui.button(t!("common.start")).clicked() {
                    history_input::record_fields(history, &[(TARGETS_HISTORY_KEY, &s.targets)]);
                    self.restart(s, rt);
                }
            }
            TaskState::Running => {
                if ui.button(t!("common.pause")).clicked() {
                    self.ctrl.pause();
                }
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

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("tls-check", "csv", &self.to_csv())
            }
            ToolbarAction::ExportJson => {
                crate::ui::export::save_file("tls-check", "json", &self.to_json())
            }
            ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("tls-check", "html", &self.to_html())
            }
            ToolbarAction::Clear => self.reset(),
            ToolbarAction::None => {}
        }
    }

    fn summary_ui(&self, ui: &mut egui::Ui) {
        let mut ok = 0usize;
        let mut expiring = 0usize;
        let mut expired = 0usize;
        let mut revoked = 0usize;
        let mut failed = 0usize;
        let mut pending = 0usize;
        for result in &self.results {
            match result {
                None => pending += 1,
                Some(result) => match result.health {
                    TlsHealth::Ok => ok += 1,
                    TlsHealth::ExpiringSoon => expiring += 1,
                    TlsHealth::Expired => expired += 1,
                    TlsHealth::Revoked => revoked += 1,
                    TlsHealth::Error | TlsHealth::HostnameMismatch | TlsHealth::Untrusted => {
                        failed += 1
                    }
                },
            }
        }
        let total = self.results.len();
        ui.horizontal_wrapped(|ui| {
            ui.label(t!("tls.summary.total", count = total));
            ui.label(t!("tls.summary.ok", count = ok));
            if expiring > 0 {
                let palette = Palette::from_ui(ui);
                ui.colored_label(
                    palette.warning_text,
                    t!("tls.summary.expiring", count = expiring),
                );
            }
            if expired > 0 || revoked > 0 {
                let palette = Palette::from_ui(ui);
                ui.colored_label(
                    palette.error_text,
                    t!("tls.summary.risky", expired = expired, revoked = revoked),
                );
            }
            if failed > 0 {
                ui.label(t!("tls.summary.failed", count = failed));
            }
            if pending > 0 {
                ui.weak(t!("tls.summary.pending", count = pending));
            }
        });
        if let Some(progress) = self.progress {
            ui.weak(t!(
                "tls.progress",
                done = progress.done,
                total = progress.total
            ));
        }
    }

    fn table_ui(&mut self, ui: &mut egui::Ui, warn_days: u32) {
        let headers = [
            t!("common.target"),
            t!("tls.column.status"),
            t!("tls.column.protocol"),
            t!("tls.column.cipher"),
            t!("tls.column.certificate"),
            t!("tls.column.expires"),
            t!("tls.column.days"),
            t!("tls.column.revocation"),
        ];
        // Most columns size themselves from their cell content. The cipher
        // column keeps a fixed width so long suite names cannot dominate the
        // table; all auto columns are bounded to keep the table usable.
        let columns = [
            Column::auto().at_least(120.0).at_most(260.0).clip(true),
            Column::auto().at_least(64.0).at_most(120.0).clip(true),
            Column::auto().at_least(56.0).at_most(90.0).clip(true),
            Column::exact(150.0),
            Column::auto().at_least(120.0).at_most(240.0).clip(true),
            Column::auto().at_least(90.0).at_most(160.0).clip(true),
            Column::auto().at_least(56.0).at_most(90.0).clip(true),
            Column::auto().at_least(64.0).at_most(110.0).clip(true),
        ];
        let palette = Palette::from_ui(ui);
        let selected = if self.selected == Some(usize::MAX) {
            None
        } else {
            self.selected
        };
        let clicked = table_selectable_with_columns(
            ui,
            &headers,
            self.entries.len(),
            VISIBLE_ROWS,
            selected,
            columns,
            |index, row| {
                let target = self.entries.get(index);
                let result = self.results.get(index).and_then(Option::as_ref);
                row.col(|ui| {
                    let label = target.map(|t| t.target.clone()).unwrap_or_default();
                    if result_available(result) {
                        let text = format!("{}:{}", result.unwrap().host, result.unwrap().port);
                        ui.label(label).on_hover_text(text);
                    } else {
                        ui.weak(label);
                    }
                });
                row.col(|ui| match result {
                    Some(result) => {
                        let color = health_color(&palette, result.health);
                        ui.colored_label(color, health_label(result.health));
                    }
                    None => {
                        ui.weak(t!("tls.pending"));
                    }
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .and_then(|r| r.protocol.clone())
                            .unwrap_or_else(|| "-".into()),
                    );
                });
                row.col(|ui| {
                    let text = result
                        .and_then(|r| r.cipher_suite.clone())
                        .unwrap_or_else(|| "-".into());
                    ui.label(&text).on_hover_text(&text);
                });
                row.col(|ui| {
                    let text = result
                        .and_then(|r| r.certs.first())
                        .and_then(|cert| {
                            cert.common_name
                                .clone()
                                .or_else(|| cert.san_dns.first().cloned())
                        })
                        .unwrap_or_else(|| "-".into());
                    ui.label(&text).on_hover_text(&text);
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .and_then(|r| r.certs.first())
                            .map(|cert| cert.not_after.clone())
                            .unwrap_or_else(|| "-".into()),
                    );
                });
                row.col(|ui| {
                    let days = result.and_then(|r| r.certs.first()).map(|cert| {
                        cert.days_remaining(time::OffsetDateTime::now_utc().unix_timestamp())
                    });
                    let (text, color) = match days {
                        Some(days) if days < 0 => (
                            t!("tls.days_expired", days = -days).to_string(),
                            palette.error_text,
                        ),
                        Some(days) if days <= warn_days as i64 => (
                            t!("tls.days", days = days).to_string(),
                            palette.warning_text,
                        ),
                        Some(days) => (t!("tls.days", days = days).to_string(), palette.card_text),
                        None => ("-".into(), palette.card_text),
                    };
                    ui.colored_label(color, text);
                });
                row.col(|ui| {
                    let status = result.map(|r| r.security.revocation.status);
                    match status {
                        Some(RevocationStatus::Revoked) => {
                            ui.colored_label(palette.error_text, t!("tls.revocation.revoked"));
                        }
                        Some(RevocationStatus::Good) => {
                            ui.colored_label(palette.success_text, t!("tls.revocation.good"));
                        }
                        Some(other) => {
                            ui.weak(revocation_label(other));
                        }
                        None => {
                            ui.weak("-");
                        }
                    }
                });
            },
        );
        if let Some(index) = clicked {
            self.selected = Some(index);
        }
    }

    fn detail_ui(&self, ui: &mut egui::Ui, result: &TlsResult, settings: &TlsSettings) {
        let palette = Palette::from_ui(ui);
        ui.horizontal(|ui| {
            ui.heading(format!("{}:{}", result.host, result.port));
            ui.colored_label(
                health_color(&palette, result.health),
                health_label(result.health),
            );
            if let Some(error) = &result.error {
                ui.colored_label(palette.error_text, error);
            }
        });

        if let Some(leaf) = result.certs.first() {
            let days = leaf.days_remaining(time::OffsetDateTime::now_utc().unix_timestamp());
            let text = if days < 0 {
                t!("tls.expired_banner", days = -days).to_string()
            } else {
                t!("tls.expiry_banner", days = days, date = &leaf.not_after).to_string()
            };
            let color = if days < 0 {
                palette.error_text
            } else if days <= settings.warn_days as i64 {
                palette.warning_text
            } else {
                palette.success_text
            };
            egui::Frame::new()
                .fill(palette.badge_bg(color))
                .corner_radius(4.0)
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    ui.colored_label(color, text);
                });
        }

        ui.add_space(8.0);
        ui.label(egui::RichText::new(t!("tls.connection")).strong());
        let mut rows = vec![
            (t!("common.target").to_string(), result.target.clone()),
            (t!("common.host").to_string(), result.host.clone()),
            (t!("common.port").to_string(), result.port.to_string()),
            (
                t!("tls.resolved_ip").to_string(),
                result.resolved_ip.clone().unwrap_or_else(|| "-".into()),
            ),
            (
                t!("tls.elapsed").to_string(),
                format!("{:.1} ms", result.elapsed_ms),
            ),
            (
                t!("tls.protocol").to_string(),
                result.protocol.clone().unwrap_or_else(|| "-".into()),
            ),
            (
                t!("tls.cipher").to_string(),
                result.cipher_suite.clone().unwrap_or_else(|| "-".into()),
            ),
            (
                t!("tls.key_exchange").to_string(),
                result.key_exchange.clone().unwrap_or_else(|| "-".into()),
            ),
            (
                t!("tls.alpn").to_string(),
                result.alpn_negotiated.clone().unwrap_or_else(|| "-".into()),
            ),
        ];
        rows.push((
            t!("tls.chain_valid").to_string(),
            tls_bool(result.chain_valid),
        ));
        if let Some(error) = &result.chain_error {
            rows.push((t!("tls.chain_error").to_string(), error.clone()));
        }
        crate::ui::result_table::key_value_table(
            ui,
            "tls_connection",
            &t!("tls.field"),
            &t!("tls.value"),
            &rows,
        );

        ui.add_space(6.0);
        ui.label(
            t!(
                "tls.capabilities",
                tls12 = yes_no(result.tls12_supported),
                tls13 = yes_no(result.tls13_supported),
                h2 = yes_no(result.alpn_h2_supported),
                http1 = yes_no(result.alpn_http1_supported)
            )
            .to_string(),
        );

        ui.add_space(10.0);
        ui.label(egui::RichText::new(t!("tls.security_checks")).strong());
        if settings.check_revocation {
            revocation_ui(ui, &result.security.revocation);
        } else {
            ui.weak(t!("tls.not_checked"));
        }
        if settings.check_hsts {
            hsts_ui(ui, &result.security.hsts);
        } else {
            ui.weak(t!("tls.not_checked"));
        }
        if settings.check_ct {
            ct_ui(ui, &result.security.ct);
        } else {
            ui.weak(t!("tls.not_checked"));
        }
        if settings.check_caa {
            caa_ui(ui, &result.security.caa);
        } else {
            ui.weak(t!("tls.not_checked"));
        }

        ui.add_space(10.0);
        ui.label(egui::RichText::new(t!("tls.certificate_chain")).strong());
        ui.weak(t!("tls.chain_hint"));
        for (index, cert) in result.certs.iter().enumerate() {
            cert_ui(ui, result.index, index, cert);
        }
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "target,host,port,status,protocol,cipher,key_exchange,alpn,tls12,tls13,chain_valid,chain_error,leaf_cn,leaf_issuer,not_before,not_after,days_remaining,key_algorithm,key_bits,fingerprint_sha256,revocation,revocation_source,hsts,hsts_max_age,hsts_include_subdomains,hsts_preload,ct_scts,ct_verified,ct_unknown,ct_invalid,caa_source,caa_records,error\n",
        );
        for result in self.results.iter().flatten() {
            let leaf = result.certs.first();
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let caa = result
                .security
                .caa
                .records
                .iter()
                .map(|record| format!("{} {} {}", record.flags, record.tag, record.value))
                .collect::<Vec<_>>()
                .join("; ");
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                crate::ui::export::csv_field(&result.target),
                crate::ui::export::csv_field(&result.host),
                result.port,
                result.health.label(),
                crate::ui::export::csv_field(&result.protocol.clone().unwrap_or_default()),
                crate::ui::export::csv_field(&result.cipher_suite.clone().unwrap_or_default()),
                crate::ui::export::csv_field(&result.key_exchange.clone().unwrap_or_default()),
                crate::ui::export::csv_field(&result.alpn_negotiated.clone().unwrap_or_default()),
                yes_no(result.tls12_supported),
                yes_no(result.tls13_supported),
                result.chain_valid,
                crate::ui::export::csv_field(&result.chain_error.clone().unwrap_or_default()),
                crate::ui::export::csv_field(&leaf.and_then(|c| c.common_name.clone()).unwrap_or_default()),
                crate::ui::export::csv_field(&leaf.map(|c| c.issuer.clone()).unwrap_or_default()),
                crate::ui::export::csv_field(&leaf.map(|c| c.not_before.clone()).unwrap_or_default()),
                crate::ui::export::csv_field(&leaf.map(|c| c.not_after.clone()).unwrap_or_default()),
                leaf.map(|c| c.days_remaining(now).to_string()).unwrap_or_else(|| "-".into()),
                crate::ui::export::csv_field(&leaf.map(|c| c.key_algorithm.clone()).unwrap_or_default()),
                leaf.and_then(|c| c.key_bits).map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                crate::ui::export::csv_field(&leaf.map(|c| c.fingerprint_sha256.clone()).unwrap_or_default()),
                result.security.revocation.status.label(),
                crate::ui::export::csv_field(&result.security.revocation.source.clone().unwrap_or_default()),
                result.security.hsts.enabled,
                result.security.hsts.max_age.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                result.security.hsts.include_subdomains,
                result.security.hsts.preload,
                result.security.ct.sct_count,
                result.security.ct.verified,
                result.security.ct.unknown_logs,
                result.security.ct.invalid,
                crate::ui::export::csv_field(&result.security.caa.source.clone().unwrap_or_default()),
                crate::ui::export::csv_field(&caa),
                crate::ui::export::csv_field(&result.error.clone().unwrap_or_default()),
            ));
        }
        out
    }

    pub fn to_json(&self) -> String {
        let completed: Vec<&TlsResult> = self.results.iter().flatten().collect();
        serde_json::to_string_pretty(&completed).unwrap_or_default()
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}

fn result_available(result: Option<&TlsResult>) -> bool {
    result.is_some()
}

fn health_color(palette: &Palette, health: TlsHealth) -> egui::Color32 {
    match health {
        TlsHealth::Ok => palette.success_text,
        TlsHealth::ExpiringSoon => palette.warning_text,
        TlsHealth::Expired | TlsHealth::Revoked | TlsHealth::Error => palette.error_text,
        TlsHealth::HostnameMismatch | TlsHealth::Untrusted => palette.warning_text,
    }
}

fn health_label(health: TlsHealth) -> String {
    match health {
        TlsHealth::Ok => t!("tls.health.ok"),
        TlsHealth::ExpiringSoon => t!("tls.health.expiring"),
        TlsHealth::Expired => t!("tls.health.expired"),
        TlsHealth::Revoked => t!("tls.health.revoked"),
        TlsHealth::HostnameMismatch => t!("tls.health.hostname_mismatch"),
        TlsHealth::Untrusted => t!("tls.health.untrusted"),
        TlsHealth::Error => t!("tls.health.error"),
    }
    .to_string()
}

fn revocation_label(status: RevocationStatus) -> String {
    match status {
        RevocationStatus::Good => t!("tls.revocation.good"),
        RevocationStatus::Revoked => t!("tls.revocation.revoked"),
        RevocationStatus::Unknown => t!("tls.revocation.unknown"),
        RevocationStatus::Unavailable => t!("tls.revocation.unavailable"),
        RevocationStatus::Error => t!("tls.revocation.error"),
    }
    .to_string()
}

fn yes_no(value: Option<bool>) -> String {
    match value {
        Some(true) => t!("tls.yes").to_string(),
        Some(false) => t!("tls.no").to_string(),
        None => t!("tls.unknown").to_string(),
    }
}

fn tls_bool(value: bool) -> String {
    if value {
        t!("tls.yes").to_string()
    } else {
        t!("tls.no").to_string()
    }
}

fn revocation_ui(ui: &mut egui::Ui, check: &RevocationCheck) {
    let palette = Palette::from_ui(ui);
    let color = match check.status {
        RevocationStatus::Good => palette.success_text,
        RevocationStatus::Revoked => palette.error_text,
        RevocationStatus::Unknown | RevocationStatus::Unavailable => palette.warning_text,
        RevocationStatus::Error => palette.error_text,
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(t!("tls.revocation.title")).strong());
        ui.colored_label(color, revocation_label(check.status));
        if let Some(source) = &check.source {
            ui.weak(source);
        }
    });
    if let Some(detail) = &check.detail {
        ui.weak(detail);
    }
    if let (Some(this), Some(next)) = (&check.this_update, &check.next_update) {
        ui.weak(format!("{this} → {next}"));
    }
}

fn hsts_ui(ui: &mut egui::Ui, check: &HstsCheck) {
    let palette = Palette::from_ui(ui);
    let color = if check.enabled {
        palette.success_text
    } else {
        palette.warning_text
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(t!("tls.hsts.title")).strong());
        let value = if check.enabled {
            t!("tls.hsts.enabled")
        } else if check.present {
            t!("tls.hsts.disabled")
        } else {
            t!("tls.hsts.missing")
        };
        ui.colored_label(color, value);
        if let Some(max_age) = check.max_age {
            ui.weak(t!("tls.hsts.max_age", value = max_age));
        }
        if check.include_subdomains {
            ui.weak(t!("tls.hsts.include_subdomains"));
        }
        if check.preload {
            ui.weak(t!("tls.hsts.preload"));
        }
    });
    if let Some(header) = &check.header {
        ui.label(egui::RichText::new(header).monospace().small());
    }
    if let Some(error) = &check.error {
        ui.colored_label(palette.warning_text, error);
    }
}

fn ct_ui(ui: &mut egui::Ui, check: &CtCheck) {
    let palette = Palette::from_ui(ui);
    if check.sct_count == 0 {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new(t!("tls.ct.title")).strong());
            ui.colored_label(palette.warning_text, t!("tls.ct.missing"));
        });
    } else {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new(t!("tls.ct.title")).strong());
            ui.weak(t!(
                "tls.ct.counts",
                total = check.sct_count,
                verified = check.verified,
                unknown = check.unknown_logs,
                invalid = check.invalid
            ));
        });
    }
    if !check.log_ids.is_empty() {
        ui.label(
            egui::RichText::new(check.log_ids.join(", "))
                .monospace()
                .small(),
        );
    }
    if let Some(error) = &check.error {
        ui.colored_label(palette.warning_text, error);
    }
}

fn caa_ui(ui: &mut egui::Ui, check: &CaaCheck) {
    let palette = Palette::from_ui(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(t!("tls.caa.title")).strong());
        if let Some(source) = &check.source {
            ui.weak(t!("tls.caa.source", source = source));
        } else {
            ui.weak(t!("tls.caa.missing"));
        }
    });
    for record in &check.records {
        ui.label(
            egui::RichText::new(format!(
                "{} {} \"{}\"{}",
                record.flags,
                record.tag,
                record.value,
                if record.critical { " (critical)" } else { "" }
            ))
            .monospace()
            .small(),
        );
    }
    if let Some(error) = &check.error {
        ui.colored_label(palette.warning_text, error);
    }
}

fn cert_ui(ui: &mut egui::Ui, result_index: usize, index: usize, cert: &TlsCertInfo) {
    let title = format!(
        "{} · {}",
        cert.role,
        cert.common_name
            .clone()
            .unwrap_or_else(|| cert.subject.clone())
    );
    egui::CollapsingHeader::new(title)
        .id_salt(("tls-cert", result_index, index))
        .default_open(index == 0)
        .show(ui, |ui| {
            let rows = vec![
                (t!("tls.cert.role").to_string(), cert.role.clone()),
                (t!("tls.cert.subject").to_string(), cert.subject.clone()),
                (t!("tls.cert.issuer").to_string(), cert.issuer.clone()),
                (
                    t!("tls.cert.common_name").to_string(),
                    cert.common_name.clone().unwrap_or_else(|| "-".into()),
                ),
                (t!("tls.cert.serial").to_string(), cert.serial.clone()),
                (
                    t!("tls.cert.not_before").to_string(),
                    cert.not_before.clone(),
                ),
                (t!("tls.cert.not_after").to_string(), cert.not_after.clone()),
                (
                    t!("tls.cert.key").to_string(),
                    format!(
                        "{} {}{}",
                        cert.key_algorithm,
                        cert.key_bits
                            .map(|bits| format!("{bits} bits"))
                            .unwrap_or_else(|| "-".into()),
                        cert.curve
                            .as_ref()
                            .map(|curve| format!(" ({curve})"))
                            .unwrap_or_default()
                    ),
                ),
                (
                    t!("tls.cert.signature").to_string(),
                    cert.signature_algorithm.clone(),
                ),
                (
                    t!("tls.cert.fingerprint").to_string(),
                    cert.fingerprint_sha256.clone(),
                ),
                (
                    t!("tls.cert.san_dns").to_string(),
                    join_or_dash(&cert.san_dns),
                ),
                (
                    t!("tls.cert.san_ips").to_string(),
                    join_or_dash(&cert.san_ips),
                ),
                (
                    t!("tls.cert.san_emails").to_string(),
                    join_or_dash(&cert.san_emails),
                ),
                (
                    t!("tls.cert.san_uris").to_string(),
                    join_or_dash(&cert.san_uris),
                ),
            ];
            crate::ui::result_table::key_value_table(
                ui,
                ("tls_cert", result_index, index),
                &t!("tls.field"),
                &t!("tls.value"),
                &rows,
            );
        });
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".into()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tab_renders_without_panic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut tab = TlsTab::new();
        let mut settings = TlsSettings::default();
        let mut history = InputHistory::default();
        let ctx = egui::Context::default();
        for _ in 0..4 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(1200.0, 800.0),
                )),
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                let _ = tab.ui(ui, &mut settings, &mut history, runtime.handle(), true);
            })
            .textures_delta
            .clear();
        }
    }
}
