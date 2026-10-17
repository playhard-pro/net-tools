//! NTP tab: query a server, render a live clock and optionally set the system
//! time after an explicit confirmation.

use std::f32::consts::{FRAC_PI_2, TAU};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use net_tools_core::config::{InputHistory, NtpSettings};
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{NtpResult, ProbeEvent};
use net_tools_core::system_time;
use rust_i18n::t;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

use crate::ui::common::{error_banner, state_badge};
use crate::ui::history_input;

/// Servers always offered in the target drop-down. They are pinned and cannot
/// be removed or cleared, regardless of the stored history.
pub const PRESET_SERVERS: &[&str] = &[
    "time.cloudflare.com",
    "time.apple.com",
    "time.windows.com",
    "time.nist.gov",
    "pool.ntp.org",
];

/// History bucket for the target input.
const TARGET_HISTORY_KEY: &str = "ntp.target";

/// Diameter of the analog clock.
const CLOCK_SIZE: f32 = 220.0;

/// Repaint cadence while a clock is displayed, so milliseconds keep moving
/// without redrawing as fast as the display refresh rate.
const CLOCK_REPAINT: Duration = Duration::from_millis(50);

/// Result of the latest NTP query plus the monotonic anchor used to keep the
/// displayed time running between queries.
pub struct NtpTab {
    pub ctrl: TaskController<ProbeEvent>,
    pub result: Option<NtpResult>,
    /// Monotonic instant matching `result.server_time_unix`.
    anchor: Option<Instant>,
    pub error: Option<(String, Option<String>)>,
    /// Feedback shown after a successful system clock update.
    pub notice: Option<String>,
    /// Result channel for a clock update performed by an elevated helper.
    pending_set: Option<Receiver<Result<(), system_time::SetTimeError>>>,
    /// Whether the confirmation dialog for setting the system clock is open.
    confirm_open: bool,
    /// Whether this tab is currently being rendered. Events arriving while the
    /// tab is hidden are discarded so a stale result cannot reappear later.
    visible: bool,
}

impl Default for NtpTab {
    fn default() -> Self {
        Self::new()
    }
}

impl NtpTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            result: None,
            anchor: None,
            error: None,
            notice: None,
            pending_set: None,
            confirm_open: false,
            visible: false,
        }
    }

    pub fn reset(&mut self) {
        self.result = None;
        self.anchor = None;
        self.error = None;
        self.notice = None;
        self.confirm_open = false;
    }

    pub fn start(&mut self, s: &NtpSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.restart(s, rt);
    }

    /// Start a fresh query, replacing any previous result.
    pub fn restart(&mut self, s: &NtpSettings, rt: &tokio::runtime::Handle) {
        self.reset();
        let settings = s.clone();
        self.ctrl.start(rt, move |handle| async move {
            net_tools_core::net::ntp::run_query(&handle, &settings).await;
        });
    }

    pub fn drain(&mut self) {
        for ev in self.ctrl.drain() {
            // Ignore results that arrive while another tab is active. The UI
            // sets `visible` after this drain, so the first frame after
            // returning also clears anything left in the channel.
            if !self.visible {
                continue;
            }
            match ev {
                ProbeEvent::Ntp(result) => {
                    self.result = Some(result);
                    // The result carries the server time at response arrival;
                    // anchor it to the current monotonic instant so the clock
                    // can advance without querying again.
                    self.anchor = Some(Instant::now());
                    self.error = None;
                }
                ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    /// Drop the live result when another tab is selected. This stops the clock
    /// repaint loop and discards an in-flight query so no work continues in the
    /// background. An already approved elevation request is left running.
    pub fn clear_on_hide(&mut self) {
        self.visible = false;
        if self.ctrl.is_active() {
            self.ctrl.stop();
        }
        // Discard events produced before the stop. Any late events are dropped
        // by `drain` because the tab is no longer visible.
        let _ = self.ctrl.drain();
        self.result = None;
        self.anchor = None;
        self.error = None;
        self.notice = None;
        self.confirm_open = false;
    }

    /// Current NTP-derived UTC time, or `None` before the first result.
    fn current_utc(&self) -> Option<OffsetDateTime> {
        let result = self.result.as_ref()?;
        let anchor = self.anchor?;
        let unix = result.server_time_unix + anchor.elapsed().as_secs_f64();
        let nanos = (unix * 1_000_000_000.0).round() as i128;
        OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut NtpSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        self.drain();
        self.visible = true;
        self.poll_pending_set(ui);
        if self.ctrl.is_active() || self.result.is_some() || self.pending_set.is_some() {
            ui.ctx().request_repaint_after(CLOCK_REPAINT);
        }

        let mut submit = false;
        egui::CollapsingHeader::new(t!("common.settings"))
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("ntp_settings")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(t!("common.target"));
                        if history_input::singleline_with_presets(
                            ui,
                            TARGET_HISTORY_KEY,
                            PRESET_SERVERS,
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

                        ui.label("");
                        ui.weak(t!("ntp.target_hint"));
                        ui.end_row();
                    });
            });
        if submit {
            self.record_target(s, history);
            self.restart(s, rt);
        }

        ui.horizontal(|ui| {
            self.control_row(ui, s, history, rt);
            state_badge(ui, self.ctrl.state);
        });

        if let Some((msg, hint)) = &self.error {
            error_banner(ui, msg, hint.as_deref());
        }
        if let Some(notice) = &self.notice {
            ui.colored_label(egui::Color32::from_rgb(120, 210, 140), notice);
        }

        ui.separator();
        self.result_ui(ui);

        if self.confirm_open {
            self.confirm_dialog(ui.ctx(), s);
        }
    }

    /// Query and set-time buttons. The query button is disabled while a query
    /// is in flight; the set-time button requires a usable result.
    fn control_row(
        &mut self,
        ui: &mut egui::Ui,
        s: &NtpSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        let query_enabled = !self.ctrl.is_active();
        if ui
            .add_enabled(query_enabled, egui::Button::new(t!("ntp.query")))
            .clicked()
        {
            self.record_target(s, history);
            self.start(s, rt);
        }

        let set_enabled = self.ctrl.state == TaskState::Finished
            && self.pending_set.is_none()
            && self.result.as_ref().is_some_and(|result| result.leap != 3);
        if ui
            .add_enabled(set_enabled, egui::Button::new(t!("ntp.set_time")))
            .on_disabled_hover_text(t!("ntp.set_time_disabled"))
            .clicked()
        {
            self.confirm_open = true;
        }

        if self.ctrl.state == TaskState::Running {
            ui.spinner();
            ui.weak(t!("ntp.querying"));
        }
        if self.pending_set.is_some() {
            ui.spinner();
            ui.weak(t!("ntp.elevation_pending"));
        }
    }

    /// Store a custom target in the history. Presets are never written there,
    /// so clearing the history cannot remove them.
    fn record_target(&self, s: &NtpSettings, history: &mut InputHistory) {
        let target = s.target.trim();
        if !PRESET_SERVERS.contains(&target) {
            history.record(TARGET_HISTORY_KEY, target);
        }
    }

    /// Render the live clock, the local and UTC time lines and the metrics.
    fn result_ui(&self, ui: &mut egui::Ui) {
        let Some(result) = &self.result else {
            ui.vertical_centered(|ui| {
                ui.add_space(48.0);
                ui.weak(t!("ntp.empty"));
            });
            return;
        };
        let Some(utc) = self.current_utc() else {
            return;
        };
        let offset = local_offset();
        let local = utc.to_offset(offset);

        ui.add_space(8.0);
        ui.vertical_centered(|ui| {
            draw_clock(ui, &local);
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format_local_ms(&local))
                    .monospace()
                    .size(34.0)
                    .strong(),
            );
            ui.label(
                egui::RichText::new(format!(
                    "{} ({})",
                    t!("ntp.local_time"),
                    offset_label(offset)
                ))
                .small()
                .weak(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("{} UTC", format_utc_ms(&utc)))
                    .monospace()
                    .size(18.0),
            );
            ui.add_space(6.0);
            metrics_ui(ui, result);
        });
    }

    /// Start an elevated helper on platforms that support it. Returns whether
    /// the prompt was started; platforms without automatic elevation keep the
    /// regular permission hint.
    fn try_prompt_elevation(&mut self, server: &str, timeout_ms: u64) -> bool {
        if !system_time::supports_elevation_prompt() {
            return false;
        }
        #[cfg(windows)]
        {
            self.begin_elevation(server, timeout_ms);
            true
        }
        #[cfg(not(windows))]
        {
            let _ = (server, timeout_ms);
            false
        }
    }

    /// Spawn the blocking UAC request off the UI thread and remember the result
    /// channel so the next frames can report success or failure.
    #[cfg(windows)]
    fn begin_elevation(&mut self, server: &str, timeout_ms: u64) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.pending_set = Some(rx);
        let server = server.to_string();
        std::thread::spawn(move || {
            let _ = tx.send(system_time::set_system_time_elevated(&server, timeout_ms));
        });
    }

    /// Poll the background elevation request and turn its result into a notice
    /// or an error banner.
    fn poll_pending_set(&mut self, ui: &egui::Ui) {
        let received = self.pending_set.as_ref().map(Receiver::try_recv);
        match received {
            Some(Ok(Ok(()))) => {
                self.pending_set = None;
                self.notice = Some(t!("ntp.time_set_ok").to_string());
                self.error = None;
            }
            Some(Ok(Err(err))) => {
                self.pending_set = None;
                self.error = Some((err.message, None));
                self.notice = None;
            }
            Some(Err(TryRecvError::Empty)) => {
                // The helper is still waiting for the UAC decision.
                ui.ctx().request_repaint_after(CLOCK_REPAINT);
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.pending_set = None;
                self.error = Some((t!("ntp.time_set_failed").to_string(), None));
                self.notice = None;
            }
            None => {}
        }
    }

    /// Confirmation dialog shown before the system clock is changed.
    fn confirm_dialog(&mut self, ctx: &egui::Context, settings: &NtpSettings) {
        let Some(result) = self.result.clone() else {
            self.confirm_open = false;
            return;
        };
        // Recompute right before showing, so the preview uses the live time
        // rather than a value captured when the query finished.
        let Some(ntp_now) = self.current_utc() else {
            self.confirm_open = false;
            return;
        };
        let system_now = OffsetDateTime::now_utc();
        let delta_ms = (ntp_now - system_now).whole_microseconds() as f64 / 1000.0;
        let offset = local_offset();

        let mut apply = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::new("ntp_set_time_confirm")).show(ctx, |ui| {
            ui.set_width(460.0);
            ui.heading(t!("ntp.confirm_title"));
            ui.colored_label(
                egui::Color32::from_rgb(240, 205, 120),
                t!("ntp.confirm_warning"),
            );
            ui.add_space(6.0);
            egui::Grid::new("ntp_confirm_grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(t!("ntp.system_time"));
                    ui.monospace(format!(
                        "{}  ({})",
                        format_local_ms(&system_now.to_offset(offset)),
                        format_utc_ms(&system_now)
                    ));
                    ui.end_row();

                    ui.label(t!("ntp.ntp_time"));
                    ui.monospace(format!(
                        "{}  ({})",
                        format_local_ms(&ntp_now.to_offset(offset)),
                        format_utc_ms(&ntp_now)
                    ));
                    ui.end_row();

                    ui.label(t!("ntp.delta"));
                    ui.monospace(format!("{delta_ms:+.3} ms"));
                    ui.end_row();

                    ui.label(t!("ntp.source"));
                    ui.monospace(&result.server_addr);
                    ui.end_row();
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(t!("ntp.confirm_apply")).clicked() {
                    apply = true;
                }
                if ui.button(t!("common.cancel")).clicked() {
                    cancel = true;
                }
            });
        });

        if apply {
            // The confirmation may have been open for a while, so use the
            // latest derived NTP time instead of the preview value.
            let target = self.current_utc();
            match target {
                Some(target) => match system_time::set_system_time_utc(target) {
                    Ok(()) => {
                        self.notice = Some(t!("ntp.time_set_ok").to_string());
                        self.error = None;
                    }
                    Err(err) => {
                        if err.permission_denied
                            && self.try_prompt_elevation(&result.target, settings.timeout_ms)
                        {
                            self.notice = Some(t!("ntp.elevation_pending").to_string());
                            self.error = None;
                        } else {
                            let hint = err.permission_denied.then(system_time::elevation_hint);
                            self.error = Some((err.message, hint));
                            self.notice = None;
                        }
                    }
                },
                None => {
                    self.error = Some((t!("ntp.time_set_failed").to_string(), None));
                }
            }
            self.confirm_open = false;
        } else if cancel || modal.should_close() {
            self.confirm_open = false;
        }
    }
}

/// Draw an analog clock whose hands follow `local`, including a smooth second
/// hand based on the millisecond fraction.
fn draw_clock(ui: &mut egui::Ui, local: &OffsetDateTime) {
    let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(CLOCK_SIZE), egui::Sense::hover());
    let painter = ui.painter();
    let center = rect.center();
    let radius = rect.width().min(rect.height()) * 0.5 - 8.0;
    let face = egui::Color32::from_rgb(24, 28, 36);
    let rim = egui::Color32::from_rgb(90, 150, 230);
    let tick = egui::Color32::from_rgb(130, 145, 165);
    let text = egui::Color32::from_rgb(220, 230, 245);

    painter.circle_filled(center, radius, face);
    painter.circle_stroke(center, radius, egui::Stroke::new(2.5, rim));
    painter.circle_stroke(
        center,
        radius - 6.0,
        egui::Stroke::new(1.0, tick.gamma_multiply(0.5)),
    );

    // Minute ticks, with longer ticks for the hour marks.
    for i in 0..60 {
        let angle = i as f32 / 60.0 * TAU - FRAC_PI_2;
        let (outer, inner) = if i % 5 == 0 {
            (radius - 8.0, radius - 19.0)
        } else {
            (radius - 8.0, radius - 13.0)
        };
        let dir = egui::Vec2::new(angle.cos(), angle.sin());
        painter.line_segment(
            [center + dir * inner, center + dir * outer],
            egui::Stroke::new(if i % 5 == 0 { 2.0 } else { 1.0 }, tick),
        );
    }

    // Hour marks around the dial.
    for (index, hour) in [12, 3, 6, 9].iter().enumerate() {
        let angle = index as f32 / 4.0 * TAU - FRAC_PI_2;
        let pos = center + egui::Vec2::new(angle.cos(), angle.sin()) * (radius - 34.0);
        painter.text(
            pos,
            egui::Align2::CENTER_CENTER,
            hour.to_string(),
            egui::FontId::proportional(16.0),
            text,
        );
    }

    let seconds = local.second() as f32 + local.nanosecond() as f32 / 1_000_000_000.0;
    let minutes = local.minute() as f32 + seconds / 60.0;
    let hours = (local.hour() % 12) as f32 + minutes / 60.0;

    draw_hand(painter, center, hours / 12.0, radius * 0.50, 6.0, text);
    draw_hand(painter, center, minutes / 60.0, radius * 0.70, 4.0, text);
    draw_hand(
        painter,
        center,
        seconds / 60.0,
        radius * 0.78,
        2.0,
        egui::Color32::from_rgb(230, 110, 100),
    );
    painter.circle_filled(center, 4.0, rim);
}

/// Draw one clock hand. `fraction` is the position within the full turn,
/// starting at 12 o'clock.
fn draw_hand(
    painter: &egui::Painter,
    center: egui::Pos2,
    fraction: f32,
    length: f32,
    width: f32,
    color: egui::Color32,
) {
    let angle = fraction * TAU - FRAC_PI_2;
    let end = center + egui::Vec2::new(angle.cos(), angle.sin()) * length;
    painter.line_segment([center, end], egui::Stroke::new(width, color));
}

/// Technical metrics below the clock, centered and wrapped when the window is
/// narrow.
fn metrics_ui(ui: &mut egui::Ui, result: &NtpResult) {
    let leap = match result.leap {
        0 => t!("ntp.leap_synchronized"),
        1 => t!("ntp.leap_add"),
        2 => t!("ntp.leap_delete"),
        _ => t!("ntp.leap_unsynchronized"),
    };
    let line_one = t!(
        "ntp.metrics_line_one",
        server = &result.server_addr,
        stratum = result.stratum,
        leap = leap,
        version = result.version
    );
    let line_two = t!(
        "ntp.metrics_line_two",
        offset = format!("{:+.3}", result.offset_ms),
        delay = format!("{:.3}", result.delay_ms),
        root_delay = format!("{:.3}", result.root_delay_ms),
        root_dispersion = format!("{:.3}", result.root_dispersion_ms)
    );
    let line_three = t!(
        "ntp.metrics_line_three",
        precision = format!("2^{}", result.precision),
        reference_id = &result.reference_id,
        reference_time = &result.reference_time,
        elapsed = format!("{:.1}", result.elapsed_ms)
    );

    for line in [line_one, line_two, line_three] {
        ui.label(egui::RichText::new(line).small().weak());
    }
}

/// Current local offset, falling back to UTC when the platform cannot report
/// it (for example in a restricted environment).
fn local_offset() -> UtcOffset {
    UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC)
}

const LOCAL_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");

/// Format a date-time in its own offset with milliseconds.
fn format_local_ms(dt: &OffsetDateTime) -> String {
    dt.format(LOCAL_FORMAT).unwrap_or_else(|_| "-".to_string())
}

/// Format a date-time as UTC with milliseconds.
fn format_utc_ms(dt: &OffsetDateTime) -> String {
    dt.to_offset(UtcOffset::UTC)
        .format(LOCAL_FORMAT)
        .unwrap_or_else(|_| "-".to_string())
}

/// Render an offset as `UTC+HH:MM` / `UTC-HH:MM`.
fn offset_label(offset: UtcOffset) -> String {
    let total = offset.whole_seconds();
    let sign = if total < 0 { '-' } else { '+' };
    let total = total.abs();
    format!("UTC{sign}{:02}:{:02}", total / 3600, (total % 3600) / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_labels_are_stable() {
        assert_eq!(offset_label(UtcOffset::UTC), "UTC+00:00");
        assert_eq!(
            offset_label(UtcOffset::from_hms(8, 0, 0).unwrap()),
            "UTC+08:00"
        );
        assert_eq!(
            offset_label(UtcOffset::from_hms(-5, -30, 0).unwrap()),
            "UTC-05:30"
        );
    }

    #[test]
    fn presets_are_unique() {
        let mut sorted = PRESET_SERVERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), PRESET_SERVERS.len());
    }
}
