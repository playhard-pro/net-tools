//! Background update checks and their UI-facing state.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui;
use net_tools_core::config::UpdateSettings;
use net_tools_core::control::TaskController;
use net_tools_core::update::{AvailableUpdate, UpdateStatus, UPDATE_MANIFEST_URL};

/// Minimum time between automatic checks.
const AUTO_CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Message sent from the background task back to the UI.
enum UpdateEvent {
    Finished(Result<UpdateStatus, String>),
}

/// What the update dialog should display for the most recent check.
#[derive(Debug, Clone)]
pub enum UpdateDialog {
    Available(AvailableUpdate),
    UpToDate,
    Error(String),
}

/// Owns the background check task and the result shown to the user.
pub struct UpdateChecker {
    ctrl: TaskController<UpdateEvent>,
    available: Option<AvailableUpdate>,
    dialog: Option<UpdateDialog>,
    manual: bool,
}

impl Default for UpdateChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl UpdateChecker {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            available: None,
            dialog: None,
            manual: false,
        }
    }

    pub fn is_checking(&self) -> bool {
        self.ctrl.is_active()
    }

    /// Latest version offered by the manifest, if it is newer than the app.
    pub fn available(&self) -> Option<&AvailableUpdate> {
        self.available.as_ref()
    }

    pub fn dialog(&self) -> Option<UpdateDialog> {
        self.dialog.clone()
    }

    pub fn close_dialog(&mut self) {
        self.dialog = None;
    }

    /// Start a check unless one is already running.
    ///
    /// `ctx` is captured by the worker so the UI is repainted as soon as the
    /// result is ready, even when no tab is producing updates.
    pub fn start(
        &mut self,
        rt: &tokio::runtime::Handle,
        current_version: &str,
        manual: bool,
        ctx: &egui::Context,
    ) {
        if self.is_checking() {
            return;
        }
        self.available = None;
        self.dialog = None;
        self.manual = manual;

        let current = current_version.to_string();
        let ctx = ctx.clone();
        self.ctrl.start(rt, move |handle| async move {
            let result = net_tools_core::update::check_for_update(UPDATE_MANIFEST_URL, &current)
                .await
                .map_err(|err| err.to_string());
            handle.send(UpdateEvent::Finished(result));
            ctx.request_repaint();
        });
    }

    /// Drain finished checks and update the dialog state.
    ///
    /// Returns `true` when the last-check timestamp changed, so the caller can
    /// persist the configuration.
    pub fn poll(&mut self, settings: &mut UpdateSettings) -> bool {
        let mut changed = false;
        for event in self.ctrl.drain() {
            let UpdateEvent::Finished(result) = event;
            settings.last_checked = unix_now();
            changed = true;

            match result {
                Ok(UpdateStatus::Available(update)) => {
                    let skipped = update.version == settings.skipped_version;
                    // Automatic checks stay quiet for a version the user
                    // explicitly skipped; a manual check always reports it.
                    if self.manual || !skipped {
                        self.available = Some(update.clone());
                        self.dialog = Some(UpdateDialog::Available(update));
                    } else {
                        self.available = None;
                    }
                }
                Ok(UpdateStatus::UpToDate) => {
                    self.available = None;
                    if self.manual {
                        self.dialog = Some(UpdateDialog::UpToDate);
                    }
                }
                Err(error) => {
                    self.available = None;
                    if self.manual {
                        self.dialog = Some(UpdateDialog::Error(error));
                    }
                }
            }
        }
        changed
    }

    /// Store the currently offered version as skipped.
    pub fn skip_available(&mut self, settings: &mut UpdateSettings) -> bool {
        let Some(update) = &self.available else {
            return false;
        };
        settings.skipped_version = update.version.clone();
        self.available = None;
        self.dialog = None;
        true
    }

    /// Whether an automatic check is due.
    pub fn auto_check_due(&self, settings: &UpdateSettings) -> bool {
        if !settings.auto_check || self.is_checking() {
            return false;
        }
        should_auto_check(settings, unix_now())
    }

    /// Delay until the next automatic check, used to wake an idle UI.
    pub fn next_auto_check_delay(settings: &UpdateSettings) -> Option<Duration> {
        if !settings.auto_check {
            return None;
        }
        let elapsed = unix_now().saturating_sub(settings.last_checked).max(0) as u64;
        Some(Duration::from_secs(
            AUTO_CHECK_INTERVAL_SECS.saturating_sub(elapsed),
        ))
    }
}

fn should_auto_check(settings: &UpdateSettings, now: i64) -> bool {
    if !settings.auto_check {
        return false;
    }
    // Zero means the application has never completed a check.
    if settings.last_checked <= 0 {
        return true;
    }
    // A clock that moved backwards should not suppress updates indefinitely.
    if now < settings.last_checked {
        return true;
    }
    now.saturating_sub(settings.last_checked) as u64 >= AUTO_CHECK_INTERVAL_SECS
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(auto_check: bool, last_checked: i64) -> UpdateSettings {
        UpdateSettings {
            auto_check,
            last_checked,
            skipped_version: String::new(),
        }
    }

    #[test]
    fn auto_check_respects_interval_and_switch() {
        assert!(should_auto_check(&settings(true, 0), 1));
        assert!(should_auto_check(
            &settings(true, 1_000),
            1_000 + AUTO_CHECK_INTERVAL_SECS as i64
        ));
        assert!(!should_auto_check(
            &settings(true, 1_000),
            1_000 + AUTO_CHECK_INTERVAL_SECS as i64 - 1
        ));
        assert!(!should_auto_check(
            &settings(false, 0),
            AUTO_CHECK_INTERVAL_SECS as i64 * 2
        ));
    }

    #[test]
    fn clock_moving_backwards_triggers_a_check() {
        assert!(should_auto_check(&settings(true, 10_000), 5));
    }
}
