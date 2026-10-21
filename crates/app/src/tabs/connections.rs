//! Connections tab: local listening sockets and active connections.
//!
//! Collection runs on a short-lived background thread so a slow `/proc` scan or
//! `lsof` call never blocks the UI. Filtering and selection operate on the latest
//! snapshot only; the tab does not keep historical samples.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::ConnectionSettings;
use net_tools_core::net::connections::{
    self, ConnectionEntry, ConnectionProtocol, ConnectionSnapshot, ConnectionState,
};
use rust_i18n::t;

use crate::ui::common::{error_banner, info_line, result_toolbar, ToolbarAction};
use crate::ui::result_table::table_selectable_fill_with_columns;
use crate::ui::theme::Palette;

/// Smallest accepted automatic refresh interval.
const MIN_INTERVAL_MS: u64 = 500;

/// Largest accepted automatic refresh interval.
const MAX_INTERVAL_MS: u64 = 60_000;

/// Repaint cadence while a collection is outstanding.
const PENDING_REPAINT: Duration = Duration::from_millis(200);

/// Protocol filter options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolFilter {
    All,
    Tcp,
    Udp,
}

impl ProtocolFilter {
    fn label(self) -> String {
        match self {
            ProtocolFilter::All => t!("connections.protocol_all").to_string(),
            ProtocolFilter::Tcp => "TCP".to_string(),
            ProtocolFilter::Udp => "UDP".to_string(),
        }
    }
}

/// State filter options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateFilter {
    All,
    Listening,
    Established,
    Other,
}

impl StateFilter {
    fn label(self) -> String {
        match self {
            StateFilter::All => t!("connections.state_all").to_string(),
            StateFilter::Listening => t!("connections.state_listening").to_string(),
            StateFilter::Established => t!("connections.state_established").to_string(),
            StateFilter::Other => t!("connections.state_other").to_string(),
        }
    }
}

/// Action awaiting confirmation.
#[derive(Debug, Clone)]
enum ConfirmAction {
    Terminate(ConnectionEntry),
    Close(ConnectionEntry),
}

/// Tab state.
pub struct ConnectionsTab {
    snapshot: Option<ConnectionSnapshot>,
    pending: Option<Receiver<Result<ConnectionSnapshot, String>>>,
    last_refresh: Option<Instant>,
    error: Option<String>,
    notice: Option<String>,
    /// Indices into `snapshot.entries` that pass the current filters.
    filtered: Vec<usize>,
    filter_dirty: bool,
    protocol_filter: ProtocolFilter,
    state_filter: StateFilter,
    process_filter: String,
    port_filter: String,
    remote_filter: String,
    selected: Option<ConnectionEntry>,
    confirm: Option<ConfirmAction>,
    force_kill: bool,
}

impl Default for ConnectionsTab {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionsTab {
    pub fn new() -> Self {
        Self {
            snapshot: None,
            pending: None,
            last_refresh: None,
            error: None,
            notice: None,
            filtered: Vec::new(),
            filter_dirty: true,
            protocol_filter: ProtocolFilter::All,
            state_filter: StateFilter::All,
            process_filter: String::new(),
            port_filter: String::new(),
            remote_filter: String::new(),
            selected: None,
            confirm: None,
            force_kill: false,
        }
    }

    /// Stop background polling when another tab is selected. The latest
    /// snapshot and filters remain available for when the tab is reopened.
    pub fn clear_on_hide(&mut self) {
        // Dropping the receiver makes a late collection result a no-op.
        self.pending = None;
        self.confirm = None;
    }

    /// Render the tab and return the shared settings-panel state unchanged.
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut ConnectionSettings,
        settings_expanded: bool,
    ) -> bool {
        self.poll_refresh();
        if self.snapshot.is_none() && self.pending.is_none() {
            self.request_refresh();
        }

        let interval = Duration::from_millis(s.interval_ms.clamp(MIN_INTERVAL_MS, MAX_INTERVAL_MS));
        if s.auto_refresh
            && self.pending.is_none()
            && self
                .last_refresh
                .is_some_and(|last| last.elapsed() >= interval)
        {
            self.request_refresh();
        }

        if self.pending.is_some() {
            ui.ctx().request_repaint_after(PENDING_REPAINT);
        } else if s.auto_refresh {
            ui.ctx().request_repaint_after(interval);
        }

        let before_filters = self.filter_state();
        let mut refresh_now = false;
        let (_, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            egui::Grid::new("connections_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("connections.auto_refresh"));
                    ui.checkbox(&mut s.auto_refresh, "");
                    ui.end_row();

                    ui.label(t!("connections.refresh_interval"));
                    ui.add(
                        egui::DragValue::new(&mut s.interval_ms)
                            .range(MIN_INTERVAL_MS..=MAX_INTERVAL_MS)
                            .suffix(" ms"),
                    );
                    ui.end_row();

                    ui.label(t!("common.protocol"));
                    egui::ComboBox::from_id_salt("connections_protocol_filter")
                        .selected_text(self.protocol_filter.label())
                        .show_ui(ui, |ui| {
                            for value in [
                                ProtocolFilter::All,
                                ProtocolFilter::Tcp,
                                ProtocolFilter::Udp,
                            ] {
                                ui.selectable_value(
                                    &mut self.protocol_filter,
                                    value,
                                    value.label(),
                                );
                            }
                        });
                    ui.end_row();

                    ui.label(t!("common.state"));
                    egui::ComboBox::from_id_salt("connections_state_filter")
                        .selected_text(self.state_filter.label())
                        .show_ui(ui, |ui| {
                            for value in [
                                StateFilter::All,
                                StateFilter::Listening,
                                StateFilter::Established,
                                StateFilter::Other,
                            ] {
                                ui.selectable_value(&mut self.state_filter, value, value.label());
                            }
                        });
                    ui.end_row();

                    ui.label(t!("connections.filter_process"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.process_filter)
                            .desired_width(150.0)
                            .hint_text(t!("connections.filter_process_hint")),
                    );
                    ui.end_row();

                    ui.label(t!("connections.filter_port"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.port_filter)
                            .desired_width(150.0)
                            .hint_text(t!("connections.filter_port_hint")),
                    );
                    ui.end_row();

                    ui.label(t!("connections.filter_remote"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.remote_filter)
                            .desired_width(150.0)
                            .hint_text(t!("connections.filter_remote_hint")),
                    );
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(t!("connections.refresh_now")).clicked() {
                    refresh_now = true;
                }
                if self.pending.is_some() {
                    ui.spinner();
                    ui.weak(t!("connections.collecting"));
                }
            });
        });

        if before_filters != self.filter_state() {
            self.filter_dirty = true;
        }
        if refresh_now {
            self.request_refresh();
        }
        if self.filter_dirty {
            self.apply_filters();
        }

        crate::ui::layout::results_panel(ui, |ui| {
            self.status_line(ui);
            self.action_toolbar(ui);
            self.table_toolbar(ui);
            self.messages(ui);
            self.table_ui(ui);
        });

        self.confirm_dialog(ui.ctx());
        expanded
    }

    /// Start one background collection unless one is already running.
    fn request_refresh(&mut self) {
        if self.pending.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.last_refresh = Some(Instant::now());
        std::thread::spawn(move || {
            let _ = tx.send(connections::collect());
        });
    }

    /// Apply a completed collection or report its failure.
    fn poll_refresh(&mut self) {
        let received = self.pending.as_ref().map(Receiver::try_recv);
        match received {
            Some(Ok(Ok(snapshot))) => {
                self.pending = None;
                self.error = None;
                self.snapshot = Some(snapshot);
                self.filter_dirty = true;
                self.keep_selection_if_present();
            }
            Some(Ok(Err(error))) => {
                self.pending = None;
                self.error = Some(error);
            }
            Some(Err(TryRecvError::Empty)) => {}
            Some(Err(TryRecvError::Disconnected)) => {
                self.pending = None;
                self.error = Some(t!("connections.collect_failed").to_string());
            }
            None => {}
        }
    }

    /// Clear the selection when a new snapshot no longer contains it.
    fn keep_selection_if_present(&mut self) {
        let keep = self.selected.as_ref().is_some_and(|selected| {
            self.snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.entries.iter().any(|entry| entry == selected))
        });
        if !keep {
            self.selected = None;
        }
    }

    /// Snapshot of the editable filters, used to detect changes after the panel
    /// closure has run.
    fn filter_state(&self) -> (ProtocolFilter, StateFilter, String, String, String) {
        (
            self.protocol_filter,
            self.state_filter,
            self.process_filter.clone(),
            self.port_filter.clone(),
            self.remote_filter.clone(),
        )
    }

    /// Rebuild the visible index list from the latest snapshot.
    fn apply_filters(&mut self) {
        let Some(snapshot) = &self.snapshot else {
            self.filtered.clear();
            self.filter_dirty = false;
            return;
        };
        let process = self.process_filter.trim().to_ascii_lowercase();
        let port = self.port_filter.trim().to_ascii_lowercase();
        let remote = self.remote_filter.trim().to_ascii_lowercase();

        self.filtered = snapshot
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                self.matches_protocol(entry)
                    && self.matches_state(entry.state)
                    && matches_process(entry, &process)
                    && matches_local_port(entry, &port)
                    && entry
                        .remote_endpoint()
                        .to_ascii_lowercase()
                        .contains(&remote)
            })
            .map(|(index, _)| index)
            .collect();

        let keep = self.selected.as_ref().is_some_and(|selected| {
            self.filtered
                .iter()
                .any(|index| &snapshot.entries[*index] == selected)
        });
        if !keep {
            self.selected = None;
        }
        self.filter_dirty = false;
    }

    fn matches_protocol(&self, entry: &ConnectionEntry) -> bool {
        match self.protocol_filter {
            ProtocolFilter::All => true,
            ProtocolFilter::Tcp => entry.protocol == ConnectionProtocol::Tcp,
            ProtocolFilter::Udp => entry.protocol == ConnectionProtocol::Udp,
        }
    }

    fn matches_state(&self, state: ConnectionState) -> bool {
        match self.state_filter {
            StateFilter::All => true,
            StateFilter::Listening => state.is_listening(),
            StateFilter::Established => state == ConnectionState::Established,
            StateFilter::Other => !state.is_listening() && state != ConnectionState::Established,
        }
    }

    /// Captured time and row counts.
    fn status_line(&self, ui: &mut egui::Ui) {
        let captured = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.captured_at.as_str())
            .unwrap_or("-");
        let total = self
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.entries.len());
        ui.horizontal(|ui| {
            ui.label(format!("{}: {captured}", t!("connections.captured")));
            ui.separator();
            ui.label(format!("{}: {total}", t!("connections.total")));
            ui.separator();
            ui.label(format!(
                "{}: {}",
                t!("connections.shown"),
                self.filtered.len()
            ));
        });
    }

    /// Selected-row actions. Destructive operations only open a confirmation
    /// dialog here; the actual call happens after explicit approval.
    fn action_toolbar(&mut self, ui: &mut egui::Ui) {
        let selected = self.selected.clone();
        let can_kill = selected.as_ref().is_some_and(|entry| entry.pid.is_some());
        let can_close = selected
            .as_ref()
            .is_some_and(connections::close_connection_supported);
        let mut requested = None;

        ui.horizontal(|ui| {
            let kill = ui
                .add_enabled(can_kill, egui::Button::new(t!("connections.end_process")))
                .on_disabled_hover_text(t!("connections.select_process_hint"));
            if kill.clicked() {
                if let Some(entry) = selected.clone() {
                    requested = Some(ConfirmAction::Terminate(entry));
                }
            }

            let close = ui
                .add_enabled(
                    can_close,
                    egui::Button::new(t!("connections.close_connection")),
                )
                .on_disabled_hover_text(close_unavailable_hint(selected.as_ref()));
            if close.clicked() {
                if let Some(entry) = selected.clone() {
                    requested = Some(ConfirmAction::Close(entry));
                }
            }

            if let Some(entry) = &selected {
                ui.separator();
                ui.weak(selected_summary(entry));
            }
        });

        if let Some(action) = requested {
            self.force_kill = false;
            self.confirm = Some(action);
        }
    }

    /// Copy and export controls for the currently visible rows.
    fn table_toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv()),
            ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("connections", "csv", &self.to_csv())
            }
            ToolbarAction::ExportJson => {
                crate::ui::export::save_file("connections", "json", &self.to_json())
            }
            ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("connections", "html", &self.to_html())
            }
            ToolbarAction::Clear => self.clear_filters(),
            ToolbarAction::None => {}
        }
    }

    /// Error, warning and success messages.
    fn messages(&self, ui: &mut egui::Ui) {
        if let Some(error) = &self.error {
            error_banner(ui, error, None);
        }
        if let Some(warning) = &self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.warnings.first())
        {
            let color = Palette::from_ui(ui).warning_text;
            ui.colored_label(color, warning.as_str());
        }
        if let Some(notice) = &self.notice {
            let color = Palette::from_ui(ui).success_text;
            ui.colored_label(color, notice);
        }
        if self.snapshot.is_none() && self.pending.is_none() && self.error.is_none() {
            info_line(ui, &t!("connections.empty"));
        }
    }

    /// Render the selectable socket table.
    fn table_ui(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let headers = [
            t!("common.protocol"),
            t!("connections.local"),
            t!("connections.remote"),
            t!("common.state"),
            t!("connections.pid"),
            t!("connections.process"),
            t!("connections.uid"),
        ];
        let width = ui.available_width();
        let columns = [
            Column::exact(width * 0.06),
            Column::exact(width * 0.23),
            Column::exact(width * 0.23),
            Column::exact(width * 0.13),
            Column::exact(width * 0.07),
            Column::remainder().at_least(90.0),
            Column::exact(width * 0.06),
        ];
        let palette = Palette::from_ui(ui);
        let selected_index = self.selected.as_ref().and_then(|selected| {
            self.filtered
                .iter()
                .position(|index| &snapshot.entries[*index] == selected)
        });
        let clicked = table_selectable_fill_with_columns(
            ui,
            &headers,
            self.filtered.len(),
            selected_index,
            columns,
            |row_index, row| {
                let entry = &snapshot.entries[self.filtered[row_index]];
                row.col(|ui| {
                    ui.label(entry.protocol.label());
                });
                row.col(|ui| {
                    let local = entry.local_endpoint();
                    ui.label(&local).on_hover_text(local);
                });
                row.col(|ui| {
                    let remote = entry.remote_endpoint();
                    ui.label(&remote).on_hover_text(remote);
                });
                row.col(|ui| {
                    ui.colored_label(state_color(&palette, entry.state), entry.state.label());
                });
                row.col(|ui| {
                    ui.label(
                        entry
                            .pid
                            .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
                    );
                });
                row.col(|ui| {
                    let process = entry.process.clone().unwrap_or_else(|| "-".to_string());
                    ui.label(&process).on_hover_text(process);
                });
                row.col(|ui| {
                    ui.label(
                        entry
                            .uid
                            .map_or_else(|| "-".to_string(), |uid| uid.to_string()),
                    );
                });
            },
        );

        if let Some(row_index) = clicked {
            self.selected = Some(snapshot.entries[self.filtered[row_index]].clone());
        }
    }

    /// Reset all filters without discarding the latest snapshot.
    fn clear_filters(&mut self) {
        self.protocol_filter = ProtocolFilter::All;
        self.state_filter = StateFilter::All;
        self.process_filter.clear();
        self.port_filter.clear();
        self.remote_filter.clear();
        self.filter_dirty = true;
    }

    /// Confirmation dialog for process termination or socket destruction.
    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(action) = self.confirm.clone() else {
            return;
        };
        let (entry, terminating) = match &action {
            ConfirmAction::Terminate(entry) => (entry, true),
            ConfirmAction::Close(entry) => (entry, false),
        };
        let mut apply = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::new("connections_confirm")).show(ctx, |ui| {
            ui.set_width(460.0);
            let warning = Palette::from_ui(ui).warning_text;
            ui.heading(if terminating {
                t!("connections.confirm_terminate_title")
            } else {
                t!("connections.confirm_close_title")
            });
            ui.colored_label(
                warning,
                if terminating {
                    t!("connections.confirm_terminate_warning")
                } else {
                    t!("connections.confirm_close_warning")
                },
            );
            ui.add_space(6.0);
            egui::Grid::new("connections_confirm_grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(t!("connections.protocol"));
                    ui.monospace(entry.protocol.label());
                    ui.end_row();

                    ui.label(t!("connections.process"));
                    ui.monospace(entry.process.as_deref().unwrap_or("-"));
                    ui.end_row();

                    ui.label(t!("connections.pid"));
                    ui.monospace(
                        entry
                            .pid
                            .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
                    );
                    ui.end_row();

                    ui.label(t!("connections.local"));
                    ui.monospace(entry.local_endpoint());
                    ui.end_row();

                    ui.label(t!("connections.remote"));
                    ui.monospace(entry.remote_endpoint());
                    ui.end_row();

                    ui.label(t!("common.state"));
                    ui.monospace(entry.state.label());
                    ui.end_row();
                });

            if terminating {
                ui.add_space(6.0);
                ui.checkbox(&mut self.force_kill, t!("connections.force_kill"));
                if cfg!(windows) {
                    ui.weak(t!("connections.windows_force_note"));
                }
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .button(if terminating {
                        t!("connections.confirm_terminate")
                    } else {
                        t!("connections.confirm_close")
                    })
                    .clicked()
                {
                    apply = true;
                }
                if ui.button(t!("common.cancel")).clicked() {
                    cancel = true;
                }
            });
        });

        if apply {
            let result = match &action {
                ConfirmAction::Terminate(entry) => entry
                    .pid
                    .ok_or_else(|| t!("connections.no_pid").to_string())
                    .and_then(|pid| connections::terminate_process(pid, self.force_kill)),
                ConfirmAction::Close(entry) => connections::close_connection(entry),
            };
            match result {
                Ok(()) => {
                    self.notice = Some(
                        if terminating {
                            t!("connections.terminate_ok")
                        } else {
                            t!("connections.close_ok")
                        }
                        .to_string(),
                    );
                    self.error = None;
                }
                Err(error) => {
                    self.notice = None;
                    self.error = Some(if terminating {
                        format!("{}: {error}", t!("connections.terminate_failed"))
                    } else {
                        format!("{}: {error}", t!("connections.close_failed"))
                    });
                }
            }
            self.confirm = None;
            self.request_refresh();
        } else if cancel || modal.should_close() {
            self.confirm = None;
        }
    }

    /// CSV export of the visible rows, matching the table columns.
    pub fn to_csv(&self) -> String {
        let mut out = String::from("protocol,local,remote,state,pid,process,uid\n");
        for entry in self.filtered_entries() {
            out.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                entry.protocol.label(),
                crate::ui::export::csv_field(&entry.local_endpoint()),
                crate::ui::export::csv_field(&entry.remote_endpoint()),
                entry.state.label(),
                entry
                    .pid
                    .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
                crate::ui::export::csv_field(entry.process.as_deref().unwrap_or("-")),
                entry
                    .uid
                    .map_or_else(|| "-".to_string(), |uid| uid.to_string()),
            ));
        }
        out
    }

    /// JSON export of the visible rows.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.filtered_entries()).unwrap_or_default()
    }

    /// HTML export built from the CSV representation.
    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }

    /// Entries in the current table order.
    fn filtered_entries(&self) -> Vec<&ConnectionEntry> {
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        self.filtered
            .iter()
            .filter_map(|index| snapshot.entries.get(*index))
            .collect()
    }
}

/// Process and PID substring match.
fn matches_process(entry: &ConnectionEntry, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let process = entry
        .process
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let pid = entry.pid.map(|pid| pid.to_string()).unwrap_or_default();
    process.contains(needle) || pid.contains(needle)
}

/// Local port match. Numeric input matches the exact port, other text matches
/// the formatted endpoint.
fn matches_local_port(entry: &ConnectionEntry, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if let Ok(port) = needle.parse::<u16>() {
        entry.local_port == port
    } else {
        entry.local_endpoint().to_ascii_lowercase().contains(needle)
    }
}

/// Color for the normalized state label.
fn state_color(palette: &Palette, state: ConnectionState) -> egui::Color32 {
    if state.is_listening() {
        palette.state_running
    } else if state == ConnectionState::Established {
        palette.state_finished
    } else if matches!(state, ConnectionState::TimeWait | ConnectionState::Closed) {
        palette.state_idle
    } else {
        palette.state_paused
    }
}

/// Short description of the selected socket for the action toolbar.
fn selected_summary(entry: &ConnectionEntry) -> String {
    format!(
        "{} {} {} {}",
        entry.protocol.label(),
        entry.local_endpoint(),
        entry.state.label(),
        entry.process.as_deref().unwrap_or("-")
    )
}

/// Explain why the close button is unavailable for the current selection.
fn close_unavailable_hint(entry: Option<&ConnectionEntry>) -> String {
    if entry.is_none() {
        return t!("connections.select_connection_hint").to_string();
    }
    if cfg!(target_os = "macos") {
        t!("connections.close_unsupported_macos").to_string()
    } else if cfg!(windows) {
        t!("connections.close_unsupported_windows").to_string()
    } else {
        t!("connections.close_unavailable").to_string()
    }
}
