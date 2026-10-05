//! Common widgets: state badge, error banner, copy button.

use eframe::egui;
use net_tools_core::control::TaskState;
use rust_i18n::t;

/// Colored task-state badge.
pub fn state_badge(ui: &mut egui::Ui, state: TaskState) {
    let (text, color) = match state {
        TaskState::Idle => (t!("state.idle"), egui::Color32::GRAY),
        TaskState::Running => (t!("state.running"), egui::Color32::from_rgb(0, 180, 0)),
        TaskState::Paused => (t!("state.paused"), egui::Color32::from_rgb(230, 160, 0)),
        TaskState::Stopping => (t!("state.stopping"), egui::Color32::from_rgb(200, 120, 0)),
        TaskState::Finished => (t!("state.finished"), egui::Color32::from_rgb(90, 140, 220)),
    };
    egui::Frame::new()
        .fill(color.gamma_multiply(0.18))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.colored_label(color, text);
        });
}

/// Error message plus an optional hint, with a copy button.
pub fn error_banner(ui: &mut egui::Ui, message: &str, hint: Option<&str>) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(90, 20, 20))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.colored_label(egui::Color32::from_rgb(255, 130, 130), message);
            if let Some(h) = hint {
                ui.label(
                    egui::RichText::new(h)
                        .color(egui::Color32::from_rgb(255, 200, 160))
                        .monospace(),
                );
                copy_button(ui, h);
            }
        });
}

/// Copy text to the clipboard.
pub fn copy_button(ui: &mut egui::Ui, text: &str) {
    if ui.small_button(t!("common.copy")).clicked() {
        ui.ctx().copy_text(text.to_owned());
    }
}

/// A plain informational line.
pub fn info_line(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(egui::Color32::from_rgb(150, 200, 255)));
}

/// Action chosen from the result toolbar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolbarAction {
    None,
    Copy,
    ExportCsv,
    ExportJson,
    ExportHtml,
    Clear,
}

/// Render the result toolbar (copy all / export / clear) and return the user's
/// choice.
///
/// Only the action is returned; the caller generates the actual content on
/// click, avoiding serializing all results on every frame (which is noticeably
/// slow for large result sets).
pub fn result_toolbar(ui: &mut egui::Ui) -> ToolbarAction {
    let mut action = ToolbarAction::None;
    ui.horizontal(|ui| {
        if ui.small_button(t!("common.copy_all")).clicked() {
            action = ToolbarAction::Copy;
        }
        ui.menu_button(t!("common.export"), |ui| {
            if ui.button("CSV").clicked() {
                ui.close();
                action = ToolbarAction::ExportCsv;
            }
            if ui.button("JSON").clicked() {
                ui.close();
                action = ToolbarAction::ExportJson;
            }
            if ui.button("HTML").clicked() {
                ui.close();
                action = ToolbarAction::ExportHtml;
            }
        });
        if ui.small_button(t!("common.clear")).clicked() {
            action = ToolbarAction::Clear;
        }
    });
    action
}
