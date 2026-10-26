//! Common widgets: state badge, error banner, copy button.

use eframe::egui;
use net_tools_core::control::TaskState;
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use super::theme::Palette;

/// Colored task-state badge.
///
/// The badge is painted at the same height as a regular button so it stays
/// vertically aligned when placed next to controls in a horizontal row.
pub fn state_badge(ui: &mut egui::Ui, state: TaskState) -> egui::Response {
    let palette = Palette::from_ui(ui);
    let text = match state {
        TaskState::Idle => t!("state.idle"),
        TaskState::Running => t!("state.running"),
        TaskState::Paused => t!("state.paused"),
        TaskState::Stopping => t!("state.stopping"),
        TaskState::Finished => t!("state.finished"),
    };
    let color = palette.state_color(state);
    let font_id = egui::TextStyle::Body.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_string(), font_id, color);

    // Match the effective button height, including text that grows with the
    // font scale, while respecting the minimum interaction size.
    let button_padding = ui.spacing().button_padding.y;
    let height = ui
        .spacing()
        .interact_size
        .y
        .max(galley.size().y + 2.0 * button_padding);
    let width = galley.size().x + 16.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());

    let painter = ui.painter();
    painter.rect_filled(rect, 6.0, palette.badge_bg(color));
    painter.galley(rect.center() - galley.size() * 0.5, galley, color);
    response
}

/// Inline note for a mode whose capability is currently unavailable.
///
/// Renders nothing when `available` is true, so callers can show it
/// unconditionally for the relevant mode. The copyable elevation command comes
/// from the privilege status.
pub fn privilege_note(ui: &mut egui::Ui, available: bool, status: &PrivilegeStatus, message: &str) {
    if available {
        return;
    }
    let palette = Palette::from_ui(ui);
    egui::Frame::new()
        .fill(palette.warning_bg)
        .corner_radius(4.0)
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.colored_label(palette.warning_text, message);
            if let Some(hint) = &status.hint {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(hint)
                            .color(palette.warning_hint)
                            .monospace(),
                    );
                    copy_button(ui, hint);
                });
            }
        });
}

/// Error message plus an optional hint, with a copy button.
pub fn error_banner(ui: &mut egui::Ui, message: &str, hint: Option<&str>) {
    let palette = Palette::from_ui(ui);
    egui::Frame::new()
        .fill(palette.error_bg)
        .corner_radius(4.0)
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.colored_label(palette.error_text, message);
            if let Some(h) = hint {
                ui.label(egui::RichText::new(h).color(palette.error_hint).monospace());
                copy_button(ui, h);
            }
        });
}

/// Small drop-down button whose arrow is painted instead of rendered from a
/// font glyph. This keeps the control independent of the CJK fallback font.
pub fn dropdown_button(ui: &mut egui::Ui, tooltip: &str) -> egui::Response {
    let height = ui.spacing().interact_size.y;
    let response = ui.add(egui::Button::new("").min_size(egui::vec2(height.max(20.0), height)));
    let visuals = ui.style().interact(&response);
    let painter = ui.painter();
    let center = response.rect.center();
    let half_width = 3.5;
    let half_height = 2.5;
    painter.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(center.x - half_width, center.y - half_height),
            egui::pos2(center.x + half_width, center.y - half_height),
            egui::pos2(center.x, center.y + half_height),
        ],
        visuals.fg_stroke.color,
        egui::Stroke::NONE,
    ));
    response.on_hover_text(tooltip)
}

/// Copy text to the clipboard.
pub fn copy_button(ui: &mut egui::Ui, text: &str) {
    if ui.small_button(t!("common.copy")).clicked() {
        ui.ctx().copy_text(text.to_owned());
    }
}

/// A plain informational line.
pub fn info_line(ui: &mut egui::Ui, text: &str) {
    let color = Palette::from_ui(ui).info_text;
    ui.label(egui::RichText::new(text).color(color));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The badge must line up with buttons placed in the same row, both in
    /// height and in vertical center.
    #[test]
    fn state_badge_aligns_with_button_height() {
        let ctx = egui::Context::default();
        let mut sizes = None;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(400.0, 200.0),
            )),
            ..Default::default()
        };
        ctx.run_ui(input, |ui| {
            ui.horizontal(|ui| {
                let button = ui.button("Start");
                let badge = state_badge(ui, TaskState::Idle);
                sizes = Some((button.rect, badge.rect));
            });
        })
        .textures_delta
        .clear();

        let (button, badge) = sizes.expect("the row must be laid out");
        assert!((button.height() - badge.height()).abs() < 0.5);
        assert!((button.center().y - badge.center().y).abs() < 0.5);
    }
}
