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

/// Render a menu button using the compact button size.
///
/// `Ui::menu_button` always builds a regular-size button. Result toolbars mix
/// menu buttons with `small_button`s, so using the regular size there makes the
/// export control visibly taller than its neighbours.
fn small_menu_button<R>(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::Response {
    let (response, _) =
        egui::containers::menu::MenuButton::from_button(egui::Button::new(text.into()).small())
            .ui(ui, add_contents);
    response
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
        small_menu_button(ui, t!("common.export"), |ui| {
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

    #[test]
    fn toolbar_menu_button_matches_small_button_height() {
        let ctx = egui::Context::default();
        // Use the real theme so the test covers the same padding and sizing the
        // application uses.
        crate::ui::theme::apply(&ctx, crate::ui::theme::DEFAULT_THEME);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(400.0, 200.0),
            )),
            ..Default::default()
        };
        let mut rects = None;
        ctx.run_ui(input, |ui| {
            ui.horizontal(|ui| {
                let copy = ui.small_button("Copy all");
                let export = small_menu_button(ui, "Export", |ui| {
                    let _ = ui.button("CSV");
                });
                let clear = ui.small_button("Clear");
                rects = Some((copy.rect, export.rect, clear.rect));
            });
        })
        .textures_delta
        .clear();

        let (copy, export, clear) = rects.expect("the toolbar must be laid out");
        assert!((copy.height() - export.height()).abs() < 0.5);
        assert!((export.height() - clear.height()).abs() < 0.5);
        assert!((copy.center().y - export.center().y).abs() < 0.5);
        assert!((export.center().y - clear.center().y).abs() < 0.5);
    }
}
