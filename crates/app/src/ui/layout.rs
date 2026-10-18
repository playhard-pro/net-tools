//! Shared two-column layout: settings on the left, results on the right.

use eframe::egui;

/// Stable id shared by every tab so the panel width and collapse state stay
/// consistent while switching between tabs.
const SETTINGS_PANEL_ID: &str = "app.settings";

/// Width of the settings panel when it is first opened.
const SETTINGS_DEFAULT_WIDTH: f32 = 280.0;

/// Allowed width range. Dragging the edge beyond the minimum collapses the
/// panel; dragging it back out expands it again.
const SETTINGS_WIDTH_RANGE: std::ops::RangeInclusive<f32> = 240.0..=360.0;

/// Render the collapsible settings panel and return the contents' result.
///
/// `expanded` is taken by value and returned in its new state because the
/// caller's closure usually borrows the owning tab mutably; sharing a
/// `&mut bool` with that closure would conflict.
pub fn settings_panel<R>(
    ui: &mut egui::Ui,
    expanded: bool,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> (Option<R>, bool) {
    let mut expanded = expanded;
    let response = egui::Panel::left(SETTINGS_PANEL_ID)
        .resizable(true)
        .default_size(SETTINGS_DEFAULT_WIDTH)
        .size_range(SETTINGS_WIDTH_RANGE)
        .show_collapsible(ui, &mut expanded, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("app.settings.scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // Keep long hints inside the panel instead of letting
                    // their measured width expand the whole sidebar. A wider
                    // minimum interaction width also gives every settings grid
                    // a label column wide enough for two-word labels.
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                    ui.spacing_mut().interact_size.x = 90.0;
                    ui.set_max_width(ui.available_width());
                    add_contents(ui)
                })
                .inner
        });

    (response.map(|response| response.inner), expanded)
}

/// Render the results area in the space left by the settings panel.
///
/// The outer central panel already provides the window margins, so this one
/// only adds breathing room next to the panel divider.
pub fn results_panel<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let frame = egui::Frame::NONE.inner_margin(egui::Margin {
        left: 12,
        right: 0,
        top: 0,
        bottom: 0,
    });
    egui::CentralPanel::no_frame()
        .frame(frame)
        .show(ui, add_contents)
        .inner
}
