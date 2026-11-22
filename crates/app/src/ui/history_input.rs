//! Editable text inputs with a drop-down of recently entered values.
//!
//! History is keyed by a stable field id, so each input keeps its own list.
//! Entries can be picked, deleted individually, or cleared in one click.

use eframe::egui;
use net_tools_core::config::InputHistory;
use rust_i18n::t;

/// Maximum height of the drop-down before it starts scrolling.
const POPUP_MAX_HEIGHT: f32 = 240.0;
/// Width of the drop-down pop-up.
const POPUP_WIDTH: f32 = 320.0;
/// Longest value shown verbatim in the list. Longer values are shortened for
/// display only; selecting one still restores the full value.
const MAX_DISPLAY_CHARS: usize = 40;

/// One fixed drop-down entry with a display label and an underlying value.
struct Preset {
    label: String,
    value: String,
}

/// Single-line text input with a history drop-down.
///
/// Returns `true` when Enter was pressed while the field had focus, so callers
/// can treat it as a submit action.
pub fn singleline(
    ui: &mut egui::Ui,
    key: &str,
    text: &mut String,
    history: &mut InputHistory,
    width: f32,
) -> bool {
    singleline_impl(ui, key, &[], text, history, width)
}

/// Single-line text input whose drop-down always offers a fixed set of
/// presets in addition to the editable history.
///
/// Presets are supplied by the caller and are never stored in the history, so
/// clearing the history cannot remove them.
pub fn singleline_with_presets(
    ui: &mut egui::Ui,
    key: &str,
    presets: &[&str],
    text: &mut String,
    history: &mut InputHistory,
    width: f32,
) -> bool {
    let presets: Vec<Preset> = presets
        .iter()
        .map(|value| Preset {
            label: (*value).to_string(),
            value: (*value).to_string(),
        })
        .collect();
    singleline_impl(ui, key, &presets, text, history, width)
}

/// Single-line text input whose drop-down offers labeled presets in addition
/// to the editable history. `presets` contains `(label, value)` pairs, which
/// allows an entry such as "All interfaces" to store an empty value.
pub fn singleline_with_labeled_presets(
    ui: &mut egui::Ui,
    key: &str,
    presets: &[(&str, &str)],
    text: &mut String,
    history: &mut InputHistory,
    width: f32,
) -> bool {
    let presets: Vec<Preset> = presets
        .iter()
        .map(|(label, value)| Preset {
            label: (*label).to_string(),
            value: (*value).to_string(),
        })
        .collect();
    singleline_impl(ui, key, &presets, text, history, width)
}

fn singleline_impl(
    ui: &mut egui::Ui,
    key: &str,
    presets: &[Preset],
    text: &mut String,
    history: &mut InputHistory,
    width: f32,
) -> bool {
    let mut submit = false;
    ui.horizontal(|ui| {
        let edit = ui.add(egui::TextEdit::singleline(text).desired_width(width));
        // Enter submits the current value; history is recorded by the caller
        // when the task actually starts.
        if edit.lost_focus() {
            submit = ui.input(|i| i.key_pressed(egui::Key::Enter));
        }
        history_button(ui, key, presets, text, history);
    });
    submit
}

/// Multi-line text input with a history drop-down.
pub fn multiline(
    ui: &mut egui::Ui,
    key: &str,
    text: &mut String,
    history: &mut InputHistory,
    width: f32,
    rows: usize,
) {
    ui.vertical(|ui| {
        ui.add(
            egui::TextEdit::multiline(text)
                .desired_rows(rows)
                .desired_width(width),
        );
        history_button(ui, key, &[], text, history);
    });
}

/// Remember several field values at once. Call this when a task is started so
/// history only grows on an explicit submit, not on every focus change.
pub fn record_fields(history: &mut InputHistory, fields: &[(&str, &str)]) {
    for (key, value) in fields {
        history.record(key, value);
    }
}

/// Drop-down toggle button anchored to the pop-up that lists the presets and
/// the history.
fn history_button(
    ui: &mut egui::Ui,
    key: &str,
    presets: &[Preset],
    text: &mut String,
    history: &mut InputHistory,
) {
    // Scope the auto-generated ids by field key so multiple buttons never
    // collide and the open state stays attached to the right field.
    ui.push_id(("history", key), |ui| {
        let button = super::common::dropdown_button(ui, &t!("common.history"));
        egui::Popup::from_toggle_button_response(&button)
            // Keep the pop-up open while entries are deleted inside it; it is
            // closed explicitly when an entry is picked or cleared.
            .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
            .width(POPUP_WIDTH)
            .show(|ui| history_menu(ui, key, presets, text, history));
    });
}

/// Contents of the history pop-up for one field.
fn history_menu(
    ui: &mut egui::Ui,
    key: &str,
    presets: &[Preset],
    text: &mut String,
    history: &mut InputHistory,
) {
    // Presets are pinned entries: they are always shown and have no delete
    // action, so they can never be removed from the list.
    if !presets.is_empty() {
        ui.weak(t!("common.presets"));
        for preset in presets {
            if ui
                .selectable_label(text == &preset.value, &preset.label)
                .clicked()
            {
                *text = preset.value.clone();
                ui.close();
            }
        }
        ui.separator();
    }

    // Work on a snapshot so the list stays readable while the delete button
    // mutates the stored history. Presets are filtered out even if an older
    // configuration recorded one of them.
    let entries: Vec<(usize, String)> = history
        .entries(key)
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !presets
                .iter()
                .any(|preset| preset.value.as_str() == entry.as_str())
        })
        .map(|(index, entry)| (index, entry.clone()))
        .collect();
    if entries.is_empty() {
        if presets.is_empty() {
            ui.weak(t!("common.history_empty"));
        } else {
            ui.weak(t!("common.no_custom_history"));
        }
        return;
    }

    ui.weak(t!("common.history"));
    let mut remove = None;
    egui::ScrollArea::vertical()
        .max_height(POPUP_MAX_HEIGHT)
        .show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            for (index, entry) in entries {
                ui.horizontal(|ui| {
                    // Lay the entry row out from the right so the delete button
                    // keeps its natural size and the selectable label only uses
                    // the space that is genuinely left over. Deriving the label
                    // width from an assumed button width let the row overflow,
                    // which made the pop-up grow a little on every frame.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("x").clicked() {
                            remove = Some(index);
                        }
                        let label = ui.add_sized(
                            [ui.available_width().max(1.0), ui.spacing().interact_size.y],
                            egui::Button::selectable(false, display_value(&entry)),
                        );
                        if label.clicked() {
                            *text = entry.clone();
                            ui.close();
                        }
                    });
                });
            }
        });

    ui.separator();
    if ui.button(t!("common.clear_history")).clicked() {
        history.clear(key);
        ui.close();
    }

    if let Some(index) = remove {
        history.remove(key, index);
    }
}

/// Shorten a value for display, keeping the beginning and adding an ellipsis
/// when it does not fit the fixed entry width.
fn display_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= MAX_DISPLAY_CHARS {
        return value.to_owned();
    }
    let mut out: String = chars.into_iter().take(MAX_DISPLAY_CHARS).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pop-up is sized from its contents, so an entry row that reports more
    /// width than the pop-up has would make the next frame wider again. Render
    /// the open pop-up over several frames and require the width to settle.
    #[test]
    fn history_popup_width_stays_stable() {
        let ctx = egui::Context::default();
        crate::ui::theme::apply(&ctx, crate::ui::theme::DEFAULT_THEME);
        let mut history = InputHistory::default();
        history.record("key", "some-value");
        let mut text = String::new();
        let mut widths = Vec::new();

        for _ in 0..12 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(900.0, 700.0),
                )),
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                let button = super::super::common::dropdown_button(ui, "history");
                egui::Popup::from_toggle_button_response(&button)
                    .open(true)
                    .width(POPUP_WIDTH)
                    .show(|ui| {
                        history_menu(ui, "key", &[], &mut text, &mut history);
                        widths.push(ui.min_rect().width());
                    });
            })
            .textures_delta
            .clear();
        }

        let first = widths[0];
        assert!(
            widths.iter().all(|width| (width - first).abs() < 0.5),
            "pop-up width changed between frames: {widths:?}"
        );
    }
}
