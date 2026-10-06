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
    let mut submit = false;
    ui.horizontal(|ui| {
        let edit = ui.add(egui::TextEdit::singleline(text).desired_width(width));
        // Enter submits the current value; history is recorded by the caller
        // when the task actually starts.
        if edit.lost_focus() {
            submit = ui.input(|i| i.key_pressed(egui::Key::Enter));
        }
        history_button(ui, key, text, history);
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
        history_button(ui, key, text, history);
    });
}

/// Remember several field values at once. Call this when a task is started so
/// history only grows on an explicit submit, not on every focus change.
pub fn record_fields(history: &mut InputHistory, fields: &[(&str, &str)]) {
    for (key, value) in fields {
        history.record(key, value);
    }
}

/// Drop-down toggle button anchored to the pop-up that lists the history.
fn history_button(ui: &mut egui::Ui, key: &str, text: &mut String, history: &mut InputHistory) {
    // Scope the auto-generated ids by field key so multiple buttons never
    // collide and the open state stays attached to the right field.
    ui.push_id(("history", key), |ui| {
        let button = ui.button("▼").on_hover_text(t!("common.history"));
        egui::Popup::from_toggle_button_response(&button)
            // Keep the pop-up open while entries are deleted inside it; it is
            // closed explicitly when an entry is picked or cleared.
            .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
            .width(POPUP_WIDTH)
            .show(|ui| history_menu(ui, key, text, history));
    });
}

/// Contents of the history pop-up for one field.
fn history_menu(ui: &mut egui::Ui, key: &str, text: &mut String, history: &mut InputHistory) {
    // Work on a snapshot so the list stays readable while the delete button
    // mutates the stored history.
    let entries = history.entries(key).to_vec();
    if entries.is_empty() {
        ui.weak(t!("common.history_empty"));
        return;
    }

    let mut remove = None;
    egui::ScrollArea::vertical()
        .max_height(POPUP_MAX_HEIGHT)
        .show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            for (index, entry) in entries.iter().enumerate() {
                ui.horizontal(|ui| {
                    let delete_width = ui.spacing().interact_size.y;
                    let label_width =
                        (ui.available_width() - delete_width - ui.spacing().item_spacing.x)
                            .max(40.0);
                    let label = ui.add_sized(
                        [label_width, ui.spacing().interact_size.y],
                        egui::Button::selectable(false, display_value(entry)),
                    );
                    if label.clicked() {
                        *text = entry.clone();
                        ui.close();
                    }
                    if ui.small_button("✕").clicked() {
                        remove = Some(index);
                    }
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
