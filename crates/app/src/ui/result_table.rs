//! Reusable result table (based on egui_extras::TableBuilder).

use eframe::egui;
use egui_extras::{Column, TableBuilder, TableRow};

/// Generic table: `headers` are the column titles, `num_rows` the number of data
/// rows, and `row_fn(index, &mut TableRow)` fills each row.
///
/// Every column uses `Column::auto()` and the table is not resizable: in
/// egui_extras a resizable column keeps a fixed width, whereas a non-resizable
/// auto column re-measures itself each frame to fit the visible content.
pub fn table<H: AsRef<str>>(
    ui: &mut egui::Ui,
    headers: &[H],
    num_rows: usize,
    mut row_fn: impl FnMut(usize, &mut TableRow<'_, '_>),
) {
    // Cells must not wrap: a wrapping label is measured at the (narrow) cell
    // width, so auto-sized columns would never grow to fit their content.
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);

    // Bound the table height to the remaining space so it scrolls internally
    // instead of growing without limit and pushing later content off-screen.
    let max_height = ui.available_height().max(120.0);
    let mut builder = TableBuilder::new(ui)
        .striped(true)
        .resizable(false)
        .max_scroll_height(max_height)
        .min_scrolled_height(80.0)
        .auto_shrink([false, false]);
    for _ in headers {
        builder = builder.column(Column::auto().at_least(24.0));
    }
    builder
        .header(20.0, |mut header| {
            for h in headers {
                header.col(|ui| {
                    ui.strong(h.as_ref());
                });
            }
        })
        .body(|body| {
            body.rows(18.0, num_rows, |mut row| {
                row_fn(row.index(), &mut row);
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table must not grow beyond the available height, otherwise it would
    /// push widgets placed before it (toolbar) off-screen.
    #[test]
    fn height_is_bounded_by_available_space() {
        let ctx = egui::Context::default();
        let screen = egui::vec2(800.0, 600.0);
        let mut table_bottom = 0.0f32;
        let mut screen_bottom = 0.0f32;

        // A few frames so the table's sizing pass settles.
        for _ in 0..4 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::pos2(0.0, 0.0), screen)),
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                egui::Panel::top("top_bar").show(ui, |ui| {
                    let _ = ui.label("tabs");
                });
                egui::CentralPanel::default().show(ui, |ui| {
                    let _settings = ui.label("settings");
                    let _toolbar = ui.horizontal(|ui| {
                        let _ = ui.button("copy");
                    });
                    let table = ui.scope(|ui| {
                        table(ui, &["a", "b"], 1000, |_i, row| {
                            row.col(|ui| {
                                ui.label("x");
                            });
                            row.col(|ui| {
                                ui.label("y");
                            });
                        });
                    });
                    table_bottom = table.response.rect.bottom();
                    screen_bottom = ui.max_rect().bottom();
                });
            })
            .textures_delta
            .clear();
        }

        assert!(
            table_bottom <= screen_bottom + 1.0,
            "table grew to {table_bottom} beyond screen bottom {screen_bottom}"
        );
    }

    /// Auto columns must widen when the content gets wider.
    #[test]
    fn width_adapts_to_content() {
        let ctx = egui::Context::default();

        let measure = |content: String| -> f32 {
            let mut second_col_left = 0.0f32;
            for _ in 0..8 {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::pos2(0.0, 0.0),
                        egui::vec2(1000.0, 600.0),
                    )),
                    ..Default::default()
                };
                ctx.run_ui(input, |ui| {
                    egui::CentralPanel::default().show(ui, |ui| {
                        let content = content.clone();
                        table(ui, &["a", "b"], 1, |_i, row| {
                            row.col(|ui| {
                                let _ = ui.label(content.clone());
                            });
                            row.col(|ui| {
                                second_col_left = ui.label("x").rect.left();
                            });
                        });
                    });
                })
                .textures_delta
                .clear();
            }
            second_col_left
        };

        let narrow = measure("a".to_string());
        let wide = measure("a".repeat(200));
        assert!(
            wide > narrow + 50.0,
            "expected wider content to widen the first column: narrow={narrow}, wide={wide}"
        );
    }

    /// A widget placed before the table must stay above the table header,
    /// regardless of how many rows the table has.
    #[test]
    fn widget_before_table_stays_above() {
        let ctx = egui::Context::default();
        let mut toolbar_bottom = 0.0f32;
        let mut table_top = 0.0f32;

        for _ in 0..4 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(1000.0, 600.0),
                )),
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    let toolbar = ui.horizontal(|ui| {
                        let _ = ui.button("copy");
                    });
                    toolbar_bottom = toolbar.response.rect.bottom();
                    let t = ui.scope(|ui| {
                        table(ui, &["a", "b"], 500, |_i, row| {
                            row.col(|ui| {
                                let _ = ui.label("x");
                            });
                            row.col(|ui| {
                                let _ = ui.label("y");
                            });
                        });
                    });
                    table_top = t.response.rect.top();
                });
            })
            .textures_delta
            .clear();
        }

        assert!(
            toolbar_bottom <= table_top + 0.5,
            "toolbar bottom {toolbar_bottom} is not above table top {table_top}"
        );
    }
}
