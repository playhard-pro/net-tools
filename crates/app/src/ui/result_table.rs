//! Reusable result table (based on egui_extras::TableBuilder).

use eframe::egui;
use egui_extras::{Column, TableBuilder, TableRow};

/// Data row height, shared by the fixed and the adaptive table.
const ROW_HEIGHT: f32 = 18.0;
/// Header row height.
const HEADER_HEIGHT: f32 = 20.0;

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
    row_fn: impl FnMut(usize, &mut TableRow<'_, '_>),
) {
    table_impl(ui, headers, num_rows, None, row_fn);
}

/// Like [`table`], but the scrollable body keeps a fixed height of `rows`
/// visible rows instead of adapting to the remaining space. The extra rows
/// scroll inside the table.
pub fn table_fixed_rows<H: AsRef<str>>(
    ui: &mut egui::Ui,
    headers: &[H],
    num_rows: usize,
    rows: usize,
    row_fn: impl FnMut(usize, &mut TableRow<'_, '_>),
) {
    table_impl(
        ui,
        headers,
        num_rows,
        Some(ROW_HEIGHT * rows as f32),
        row_fn,
    );
}

/// Render a two-column key/value table with a simple grid.
///
/// Unlike [`table`], this does not scroll internally, so several of them can be
/// stacked on one scrolling page (one per API provider).
pub fn key_value_table(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    key_header: &str,
    value_header: &str,
    rows: &[(String, String)],
) {
    egui::Grid::new(id)
        .num_columns(2)
        .striped(true)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            ui.strong(key_header);
            ui.strong(value_header);
            ui.end_row();
            for (key, value) in rows {
                ui.label(key);
                ui.label(value);
                ui.end_row();
            }
        });
}

fn table_impl<H: AsRef<str>>(
    ui: &mut egui::Ui,
    headers: &[H],
    num_rows: usize,
    fixed_body_height: Option<f32>,
    mut row_fn: impl FnMut(usize, &mut TableRow<'_, '_>),
) {
    // Cells must not wrap: a wrapping label is measured at the (narrow) cell
    // width, so auto-sized columns would never grow to fit their content.
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);

    // Without a fixed height, bound the table to the remaining space so it
    // scrolls internally instead of growing without limit and pushing later
    // content off-screen.
    let max_height = fixed_body_height.unwrap_or_else(|| ui.available_height().max(120.0));
    let min_height = fixed_body_height.unwrap_or(80.0);
    let mut builder = TableBuilder::new(ui)
        .striped(true)
        .resizable(false)
        .max_scroll_height(max_height)
        .min_scrolled_height(min_height)
        .auto_shrink([false, false]);
    for _ in headers {
        builder = builder.column(Column::auto().at_least(24.0));
    }
    builder
        .header(HEADER_HEIGHT, |mut header| {
            for h in headers {
                header.col(|ui| {
                    ui.strong(h.as_ref());
                });
            }
        })
        .body(|body| {
            body.rows(ROW_HEIGHT, num_rows, |mut row| {
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

    /// A fixed-height table must keep the same height whether it holds fewer
    /// or more rows than the visible window.
    #[test]
    fn fixed_rows_keep_constant_height() {
        let ctx = egui::Context::default();

        let measure = |num_rows: usize| -> f32 {
            let mut height = 0.0f32;
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
                        let scope = ui.scope(|ui| {
                            table_fixed_rows(ui, &["a", "b"], num_rows, 5, |_i, row| {
                                row.col(|ui| {
                                    let _ = ui.label("x");
                                });
                                row.col(|ui| {
                                    let _ = ui.label("y");
                                });
                            });
                        });
                        height = scope.response.rect.height();
                    });
                })
                .textures_delta
                .clear();
            }
            height
        };

        let few = measure(1);
        let many = measure(100);
        assert!(
            (few - many).abs() < 2.0,
            "fixed-height table changed with row count: few={few}, many={many}"
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
