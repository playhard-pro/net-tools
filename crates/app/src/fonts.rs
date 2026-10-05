//! Bundled CJK font installation.
//!
//! egui only ships Latin/emoji fonts, so Chinese (and other CJK) text would be
//! rendered as missing-glyph boxes. We embed a CJK font and register it as a
//! fallback for both the proportional and monospace families.

use std::sync::Arc;

use eframe::egui;

/// Bundled CJK font: WenQuanYi Micro Hei (Apache-2.0), see
/// `assets/fonts/LICENSE-wqy-microhei.txt`.
const CJK_FONT: &[u8] = include_bytes!("../../../assets/fonts/wqy-microhei.ttc");

/// Register the bundled CJK font as a fallback so CJK glyphs render everywhere.
pub fn install(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "cjk".to_owned(),
        Arc::new(egui::FontData::from_static(CJK_FONT)),
    );

    // Append as a fallback after the default fonts for both families.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("cjk".to_owned());
    }

    ctx.set_fonts(fonts);
}
