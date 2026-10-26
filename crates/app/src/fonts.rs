//! System CJK font fallback installation.
//!
//! egui only ships Latin/emoji fonts, so Chinese (and other CJK) text would be
//! rendered as missing-glyph boxes. Instead of embedding a font in the binary,
//! we look up a CJK font installed on the host and register it as a fallback
//! for both the proportional and monospace families.

use std::sync::Arc;

use eframe::egui;
use fontdb::{Database, Family, Query};

/// CJK-capable font families to try, in order of preference.
///
/// The list covers the families commonly preinstalled on Windows, macOS and
/// Linux. `fontdb` compares family names case-sensitively, so the entries must
/// match the names stored in the font files.
const CJK_FAMILIES: &[&str] = &[
    // Windows
    "Microsoft YaHei",
    "Microsoft YaHei UI",
    "SimHei",
    "SimSun",
    "NSimSun",
    "Microsoft JhengHei",
    // macOS
    "PingFang SC",
    "PingFang TC",
    "PingFang HK",
    "Heiti SC",
    "Heiti TC",
    "STHeiti",
    "Songti SC",
    // Linux and cross-platform open fonts
    "Noto Sans CJK SC",
    "Noto Sans CJK TC",
    "Noto Sans CJK JP",
    "Noto Sans CJK KR",
    "Noto Sans SC",
    "Noto Sans TC",
    "Noto Serif CJK SC",
    "Source Han Sans SC",
    "Source Han Sans CN",
    "Source Han Serif SC",
    "WenQuanYi Micro Hei",
    "WenQuanYi Zen Hei",
    "Droid Sans Fallback",
    "AR PL UMing CN",
];

/// A font face loaded from the system font database.
struct LoadedFace {
    data: Vec<u8>,
    index: u32,
}

/// Register a system CJK font as a fallback so CJK glyphs render everywhere.
pub fn install(ctx: &egui::Context) {
    let Some(face) = load_cjk_face() else {
        tracing::warn!("no system CJK font found; CJK text may render as boxes");
        return;
    };

    let mut fonts = egui::FontDefinitions::default();
    let mut data = egui::FontData::from_owned(face.data);
    data.index = face.index;
    fonts
        .font_data
        .insert("system-cjk".to_owned(), Arc::new(data));

    // Append as a fallback after the default fonts for both families.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("system-cjk".to_owned());
    }

    ctx.set_fonts(fonts);
}

/// Find the first available CJK font family and copy its data out of the
/// system font database.
fn load_cjk_face() -> Option<LoadedFace> {
    let mut db = Database::new();
    db.load_system_fonts();

    let families: Vec<Family<'_>> = CJK_FAMILIES.iter().map(|name| Family::Name(name)).collect();
    let query = Query {
        families: &families,
        ..Default::default()
    };
    let id = db.query(&query)?;

    db.with_face_data(id, |data, index| LoadedFace {
        data: data.to_vec(),
        index,
    })
}
