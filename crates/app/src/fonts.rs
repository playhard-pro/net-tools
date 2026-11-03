//! System font loading and text sharpening.
//!
//! egui only ships a small Latin and emoji font set, so Chinese, Japanese,
//! Korean and many symbol glyphs need a system fallback. Font files are memory
//! mapped instead of copied into the heap, so glyph data is paged in on demand
//! and startup stays cheap even when a large CJK font is installed.
//!
//! The fallback order is deliberate: an optional native interface family is
//! tried first for Latin text, then egui's bundled fonts, then one CJK family,
//! one symbol family and one emoji family. All text styles are derived from
//! [`DEFAULT_UI_FONT_SIZE`] so the interface cannot end up with mismatched
//! sizes after switching themes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use eframe::egui;
use egui::epaint::text::{FontTweak, HintingTarget, SmoothHinting};
use egui::{FontData, FontDefinitions, FontFamily, FontId, TextStyle};

/// Base size shared by every UI text style.
pub const DEFAULT_UI_FONT_SIZE: f32 = 13.0;

/// Register the bundled egui fonts plus a best-effort set of system fallbacks.
///
/// A single call at startup is enough. Changing the application theme later
/// only needs [`apply_ui_font_size`], because the font registry itself does not
/// depend on the palette.
pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let mut database = system_database();
    let mut loaded = HashMap::new();

    // Load the first available family from each fallback group. The groups are
    // ordered by how broadly their glyphs are used: CJK first because it covers
    // the largest set of characters, then mathematical/UI symbols, then emoji.
    for candidates in FALLBACK_GROUPS {
        let Some((cache_key, font)) = load_first(&mut database, candidates) else {
            continue;
        };
        let key = insert_font(&mut fonts, &mut loaded, &cache_key, font);
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            let family_fonts = fonts.families.entry(family).or_default();
            if !family_fonts.contains(&key) {
                family_fonts.push(key.clone());
            }
        }
    }

    // Prefer a native interface family for Latin text. It is inserted before
    // the bundled fonts, while the CJK and symbol fallbacks stay behind them.
    if let Some((cache_key, font)) = load_first(&mut database, UI_FONT_FAMILIES) {
        let key = insert_font(&mut fonts, &mut loaded, &cache_key, font);
        let family_fonts = fonts.families.entry(FontFamily::Proportional).or_default();
        if let Some(index) = family_fonts.iter().position(|existing| existing == &key) {
            family_fonts.remove(index);
        }
        family_fonts.insert(0, key);
    }

    apply_sharp_text_tweaks(&mut fonts);
    ctx.set_fonts(fonts);
    apply_ui_font_size(ctx, DEFAULT_UI_FONT_SIZE);
}

/// Hinting settings used for every loaded font.
///
/// Hinting snaps glyph outlines to the pixel grid, which makes small UI text
/// noticeably crisper. Disabling symmetric rendering and preserving linear
/// metrics gives the auto-hinter room to grid-fit both axes; this is more
/// aggressive than egui's default, which leaves horizontal stems soft.
fn sharp_text_tweak() -> FontTweak {
    FontTweak {
        hinting: Some(true),
        hinting_target: HintingTarget::Smooth(SmoothHinting {
            light: false,
            symmetric_rendering: false,
            preserve_linear_metrics: false,
        }),
        subpixel_binning: Some(false),
        ..FontTweak::default()
    }
}

fn apply_sharp_text_tweaks(fonts: &mut FontDefinitions) {
    let tweak = sharp_text_tweak();
    for data in fonts.font_data.values_mut() {
        let mut updated = (**data).clone();
        updated.tweak = tweak.clone();
        *data = Arc::new(updated);
    }
}

/// Configure the sizes and rasterization options of the built-in text styles.
///
/// Every style is derived from one base size, and the same values are written
/// to both egui themes so switching palettes cannot change the typography.
pub fn apply_ui_font_size(ctx: &egui::Context, size: f32) {
    let size = size.clamp(9.0, 28.0);
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        ctx.style_mut_of(theme, |style| {
            style.visuals.text_options.font_hinting = true;
            // Sub-pixel binning renders several horizontal offsets of each
            // glyph, which improves spacing slightly but makes the atlas
            // visibly softer. The sharper hinting above is preferred.
            style.visuals.text_options.subpixel_binning = false;
            style.text_styles.insert(
                TextStyle::Small,
                FontId::new((size * 0.85).max(8.0), FontFamily::Proportional),
            );
            style
                .text_styles
                .insert(TextStyle::Body, FontId::new(size, FontFamily::Proportional));
            style.text_styles.insert(
                TextStyle::Button,
                FontId::new(size, FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Heading,
                FontId::new((size * 1.4).max(12.0), FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Monospace,
                FontId::new(size, FontFamily::Monospace),
            );
        });
    }

    // Align glyph origins to physical pixels as well.
    ctx.tessellation_options_mut(|options| {
        options.round_text_to_pixels = true;
    });
}

/// Native interface families tried before egui's bundled font.
///
/// A family that covers Latin and CJK with one set of metrics gives the most
/// consistent glyph sizes. The list falls through to families that cover only
/// Latin when no combined family is installed; the CJK group below then
/// supplies East Asian glyphs.
const UI_FONT_FAMILIES: &[&str] = {
    #[cfg(target_os = "windows")]
    {
        &["Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI"]
    }
    #[cfg(target_os = "macos")]
    {
        &["PingFang SC", "Helvetica Neue"]
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        &[
            "Noto Sans",
            "Noto Sans CJK SC",
            "Noto Sans SC",
            "Source Han Sans SC",
            "WenQuanYi Micro Hei",
            "DejaVu Sans",
        ]
    }
};

/// CJK fallbacks. Windows ships Microsoft YaHei as its default Simplified
/// Chinese UI font, so prefer it there over optional Noto/Source Han installs.
#[cfg(target_os = "windows")]
const CJK_FALLBACKS: &[&str] = &[
    "Microsoft YaHei UI",
    "Microsoft YaHei",
    "微软雅黑",
    "Noto Sans CJK SC",
    "Noto Sans SC",
    "Source Han Sans SC",
    "PingFang SC",
    "Hiragino Sans GB",
    "WenQuanYi Micro Hei",
    "Droid Sans Fallback",
    "SimHei",
    "黑体",
];

#[cfg(not(target_os = "windows"))]
const CJK_FALLBACKS: &[&str] = &[
    "Noto Sans CJK SC",
    "Noto Sans SC",
    "Source Han Sans SC",
    "Microsoft YaHei",
    "微软雅黑",
    "Microsoft YaHei UI",
    "PingFang SC",
    "Hiragino Sans GB",
    "WenQuanYi Micro Hei",
    "Droid Sans Fallback",
    "SimHei",
    "黑体",
];

const SYMBOL_FALLBACKS: &[&str] = &[
    "Noto Sans Symbols 2",
    "Noto Sans Symbols",
    "Segoe UI Symbol",
    "Apple Symbols",
    "DejaVu Sans",
];

const EMOJI_FALLBACKS: &[&str] = &["Noto Emoji", "Segoe UI Emoji", "Apple Color Emoji"];

/// One representative family per fallback purpose. The first available family
/// in each group is loaded, which bounds memory use on every desktop platform.
const FALLBACK_GROUPS: &[&[&str]] = &[CJK_FALLBACKS, SYMBOL_FALLBACKS, EMOJI_FALLBACKS];

#[derive(Clone, Copy)]
struct LoadedFont {
    /// Memory-mapped font file data that lives for the rest of the process.
    data: &'static [u8],
    index: u32,
}

/// Faces already mapped by an earlier call, keyed by requested family. This
/// avoids mapping the same file again when several groups name it.
static LOADED_FONTS: OnceLock<Mutex<HashMap<String, LoadedFont>>> = OnceLock::new();

fn loaded_fonts() -> &'static Mutex<HashMap<String, LoadedFont>> {
    LOADED_FONTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn system_database() -> fontdb::Database {
    let mut database = fontdb::Database::new();
    database.load_system_fonts();

    // fontdb does not always scan Windows font directories mounted under WSL.
    #[cfg(target_os = "linux")]
    load_wsl_fonts(&mut database);

    database
}

fn load_first(
    database: &mut fontdb::Database,
    candidates: &[&str],
) -> Option<(String, LoadedFont)> {
    for candidate in candidates {
        let cache_key = candidate.to_ascii_lowercase();
        if let Some(font) = loaded_fonts()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&cache_key)
            .copied()
        {
            return Some((cache_key, font));
        }

        let Some(face) = database
            .faces()
            .filter(|face| {
                face.families
                    .iter()
                    .any(|(family, _)| family.eq_ignore_ascii_case(candidate))
            })
            .min_by_key(|face| face_score(face))
            .map(|face| face.id)
        else {
            continue;
        };

        let Some(font) = map_face(database, face) else {
            continue;
        };
        loaded_fonts()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(cache_key.clone(), font);
        return Some((cache_key, font));
    }
    None
}

fn map_face(database: &mut fontdb::Database, id: fontdb::ID) -> Option<LoadedFont> {
    // SAFETY: The returned shared data owns the mapping. We leak that owner so
    // the slice handed to egui remains valid for the rest of the process.
    // System font files are read-only for us.
    let (shared, index) = unsafe { database.make_shared_face_data(id)? };
    let shared: &'static Arc<dyn AsRef<[u8]> + Send + Sync> = Box::leak(Box::new(shared));
    Some(LoadedFont {
        data: (*shared).as_ref().as_ref(),
        index,
    })
}

fn insert_font(
    fonts: &mut FontDefinitions,
    loaded: &mut HashMap<String, String>,
    cache_key: &str,
    font: LoadedFont,
) -> String {
    if let Some(key) = loaded.get(cache_key) {
        return key.clone();
    }
    let key = format!("system-font-{}", fonts.font_data.len());
    let mut data = FontData::from_static(font.data);
    data.index = font.index;
    fonts.font_data.insert(key.clone(), Arc::new(data));
    loaded.insert(cache_key.to_string(), key.clone());
    key
}

fn face_score(face: &fontdb::FaceInfo) -> u32 {
    let style = if matches!(face.style, fontdb::Style::Normal) {
        0
    } else {
        10
    };
    let weight = (i32::from(face.weight.0) - 400).unsigned_abs();
    let stretch = if matches!(face.stretch, fontdb::Stretch::Normal) {
        0
    } else {
        1
    };
    style + weight + stretch
}

#[cfg(target_os = "linux")]
fn load_wsl_fonts(database: &mut fontdb::Database) {
    for path in [
        "/mnt/c/Windows/Fonts/msyh.ttc",
        "/mnt/c/Windows/Fonts/msyhbd.ttc",
        "/mnt/c/Windows/Fonts/simhei.ttf",
        "/mnt/c/Windows/Fonts/simsun.ttc",
        "/mnt/c/Windows/Fonts/seguisym.ttf",
    ] {
        if std::path::Path::new(path).is_file() {
            let _ = database.load_font_file(path);
        }
    }
}
