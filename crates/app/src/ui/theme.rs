//! Application themes and semantic colors.
//!
//! Four bundled themes mirror the palettes used by FortTerm and its elegance
//! design system: two dark variants and two light variants. The active theme
//! drives egui's visuals, while [`Palette`] exposes semantic colors to the
//! custom banners, badges, charts and clock widgets in this application.

use eframe::egui::{
    self, Color32, Context, CornerRadius, Id, Margin, Stroke, ThemePreference, Vec2, Visuals,
};
use net_tools_core::control::TaskState;

/// Canonical theme order used by the picker and the quick-switch action.
pub const THEME_IDS: [&str; 4] = ["slate", "frost", "charcoal", "paper"];

/// Theme used when nothing has been chosen yet and when an unknown id is read.
pub const DEFAULT_THEME: &str = "paper";

/// Colors that make up one application theme.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThemePalette {
    /// Whether the theme is a dark theme.
    pub is_dark: bool,
    /// Overall application background.
    pub bg: Color32,
    /// Card and panel surface color.
    pub card: Color32,
    /// Background used by text edits and other input-like controls.
    pub input_bg: Color32,
    /// Border color for inputs, cards and separators.
    pub border: Color32,
    /// Primary text color.
    pub text: Color32,
    /// Secondary text color.
    pub text_muted: Color32,
    /// Tertiary text color for hints and disabled states.
    pub text_faint: Color32,
    /// Blue accent, resting state.
    pub blue: Color32,
    /// Blue accent, hover and pressed state.
    pub blue_hover: Color32,
    /// Green accent, resting state.
    pub green: Color32,
    /// Green accent, hover and pressed state.
    pub green_hover: Color32,
    /// Red accent, resting state.
    pub red: Color32,
    /// Red accent, hover and pressed state.
    pub red_hover: Color32,
    /// Purple accent, resting state.
    pub purple: Color32,
    /// Purple accent, hover and pressed state.
    pub purple_hover: Color32,
    /// Amber accent, resting state.
    pub amber: Color32,
    /// Amber accent, hover and pressed state.
    pub amber_hover: Color32,
    /// Structural accent used by focus rings, selection and active states.
    pub focus: Color32,
    /// Success color for status text and indicators.
    pub success: Color32,
    /// Danger color for errors and destructive states.
    pub danger: Color32,
    /// Warning color for transient or degraded states.
    pub warning: Color32,
}

impl ThemePalette {
    /// Cool dark blue theme.
    fn slate() -> Self {
        Self {
            is_dark: true,
            bg: rgb(0x0f, 0x17, 0x2a),
            card: rgb(0x1e, 0x29, 0x3b),
            input_bg: rgb(0x0f, 0x17, 0x2a),
            border: rgb(0x33, 0x41, 0x55),
            text: rgb(0xe2, 0xe8, 0xf0),
            text_muted: rgb(0x94, 0xa3, 0xb8),
            text_faint: rgb(0x64, 0x74, 0x8b),
            blue: rgb(0x25, 0x63, 0xeb),
            blue_hover: rgb(0x1d, 0x4e, 0xd8),
            green: rgb(0x16, 0xa3, 0x4a),
            green_hover: rgb(0x15, 0x80, 0x3d),
            red: rgb(0xdc, 0x26, 0x26),
            red_hover: rgb(0xb9, 0x1c, 0x1c),
            purple: rgb(0x7c, 0x3a, 0xed),
            purple_hover: rgb(0x6d, 0x28, 0xd9),
            amber: rgb(0xd9, 0x77, 0x06),
            amber_hover: rgb(0xb4, 0x53, 0x09),
            focus: rgb(0x38, 0xbd, 0xf8),
            success: rgb(0x4a, 0xde, 0x80),
            danger: rgb(0xf8, 0x71, 0x71),
            warning: rgb(0xfb, 0xbf, 0x24),
        }
    }

    /// Neutral dark grey theme.
    fn charcoal() -> Self {
        Self {
            is_dark: true,
            bg: rgb(0x0f, 0x0f, 0x10),
            card: rgb(0x1c, 0x1c, 0x1e),
            input_bg: rgb(0x0f, 0x0f, 0x10),
            border: rgb(0x38, 0x38, 0x3a),
            text: rgb(0xfa, 0xfa, 0xfa),
            text_muted: rgb(0xa1, 0xa1, 0xaa),
            text_faint: rgb(0x71, 0x71, 0x7a),
            blue: rgb(0x3b, 0x82, 0xf6),
            blue_hover: rgb(0x25, 0x63, 0xeb),
            green: rgb(0x22, 0xc5, 0x5e),
            green_hover: rgb(0x16, 0xa3, 0x4a),
            red: rgb(0xef, 0x44, 0x44),
            red_hover: rgb(0xdc, 0x26, 0x26),
            purple: rgb(0x8b, 0x5c, 0xf6),
            purple_hover: rgb(0x7c, 0x3a, 0xed),
            amber: rgb(0xf5, 0x9e, 0x0b),
            amber_hover: rgb(0xd9, 0x77, 0x06),
            focus: rgb(0x22, 0xd3, 0xee),
            success: rgb(0x4a, 0xde, 0x80),
            danger: rgb(0xf8, 0x71, 0x71),
            warning: rgb(0xfb, 0xbf, 0x24),
        }
    }

    /// Cool, blue-tinted light theme paired with Slate.
    fn frost() -> Self {
        Self {
            is_dark: false,
            bg: rgb(0xe2, 0xe8, 0xf0),
            card: rgb(0xf8, 0xfa, 0xfc),
            input_bg: rgb(0xff, 0xff, 0xff),
            border: rgb(0x94, 0xa3, 0xb8),
            text: rgb(0x0f, 0x17, 0x2a),
            text_muted: rgb(0x47, 0x55, 0x69),
            text_faint: rgb(0x64, 0x74, 0x8b),
            blue: rgb(0x25, 0x63, 0xeb),
            blue_hover: rgb(0x1d, 0x4e, 0xd8),
            green: rgb(0x16, 0xa3, 0x4a),
            green_hover: rgb(0x15, 0x80, 0x3d),
            red: rgb(0xdc, 0x26, 0x26),
            red_hover: rgb(0xb9, 0x1c, 0x1c),
            purple: rgb(0x7c, 0x3a, 0xed),
            purple_hover: rgb(0x6d, 0x28, 0xd9),
            amber: rgb(0xd9, 0x77, 0x06),
            amber_hover: rgb(0xb4, 0x53, 0x09),
            focus: rgb(0x03, 0x74, 0xb0),
            success: rgb(0x16, 0xa3, 0x4a),
            danger: rgb(0xdc, 0x26, 0x26),
            warning: rgb(0xd9, 0x77, 0x06),
        }
    }

    /// Warm neutral light theme paired with Charcoal. This is the default.
    fn paper() -> Self {
        Self {
            is_dark: false,
            bg: rgb(0xec, 0xe9, 0xe4),
            card: rgb(0xfa, 0xf8, 0xf3),
            input_bg: rgb(0xff, 0xff, 0xff),
            border: rgb(0xbc, 0xb6, 0xa8),
            text: rgb(0x1c, 0x1a, 0x16),
            text_muted: rgb(0x57, 0x52, 0x4a),
            text_faint: rgb(0x8a, 0x83, 0x77),
            blue: rgb(0x25, 0x63, 0xeb),
            blue_hover: rgb(0x1d, 0x4e, 0xd8),
            green: rgb(0x16, 0xa3, 0x4a),
            green_hover: rgb(0x15, 0x80, 0x3d),
            red: rgb(0xdc, 0x26, 0x26),
            red_hover: rgb(0xb9, 0x1c, 0x1c),
            purple: rgb(0x7c, 0x3a, 0xed),
            purple_hover: rgb(0x6d, 0x28, 0xd9),
            amber: rgb(0xd9, 0x77, 0x06),
            amber_hover: rgb(0xb4, 0x53, 0x09),
            focus: rgb(0x0c, 0x80, 0x9e),
            success: rgb(0x16, 0xa3, 0x4a),
            danger: rgb(0xdc, 0x26, 0x26),
            warning: rgb(0xd9, 0x77, 0x06),
        }
    }
}

/// A complete application theme: palette plus shared shape and spacing values.
#[derive(Debug, Clone, PartialEq)]
pub struct AppTheme {
    /// Stable identifier persisted in the configuration.
    pub id: &'static str,
    /// Colors used by egui and the semantic [`Palette`].
    pub palette: ThemePalette,
    /// Corner radius for buttons and inputs.
    pub control_radius: f32,
    /// Corner radius for cards and windows.
    pub card_radius: f32,
    /// Horizontal padding inside buttons and inputs.
    pub control_padding_x: f32,
    /// Vertical padding inside buttons and inputs.
    pub control_padding_y: f32,
}

impl AppTheme {
    /// Resolve a stored theme id to a concrete theme.
    pub fn for_id(id: &str) -> Self {
        let (id, palette) = match normalize(id) {
            "slate" => ("slate", ThemePalette::slate()),
            "frost" => ("frost", ThemePalette::frost()),
            "charcoal" => ("charcoal", ThemePalette::charcoal()),
            _ => ("paper", ThemePalette::paper()),
        };
        Self {
            id,
            palette,
            control_radius: 5.0,
            card_radius: 8.0,
            control_padding_x: 10.0,
            control_padding_y: 4.0,
        }
    }

    /// Read the theme currently installed in the context.
    ///
    /// The default is Paper, which keeps custom widgets readable before the
    /// first explicit theme installation (for example in tests).
    pub fn current(ctx: &Context) -> Self {
        ctx.data(|data| data.get_temp::<Self>(storage_id()))
            .unwrap_or_else(|| Self::for_id(DEFAULT_THEME))
    }

    /// Install this theme into the context and remember it for later lookups.
    pub fn install(self, ctx: &Context) {
        ctx.set_theme(if self.palette.is_dark {
            ThemePreference::Dark
        } else {
            ThemePreference::Light
        });
        ctx.all_styles_mut(|style| self.apply_to_style(style));
        ctx.data_mut(|data| data.insert_temp(storage_id(), self));

        // Keep every text style on the same typographic scale after the theme
        // has written its visuals.
        crate::fonts::apply_ui_font_size(ctx, crate::fonts::DEFAULT_UI_FONT_SIZE);
    }

    fn apply_to_style(&self, style: &mut egui::Style) {
        let p = &self.palette;

        // Scale the control rhythm with the one authoritative UI font size so
        // a larger or smaller text scale never leaves controls cramped.
        let scale = crate::fonts::DEFAULT_UI_FONT_SIZE / 13.0;
        let padding_x = (self.control_padding_x * scale).clamp(8.0, 18.0);
        let padding_y = (self.control_padding_y * scale).clamp(3.0, 8.0);
        let control_height =
            (crate::fonts::DEFAULT_UI_FONT_SIZE * 1.25 + padding_y * 2.0).max(18.0);
        let item_gap = (5.0 * scale).clamp(4.0, 8.0);
        let item_pad = (7.0 * scale).clamp(6.0, 11.0);
        let window_margin = (10.0 * scale).clamp(7.0, 16.0).round() as i8;
        let menu_margin = (window_margin as f32 * 0.6).max(4.0).round() as i8;

        style.spacing.item_spacing = Vec2::new(item_pad, item_gap);
        style.spacing.button_padding = Vec2::new(padding_x, padding_y);
        style.spacing.interact_size.y = control_height;
        style.spacing.window_margin = Margin::same(window_margin);
        style.spacing.menu_margin = Margin::same(menu_margin);
        style.spacing.indent = (16.0 * scale).clamp(12.0, 24.0);
        style.interaction.tooltip_delay = 0.35;
        style.interaction.tooltip_grace_time = 0.2;

        let v = &mut style.visuals;
        *v = if p.is_dark {
            Visuals::dark()
        } else {
            Visuals::light()
        };
        v.dark_mode = p.is_dark;
        v.override_text_color = Some(p.text);
        v.panel_fill = p.bg;
        v.window_fill = p.card;
        v.window_stroke = Stroke::new(1.0, p.border);
        v.window_corner_radius = CornerRadius::same(self.card_radius as u8);
        v.menu_corner_radius = CornerRadius::same(8);
        v.extreme_bg_color = p.input_bg;
        v.faint_bg_color = depth_tint(p, p.card, 0.02);
        v.code_bg_color = p.input_bg;
        v.hyperlink_color = p.focus;
        v.warn_fg_color = p.warning;
        v.error_fg_color = p.danger;
        v.button_frame = true;
        v.striped = false;
        v.selection = egui::style::Selection {
            bg_fill: with_alpha(p.focus, 70),
            stroke: Stroke::new(1.0, p.focus),
        };

        let control_radius = CornerRadius::same(self.control_radius as u8);
        v.widgets = egui::style::Widgets {
            noninteractive: egui::style::WidgetVisuals {
                bg_fill: p.card,
                weak_bg_fill: p.card,
                bg_stroke: Stroke::new(1.0, p.border),
                corner_radius: control_radius,
                fg_stroke: Stroke::new(1.0, p.text),
                expansion: 0.0,
            },
            inactive: egui::style::WidgetVisuals {
                bg_fill: p.input_bg,
                weak_bg_fill: p.input_bg,
                bg_stroke: Stroke::new(1.0, p.border),
                corner_radius: control_radius,
                fg_stroke: Stroke::new(1.0, p.text),
                expansion: 0.0,
            },
            hovered: egui::style::WidgetVisuals {
                bg_fill: depth_tint(p, p.input_bg, 0.04),
                weak_bg_fill: depth_tint(p, p.input_bg, 0.04),
                bg_stroke: Stroke::new(1.0, p.text_muted),
                corner_radius: control_radius,
                fg_stroke: Stroke::new(1.5, p.text),
                // Expanding controls in a tight row can grow past their
                // allocated rect and get clipped by the surrounding panel.
                expansion: 0.0,
            },
            active: egui::style::WidgetVisuals {
                bg_fill: mix(p.input_bg, p.focus, 0.15),
                weak_bg_fill: mix(p.input_bg, p.focus, 0.15),
                bg_stroke: Stroke::new(1.0, p.focus),
                corner_radius: control_radius,
                fg_stroke: Stroke::new(1.5, p.text),
                expansion: 0.0,
            },
            open: egui::style::WidgetVisuals {
                bg_fill: p.input_bg,
                weak_bg_fill: p.input_bg,
                bg_stroke: Stroke::new(1.0, p.focus),
                corner_radius: control_radius,
                fg_stroke: Stroke::new(1.0, p.text),
                expansion: 0.0,
            },
        };
    }
}

/// Stable id under which the installed theme is cached in context memory.
fn storage_id() -> Id {
    Id::unique("net_tools::app_theme")
}

/// Map legacy or unknown stored values onto a supported theme id.
pub fn normalize(id: &str) -> &'static str {
    match id {
        "slate" => "slate",
        "frost" | "light" => "frost",
        "charcoal" => "charcoal",
        "paper" => "paper",
        // Older releases only stored "dark"; slate is the closest match.
        "dark" => "slate",
        // The previous default followed the system. Paper is now the default,
        // so an old "system" value resolves to it as well.
        _ => DEFAULT_THEME,
    }
}

/// Localized display name for a theme id.
pub fn label(id: &str) -> String {
    match normalize(id) {
        "slate" => rust_i18n::t!("theme.slate"),
        "frost" => rust_i18n::t!("theme.frost"),
        "charcoal" => rust_i18n::t!("theme.charcoal"),
        _ => rust_i18n::t!("theme.paper"),
    }
    .to_string()
}

/// Install the selected theme and apply the shared typography.
pub fn apply(ctx: &Context, id: &str) {
    AppTheme::for_id(id).install(ctx);
}

/// Semantic colors derived from the active application theme.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub error_bg: Color32,
    pub error_text: Color32,
    pub error_hint: Color32,
    pub warning_bg: Color32,
    pub warning_text: Color32,
    pub warning_hint: Color32,
    pub info_text: Color32,
    pub success_text: Color32,
    pub chart_primary: Color32,
    pub chart_secondary: Color32,
    pub card_bg: Color32,
    pub card_text: Color32,
    pub key: Color32,
    pub string: Color32,
    pub number: Color32,
    pub boolean: Color32,
    pub null: Color32,
    pub clock_face: Color32,
    pub clock_rim: Color32,
    pub clock_tick: Color32,
    pub clock_text: Color32,
    pub clock_second: Color32,
    pub state_idle: Color32,
    pub state_running: Color32,
    pub state_paused: Color32,
    pub state_stopping: Color32,
    pub state_finished: Color32,
    pub privilege_ok: Color32,
    pub privilege_partial: Color32,
    pub privilege_limited: Color32,
}

impl Palette {
    /// Build the semantic palette that matches the active application theme.
    pub fn from_ui(ui: &egui::Ui) -> Self {
        Self::from_theme(&AppTheme::current(ui.ctx()))
    }

    /// Build the semantic palette for an explicit theme.
    pub fn from_theme(theme: &AppTheme) -> Self {
        let p = &theme.palette;
        let dark = p.is_dark;

        // Tinted banner backgrounds stay readable on both warm and cool light
        // surfaces, while dark surfaces use a slightly stronger tint.
        let error_tint = if dark { 0.18 } else { 0.10 };
        let warning_tint = if dark { 0.16 } else { 0.10 };

        let error_text = contrast_accent(p.danger, dark);
        let warning_text = contrast_accent(p.warning, dark);
        let success_text = contrast_accent(p.success, dark);
        let number_text = contrast_accent(p.amber, dark);
        let boolean_text = contrast_accent(p.purple, dark);

        Self {
            dark,
            error_bg: mix(p.bg, p.danger, error_tint),
            error_text,
            error_hint: mix(error_text, p.text, 0.35),
            warning_bg: mix(p.bg, p.warning, warning_tint),
            warning_text,
            warning_hint: mix(warning_text, p.text, 0.35),
            info_text: p.focus,
            success_text,
            chart_primary: p.focus,
            chart_secondary: success_text,
            card_bg: p.card,
            card_text: p.text,
            key: if dark { p.focus } else { p.blue },
            string: success_text,
            number: number_text,
            boolean: boolean_text,
            null: p.text_faint,
            clock_face: p.card,
            clock_rim: p.focus,
            clock_tick: p.text_faint,
            clock_text: p.text,
            clock_second: error_text,
            state_idle: p.text_faint,
            state_running: success_text,
            state_paused: warning_text,
            state_stopping: number_text,
            state_finished: p.focus,
            privilege_ok: success_text,
            privilege_partial: warning_text,
            privilege_limited: error_text,
        }
    }

    /// Color used by the task-state badge.
    pub fn state_color(&self, state: TaskState) -> Color32 {
        match state {
            TaskState::Idle => self.state_idle,
            TaskState::Running => self.state_running,
            TaskState::Paused => self.state_paused,
            TaskState::Stopping => self.state_stopping,
            TaskState::Finished => self.state_finished,
        }
    }

    /// Background tint for the state badge. A translucent version of the state
    /// color works on both light and dark themes.
    pub fn badge_bg(&self, color: Color32) -> Color32 {
        if self.dark {
            color.gamma_multiply(0.18)
        } else {
            color.gamma_multiply(0.12)
        }
    }
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

fn with_alpha(color: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha)
}

/// Mix two colors channel-wise in sRGB space.
fn mix(a: Color32, b: Color32, amount: f32) -> Color32 {
    let amount = amount.clamp(0.0, 1.0);
    let channel = |x: u8, y: u8| (x as f32 * (1.0 - amount) + y as f32 * amount).round() as u8;
    Color32::from_rgb(
        channel(a.r(), b.r()),
        channel(a.g(), b.g()),
        channel(a.b(), b.b()),
    )
}

/// Nudge an accent toward the text color so it stays legible on tinted
/// backgrounds in both dark and light themes.
fn contrast_accent(color: Color32, dark: bool) -> Color32 {
    if dark {
        mix(color, Color32::WHITE, 0.10)
    } else {
        mix(color, Color32::BLACK, 0.12)
    }
}

/// Mix a surface toward white for dark themes and toward black for light
/// themes, producing a subtle lift or shade without changing the hue.
fn depth_tint(palette: &ThemePalette, base: Color32, amount: f32) -> Color32 {
    let toward = if palette.is_dark {
        Color32::WHITE
    } else {
        Color32::BLACK
    };
    mix(base, toward, amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_legacy_theme_ids_resolve_to_supported_ones() {
        assert_eq!(normalize("paper"), "paper");
        assert_eq!(normalize("dark"), "slate");
        assert_eq!(normalize("light"), "frost");
        assert_eq!(normalize("system"), DEFAULT_THEME);
        assert_eq!(normalize("unknown"), DEFAULT_THEME);
    }

    #[test]
    fn default_theme_is_paper() {
        assert_eq!(normalize(DEFAULT_THEME), "paper");
        assert!(!AppTheme::for_id(DEFAULT_THEME).palette.is_dark);
    }

    #[test]
    fn every_theme_has_a_distinct_primary_surface() {
        let backgrounds: Vec<Color32> = THEME_IDS
            .iter()
            .map(|id| AppTheme::for_id(id).palette.bg)
            .collect();
        for (index, background) in backgrounds.iter().enumerate() {
            assert!(
                backgrounds[..index].iter().all(|other| other != background),
                "theme backgrounds must be distinguishable"
            );
        }
    }
}
