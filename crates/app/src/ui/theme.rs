//! Theme-aware semantic colors.
//!
//! The base widgets follow egui's light/dark visuals automatically. This module
//! covers the custom banners, badges and charts so they remain readable when the
//! user switches between light and dark themes.

use eframe::egui;
use net_tools_core::control::TaskState;

/// Semantic colors for the current light or dark theme.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub error_bg: egui::Color32,
    pub error_text: egui::Color32,
    pub error_hint: egui::Color32,
    pub warning_bg: egui::Color32,
    pub warning_text: egui::Color32,
    pub warning_hint: egui::Color32,
    pub info_text: egui::Color32,
    pub success_text: egui::Color32,
    pub chart_primary: egui::Color32,
    pub chart_secondary: egui::Color32,
    pub card_bg: egui::Color32,
    pub card_text: egui::Color32,
    pub key: egui::Color32,
    pub string: egui::Color32,
    pub number: egui::Color32,
    pub boolean: egui::Color32,
    pub null: egui::Color32,
    pub clock_face: egui::Color32,
    pub clock_rim: egui::Color32,
    pub clock_tick: egui::Color32,
    pub clock_text: egui::Color32,
    pub clock_second: egui::Color32,
    pub state_idle: egui::Color32,
    pub state_running: egui::Color32,
    pub state_paused: egui::Color32,
    pub state_stopping: egui::Color32,
    pub state_finished: egui::Color32,
    pub privilege_ok: egui::Color32,
    pub privilege_partial: egui::Color32,
    pub privilege_limited: egui::Color32,
}

impl Palette {
    /// Build the palette that matches the current egui visuals.
    pub fn from_ui(ui: &egui::Ui) -> Self {
        Self::new(ui.visuals().dark_mode)
    }

    /// Build a palette for an explicit theme.
    pub fn new(dark: bool) -> Self {
        if dark {
            Self::dark()
        } else {
            Self::light()
        }
    }

    fn dark() -> Self {
        Self {
            dark: true,
            error_bg: egui::Color32::from_rgb(90, 20, 20),
            error_text: egui::Color32::from_rgb(255, 130, 130),
            error_hint: egui::Color32::from_rgb(255, 200, 160),
            warning_bg: egui::Color32::from_rgb(64, 56, 12),
            warning_text: egui::Color32::from_rgb(240, 205, 120),
            warning_hint: egui::Color32::from_rgb(255, 220, 170),
            info_text: egui::Color32::from_rgb(150, 200, 255),
            success_text: egui::Color32::from_rgb(120, 210, 140),
            chart_primary: egui::Color32::from_rgb(0, 180, 255),
            chart_secondary: egui::Color32::from_rgb(120, 220, 140),
            card_bg: egui::Color32::from_rgb(32, 38, 48),
            card_text: egui::Color32::WHITE,
            key: egui::Color32::from_rgb(120, 180, 255),
            string: egui::Color32::from_rgb(140, 220, 140),
            number: egui::Color32::from_rgb(230, 180, 120),
            boolean: egui::Color32::from_rgb(200, 150, 230),
            null: egui::Color32::GRAY,
            clock_face: egui::Color32::from_rgb(24, 28, 36),
            clock_rim: egui::Color32::from_rgb(90, 150, 230),
            clock_tick: egui::Color32::from_rgb(130, 145, 165),
            clock_text: egui::Color32::from_rgb(220, 230, 245),
            clock_second: egui::Color32::from_rgb(230, 110, 100),
            state_idle: egui::Color32::GRAY,
            state_running: egui::Color32::from_rgb(0, 180, 0),
            state_paused: egui::Color32::from_rgb(230, 160, 0),
            state_stopping: egui::Color32::from_rgb(200, 120, 0),
            state_finished: egui::Color32::from_rgb(90, 140, 220),
            privilege_ok: egui::Color32::from_rgb(0, 180, 0),
            privilege_partial: egui::Color32::from_rgb(200, 170, 0),
            privilege_limited: egui::Color32::from_rgb(220, 110, 50),
        }
    }

    fn light() -> Self {
        Self {
            dark: false,
            // Tinted backgrounds keep the banners distinct without the heavy
            // dark blocks that would look out of place on a light window.
            error_bg: egui::Color32::from_rgb(255, 235, 235),
            error_text: egui::Color32::from_rgb(170, 30, 30),
            error_hint: egui::Color32::from_rgb(120, 45, 25),
            warning_bg: egui::Color32::from_rgb(255, 248, 215),
            warning_text: egui::Color32::from_rgb(120, 85, 0),
            warning_hint: egui::Color32::from_rgb(90, 60, 0),
            info_text: egui::Color32::from_rgb(25, 90, 160),
            success_text: egui::Color32::from_rgb(20, 120, 60),
            chart_primary: egui::Color32::from_rgb(0, 110, 200),
            chart_secondary: egui::Color32::from_rgb(0, 140, 80),
            card_bg: egui::Color32::from_rgb(238, 242, 248),
            card_text: egui::Color32::from_rgb(30, 35, 45),
            key: egui::Color32::from_rgb(20, 90, 180),
            string: egui::Color32::from_rgb(20, 120, 60),
            number: egui::Color32::from_rgb(150, 85, 0),
            boolean: egui::Color32::from_rgb(120, 50, 160),
            null: egui::Color32::from_rgb(105, 105, 105),
            clock_face: egui::Color32::from_rgb(245, 247, 250),
            clock_rim: egui::Color32::from_rgb(40, 100, 190),
            clock_tick: egui::Color32::from_rgb(100, 110, 125),
            clock_text: egui::Color32::from_rgb(35, 45, 60),
            clock_second: egui::Color32::from_rgb(190, 50, 40),
            state_idle: egui::Color32::from_rgb(100, 100, 100),
            state_running: egui::Color32::from_rgb(0, 130, 0),
            state_paused: egui::Color32::from_rgb(170, 110, 0),
            state_stopping: egui::Color32::from_rgb(160, 80, 0),
            state_finished: egui::Color32::from_rgb(40, 90, 180),
            privilege_ok: egui::Color32::from_rgb(0, 130, 0),
            privilege_partial: egui::Color32::from_rgb(150, 110, 0),
            privilege_limited: egui::Color32::from_rgb(180, 70, 20),
        }
    }

    /// Color used by the task-state badge.
    pub fn state_color(&self, state: TaskState) -> egui::Color32 {
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
    pub fn badge_bg(&self, color: egui::Color32) -> egui::Color32 {
        if self.dark {
            color.gamma_multiply(0.18)
        } else {
            color.gamma_multiply(0.12)
        }
    }
}
