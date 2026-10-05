//! Application root: tab management.

use eframe::egui;
use net_tools_core::config::AppConfig;
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use crate::tabs::http_ping::HttpPingTab;
use crate::tabs::mtr::MtrTab;
use crate::tabs::ping::PingTab;
use crate::tabs::port_scan::PortScanTab;

/// Project homepage, shown as the title link. Taken from the manifest so the
/// link and the published package metadata cannot drift apart.
const PROJECT_URL: &str = env!("CARGO_PKG_REPOSITORY");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Ping,
    Mtr,
    Http,
    PortScan,
}

pub struct App {
    pub rt: tokio::runtime::Handle,
    pub cfg: AppConfig,
    pub tab: Tab,
    pub ping: PingTab,
    pub mtr: MtrTab,
    pub http: HttpPingTab,
    pub portscan: PortScanTab,
    pub privilege: PrivilegeStatus,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: tokio::runtime::Handle) -> Self {
        // Install the bundled CJK font so CJK characters are not shown as boxes.
        crate::fonts::install(&cc.egui_ctx);
        let cfg = crate::config_store::load().unwrap_or_default();
        Self {
            rt,
            cfg,
            tab: Tab::Ping,
            ping: PingTab::new(),
            mtr: MtrTab::new(),
            http: HttpPingTab::new(),
            portscan: PortScanTab::new(),
            privilege: net_tools_core::net::privilege::probe(),
        }
    }

    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, label: &str) {
        let selected = self.tab == tab;
        if ui.selectable_label(selected, label).clicked() {
            self.tab = tab;
        }
    }

    fn language_selector(&mut self, ui: &mut egui::Ui) {
        let locales = available_locales!();
        let current = self.cfg.language.clone();
        let display = language_display_name(&current);
        egui::ComboBox::from_id_salt("language")
            .selected_text(display)
            .show_ui(ui, |ui| {
                for code in locales {
                    let code = code.to_string();
                    let name = language_display_name(&code);
                    if ui.selectable_label(current == code, name).clicked() {
                        self.cfg.language = code;
                        rust_i18n::set_locale(&self.cfg.language);
                    }
                }
            });
    }

    /// Privilege badge: reports whether the ICMP engines can open a socket, with
    /// the remaining raw-socket capability in the tooltip. Only a genuinely
    /// missing capability offers the elevation command, and only a permission
    /// error ever reaches this point with a hint.
    fn privilege_badge(&mut self, ui: &mut egui::Ui) {
        let (color, label) = match (self.privilege.icmp, self.privilege.raw) {
            (true, true) => (egui::Color32::from_rgb(0, 180, 0), t!("privilege.ok")),
            // Probing works, but the features that need a raw socket do not.
            (true, false) => (
                egui::Color32::from_rgb(200, 170, 0),
                t!("privilege.partial"),
            ),
            (false, _) => (
                egui::Color32::from_rgb(220, 110, 50),
                t!("privilege.limited"),
            ),
        };

        let icmp_state = if self.privilege.icmp {
            t!("privilege.icmp_ok")
        } else {
            t!("privilege.icmp_limited")
        };
        let raw_state = if self.privilege.raw {
            t!("privilege.raw_ok")
        } else {
            t!("privilege.raw_limited")
        };
        let tooltip = format!("{icmp_state}\n{raw_state}");

        ui.colored_label(color, label).on_hover_text(tooltip);

        if let Some(hint) = &self.privilege.hint {
            if ui
                .small_button(t!("privilege.copy_cmd"))
                .on_hover_text(hint)
                .clicked()
            {
                ui.ctx().copy_text(hint.clone());
            }
        }
    }
}

fn language_display_name(code: &str) -> String {
    match code {
        "en" => "English".to_string(),
        "zh-CN" | "zh" => "中文".to_string(),
        other => other.to_string(),
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::Hyperlink::from_label_and_url(
                    egui::RichText::new(t!("app.title")).heading(),
                    PROJECT_URL,
                ));
                ui.separator();
                self.tab_button(ui, Tab::Ping, &t!("tab.ping"));
                self.tab_button(ui, Tab::Mtr, &t!("tab.mtr"));
                self.tab_button(ui, Tab::Http, &t!("tab.http"));
                self.tab_button(ui, Tab::PortScan, &t!("tab.portscan"));
                ui.separator();
                ui.label(t!("common.language"));
                self.language_selector(ui);
                ui.separator();
                self.privilege_badge(ui);
            });
        });

        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Ping => self.ping.ui(ui, &mut self.cfg.ping, &self.rt),
            Tab::Mtr => self.mtr.ui(ui, &mut self.cfg.mtr, &self.rt),
            Tab::Http => self.http.ui(ui, &mut self.cfg.http, &self.rt),
            Tab::PortScan => self.portscan.ui(ui, &mut self.cfg.port_scan, &self.rt),
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        crate::config_store::save(&self.cfg);
    }
}
