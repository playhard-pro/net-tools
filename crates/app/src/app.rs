//! Application root: tab management.

use eframe::egui;
use net_tools_core::config::AppConfig;
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use crate::tabs::dns::DnsTab;
use crate::tabs::http_ping::HttpPingTab;
use crate::tabs::ip_insight::IpInsightTab;
use crate::tabs::lookup::LookupTab;
use crate::tabs::mtr::MtrTab;
use crate::tabs::ping::PingTab;
use crate::tabs::port_scan::PortScanTab;

/// Project homepage, shown as the title link. Taken from the manifest so the
/// link and the published package metadata cannot drift apart.
const PROJECT_URL: &str = env!("CARGO_PKG_REPOSITORY");

/// Package version shown in the About dialog. Taken from the manifest so it
/// always matches the published version.
const PROJECT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Author shown in the About dialog. Taken from the manifest.
const PROJECT_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// Author homepage shown as a link in the About dialog.
const PROJECT_HOMEPAGE: &str = env!("CARGO_PKG_HOMEPAGE");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Ping,
    Mtr,
    Http,
    PortScan,
    IpInsight,
    Lookup,
    Dns,
}

pub struct App {
    pub rt: tokio::runtime::Handle,
    pub cfg: AppConfig,
    pub tab: Tab,
    pub ping: PingTab,
    pub mtr: MtrTab,
    pub http: HttpPingTab,
    pub portscan: PortScanTab,
    pub ip_insight: IpInsightTab,
    pub lookup: LookupTab,
    pub dns: DnsTab,
    pub privilege: PrivilegeStatus,
    /// Whether the About dialog is currently open.
    pub show_about: bool,
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
            ip_insight: IpInsightTab::new(),
            lookup: LookupTab::new(),
            dns: DnsTab::new(),
            privilege: net_tools_core::net::privilege::probe(),
            show_about: false,
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

    /// About dialog: version, author, contact links and license. Values are read
    /// from the package manifest so they cannot drift from the published metadata.
    fn about_dialog(&mut self, ctx: &egui::Context) {
        let mut close = false;
        // Author entries follow the `Name <email>` form; fall back to the whole
        // string when no address is present, so the field is never blank.
        let email = PROJECT_AUTHORS
            .split_once('<')
            .and_then(|(_, rest)| rest.split_once('>'))
            .map_or(PROJECT_AUTHORS, |(addr, _)| addr);
        let modal = egui::Modal::new(egui::Id::new("about_dialog")).show(ctx, |ui| {
            ui.set_width(360.0);
            ui.heading(t!("about.title"));
            ui.add_space(4.0);
            ui.label(format!("{} {}", t!("about.version"), PROJECT_VERSION));
            ui.label(format!("{} {}", t!("about.author"), PROJECT_AUTHORS));
            ui.horizontal(|ui| {
                ui.label(t!("about.email"));
                ui.add(egui::Hyperlink::from_label_and_url(
                    email,
                    format!("mailto:{email}"),
                ));
            });
            ui.horizontal(|ui| {
                ui.label(t!("about.homepage"));
                ui.add(egui::Hyperlink::from_label_and_url(
                    PROJECT_HOMEPAGE,
                    PROJECT_HOMEPAGE,
                ));
            });
            ui.horizontal(|ui| {
                ui.label(t!("about.repository"));
                ui.add(egui::Hyperlink::from_label_and_url(
                    PROJECT_URL,
                    PROJECT_URL,
                ));
            });
            ui.label(format!("{} MIT", t!("about.license")));
            ui.add_space(8.0);
            ui.separator();
            if ui.button(t!("about.close")).clicked() {
                close = true;
            }
        });
        // Also close when the backdrop is clicked or Escape is pressed.
        if close || modal.should_close() {
            self.show_about = false;
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
                self.tab_button(ui, Tab::IpInsight, &t!("tab.ip_insight"));
                self.tab_button(ui, Tab::Lookup, &t!("tab.lookup"));
                self.tab_button(ui, Tab::Dns, &t!("tab.dns"));
                ui.separator();
                ui.label(t!("common.language"));
                self.language_selector(ui);
                ui.separator();
                self.privilege_badge(ui);
                ui.separator();
                if ui.small_button(t!("about.button")).clicked() {
                    self.show_about = true;
                }
            });
        });

        // Capture the history revision before rendering so edits made by the
        // input widgets can be written to disk immediately afterwards.
        let history_revision = self.cfg.history.revision();

        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Ping => self.ping.ui(
                ui,
                &mut self.cfg.ping,
                &mut self.cfg.history,
                &self.rt,
                &self.privilege,
            ),
            Tab::Mtr => self.mtr.ui(
                ui,
                &mut self.cfg.mtr,
                &mut self.cfg.history,
                &self.rt,
                &self.privilege,
            ),
            Tab::Http => self
                .http
                .ui(ui, &mut self.cfg.http, &mut self.cfg.history, &self.rt),
            Tab::PortScan => self.portscan.ui(
                ui,
                &mut self.cfg.port_scan,
                &mut self.cfg.history,
                &self.rt,
                &self.privilege,
            ),
            Tab::IpInsight => self.ip_insight.ui(
                ui,
                &mut self.cfg.ip_insight,
                &mut self.cfg.history,
                &self.rt,
            ),
            Tab::Lookup => {
                self.lookup
                    .ui(ui, &mut self.cfg.lookup, &mut self.cfg.history, &self.rt)
            }
            Tab::Dns => self
                .dns
                .ui(ui, &mut self.cfg.dns, &mut self.cfg.history, &self.rt),
        });

        if self.cfg.history.revision() != history_revision {
            crate::config_store::save(&self.cfg);
        }

        if self.show_about {
            self.about_dialog(ui.ctx());
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        crate::config_store::save(&self.cfg);
    }
}
