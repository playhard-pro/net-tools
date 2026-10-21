//! Application root: tab management.

use eframe::egui;
use net_tools_core::config::AppConfig;
use net_tools_core::net::privilege::PrivilegeStatus;
use rust_i18n::t;

use crate::tabs::connections::ConnectionsTab;
use crate::tabs::dns::DnsTab;
use crate::tabs::http_ping::HttpPingTab;
use crate::tabs::ip_insight::IpInsightTab;
use crate::tabs::lookup::LookupTab;
use crate::tabs::mtr::MtrTab;
use crate::tabs::ntp::NtpTab;
use crate::tabs::overview::OverviewTab;
use crate::tabs::ping::PingTab;
use crate::tabs::port_scan::PortScanTab;
use crate::tabs::speedtest::SpeedtestTab;
use crate::tabs::tls::TlsTab;
use crate::tabs::utils::UtilsTab;
use crate::ui::theme::Palette;

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

/// SPDX license expression shown in the About dialog. Taken from the manifest
/// so the dialog and the published package metadata cannot drift apart.
const PROJECT_LICENSE: &str = env!("CARGO_PKG_LICENSE");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Ping,
    Mtr,
    Http,
    Tls,
    PortScan,
    Connections,
    IpInsight,
    Lookup,
    Dns,
    Ntp,
    Utils,
    Speedtest,
}

impl Tab {
    /// Built-in order. The overview is pinned first and missing tabs are
    /// appended when a saved order is loaded.
    pub const ALL: [Tab; 13] = [
        Tab::Overview,
        Tab::Ping,
        Tab::Mtr,
        Tab::Http,
        Tab::Tls,
        Tab::PortScan,
        Tab::Connections,
        Tab::IpInsight,
        Tab::Lookup,
        Tab::Dns,
        Tab::Ntp,
        Tab::Utils,
        Tab::Speedtest,
    ];

    /// Stable identifier stored in the configuration. Changing this breaks the
    /// saved order, while changing display labels does not.
    pub fn id(self) -> &'static str {
        match self {
            Tab::Overview => "overview",
            Tab::Ping => "ping",
            Tab::Mtr => "mtr",
            Tab::Http => "http",
            Tab::Tls => "tls",
            Tab::PortScan => "port_scan",
            Tab::Connections => "connections",
            Tab::IpInsight => "ip_insight",
            Tab::Lookup => "lookup",
            Tab::Dns => "dns",
            Tab::Ntp => "ntp",
            Tab::Utils => "utils",
            Tab::Speedtest => "speedtest",
        }
    }

    /// Resolve a saved identifier. Unknown values are ignored by the caller.
    pub fn from_id(id: &str) -> Option<Self> {
        Tab::ALL.into_iter().find(|tab| tab.id() == id)
    }
}

pub struct App {
    pub rt: tokio::runtime::Handle,
    pub cfg: AppConfig,
    pub tab: Tab,
    /// Top-level tab order chosen by the user and persisted in the config.
    pub tab_order: Vec<Tab>,
    pub overview: OverviewTab,
    pub ping: PingTab,
    pub mtr: MtrTab,
    pub http: HttpPingTab,
    pub tls: TlsTab,
    pub portscan: PortScanTab,
    pub connections: ConnectionsTab,
    pub ip_insight: IpInsightTab,
    pub lookup: LookupTab,
    pub dns: DnsTab,
    pub ntp: NtpTab,
    pub utils: UtilsTab,
    pub speedtest: SpeedtestTab,
    pub privilege: PrivilegeStatus,
    /// Manual or system-following theme preference.
    pub theme_preference: egui::ThemePreference,
    /// Whether the shared settings panel is expanded. The same value is used by
    /// every tab so collapsing it stays consistent while switching tools.
    pub settings_expanded: bool,
    /// Whether the About dialog is currently open.
    pub show_about: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: tokio::runtime::Handle) -> Self {
        // Install the bundled CJK font so CJK characters are not shown as boxes.
        crate::fonts::install(&cc.egui_ctx);
        let cfg = crate::config_store::load().unwrap_or_default();
        let tab_order = normalize_tab_order(&cfg.tab_order);
        let theme_preference = theme_preference_from_key(&cfg.theme);
        cc.egui_ctx.set_theme(theme_preference);
        Self {
            rt,
            cfg,
            tab: Tab::Overview,
            tab_order,
            overview: OverviewTab::new(),
            ping: PingTab::new(),
            mtr: MtrTab::new(),
            http: HttpPingTab::new(),
            tls: TlsTab::new(),
            portscan: PortScanTab::new(),
            connections: ConnectionsTab::new(),
            ip_insight: IpInsightTab::new(),
            lookup: LookupTab::new(),
            dns: DnsTab::new(),
            ntp: NtpTab::new(),
            utils: UtilsTab::new(),
            speedtest: SpeedtestTab::new(),
            privilege: net_tools_core::net::privilege::probe(),
            theme_preference,
            settings_expanded: true,
            show_about: false,
        }
    }

    /// Switch to another tab, stopping background work that must not continue
    /// while its tab is hidden.
    fn select_tab(&mut self, tab: Tab) {
        if self.tab == tab {
            return;
        }
        // Leaving the NTP tab drops its live result and stops a query that is
        // still running, so the clock does not keep repainting and no pointless
        // probe continues in the background.
        if self.tab == Tab::Ntp && tab != Tab::Ntp {
            self.ntp.clear_on_hide();
        }
        // Leaving Utils stops an in-flight WOL or online MAC query and drops
        // its live result. Inputs remain in the configuration.
        if self.tab == Tab::Utils && tab != Tab::Utils {
            self.utils.clear_on_hide();
        }
        // Leaving the speed test tab stops a running test and drops live
        // progress, while completed session history stays available.
        if self.tab == Tab::Speedtest && tab != Tab::Speedtest {
            self.speedtest.clear_on_hide();
        }
        // Leaving the TLS tab stops a running batch and drops its rows, so no
        // OCSP/CRL download or target connection continues in the background.
        if self.tab == Tab::Tls && tab != Tab::Tls {
            self.tls.clear_on_hide();
        }
        // Leaving the Connections tab stops automatic polling and drops any
        // outstanding collection result.
        if self.tab == Tab::Connections && tab != Tab::Connections {
            self.connections.clear_on_hide();
        }
        self.tab = tab;
    }

    /// Move a dragged tab relative to a drop target and persist the new order.
    ///
    /// The overview tab is pinned first. It cannot be dragged, and other tabs
    /// cannot be dropped onto it, so the fixed position is preserved.
    fn reorder_tab(&mut self, dragged: Tab, target: Tab, after: bool) {
        if dragged == Tab::Overview || target == Tab::Overview {
            return;
        }
        let previous = self.tab_order.clone();
        move_tab(&mut self.tab_order, dragged, target, after);
        if self.tab_order != previous {
            self.cfg.tab_order = self
                .tab_order
                .iter()
                .map(|tab| tab.id().to_owned())
                .collect();
            crate::config_store::save(&self.cfg);
        }
    }

    /// Render the top tab strip and let the user drag tabs into a new order.
    fn tab_bar(&mut self, ui: &mut egui::Ui) {
        let order = self.tab_order.clone();
        let mut selected = None;
        let mut dropped = None;

        // The tab strip wraps onto additional rows when it runs out of
        // horizontal space.
        ui.horizontal_wrapped(|ui| {
            for tab in order {
                let fixed = tab == Tab::Overview;
                let response = if fixed {
                    // The pinned overview tab is selectable but not draggable.
                    ui.add(egui::Button::selectable(self.tab == tab, tab_label(tab)))
                } else {
                    let response = ui.add(
                        egui::Button::selectable(self.tab == tab, tab_label(tab))
                            .sense(egui::Sense::click_and_drag()),
                    );
                    response.dnd_set_drag_payload(tab);
                    response
                };

                if response.clicked() {
                    selected = Some(tab);
                }

                // Only draggable tabs under the pointer receive the hover
                // payload. The pinned tab is not a drop target either, so the
                // first position cannot be displaced.
                if !fixed && response.dnd_hover_payload::<Tab>().is_some() {
                    let after = ui
                        .ctx()
                        .pointer_interact_pos()
                        .is_some_and(|pos| pos.x > response.rect.center().x);
                    let x = if after {
                        response.rect.right()
                    } else {
                        response.rect.left()
                    };
                    ui.painter().line_segment(
                        [
                            egui::pos2(x, response.rect.top()),
                            egui::pos2(x, response.rect.bottom()),
                        ],
                        egui::Stroke::new(2.0, ui.visuals().selection.bg_fill),
                    );
                    if let Some(payload) = response.dnd_release_payload::<Tab>() {
                        dropped = Some((*payload, tab, after));
                    }
                }
            }
        });

        if let Some(tab) = selected {
            self.select_tab(tab);
        }
        if let Some((dragged, target, after)) = dropped {
            self.reorder_tab(dragged, target, after);
        }
    }

    /// Global controls shown at the bottom-right of the window. In a
    /// right-to-left layout this produces the visual order
    /// `Theme, Language, About, privileges`.
    fn app_controls(&mut self, ui: &mut egui::Ui) {
        self.privilege_badge(ui);
        ui.separator();
        if ui.small_button(t!("about.button")).clicked() {
            self.show_about = true;
        }
        ui.separator();
        self.language_selector(ui);
        ui.label(t!("common.language"));
        self.theme_selector(ui);
        ui.label(t!("common.theme"));
    }

    fn language_selector(&mut self, ui: &mut egui::Ui) {
        let locales = available_locales!();
        let current = self.cfg.language.clone();
        let display = language_display_name(&current);
        let response = egui::ComboBox::from_id_salt("language")
            .selected_text(display)
            .width(84.0)
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
        response.response.on_hover_text(t!("common.language"));
    }

    /// Theme selector: system, light or dark. The choice is applied immediately
    /// and persisted so it survives a restart.
    fn theme_selector(&mut self, ui: &mut egui::Ui) {
        let current = self.theme_preference;
        let response = egui::ComboBox::from_id_salt("theme")
            .selected_text(theme_label(current))
            .width(76.0)
            .show_ui(ui, |ui| {
                for theme in [
                    egui::ThemePreference::System,
                    egui::ThemePreference::Light,
                    egui::ThemePreference::Dark,
                ] {
                    if ui
                        .selectable_label(current == theme, theme_label(theme))
                        .clicked()
                    {
                        self.theme_preference = theme;
                        ui.ctx().set_theme(theme);
                        self.cfg.theme = theme_key(theme).to_string();
                        crate::config_store::save(&self.cfg);
                    }
                }
            });
        response.response.on_hover_text(t!("common.theme"));
    }

    /// Privilege badge: reports whether the ICMP engines can open a socket, with
    /// the remaining raw-socket capability in the tooltip. Only a genuinely
    /// missing capability offers the elevation command, and only a permission
    /// error ever reaches this point with a hint.
    fn privilege_badge(&mut self, ui: &mut egui::Ui) {
        let palette = Palette::from_ui(ui);
        let (color, label) = match (self.privilege.icmp, self.privilege.raw) {
            (true, true) => (palette.privilege_ok, t!("privilege.ok")),
            // Probing works, but the features that need a raw socket do not.
            (true, false) => (palette.privilege_partial, t!("privilege.partial")),
            (false, _) => (palette.privilege_limited, t!("privilege.limited")),
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

    /// Render the top tab strip. The global controls live in the bottom bar,
    /// so the tab strip has the full window width.
    fn top_bar(&mut self, ui: &mut egui::Ui) -> egui::Rect {
        egui::Panel::top("top_bar")
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.add_space(2.0);
                self.tab_bar(ui);
                ui.add_space(6.0);
            })
            .response
            .rect
    }

    /// Render the global controls in the bottom-right corner.
    fn bottom_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("bottom_bar").show(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.app_controls(ui);
                });
            });
            ui.add_space(2.0);
        });
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
            ui.label(format!("{} {}", t!("about.license"), PROJECT_LICENSE));
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

/// Display label for a top-level tab.
fn tab_label(tab: Tab) -> String {
    match tab {
        Tab::Overview => t!("tab.overview"),
        Tab::Ping => t!("tab.ping"),
        Tab::Mtr => t!("tab.mtr"),
        Tab::Http => t!("tab.http"),
        Tab::Tls => t!("tab.tls"),
        Tab::PortScan => t!("tab.portscan"),
        Tab::Connections => t!("tab.connections"),
        Tab::IpInsight => t!("tab.ip_insight"),
        Tab::Lookup => t!("tab.lookup"),
        Tab::Dns => t!("tab.dns"),
        Tab::Ntp => t!("tab.ntp"),
        Tab::Utils => t!("tab.utils"),
        Tab::Speedtest => t!("tab.speedtest"),
    }
    .to_string()
}

/// Turn the persisted identifiers into a complete tab order.
///
/// Unknown and duplicate identifiers are dropped, and tabs added in a later
/// release are appended in their built-in position instead of disappearing.
fn normalize_tab_order(saved: &[String]) -> Vec<Tab> {
    let mut order = Vec::with_capacity(Tab::ALL.len());
    // The overview is always the first tab, regardless of the saved order.
    order.push(Tab::Overview);
    for id in saved {
        if let Some(tab) = Tab::from_id(id) {
            if !order.contains(&tab) {
                order.push(tab);
            }
        }
    }
    for tab in Tab::ALL {
        if !order.contains(&tab) {
            order.push(tab);
        }
    }
    order
}

/// Move `dragged` next to `target`, optionally after it.
fn move_tab(order: &mut Vec<Tab>, dragged: Tab, target: Tab, after: bool) {
    if dragged == target {
        return;
    }
    // Keep the overview pinned in the first position.
    if dragged == Tab::Overview || target == Tab::Overview {
        return;
    }
    let Some(from) = order.iter().position(|tab| *tab == dragged) else {
        return;
    };
    order.remove(from);

    let Some(mut to) = order.iter().position(|tab| *tab == target) else {
        // The target vanished; put the dragged tab back where it was.
        order.insert(from.min(order.len()), dragged);
        return;
    };
    if after {
        to += 1;
    }
    order.insert(to, dragged);
}

/// Map the persisted theme value to egui's preference type.
fn theme_preference_from_key(key: &str) -> egui::ThemePreference {
    match key {
        "light" => egui::ThemePreference::Light,
        "dark" => egui::ThemePreference::Dark,
        _ => egui::ThemePreference::System,
    }
}

/// Stable config value for a theme preference.
fn theme_key(theme: egui::ThemePreference) -> &'static str {
    match theme {
        egui::ThemePreference::System => "system",
        egui::ThemePreference::Light => "light",
        egui::ThemePreference::Dark => "dark",
    }
}

/// Localized display label for the theme selector.
fn theme_label(theme: egui::ThemePreference) -> String {
    match theme {
        egui::ThemePreference::System => t!("theme.system"),
        egui::ThemePreference::Light => t!("theme.light"),
        egui::ThemePreference::Dark => t!("theme.dark"),
    }
    .to_string()
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
        self.top_bar(ui);
        self.bottom_bar(ui);

        // Capture the history revision before rendering so edits made by the
        // input widgets can be written to disk immediately afterwards.
        let history_revision = self.cfg.history.revision();

        let settings_expanded = self.settings_expanded;
        let expanded = egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Overview => self.overview.ui(ui, &self.rt, settings_expanded),
            Tab::Ping => self.ping.ui(
                ui,
                &mut self.cfg.ping,
                &mut self.cfg.history,
                &self.rt,
                &self.privilege,
                settings_expanded,
            ),
            Tab::Mtr => self.mtr.ui(
                ui,
                &mut self.cfg.mtr,
                &mut self.cfg.history,
                &self.rt,
                &self.privilege,
                settings_expanded,
            ),
            Tab::Http => self.http.ui(
                ui,
                &mut self.cfg.http,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
            Tab::Tls => self.tls.ui(
                ui,
                &mut self.cfg.tls,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
            Tab::PortScan => self.portscan.ui(
                ui,
                &mut self.cfg.port_scan,
                &mut self.cfg.history,
                &self.rt,
                &self.privilege,
                settings_expanded,
            ),
            Tab::Connections => {
                self.connections
                    .ui(ui, &mut self.cfg.connections, settings_expanded)
            }
            Tab::IpInsight => self.ip_insight.ui(
                ui,
                &mut self.cfg.ip_insight,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
            Tab::Lookup => self.lookup.ui(
                ui,
                &mut self.cfg.lookup,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
            Tab::Dns => self.dns.ui(
                ui,
                &mut self.cfg.dns,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
            Tab::Ntp => self.ntp.ui(
                ui,
                &mut self.cfg.ntp,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
            Tab::Utils => self.utils.ui(
                ui,
                &mut self.cfg.utils,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
            Tab::Speedtest => self.speedtest.ui(
                ui,
                &mut self.cfg.speedtest,
                &mut self.cfg.history,
                &self.rt,
                settings_expanded,
            ),
        });
        self.settings_expanded = expanded.inner;

        if self.cfg.history.revision() != history_revision {
            crate::config_store::save(&self.cfg);
        }

        if self.show_about {
            self.about_dialog(ui.ctx());
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Stop a running speed test so its hidden worker does not outlive the
        // application.
        self.speedtest.clear_on_hide();
        self.tls.clear_on_hide();
        crate::config_store::save(&self.cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_order_keeps_known_ids_and_adds_missing_tabs() {
        let saved = vec![
            "dns".to_string(),
            "overview".to_string(),
            "unknown".to_string(),
            "ping".to_string(),
            "dns".to_string(),
        ];
        let order = normalize_tab_order(&saved);
        assert_eq!(order.len(), Tab::ALL.len());
        assert_eq!(order[0], Tab::Overview);
        assert_eq!(order[1], Tab::Dns);
        assert_eq!(order[2], Tab::Ping);
        for tab in Tab::ALL {
            assert!(order.contains(&tab));
        }
    }

    #[test]
    fn empty_saved_order_uses_builtin_order() {
        assert_eq!(normalize_tab_order(&[]), Tab::ALL.to_vec());
    }

    #[test]
    fn move_tab_handles_both_directions() {
        let mut order = vec![Tab::Ping, Tab::Mtr, Tab::Http];

        // Moving forward inserts after the target after removing the source.
        move_tab(&mut order, Tab::Ping, Tab::Http, true);
        assert_eq!(order, vec![Tab::Mtr, Tab::Http, Tab::Ping]);

        // Moving backward inserts before the target.
        move_tab(&mut order, Tab::Ping, Tab::Mtr, false);
        assert_eq!(order, vec![Tab::Ping, Tab::Mtr, Tab::Http]);
    }

    #[test]
    fn theme_keys_roundtrip_and_default_to_system() {
        for theme in [
            egui::ThemePreference::System,
            egui::ThemePreference::Light,
            egui::ThemePreference::Dark,
        ] {
            assert_eq!(theme_preference_from_key(theme_key(theme)), theme);
        }
        assert_eq!(theme_preference_from_key(""), egui::ThemePreference::System);
        assert_eq!(
            theme_preference_from_key("unknown"),
            egui::ThemePreference::System
        );
    }

    #[test]
    fn move_tab_ignores_same_and_missing_targets() {
        let mut order = vec![Tab::Ping, Tab::Mtr];
        move_tab(&mut order, Tab::Ping, Tab::Ping, false);
        assert_eq!(order, vec![Tab::Ping, Tab::Mtr]);

        move_tab(&mut order, Tab::Ping, Tab::Dns, true);
        assert_eq!(order, vec![Tab::Ping, Tab::Mtr]);
    }

    #[test]
    fn top_bar_height_is_stable_across_frames() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut app = App {
            rt: runtime.handle().clone(),
            cfg: AppConfig::default(),
            tab: Tab::Overview,
            tab_order: normalize_tab_order(&[]),
            overview: OverviewTab::new(),
            ping: PingTab::new(),
            mtr: MtrTab::new(),
            http: HttpPingTab::new(),
            tls: TlsTab::new(),
            portscan: PortScanTab::new(),
            connections: ConnectionsTab::new(),
            ip_insight: IpInsightTab::new(),
            lookup: LookupTab::new(),
            dns: DnsTab::new(),
            ntp: NtpTab::new(),
            utils: UtilsTab::new(),
            speedtest: SpeedtestTab::new(),
            privilege: net_tools_core::net::privilege::probe(),
            theme_preference: egui::ThemePreference::System,
            settings_expanded: true,
            show_about: false,
        };

        for width in [960.0, 1100.0, 1400.0] {
            let ctx = egui::Context::default();
            let mut heights = Vec::new();
            for _ in 0..20 {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::pos2(0.0, 0.0),
                        egui::vec2(width, 700.0),
                    )),
                    ..Default::default()
                };
                ctx.run_ui(input, |ui| {
                    heights.push(app.top_bar(ui).height());
                })
                .textures_delta
                .clear();
            }
            let first = heights[4];
            assert!(
                first < 100.0,
                "top bar is unexpectedly tall at {width}: {heights:?}"
            );
            for height in &heights[4..] {
                assert!(
                    (height - first).abs() < 1.0,
                    "top bar height changed at {width}: {heights:?}"
                );
            }
        }
    }

    #[test]
    fn overview_stays_pinned_first() {
        let mut order = vec![Tab::Overview, Tab::Ping, Tab::Mtr];

        // The overview cannot be dragged away, and no tab can be dropped on it.
        move_tab(&mut order, Tab::Overview, Tab::Mtr, true);
        assert_eq!(order, vec![Tab::Overview, Tab::Ping, Tab::Mtr]);
        move_tab(&mut order, Tab::Ping, Tab::Overview, false);
        assert_eq!(order, vec![Tab::Overview, Tab::Ping, Tab::Mtr]);

        // Reordering the remaining tabs leaves the overview in place.
        move_tab(&mut order, Tab::Mtr, Tab::Ping, false);
        assert_eq!(order, vec![Tab::Overview, Tab::Mtr, Tab::Ping]);
    }
}
