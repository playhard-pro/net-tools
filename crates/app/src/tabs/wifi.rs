//! Wi-Fi tab: continuous current-link monitoring, nearby scanning and channel analysis.

use std::time::Duration;

use eframe::egui;
use egui_extras::Column;
use net_tools_core::config::WifiSettings;
use net_tools_core::control::TaskController;
use net_tools_core::model::{
    ProbeEvent, WifiBand, WifiCapabilities, WifiChannelUsage, WifiCurrentSnapshot, WifiNetwork,
    WifiScanSnapshot, WifiSecurity,
};
use rust_i18n::t;

use crate::ui::chart;
use crate::ui::common::{error_banner, info_line, result_toolbar, state_badge, ToolbarAction};
use crate::ui::export::{csv_field, csv_to_html, save_file};
use crate::ui::result_table::{cell_with_tooltip, table_with_columns};
use crate::ui::theme::Palette;

/// Minimum accepted full-scan interval.
const MIN_SCAN_INTERVAL_MS: u64 = 5_000;
/// Maximum accepted full-scan interval.
const MAX_SCAN_INTERVAL_MS: u64 = 600_000;
/// Minimum accepted current-link sample interval.
const MIN_SAMPLE_INTERVAL_MS: u64 = 200;
/// Maximum accepted current-link sample interval.
const MAX_SAMPLE_INTERVAL_MS: u64 = 10_000;
/// Repaint cadence while the monitor is active.
const ACTIVE_REPAINT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WifiView {
    #[default]
    Overview,
    Networks,
    Channels,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum BandFilter {
    #[default]
    All,
    Ghz24,
    Ghz5,
    Ghz6,
}

impl BandFilter {
    fn label(self) -> String {
        match self {
            BandFilter::All => t!("wifi.band_all").to_string(),
            BandFilter::Ghz24 => WifiBand::Ghz24.label().to_string(),
            BandFilter::Ghz5 => WifiBand::Ghz5.label().to_string(),
            BandFilter::Ghz6 => WifiBand::Ghz6.label().to_string(),
        }
    }

    fn matches(self, band: WifiBand) -> bool {
        match self {
            BandFilter::All => true,
            BandFilter::Ghz24 => band == WifiBand::Ghz24,
            BandFilter::Ghz5 => band == WifiBand::Ghz5,
            BandFilter::Ghz6 => band == WifiBand::Ghz6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SecurityFilter {
    #[default]
    All,
    OpenWep,
    Wpa2,
    Wpa3,
    Other,
}

impl SecurityFilter {
    fn label(self) -> String {
        match self {
            SecurityFilter::All => t!("wifi.security_all").to_string(),
            SecurityFilter::OpenWep => t!("wifi.security_open_wep").to_string(),
            SecurityFilter::Wpa2 => "WPA2".to_string(),
            SecurityFilter::Wpa3 => "WPA3".to_string(),
            SecurityFilter::Other => t!("wifi.security_other").to_string(),
        }
    }

    fn matches(self, security: WifiSecurity) -> bool {
        match self {
            SecurityFilter::All => true,
            SecurityFilter::OpenWep => security.is_insecure(),
            SecurityFilter::Wpa2 => matches!(security, WifiSecurity::Wpa2 | WifiSecurity::Wpa2Wpa3),
            SecurityFilter::Wpa3 => matches!(
                security,
                WifiSecurity::Wpa3 | WifiSecurity::Wpa2Wpa3 | WifiSecurity::Owe
            ),
            SecurityFilter::Other => matches!(
                security,
                WifiSecurity::Wpa | WifiSecurity::Enterprise | WifiSecurity::Unknown
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum NetworkSort {
    #[default]
    Signal,
    Channel,
    Ssid,
    Seen,
}

impl NetworkSort {
    fn label(self) -> String {
        match self {
            NetworkSort::Signal => t!("wifi.sort_signal").to_string(),
            NetworkSort::Channel => t!("wifi.sort_channel").to_string(),
            NetworkSort::Ssid => t!("wifi.sort_ssid").to_string(),
            NetworkSort::Seen => t!("wifi.sort_seen").to_string(),
        }
    }
}

pub struct WifiTab {
    ctrl: TaskController<ProbeEvent>,
    capabilities: Option<WifiCapabilities>,
    current: Option<WifiCurrentSnapshot>,
    scan: Option<WifiScanSnapshot>,
    error: Option<(String, Option<String>)>,
    info: Vec<String>,
    view: WifiView,
    query: String,
    band_filter: BandFilter,
    security_filter: SecurityFilter,
    sort: NetworkSort,
    channel_band: WifiBand,
}

impl Default for WifiTab {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiTab {
    pub fn new() -> Self {
        Self {
            ctrl: TaskController::new(),
            capabilities: None,
            current: None,
            scan: None,
            error: None,
            info: Vec::new(),
            view: WifiView::Overview,
            query: String::new(),
            band_filter: BandFilter::All,
            security_filter: SecurityFilter::All,
            sort: NetworkSort::Signal,
            channel_band: WifiBand::Ghz24,
        }
    }

    /// Stop monitoring when another tab is selected. Latest results stay visible.
    pub fn clear_on_hide(&mut self) {
        if self.ctrl.is_active() {
            self.ctrl.stop();
        }
    }

    fn reset_results(&mut self) {
        self.capabilities = None;
        self.current = None;
        self.scan = None;
        self.error = None;
        self.info.clear();
    }

    fn clear(&mut self) {
        if self.ctrl.is_active() {
            self.ctrl.stop();
        }
        self.reset_results();
    }

    fn start(&mut self, settings: &WifiSettings, rt: &tokio::runtime::Handle) {
        if self.ctrl.is_active() {
            return;
        }
        self.reset_results();
        let settings = settings.clone();
        self.ctrl.start(rt, move |handle| {
            net_tools_core::net::wifi::run_monitor(handle, settings)
        });
    }

    fn drain(&mut self) {
        for event in self.ctrl.drain() {
            match event {
                ProbeEvent::WifiCapabilities(capabilities) => {
                    if let Some(note) = &capabilities.note {
                        self.info.push(localize_wifi_text(note));
                    }
                    self.capabilities = Some(capabilities);
                }
                ProbeEvent::WifiCurrent(snapshot) => self.current = Some(*snapshot),
                ProbeEvent::WifiScan(snapshot) => self.scan = Some(*snapshot),
                ProbeEvent::Info(message) => {
                    self.info.push(localize_wifi_text(&message));
                    if self.info.len() > 50 {
                        self.info.remove(0);
                    }
                }
                ProbeEvent::Error { message, hint } => {
                    self.error = Some((
                        localize_wifi_text(&message),
                        hint.map(|hint| localize_wifi_text(&hint)),
                    ));
                }
                ProbeEvent::Finished => {}
                _ => {}
            }
        }
    }

    fn control_row(&mut self, ui: &mut egui::Ui) -> bool {
        let mut submit = false;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.ctrl.is_active(),
                    egui::Button::new(t!("common.start")),
                )
                .clicked()
            {
                submit = true;
            }
            if ui
                .add_enabled(self.ctrl.is_active(), egui::Button::new(t!("common.stop")))
                .clicked()
            {
                self.ctrl.stop();
            }
            if ui
                .add_enabled(
                    self.ctrl.is_active() || self.current.is_some() || self.scan.is_some(),
                    egui::Button::new(t!("common.clear")),
                )
                .clicked()
            {
                self.clear();
            }
            state_badge(ui, self.ctrl.state);
        });
        submit
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut WifiSettings,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        self.drain();
        if self.ctrl.is_active() {
            ui.ctx().request_repaint_after(ACTIVE_REPAINT);
        }

        let (submit, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            let mut submit = false;
            egui::Grid::new("wifi_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("wifi.scan_interval"));
                    ui.add(
                        egui::DragValue::new(&mut settings.scan_interval_ms)
                            .range(MIN_SCAN_INTERVAL_MS..=MAX_SCAN_INTERVAL_MS)
                            .suffix(" ms"),
                    );
                    ui.end_row();

                    ui.label(t!("wifi.sample_interval"));
                    ui.add(
                        egui::DragValue::new(&mut settings.sample_interval_ms)
                            .range(MIN_SAMPLE_INTERVAL_MS..=MAX_SAMPLE_INTERVAL_MS)
                            .suffix(" ms"),
                    );
                    ui.end_row();

                    ui.label(t!("wifi.show_hidden"));
                    ui.checkbox(&mut settings.show_hidden, "");
                    ui.end_row();

                    ui.label(t!("wifi.min_signal"));
                    ui.add(
                        egui::DragValue::new(&mut settings.min_signal_dbm)
                            .range(-100..=0)
                            .suffix(" dBm"),
                    );
                    ui.end_row();
                });

            ui.add_space(6.0);
            submit |= self.control_row(ui);
            if let Some((message, hint)) = &self.error {
                error_banner(ui, message, hint.as_deref());
            }
            if cfg!(windows)
                && self.error.is_some()
                && ui.button(t!("wifi.open_location_settings")).clicked()
            {
                open_location_settings();
            }
            for line in self.info.iter().rev().take(5) {
                info_line(ui, line);
            }
            submit
        });

        if submit == Some(true) {
            self.start(settings, rt);
        }

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);
            self.view_selector(ui);
            ui.separator();
            match self.view {
                WifiView::Overview => self.overview_ui(ui),
                WifiView::Networks => self.networks_ui(ui, settings),
                WifiView::Channels => self.channels_ui(ui),
            }
        });

        expanded
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => {
                ui.ctx().copy_text(self.to_text());
            }
            ToolbarAction::ExportCsv => save_file("wifi", "csv", &self.to_csv()),
            ToolbarAction::ExportJson => save_file("wifi", "json", &self.to_json()),
            ToolbarAction::ExportHtml => save_file("wifi", "html", &csv_to_html(&self.to_csv())),
            ToolbarAction::Clear => self.clear(),
            ToolbarAction::None => {}
        }
    }

    fn view_selector(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.view, WifiView::Overview, t!("wifi.overview"));
            ui.selectable_value(&mut self.view, WifiView::Networks, t!("wifi.networks"));
            ui.selectable_value(&mut self.view, WifiView::Channels, t!("wifi.channels"));
        });
    }

    fn current_summary(&self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.current else {
            ui.weak(t!("wifi.empty"));
            return;
        };
        let Some(connection) = &snapshot.connection else {
            ui.weak(t!("wifi.not_connected"));
            return;
        };
        let palette = Palette::from_ui(ui);
        egui::Frame::new()
            .fill(palette.badge_bg(palette.info_text))
            .corner_radius(6.0)
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let ssid = if connection.ssid.is_empty() {
                        t!("wifi.hidden").to_string()
                    } else {
                        connection.ssid.clone()
                    };
                    ui.strong(ssid);
                    ui.label(connection.bssid.as_str());
                    if !connection.interface.is_empty() {
                        ui.weak(connection.interface.as_str());
                    }
                    ui.label(format!(
                        "{} {} · {}",
                        connection.band.label(),
                        connection
                            .channel
                            .map_or("-".to_string(), |channel| channel.to_string()),
                        connection.security.label()
                    ));
                    ui.label(format!(
                        "{} {}",
                        t!("wifi.signal"),
                        format_signal(connection.signal_dbm)
                    ));
                    if let Some(quality) = connection.signal_quality {
                        ui.label(format!("{quality}%"));
                    }
                    if connection.rx_rate_mbps.is_some() || connection.tx_rate_mbps.is_some() {
                        ui.label(format!(
                            "RX {} / TX {}",
                            format_rate(connection.rx_rate_mbps),
                            format_rate(connection.tx_rate_mbps)
                        ));
                    }
                });
            });
    }

    fn overview_ui(&mut self, ui: &mut egui::Ui) {
        self.current_summary(ui);
        if let Some(snapshot) = &self.current {
            for warning in snapshot.warnings.iter().take(3) {
                info_line(ui, &localize_wifi_text(warning));
            }
        }
        ui.add_space(4.0);
        if self.scan.is_none() && self.current.is_none() {
            ui.weak(t!("wifi.start_hint"));
            return;
        }

        if let Some(snapshot) = &self.current {
            if let Some(connection) = &snapshot.connection {
                egui::Grid::new("wifi_current_details")
                    .num_columns(4)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.label(t!("wifi.frequency"));
                        ui.label(
                            connection
                                .frequency_mhz
                                .map_or("-".to_string(), |value| format!("{value} MHz")),
                        );
                        ui.label(t!("wifi.width"));
                        ui.label(
                            connection
                                .width_mhz
                                .map_or("-".to_string(), |value| format!("{value} MHz")),
                        );
                        ui.end_row();
                        ui.label(t!("wifi.noise"));
                        ui.label(format_signal(connection.noise_dbm));
                        ui.label(t!("wifi.snr"));
                        ui.label(
                            connection
                                .snr_db
                                .map_or("-".to_string(), |value| format!("{value} dB")),
                        );
                        ui.end_row();
                        ui.label(t!("wifi.standard"));
                        ui.label(connection.standard.label());
                        ui.label(t!("wifi.vendor"));
                        ui.label(connection.vendor.as_deref().unwrap_or("-"));
                        ui.end_row();
                    });
            }

            ui.add_space(6.0);
            chart::wifi_signal_chart(ui, "wifi_signal_chart", &snapshot.history, 140.0);
            let rx = snapshot
                .history
                .iter()
                .filter_map(|sample| sample.rx_rate_mbps.map(|rate| [sample.elapsed_s, rate]))
                .collect::<Vec<_>>();
            let tx = snapshot
                .history
                .iter()
                .filter_map(|sample| sample.tx_rate_mbps.map(|rate| [sample.elapsed_s, rate]))
                .collect::<Vec<_>>();
            if !rx.is_empty() || !tx.is_empty() {
                let mbps = t!("wifi.mbps").to_string();
                chart::network_rate_chart(ui, "wifi_rate_chart", &rx, &tx, 110.0, &mbps);
            }

            let stats = snapshot.stats;
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("{}: {}", t!("wifi.samples"), stats.samples));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.signal_min"),
                    format_signal(stats.min_signal_dbm)
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.signal_max"),
                    format_signal(stats.max_signal_dbm)
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.signal_avg"),
                    format_db(stats.average_signal_dbm)
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.signal_stddev"),
                    format_db(stats.stddev_db)
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.stability"),
                    stability_label(stats.stddev_db)
                ));
            });
        }

        if let Some(scan) = &self.scan {
            ui.add_space(6.0);
            ui.strong(t!("wifi.analysis"));
            let summary = &scan.summary;
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.access_points"),
                    summary.access_points
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.unique_ssids"),
                    summary.unique_ssids
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.open_networks"),
                    summary.open_networks
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.wep_networks"),
                    summary.wep_networks
                ));
                ui.label(format!(
                    "{}: {}",
                    t!("wifi.hidden_networks"),
                    summary.hidden_networks
                ));
                for band in &summary.band_counts {
                    ui.label(format!("{}: {}", band.band.label(), band.count));
                }
            });
            if let Some(ssid) = &summary.strongest_ssid {
                ui.label(format!(
                    "{}: {} ({})",
                    t!("wifi.strongest"),
                    if ssid.is_empty() {
                        t!("wifi.hidden").to_string()
                    } else {
                        ssid.clone()
                    },
                    format_signal(summary.strongest_signal_dbm)
                ));
            }
            for busiest in &summary.busiest_channels {
                ui.label(format!(
                    "{}: {} {} ({} AP)",
                    t!("wifi.busiest_channel"),
                    busiest.band.label(),
                    busiest.channel,
                    busiest.access_points
                ));
            }
            if !scan.recommendations.is_empty() {
                ui.add_space(4.0);
                ui.strong(t!("wifi.recommendations"));
                for recommendation in &scan.recommendations {
                    let current = if recommendation.is_current {
                        format!(" ({})", t!("wifi.current"))
                    } else {
                        String::new()
                    };
                    ui.label(format!(
                        "{} ch {}{} — {} AP, {:.0}%",
                        recommendation.band.label(),
                        recommendation.channel,
                        current,
                        recommendation.overlapping_aps,
                        recommendation.occupancy
                    ));
                }
                ui.weak(t!("wifi.channel_disclaimer"));
            }
            for warning in scan.warnings.iter().take(5) {
                info_line(ui, &localize_wifi_text(warning));
            }
        }
    }

    fn filtered_networks(&self, settings: &WifiSettings) -> Vec<&WifiNetwork> {
        let Some(scan) = &self.scan else {
            return Vec::new();
        };
        let query = self.query.trim().to_ascii_lowercase();
        let mut networks = scan
            .networks
            .iter()
            .filter(|network| {
                self.band_filter.matches(network.band)
                    && self.security_filter.matches(network.security)
                    && (network
                        .signal_dbm
                        .is_none_or(|signal| signal >= settings.min_signal_dbm))
                    && (settings.show_hidden || !network.is_hidden)
                    && (self.query.trim().is_empty()
                        || network.ssid.to_ascii_lowercase().contains(&query)
                        || network.bssid.to_ascii_lowercase().contains(&query)
                        || network
                            .vendor
                            .as_deref()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                            .contains(&query))
            })
            .collect::<Vec<_>>();

        match self.sort {
            NetworkSort::Signal => networks.sort_by(|left, right| {
                right
                    .signal_dbm
                    .unwrap_or(i32::MIN)
                    .cmp(&left.signal_dbm.unwrap_or(i32::MIN))
            }),
            NetworkSort::Channel => networks.sort_by(|left, right| {
                left.channel
                    .unwrap_or(u32::MAX)
                    .cmp(&right.channel.unwrap_or(u32::MAX))
            }),
            NetworkSort::Ssid => networks.sort_by(|left, right| left.ssid.cmp(&right.ssid)),
            NetworkSort::Seen => networks.sort_by_key(|left| std::cmp::Reverse(left.seen_scans)),
        }
        networks
    }

    fn networks_ui(&mut self, ui: &mut egui::Ui, settings: &mut WifiSettings) {
        if self
            .capabilities
            .as_ref()
            .is_some_and(|caps| !caps.scan_supported)
        {
            ui.weak(t!("wifi.scan_unavailable"));
        }
        if self.scan.is_none() {
            ui.weak(t!("wifi.no_scan"));
            return;
        }

        ui.horizontal_wrapped(|ui| {
            ui.label(t!("wifi.search"));
            ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .desired_width(150.0)
                    .hint_text(t!("wifi.search_hint")),
            );
            egui::ComboBox::from_id_salt("wifi_band_filter")
                .selected_text(self.band_filter.label())
                .show_ui(ui, |ui| {
                    for filter in [
                        BandFilter::All,
                        BandFilter::Ghz24,
                        BandFilter::Ghz5,
                        BandFilter::Ghz6,
                    ] {
                        ui.selectable_value(&mut self.band_filter, filter, filter.label());
                    }
                });
            egui::ComboBox::from_id_salt("wifi_security_filter")
                .selected_text(self.security_filter.label())
                .show_ui(ui, |ui| {
                    for filter in [
                        SecurityFilter::All,
                        SecurityFilter::OpenWep,
                        SecurityFilter::Wpa2,
                        SecurityFilter::Wpa3,
                        SecurityFilter::Other,
                    ] {
                        ui.selectable_value(&mut self.security_filter, filter, filter.label());
                    }
                });
            egui::ComboBox::from_id_salt("wifi_sort")
                .selected_text(self.sort.label())
                .show_ui(ui, |ui| {
                    for sort in [
                        NetworkSort::Signal,
                        NetworkSort::Channel,
                        NetworkSort::Ssid,
                        NetworkSort::Seen,
                    ] {
                        ui.selectable_value(&mut self.sort, sort, sort.label());
                    }
                });
            ui.checkbox(&mut settings.show_hidden, t!("wifi.show_hidden"));
        });

        let networks = self.filtered_networks(settings);
        if networks.is_empty() {
            ui.weak(t!("wifi.no_matches"));
            return;
        }

        let headers = [
            t!("wifi.ssid"),
            t!("wifi.bssid"),
            t!("wifi.vendor"),
            t!("wifi.band"),
            t!("wifi.channel"),
            t!("wifi.width"),
            t!("wifi.signal_dbm"),
            t!("wifi.quality"),
            t!("wifi.security"),
            t!("wifi.standard"),
            t!("wifi.max_rate"),
            t!("wifi.seen"),
        ];
        let columns = [
            Column::auto().at_least(120.0).at_most(220.0),
            Column::auto().at_least(120.0).at_most(150.0),
            Column::auto().at_least(90.0).at_most(180.0),
            Column::auto().at_least(65.0).at_most(80.0),
            Column::auto().at_least(60.0).at_most(80.0),
            Column::auto().at_least(60.0).at_most(80.0),
            Column::auto().at_least(75.0).at_most(100.0),
            Column::auto().at_least(60.0).at_most(80.0),
            Column::auto().at_least(80.0).at_most(130.0),
            Column::auto().at_least(75.0).at_most(100.0),
            Column::auto().at_least(80.0).at_most(110.0),
            Column::auto().at_least(70.0).at_most(100.0),
        ];
        table_with_columns(ui, &headers, networks.len(), columns, |index, row| {
            let network = networks[index];
            row.col(|ui| {
                let mut text = if network.is_hidden {
                    t!("wifi.hidden").to_string()
                } else if network.is_current {
                    format!("* {}", network.ssid)
                } else {
                    network.ssid.clone()
                };
                if network.is_current && network.is_hidden {
                    text.push_str(" *");
                }
                cell_with_tooltip(ui, text.clone(), text);
            });
            row.col(|ui| {
                cell_with_tooltip(ui, &network.bssid, &network.bssid);
            });
            row.col(|ui| {
                let text = network.vendor.as_deref().unwrap_or("-");
                cell_with_tooltip(ui, text, text);
            });
            row.col(|ui| {
                ui.label(network.band.label());
            });
            row.col(|ui| {
                ui.label(format_option(network.channel));
            });
            row.col(|ui| {
                ui.label(
                    network
                        .width_mhz
                        .map_or("-".to_string(), |width| format!("{width} MHz")),
                );
            });
            row.col(|ui| {
                ui.label(format_signal(network.signal_dbm));
            });
            row.col(|ui| {
                ui.label(
                    network
                        .signal_quality
                        .map_or("-".to_string(), |quality| format!("{quality}%")),
                );
            });
            row.col(|ui| {
                let text = if network.security_detail.is_empty() {
                    network.security.label().to_string()
                } else {
                    network.security_detail.clone()
                };
                cell_with_tooltip(ui, network.security.label(), text);
            });
            row.col(|ui| {
                ui.label(network.standard.label());
            });
            row.col(|ui| {
                ui.label(format_rate(network.max_rate_mbps));
            });
            row.col(|ui| {
                ui.label(format!("{}", network.seen_scans));
            });
        });
    }

    fn channels_ui(&mut self, ui: &mut egui::Ui) {
        if self
            .capabilities
            .as_ref()
            .is_some_and(|caps| !caps.scan_supported)
        {
            ui.weak(t!("wifi.scan_unavailable"));
            if let Some(connection) = self
                .current
                .as_ref()
                .and_then(|snapshot| snapshot.connection.as_ref())
            {
                ui.label(format!(
                    "{}: {} {} · {}",
                    t!("wifi.current"),
                    connection.band.label(),
                    connection
                        .channel
                        .map_or("-".to_string(), |channel| channel.to_string()),
                    format_signal(connection.signal_dbm)
                ));
            }
            return;
        }
        let Some(scan) = &self.scan else {
            ui.weak(t!("wifi.no_scan"));
            return;
        };

        ui.horizontal_wrapped(|ui| {
            for band in [WifiBand::Ghz24, WifiBand::Ghz5, WifiBand::Ghz6] {
                ui.selectable_value(&mut self.channel_band, band, band.label());
            }
        });
        let usage = scan
            .channel_usage
            .iter()
            .filter(|entry| entry.band == self.channel_band)
            .cloned()
            .collect::<Vec<_>>();
        if usage.is_empty() {
            ui.weak(t!("wifi.no_channel_data"));
            return;
        }
        chart::wifi_channel_chart(ui, "wifi_channel_chart", &usage, 160.0);

        let headers = [
            t!("wifi.channel"),
            t!("wifi.frequency"),
            t!("wifi.width"),
            t!("wifi.access_points_short"),
            t!("wifi.strongest_signal"),
            t!("wifi.interference"),
            t!("wifi.occupancy"),
            t!("wifi.current"),
        ];
        let columns = [
            Column::auto().at_least(60.0),
            Column::auto().at_least(90.0),
            Column::auto().at_least(70.0),
            Column::auto().at_least(70.0),
            Column::auto().at_least(90.0),
            Column::auto().at_least(90.0),
            Column::auto().at_least(80.0),
            Column::auto().at_least(70.0),
        ];
        table_with_columns(ui, &headers, usage.len(), columns, |index, row| {
            let entry: &WifiChannelUsage = &usage[index];
            row.col(|ui| {
                ui.label(format!("{}", entry.channel));
            });
            row.col(|ui| {
                ui.label(format!("{} MHz", entry.frequency_mhz));
            });
            row.col(|ui| {
                ui.label(format!("{} MHz", entry.width_mhz));
            });
            row.col(|ui| {
                ui.label(format!("{}", entry.access_points));
            });
            row.col(|ui| {
                ui.label(format_signal(entry.strongest_signal_dbm));
            });
            row.col(|ui| {
                ui.label(format_db(entry.interference_dbm));
            });
            row.col(|ui| {
                ui.label(format!("{:.0}%", entry.occupancy));
            });
            row.col(|ui| {
                if entry.is_current {
                    ui.strong("*");
                } else {
                    ui.label("-");
                }
            });
        });

        let recommendations = scan
            .recommendations
            .iter()
            .filter(|entry| entry.band == self.channel_band)
            .collect::<Vec<_>>();
        if !recommendations.is_empty() {
            ui.add_space(4.0);
            ui.strong(t!("wifi.recommendations"));
            for recommendation in recommendations {
                ui.label(format!(
                    "ch {} — {} AP, {:.0}%{}",
                    recommendation.channel,
                    recommendation.overlapping_aps,
                    recommendation.occupancy,
                    if recommendation.is_current {
                        format!(" ({})", t!("wifi.current"))
                    } else {
                        String::new()
                    }
                ));
            }
        }
        ui.weak(t!("wifi.channel_disclaimer"));
        for warning in scan.warnings.iter().take(5) {
            info_line(ui, &localize_wifi_text(warning));
        }
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        if let Some(connection) = self
            .current
            .as_ref()
            .and_then(|snapshot| snapshot.connection.as_ref())
        {
            out.push_str(&format!(
                "{}: {}\n{}: {}\n{}: {} {} / {}\n{}: {}\n{}: {}\n",
                t!("wifi.ssid"),
                if connection.ssid.is_empty() {
                    t!("wifi.hidden")
                } else {
                    connection.ssid.as_str().into()
                },
                t!("wifi.bssid"),
                connection.bssid,
                t!("wifi.band"),
                connection.band.label(),
                connection
                    .channel
                    .map_or("-".to_string(), |channel| channel.to_string()),
                connection.security.label(),
                t!("wifi.signal"),
                format_signal(connection.signal_dbm),
                t!("wifi.standard"),
                connection.standard.label(),
            ));
        }
        if let Some(scan) = &self.scan {
            out.push_str(&format!("\n{}\n", t!("wifi.networks")));
            for network in &scan.networks {
                out.push_str(&format!(
                    "{}  {}  {}  ch {}  {}  {}  {}  {} AP seen\n",
                    if network.ssid.is_empty() {
                        t!("wifi.hidden")
                    } else {
                        network.ssid.as_str().into()
                    },
                    network.bssid,
                    network.band.label(),
                    network
                        .channel
                        .map_or("-".to_string(), |channel| channel.to_string()),
                    format_signal(network.signal_dbm),
                    network.security.label(),
                    network.standard.label(),
                    network.seen_scans
                ));
            }
            if !scan.recommendations.is_empty() {
                out.push_str(&format!("\n{}\n", t!("wifi.recommendations")));
                for recommendation in &scan.recommendations {
                    out.push_str(&format!(
                        "{} ch {} — {} AP, {:.0}%\n",
                        recommendation.band.label(),
                        recommendation.channel,
                        recommendation.overlapping_aps,
                        recommendation.occupancy
                    ));
                }
            }
        }
        out
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from("section,item,key,value\n");
        let row = |out: &mut String, section: &str, item: &str, key: &str, value: &str| {
            out.push_str(&format!(
                "{},{},{},{}\n",
                csv_field(section),
                csv_field(item),
                csv_field(key),
                csv_field(value)
            ));
        };
        if let Some(connection) = self
            .current
            .as_ref()
            .and_then(|snapshot| snapshot.connection.as_ref())
        {
            let item = &connection.bssid;
            row(&mut out, "current", item, "ssid", &connection.ssid);
            row(
                &mut out,
                "current",
                item,
                "interface",
                &connection.interface,
            );
            row(&mut out, "current", item, "band", connection.band.label());
            row(
                &mut out,
                "current",
                item,
                "channel",
                &format_option(connection.channel),
            );
            row(
                &mut out,
                "current",
                item,
                "frequency_mhz",
                &format_option(connection.frequency_mhz),
            );
            row(
                &mut out,
                "current",
                item,
                "width_mhz",
                &format_option(connection.width_mhz),
            );
            row(
                &mut out,
                "current",
                item,
                "signal_dbm",
                &format_signal(connection.signal_dbm),
            );
            row(
                &mut out,
                "current",
                item,
                "security",
                connection.security.label(),
            );
            row(
                &mut out,
                "current",
                item,
                "standard",
                connection.standard.label(),
            );
        }
        if let Some(scan) = &self.scan {
            for network in &scan.networks {
                let item = &network.bssid;
                row(&mut out, "network", item, "ssid", &network.ssid);
                row(
                    &mut out,
                    "network",
                    item,
                    "vendor",
                    network.vendor.as_deref().unwrap_or(""),
                );
                row(&mut out, "network", item, "band", network.band.label());
                row(
                    &mut out,
                    "network",
                    item,
                    "channel",
                    &format_option(network.channel),
                );
                row(
                    &mut out,
                    "network",
                    item,
                    "width_mhz",
                    &format_option(network.width_mhz),
                );
                row(
                    &mut out,
                    "network",
                    item,
                    "signal_dbm",
                    &format_signal(network.signal_dbm),
                );
                row(
                    &mut out,
                    "network",
                    item,
                    "security",
                    network.security.label(),
                );
                row(
                    &mut out,
                    "network",
                    item,
                    "standard",
                    network.standard.label(),
                );
                row(
                    &mut out,
                    "network",
                    item,
                    "seen_scans",
                    &network.seen_scans.to_string(),
                );
            }
            for entry in &scan.channel_usage {
                let item = format!("{} {}", entry.band.label(), entry.channel);
                row(
                    &mut out,
                    "channel",
                    &item,
                    "frequency_mhz",
                    &entry.frequency_mhz.to_string(),
                );
                row(
                    &mut out,
                    "channel",
                    &item,
                    "access_points",
                    &entry.access_points.to_string(),
                );
                row(
                    &mut out,
                    "channel",
                    &item,
                    "occupancy",
                    &format!("{:.0}", entry.occupancy),
                );
            }
            for recommendation in &scan.recommendations {
                let item = format!("{} {}", recommendation.band.label(), recommendation.channel);
                row(
                    &mut out,
                    "recommendation",
                    &item,
                    "overlapping_aps",
                    &recommendation.overlapping_aps.to_string(),
                );
                row(
                    &mut out,
                    "recommendation",
                    &item,
                    "occupancy",
                    &format!("{:.0}", recommendation.occupancy),
                );
            }
        }
        out
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&(&self.capabilities, &self.current, &self.scan))
            .unwrap_or_else(|_| "{}".to_string())
    }
}

/// Translate platform diagnostics into the active UI language.
fn localize_wifi_text(text: &str) -> String {
    let trimmed = text.trim();
    let translated = match trimmed {
        "The Wi-Fi radio is turned off" => t!("wifi.msg_radio_off").to_string(),
        "Turn Wi-Fi on in the Windows quick settings or Settings > Network & Internet > Wi-Fi, then retry." => {
            t!("wifi.msg_radio_on_hint").to_string()
        }
        "Windows denies Wi-Fi scanning when the executable runs from a network/UNC path such as \\wsl.localhost. Copy net-tools.exe to a local drive and run it there." => {
            t!("wifi.msg_unc_scan").to_string()
        }
        "Windows blocks Wi-Fi scanning when net-tools runs from a network/UNC path such as \\wsl.localhost. Copy the executable to a local drive and run it there." => {
            t!("wifi.msg_unc_capabilities").to_string()
        }
        "Windows blocks nearby Wi-Fi scans while Location Services is off. Open Settings > Privacy & security > Location and enable Location services and the global desktop-app location access. Windows does not list net-tools as a separate app there. Administrator rights do not bypass this restriction." => {
            t!("wifi.msg_location_denied").to_string()
        }
        "The WLAN AutoConfig service is not running. Start the service, then retry." => {
            t!("wifi.msg_wlan_service").to_string()
        }
        "Using the native Windows WLAN API. Nearby scanning requires Location Services." => {
            t!("wifi.msg_windows_api").to_string()
        }
        "NetworkManager is unavailable; using iw. Some scans may require privileges." => {
            t!("wifi.msg_nm_missing").to_string()
        }
        "Using iwlist. Detail fields may be limited." => t!("wifi.msg_iwlist").to_string(),
        "Install NetworkManager (nmcli) or iw to scan Wi-Fi networks." => {
            t!("wifi.msg_install_tools").to_string()
        }
        "No wireless interface was found." | "No wireless interface was found" => {
            t!("wifi.msg_no_wireless_iface").to_string()
        }
        "No WLAN interface was found" => t!("wifi.msg_no_wlan_iface").to_string(),
        "The Wi-Fi scan returned no usable results" => t!("wifi.msg_no_scan_results").to_string(),
        "Wireless scanning may require NetworkManager or additional privileges." => {
            t!("wifi.msg_scan_privileges").to_string()
        }
        "macOS shows current connection details through wdutil; nearby scanning is not available." => {
            t!("wifi.msg_macos_capabilities").to_string()
        }
        "macOS only exposes the current connection through wdutil; nearby scanning is not available" => {
            t!("wifi.msg_macos_scan").to_string()
        }
        "wdutil is not available on this system." | "wdutil is not available on this system" => {
            t!("wifi.msg_wdutil_missing").to_string()
        }
        "wdutil may require elevated privileges or Location Services permission." => {
            t!("wifi.msg_wdutil_permission").to_string()
        }
        "wdutil returned more output than expected" => t!("wifi.msg_wdutil_too_large").to_string(),
        _ => {
            if let Some(rest) = trimmed.strip_prefix("Using NetworkManager on ") {
                return t!("wifi.msg_nm_active", interfaces = rest).to_string();
            }
            if let Some(code) = trimmed.strip_prefix("WlanOpenHandle failed with error ") {
                return t!("wifi.msg_wlan_open_error", code = code).to_string();
            }
            if let Some(code) = trimmed.strip_prefix("WlanEnumInterfaces failed with error ") {
                return t!("wifi.msg_wlan_enum_error", code = code).to_string();
            }
            if let Some(code) = trimmed.strip_prefix("WlanGetNetworkBssList failed with error ") {
                return t!("wifi.msg_wlan_bss_error", code = code).to_string();
            }
            if let Some(error) = trimmed.strip_prefix("WLAN task failed: ") {
                return t!("wifi.msg_wlan_task_failed", error = error).to_string();
            }
            if let Some(program) = trimmed.strip_suffix(" timed out") {
                return t!("wifi.msg_command_timeout", program = program).to_string();
            }
            trimmed.to_string()
        }
    };
    translated
}

fn open_location_settings() {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "ms-settings:privacy-location"])
            .spawn();
    }
}

fn format_option<T: ToString>(value: Option<T>) -> String {
    value.map_or("-".to_string(), |value| value.to_string())
}

fn format_signal(value: Option<i32>) -> String {
    value.map_or("-".to_string(), |value| format!("{value} dBm"))
}

fn format_db(value: Option<f64>) -> String {
    value.map_or("-".to_string(), |value| format!("{value:.1} dB"))
}

fn format_rate(value: Option<f64>) -> String {
    value.map_or("-".to_string(), |value| format!("{value:.0} Mbps"))
}

fn stability_label(stddev: Option<f64>) -> String {
    match stddev {
        Some(value) if value <= 3.0 => t!("wifi.stability_stable").to_string(),
        Some(value) if value <= 6.0 => t!("wifi.stability_moderate").to_string(),
        Some(_) => t!("wifi.stability_unstable").to_string(),
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_tools_core::model::{
        WifiCurrentConnection, WifiSignalSample, WifiSignalStats, WifiStandard,
    };

    fn sample_tab() -> WifiTab {
        let mut tab = WifiTab::new();
        let connection = WifiCurrentConnection {
            interface: "wlan0".into(),
            ssid: "Home".into(),
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            signal_dbm: Some(-52),
            signal_quality: Some(96),
            channel: Some(36),
            frequency_mhz: Some(5_180),
            width_mhz: Some(80),
            band: WifiBand::Ghz5,
            security: WifiSecurity::Wpa3,
            standard: WifiStandard::Wifi6,
            rx_rate_mbps: Some(866.0),
            tx_rate_mbps: Some(780.0),
            ..WifiCurrentConnection::default()
        };
        tab.current = Some(WifiCurrentSnapshot {
            connection: Some(connection),
            history: vec![WifiSignalSample {
                elapsed_s: 1.0,
                signal_dbm: Some(-52),
                signal_quality: Some(96),
                rx_rate_mbps: Some(866.0),
                tx_rate_mbps: Some(780.0),
            }],
            stats: WifiSignalStats {
                samples: 1,
                min_signal_dbm: Some(-52),
                max_signal_dbm: Some(-52),
                average_signal_dbm: Some(-52.0),
                stddev_db: Some(0.0),
                average_rx_rate_mbps: Some(866.0),
                average_tx_rate_mbps: Some(780.0),
            },
            captured_at: "now".into(),
            warnings: Vec::new(),
        });
        let mut network = WifiNetwork::new("aa:bb:cc:dd:ee:ff");
        network.ssid = "Home".into();
        network.signal_dbm = Some(-52);
        network.signal_quality = Some(96);
        network.channel = Some(36);
        network.frequency_mhz = Some(5_180);
        network.width_mhz = Some(80);
        network.band = WifiBand::Ghz5;
        network.security = WifiSecurity::Wpa3;
        network.standard = WifiStandard::Wifi6;
        network.seen_scans = 2;
        network.is_current = true;
        let analysis = net_tools_core::net::wifi::analysis::analyze(
            std::slice::from_ref(&network),
            tab.current
                .as_ref()
                .and_then(|snapshot| snapshot.connection.as_ref()),
        );
        tab.scan = Some(WifiScanSnapshot {
            networks: vec![network],
            channel_usage: analysis.channel_usage,
            recommendations: analysis.recommendations,
            summary: analysis.summary,
            scan_count: 2,
            duration_ms: 0,
            captured_at: "now".into(),
            warnings: Vec::new(),
        });
        tab
    }

    #[test]
    fn wifi_diagnostics_are_localized() {
        let previous = rust_i18n::locale().to_string();
        rust_i18n::set_locale("zh-CN");
        let message = localize_wifi_text("WlanGetNetworkBssList failed with error 5");
        let hint = localize_wifi_text(
            "Windows denies Wi-Fi scanning when the executable runs from a network/UNC path such as \\wsl.localhost. Copy net-tools.exe to a local drive and run it there.",
        );
        rust_i18n::set_locale(&previous);
        assert!(message.contains("调用失败"), "message was {message}");
        assert!(hint.contains("UNC"), "hint was {hint}");
        assert!(hint.contains("本地磁盘"), "hint was {hint}");
    }

    #[test]
    fn csv_contains_network_rows() {
        let tab = sample_tab();
        let csv = tab.to_csv();
        assert!(csv.starts_with("section,item,key,value"));
        assert!(csv.contains("network,aa:bb:cc:dd:ee:ff,ssid,Home"));
    }

    #[test]
    fn every_view_renders_without_panic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut tab = sample_tab();
        let mut settings = WifiSettings::default();
        let ctx = egui::Context::default();
        for view in [WifiView::Overview, WifiView::Networks, WifiView::Channels] {
            tab.view = view;
            for _ in 0..3 {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::pos2(0.0, 0.0),
                        egui::vec2(1200.0, 800.0),
                    )),
                    ..Default::default()
                };
                ctx.run_ui(input, |ui| {
                    let _ = tab.ui(ui, &mut settings, runtime.handle(), true);
                })
                .textures_delta
                .clear();
            }
        }
    }
}
