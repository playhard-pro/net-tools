//! Network overview tab: local interfaces, addressing, routes, live counters
//! and the public egress address.

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use net_tools_core::net::overview::{
    self, InterfaceCounters, NetworkInterface, NetworkSnapshot, PublicEgress, PublicIp,
};
use rust_i18n::t;

use crate::tabs::speedtest::metric_card;
use crate::ui::common::{error_banner, result_toolbar, ToolbarAction};
use crate::ui::result_table::table_fixed_rows;
use crate::ui::theme::Palette;

/// History key used for the aggregate rate across all non-loopback interfaces.
const ALL_INTERFACES: &str = "__all__";

/// Number of rate samples kept for each chart.
const MAX_RATE_SAMPLES: usize = 120;

/// Default automatic refresh cadence.
const DEFAULT_INTERVAL_MS: u64 = 1000;

/// Minimum interval accepted by the interval control.
const MIN_INTERVAL_MS: u64 = 250;

/// Repaint cadence while a background request is outstanding.
const PENDING_REPAINT: Duration = Duration::from_millis(200);

/// Character budget for the interface name in the collapsed row.
const INTERFACE_NAME_PREVIEW_CHARS: usize = 16;

/// Minimum width for the label column in the public egress details grid.
const PUBLIC_IP_LABEL_COLUMN_WIDTH: f32 = 104.0;

/// Maximum initial body height of the route table, expressed in visible rows.
const ROUTE_VISIBLE_ROWS: usize = 14;

/// Minimum body height kept for the route table when few routes are present.
const ROUTE_MIN_VISIBLE_ROWS: usize = 6;

/// One computed rate sample.
#[derive(Debug, Clone, Copy, Default)]
struct RatePoint {
    /// Seconds since this tab started collecting samples.
    t: f64,
    rx_bytes: f64,
    tx_bytes: f64,
    rx_packets: f64,
    tx_packets: f64,
}

/// Tracks previous counters and turns successive snapshots into rates.
struct RateTracker {
    previous: BTreeMap<String, InterfaceCounters>,
    last_seen: Option<Instant>,
    started: Instant,
    latest: BTreeMap<String, RatePoint>,
    latest_all: RatePoint,
    history: BTreeMap<String, VecDeque<RatePoint>>,
    all_history: VecDeque<RatePoint>,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            previous: BTreeMap::new(),
            last_seen: None,
            started: Instant::now(),
            latest: BTreeMap::new(),
            latest_all: RatePoint::default(),
            history: BTreeMap::new(),
            all_history: VecDeque::new(),
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    /// Compute per-interface and aggregate rates from the new snapshot.
    ///
    /// The first snapshot only establishes a baseline because no elapsed time
    /// is known yet.
    fn update(&mut self, snapshot: &NetworkSnapshot) {
        let now = Instant::now();
        if let Some(last) = self.last_seen {
            let elapsed = now.duration_since(last).as_secs_f64().max(0.001);
            let t = self.started.elapsed().as_secs_f64();
            let mut all = RatePoint {
                t,
                ..RatePoint::default()
            };
            let mut latest = BTreeMap::new();

            for interface in &snapshot.interfaces {
                let previous = self
                    .previous
                    .get(&interface.name)
                    .copied()
                    .unwrap_or_default();
                let point = rate_point(t, elapsed, previous, interface.counters);
                latest.insert(interface.name.clone(), point);
                push_sample(&mut self.history, &interface.name, point);
                if !is_loopback(interface) {
                    all.rx_bytes += point.rx_bytes;
                    all.tx_bytes += point.tx_bytes;
                    all.rx_packets += point.rx_packets;
                    all.tx_packets += point.tx_packets;
                }
            }

            self.latest = latest;
            self.latest_all = all;
            self.all_history.push_back(all);
            trim_history(&mut self.all_history);
        }

        self.previous = snapshot
            .interfaces
            .iter()
            .map(|interface| (interface.name.clone(), interface.counters))
            .collect();
        self.last_seen = Some(now);
    }
}

fn rate_point(
    t: f64,
    elapsed: f64,
    previous: InterfaceCounters,
    current: InterfaceCounters,
) -> RatePoint {
    let delta = |current: u64, previous: u64| current.saturating_sub(previous) as f64 / elapsed;
    RatePoint {
        t,
        rx_bytes: delta(current.rx_bytes, previous.rx_bytes),
        tx_bytes: delta(current.tx_bytes, previous.tx_bytes),
        rx_packets: delta(current.rx_packets, previous.rx_packets),
        tx_packets: delta(current.tx_packets, previous.tx_packets),
    }
}

fn push_sample(history: &mut BTreeMap<String, VecDeque<RatePoint>>, key: &str, point: RatePoint) {
    let samples = history.entry(key.to_string()).or_default();
    samples.push_back(point);
    trim_history(samples);
}

fn trim_history(samples: &mut VecDeque<RatePoint>) {
    while samples.len() > MAX_RATE_SAMPLES {
        samples.pop_front();
    }
}

/// Loopback traffic is excluded from the aggregate rate so the chart reflects
/// real link usage rather than local IPC traffic.
fn is_loopback(interface: &NetworkInterface) -> bool {
    matches!(interface.name.as_str(), "lo" | "lo0")
        || interface
            .ipv4
            .iter()
            .any(|address| address.starts_with("127."))
        || interface
            .ipv6
            .iter()
            .any(|address| address.starts_with("::1/"))
}

pub struct OverviewTab {
    snapshot: Option<NetworkSnapshot>,
    error: Option<String>,
    pending_snapshot: Option<Receiver<Result<NetworkSnapshot, String>>>,
    last_refresh: Option<Instant>,
    auto_refresh: bool,
    interval_ms: u64,
    tracker: RateTracker,
    /// Interface name, or [`ALL_INTERFACES`] for the aggregate chart.
    selected_interface: Option<String>,
    public_egress: Option<PublicEgress>,
    public_ip_error: Option<String>,
    pending_public_ip: Option<Receiver<PublicEgress>>,
}

impl Default for OverviewTab {
    fn default() -> Self {
        Self::new()
    }
}

impl OverviewTab {
    pub fn new() -> Self {
        Self {
            snapshot: None,
            error: None,
            pending_snapshot: None,
            last_refresh: None,
            auto_refresh: true,
            interval_ms: DEFAULT_INTERVAL_MS,
            tracker: RateTracker::new(),
            selected_interface: None,
            public_egress: None,
            public_ip_error: None,
            pending_public_ip: None,
        }
    }

    /// Render the tab and return the shared settings-panel state unchanged.
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        self.poll_snapshot();
        self.poll_public_ip();

        if self.snapshot.is_none() && self.pending_snapshot.is_none() {
            self.request_refresh();
        }
        if self.public_egress.is_none()
            && self.public_ip_error.is_none()
            && self.pending_public_ip.is_none()
        {
            self.start_public_ip(rt);
        }

        let interval = Duration::from_millis(self.interval_ms.max(MIN_INTERVAL_MS));
        if self.auto_refresh
            && self.pending_snapshot.is_none()
            && self
                .last_refresh
                .is_some_and(|last| last.elapsed() >= interval)
        {
            self.request_refresh();
        }

        if self.auto_refresh || self.pending_snapshot.is_some() || self.pending_public_ip.is_some()
        {
            ui.ctx().request_repaint_after(
                if self.pending_snapshot.is_some() || self.pending_public_ip.is_some() {
                    PENDING_REPAINT
                } else {
                    interval
                },
            );
        }

        crate::ui::layout::results_panel(ui, |ui| {
            self.toolbar(ui);
            if let Some(error) = &self.error {
                error_banner(ui, error, None);
            }
            let snapshot = self.snapshot.clone();
            if let Some(snapshot) = snapshot {
                self.content(ui, &snapshot, rt);
            } else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.weak(t!("overview.loading"));
                });
            }
        });

        settings_expanded
    }

    /// Start a background snapshot collection so a slow platform command does
    /// not block the UI thread.
    fn request_refresh(&mut self) {
        if self.pending_snapshot.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.pending_snapshot = Some(rx);
        self.last_refresh = Some(Instant::now());
        std::thread::spawn(move || {
            let _ = tx.send(overview::collect());
        });
    }

    fn poll_snapshot(&mut self) {
        let received = self.pending_snapshot.as_ref().map(Receiver::try_recv);
        match received {
            Some(Ok(Ok(snapshot))) => {
                self.pending_snapshot = None;
                self.error = None;
                self.ensure_selection(&snapshot);
                self.tracker.update(&snapshot);
                self.snapshot = Some(snapshot);
            }
            Some(Ok(Err(error))) => {
                self.pending_snapshot = None;
                self.error = Some(error);
            }
            Some(Err(TryRecvError::Empty)) => {}
            Some(Err(TryRecvError::Disconnected)) => {
                self.pending_snapshot = None;
                self.error = Some(t!("overview.collect_failed").to_string());
            }
            None => {}
        }
    }

    /// Keep the chart selection valid when interfaces disappear.
    fn ensure_selection(&mut self, snapshot: &NetworkSnapshot) {
        let valid = self.selected_interface.as_deref().is_some_and(|selected| {
            selected == ALL_INTERFACES
                || snapshot
                    .interfaces
                    .iter()
                    .any(|interface| interface.name == selected)
        });
        if !valid {
            self.selected_interface = Some(
                snapshot
                    .interfaces
                    .iter()
                    .find(|interface| interface.up && !is_loopback(interface))
                    .or_else(|| snapshot.interfaces.first())
                    .map(|interface| interface.name.clone())
                    .unwrap_or_else(|| ALL_INTERFACES.to_string()),
            );
        }
    }

    fn start_public_ip(&mut self, rt: &tokio::runtime::Handle) {
        if self.pending_public_ip.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.pending_public_ip = Some(rx);
        self.public_ip_error = None;
        rt.spawn(async move {
            let result = overview::public_egress(Duration::from_secs(10)).await;
            let _ = tx.send(result);
        });
    }

    fn poll_public_ip(&mut self) {
        let received = self.pending_public_ip.as_ref().map(Receiver::try_recv);
        match received {
            Some(Ok(public_egress)) => {
                self.pending_public_ip = None;
                self.public_egress = Some(public_egress);
                self.public_ip_error = None;
            }
            Some(Err(TryRecvError::Empty)) => {}
            Some(Err(TryRecvError::Disconnected)) => {
                self.pending_public_ip = None;
                self.public_ip_error = Some(t!("overview.public_ip_failed").to_string());
            }
            None => {}
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button(t!("overview.refresh")).clicked() {
                self.request_refresh();
            }
            ui.checkbox(&mut self.auto_refresh, t!("overview.auto_refresh"));
            ui.add(
                egui::DragValue::new(&mut self.interval_ms)
                    .range(MIN_INTERVAL_MS..=60_000)
                    .suffix(" ms"),
            )
            .on_hover_text(t!("overview.refresh_interval"));
            ui.separator();
            match result_toolbar(ui) {
                ToolbarAction::Copy => ui.ctx().copy_text(self.to_text()),
                ToolbarAction::ExportCsv => {
                    crate::ui::export::save_file("network-overview", "csv", &self.to_csv())
                }
                ToolbarAction::ExportJson => {
                    crate::ui::export::save_file("network-overview", "json", &self.to_json())
                }
                ToolbarAction::ExportHtml => {
                    crate::ui::export::save_file("network-overview", "html", &self.to_html())
                }
                ToolbarAction::Clear => {
                    self.tracker.reset();
                    self.public_egress = None;
                    self.public_ip_error = None;
                    self.request_refresh();
                }
                ToolbarAction::None => {}
            }
        });

        if let Some(snapshot) = &self.snapshot {
            ui.weak(format!(
                "{} {}",
                t!("overview.captured"),
                snapshot.captured_at
            ));
        }
    }

    fn content(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &NetworkSnapshot,
        rt: &tokio::runtime::Handle,
    ) {
        egui::ScrollArea::vertical()
            .id_salt("network_overview_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.columns(2, |columns| {
                    // First column: local configuration, public egress and
                    // the routing table.
                    gateway_section(&mut columns[0], snapshot);
                    dns_section(&mut columns[0], snapshot);
                    self.public_egress_ui(&mut columns[0], rt);
                    section_heading(&mut columns[0], &t!("overview.routes"));
                    routes_table(&mut columns[0], snapshot);

                    // Second column: live rates followed by the interfaces.
                    self.rates_ui(&mut columns[1], snapshot, true);
                    section_heading(&mut columns[1], &t!("overview.interfaces"));
                    interfaces_list(&mut columns[1], snapshot);
                });
            });
    }

    fn rates_ui(&mut self, ui: &mut egui::Ui, snapshot: &NetworkSnapshot, stack_charts: bool) {
        section_heading(ui, &t!("overview.live_rates"));

        let mut options: Vec<(String, String)> = vec![(
            ALL_INTERFACES.to_string(),
            t!("overview.all_interfaces").to_string(),
        )];
        options.extend(
            snapshot
                .interfaces
                .iter()
                .map(|interface| (interface.name.clone(), interface.name.clone())),
        );
        let selected = self
            .selected_interface
            .clone()
            .unwrap_or_else(|| ALL_INTERFACES.to_string());
        let selected_text = options
            .iter()
            .find(|(value, _)| *value == selected)
            .map(|(_, label)| label.clone())
            .unwrap_or_else(|| selected.clone());

        let mut chosen = selected.clone();
        let combo = egui::ComboBox::from_id_salt("overview_rate_interface")
            .selected_text(preview_interface_name(&selected_text))
            .width((ui.available_width() - 4.0).max(120.0))
            .show_ui(ui, |ui| {
                for (value, label) in &options {
                    ui.selectable_value(&mut chosen, value.clone(), preview_interface_name(label))
                        .on_hover_text(label);
                }
            });
        combo.response.on_hover_text(&selected_text);
        if chosen != selected {
            self.selected_interface = Some(chosen.clone());
        }

        let empty = VecDeque::new();
        let history = match chosen.as_str() {
            ALL_INTERFACES => &self.tracker.all_history,
            name => self.tracker.history.get(name).unwrap_or(&empty),
        };
        let rate = match chosen.as_str() {
            ALL_INTERFACES => self.tracker.latest_all,
            name => self.tracker.latest.get(name).copied().unwrap_or_default(),
        };

        ui.columns(2, |columns| {
            metric_card(
                &mut columns[0],
                t!("overview.rx_bytes"),
                &format_bytes_rate(rate.rx_bytes),
            );
            metric_card(
                &mut columns[1],
                t!("overview.tx_bytes"),
                &format_bytes_rate(rate.tx_bytes),
            );
        });
        ui.columns(2, |columns| {
            metric_card(
                &mut columns[0],
                t!("overview.rx_packets"),
                &format_packet_rate(rate.rx_packets),
            );
            metric_card(
                &mut columns[1],
                t!("overview.tx_packets"),
                &format_packet_rate(rate.tx_packets),
            );
        });

        let rx_bytes: Vec<[f64; 2]> = history.iter().map(|p| [p.t, p.rx_bytes]).collect();
        let tx_bytes: Vec<[f64; 2]> = history.iter().map(|p| [p.t, p.tx_bytes]).collect();
        let rx_packets: Vec<[f64; 2]> = history.iter().map(|p| [p.t, p.rx_packets]).collect();
        let tx_packets: Vec<[f64; 2]> = history.iter().map(|p| [p.t, p.tx_packets]).collect();

        if stack_charts {
            crate::ui::chart::network_rate_chart(
                ui,
                "overview_bytes_chart",
                &rx_bytes,
                &tx_bytes,
                150.0,
                t!("overview.bytes_per_second").as_ref(),
            );
            ui.add_space(6.0);
            crate::ui::chart::network_rate_chart(
                ui,
                "overview_packets_chart",
                &rx_packets,
                &tx_packets,
                150.0,
                t!("overview.packets_per_second").as_ref(),
            );
        } else {
            ui.columns(2, |columns| {
                crate::ui::chart::network_rate_chart(
                    &mut columns[0],
                    "overview_bytes_chart",
                    &rx_bytes,
                    &tx_bytes,
                    150.0,
                    t!("overview.bytes_per_second").as_ref(),
                );
                crate::ui::chart::network_rate_chart(
                    &mut columns[1],
                    "overview_packets_chart",
                    &rx_packets,
                    &tx_packets,
                    150.0,
                    t!("overview.packets_per_second").as_ref(),
                );
            });
        }
    }

    fn public_egress_ui(&mut self, ui: &mut egui::Ui, rt: &tokio::runtime::Handle) {
        ui.horizontal(|ui| {
            ui.heading(t!("overview.public_egress"));
            if ui.small_button(t!("overview.refresh")).clicked() {
                self.start_public_ip(rt);
            }
            if self.pending_public_ip.is_some() {
                ui.spinner();
            }
        });
        ui.add_space(2.0);

        if let Some(egress) = &self.public_egress {
            public_ip_card(ui, "IPv4", egress.ipv4.as_ref());
            ui.add_space(4.0);
            public_ip_card(ui, "IPv6", egress.ipv6.as_ref());
            if !egress.errors.is_empty() {
                let palette = Palette::from_ui(ui);
                for error in &egress.errors {
                    ui.colored_label(palette.warning_text, error);
                }
            }
        } else if let Some(error) = &self.public_ip_error {
            let palette = Palette::from_ui(ui);
            ui.colored_label(palette.error_text, error);
            if ui.button(t!("overview.retry")).clicked() {
                self.start_public_ip(rt);
            }
        } else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak(t!("overview.public_ip_loading"));
            });
        }
    }

    /// Human-readable text used by the copy action.
    pub fn to_text(&self) -> String {
        let Some(snapshot) = &self.snapshot else {
            return String::new();
        };
        let mut out = String::new();
        out.push_str(&format!(
            "{} {}\n\n{}\n",
            t!("overview.captured"),
            snapshot.captured_at,
            t!("overview.interfaces")
        ));
        for interface in &snapshot.interfaces {
            out.push_str(&format!(
                "{}  {}  {}  MTU {}  {}  RX {}  TX {}\n",
                interface.name,
                if interface.up {
                    t!("overview.up")
                } else {
                    t!("overview.down")
                },
                interface.mac.as_deref().unwrap_or("-"),
                interface
                    .mtu
                    .map(|mtu| mtu.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                format_link_speed(interface.link_speed_bps),
                format_bytes_rate(
                    self.tracker
                        .latest
                        .get(&interface.name)
                        .map(|rate| rate.rx_bytes)
                        .unwrap_or(0.0)
                ),
                format_bytes_rate(
                    self.tracker
                        .latest
                        .get(&interface.name)
                        .map(|rate| rate.tx_bytes)
                        .unwrap_or(0.0)
                ),
            ));
            if !interface.ipv4.is_empty() {
                out.push_str(&format!("  IPv4: {}\n", interface.ipv4.join(", ")));
            }
            if !interface.ipv6.is_empty() {
                out.push_str(&format!("  IPv6: {}\n", interface.ipv6.join(", ")));
            }
        }

        out.push_str(&format!("\n{}\n", t!("overview.default_gateway")));
        for gateway in &snapshot.default_gateways {
            out.push_str(&format!(
                "{}  {}  {}  metric {}\n",
                gateway.family,
                gateway.gateway,
                gateway.interface,
                gateway
                    .metric
                    .map(|metric| metric.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ));
        }
        out.push_str(&format!("\n{}\n", t!("overview.dns_servers")));
        for server in &snapshot.dns_servers {
            out.push_str(&format!("{server}\n"));
        }

        out.push_str(&format!("\n{}\n", t!("overview.routes")));
        for route in &snapshot.routes {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\tmetric {}\n",
                route.family,
                route.destination,
                route.gateway,
                route.interface,
                route
                    .metric
                    .map(|metric| metric.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ));
        }

        if let Some(egress) = &self.public_egress {
            out.push_str(&format!("\n{}\n", t!("overview.public_egress")));
            for (family, public_ip) in [
                ("IPv4", egress.ipv4.as_ref()),
                ("IPv6", egress.ipv6.as_ref()),
            ] {
                match public_ip {
                    Some(public_ip) => {
                        out.push_str(&format!("{family}\n"));
                        for (key, value) in public_ip_fields(public_ip) {
                            out.push_str(&format!("  {key}: {value}\n"));
                        }
                    }
                    None => out.push_str(&format!("{family}: {}\n", t!("overview.unavailable"))),
                }
            }
            for error in &egress.errors {
                out.push_str(&format!("{error}\n"));
            }
        }
        out
    }

    pub fn to_csv(&self) -> String {
        let mut out = String::from("section,item,key,value\n");
        let Some(snapshot) = &self.snapshot else {
            return out;
        };
        for interface in &snapshot.interfaces {
            let item = interface.name.as_str();
            csv_row(&mut out, "interface", item, "name", item);
            csv_row(
                &mut out,
                "interface",
                item,
                "status",
                if interface.up { "up" } else { "down" },
            );
            csv_row(
                &mut out,
                "interface",
                item,
                "mac",
                interface.mac.as_deref().unwrap_or("-"),
            );
            csv_row(
                &mut out,
                "interface",
                item,
                "ipv4",
                &interface.ipv4.join(" "),
            );
            csv_row(
                &mut out,
                "interface",
                item,
                "ipv6",
                &interface.ipv6.join(" "),
            );
            csv_row(
                &mut out,
                "interface",
                item,
                "mtu",
                &interface
                    .mtu
                    .map(|mtu| mtu.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            csv_row(
                &mut out,
                "interface",
                item,
                "link_speed",
                &format_link_speed(interface.link_speed_bps),
            );
            if let Some(rate) = self.tracker.latest.get(item) {
                csv_row(
                    &mut out,
                    "interface",
                    item,
                    "rx_rate",
                    &format_bytes_rate(rate.rx_bytes),
                );
                csv_row(
                    &mut out,
                    "interface",
                    item,
                    "tx_rate",
                    &format_bytes_rate(rate.tx_bytes),
                );
            }
        }

        for gateway in &snapshot.default_gateways {
            csv_row(
                &mut out,
                "gateway",
                &gateway.family,
                "gateway",
                &gateway.gateway,
            );
            csv_row(
                &mut out,
                "gateway",
                &gateway.family,
                "interface",
                &gateway.interface,
            );
            csv_row(
                &mut out,
                "gateway",
                &gateway.family,
                "metric",
                &gateway
                    .metric
                    .map(|metric| metric.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
        }

        for (index, server) in snapshot.dns_servers.iter().enumerate() {
            csv_row(&mut out, "dns", &index.to_string(), "server", server);
        }

        for route in &snapshot.routes {
            let item = format!("{} {}", route.family, route.destination);
            csv_row(&mut out, "route", &item, "gateway", &route.gateway);
            csv_row(&mut out, "route", &item, "interface", &route.interface);
            csv_row(
                &mut out,
                "route",
                &item,
                "metric",
                &route
                    .metric
                    .map(|metric| metric.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
        }

        if let Some(egress) = &self.public_egress {
            for (family, public_ip) in [
                ("IPv4", egress.ipv4.as_ref()),
                ("IPv6", egress.ipv6.as_ref()),
            ] {
                if let Some(public_ip) = public_ip {
                    for (key, value) in public_ip_fields(public_ip) {
                        csv_row(&mut out, "public_ip", family, key, &value);
                    }
                }
            }
            for error in &egress.errors {
                csv_row(&mut out, "public_ip", "error", "message", error);
            }
        }
        out
    }

    pub fn to_json(&self) -> String {
        let value = serde_json::json!({
            "snapshot": self.snapshot,
            "public_egress": self.public_egress,
        });
        serde_json::to_string_pretty(&value).unwrap_or_default()
    }

    pub fn to_html(&self) -> String {
        crate::ui::export::csv_to_html(&self.to_csv())
    }
}

/// Render one public address family as a compact information card.
fn public_ip_card(ui: &mut egui::Ui, family: &str, entry: Option<&PublicIp>) {
    let palette = Palette::from_ui(ui);
    egui::Frame::new()
        .fill(palette.card_bg)
        .corner_radius(6.0)
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
            ui.horizontal(|ui| {
                ui.strong(family);
                if let Some(public_ip) = entry {
                    ui.monospace(egui::RichText::new(&public_ip.address).strong().size(16.0));
                    crate::ui::common::copy_button(ui, &public_ip.address);
                } else {
                    ui.weak(t!("overview.unavailable"));
                }
            });

            let Some(public_ip) = entry else {
                return;
            };

            let mut rows: Vec<(String, String)> = Vec::new();
            if let Some(value) = joined([
                public_ip.country_code.as_deref(),
                public_ip.country.as_deref(),
            ]) {
                rows.push((t!("overview.country").to_string(), value));
            }
            if let Some(value) = joined([
                public_ip.region_code.as_deref(),
                public_ip.region.as_deref(),
            ]) {
                rows.push((t!("overview.region").to_string(), value));
            }
            if let Some(value) = &public_ip.city {
                rows.push((t!("overview.city").to_string(), value.clone()));
            }
            if let Some(value) = &public_ip.postal_code {
                rows.push((t!("overview.postal_code").to_string(), value.clone()));
            }
            if let Some(value) = &public_ip.continent_code {
                rows.push((t!("overview.continent").to_string(), value.clone()));
            }
            if let (Some(latitude), Some(longitude)) = (public_ip.latitude, public_ip.longitude) {
                rows.push((
                    t!("overview.coordinates").to_string(),
                    format!("{latitude:.4}, {longitude:.4}"),
                ));
            }
            if let Some(timezone) = &public_ip.timezone {
                let value = match public_ip.offset {
                    Some(offset) => format!("{timezone} ({})", format_offset(offset)),
                    None => timezone.clone(),
                };
                rows.push((t!("overview.timezone").to_string(), value));
            }
            if let Some(value) = joined([
                public_ip.asn.map(|asn| format!("AS{asn}")).as_deref(),
                public_ip.asn_organization.as_deref(),
            ]) {
                rows.push((t!("overview.asn").to_string(), value));
            }
            if let Some(value) = &public_ip.isp {
                rows.push((t!("overview.isp").to_string(), value.clone()));
            }
            if let Some(value) = &public_ip.organization {
                rows.push((t!("overview.organization").to_string(), value.clone()));
            }

            if !rows.is_empty() {
                ui.add_space(4.0);
                egui::Grid::new(format!("overview_public_ip_{family}"))
                    .num_columns(2)
                    .min_col_width(PUBLIC_IP_LABEL_COLUMN_WIDTH)
                    .spacing([8.0, 2.0])
                    .show(ui, |ui| {
                        for (label, value) in rows {
                            ui.weak(label);
                            ui.label(value);
                            ui.end_row();
                        }
                    });
            }
            ui.weak(format!(
                "{} {}",
                t!("overview.public_ip_source"),
                public_ip.source
            ));
        });
}

/// Join the non-empty parts with a middle dot, returning `None` when all parts
/// are missing.
fn joined<const N: usize>(parts: [Option<&str>; N]) -> Option<String> {
    let text = parts
        .into_iter()
        .flatten()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    (!text.is_empty()).then_some(text)
}

/// Format a UTC offset in seconds as `UTC+HH:MM`.
fn format_offset(seconds: i64) -> String {
    let sign = if seconds < 0 { '-' } else { '+' };
    let seconds = seconds.abs();
    format!(
        "UTC{sign}{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60
    )
}

/// Export fields in the same names the IP.SB response uses.
fn public_ip_fields(public_ip: &PublicIp) -> Vec<(&'static str, String)> {
    let mut fields = vec![("ip", public_ip.address.clone())];
    push_export_field(&mut fields, "country_code", &public_ip.country_code);
    push_export_field(&mut fields, "country", &public_ip.country);
    push_export_field(&mut fields, "region_code", &public_ip.region_code);
    push_export_field(&mut fields, "region", &public_ip.region);
    push_export_field(&mut fields, "city", &public_ip.city);
    push_export_field(&mut fields, "postal_code", &public_ip.postal_code);
    push_export_field(&mut fields, "continent_code", &public_ip.continent_code);
    if let Some(value) = public_ip.latitude {
        fields.push(("latitude", value.to_string()));
    }
    if let Some(value) = public_ip.longitude {
        fields.push(("longitude", value.to_string()));
    }
    push_export_field(&mut fields, "timezone", &public_ip.timezone);
    if let Some(value) = public_ip.offset {
        fields.push(("offset", value.to_string()));
    }
    if let Some(value) = public_ip.asn {
        fields.push(("asn", value.to_string()));
    }
    push_export_field(&mut fields, "asn_organization", &public_ip.asn_organization);
    push_export_field(&mut fields, "isp", &public_ip.isp);
    push_export_field(&mut fields, "organization", &public_ip.organization);
    push_export_field(&mut fields, "source", &Some(public_ip.source.clone()));
    fields
}

fn push_export_field(
    fields: &mut Vec<(&'static str, String)>,
    key: &'static str,
    value: &Option<String>,
) {
    if let Some(value) = value.as_deref().filter(|value| !value.trim().is_empty()) {
        fields.push((key, value.to_string()));
    }
}

/// Compact default-gateway summary used by both dashboard layouts.
fn gateway_section(ui: &mut egui::Ui, snapshot: &NetworkSnapshot) {
    section_heading(ui, &t!("overview.default_gateway"));
    if snapshot.default_gateways.is_empty() {
        ui.weak(t!("overview.none"));
        return;
    }
    for gateway in &snapshot.default_gateways {
        ui.horizontal(|ui| {
            ui.label(&gateway.family);
            ui.monospace(&gateway.gateway);
        });
        ui.weak(format!(
            "{} · {} {}",
            gateway.interface,
            t!("overview.metric"),
            gateway
                .metric
                .map(|metric| metric.to_string())
                .unwrap_or_else(|| "-".to_string())
        ));
    }
}

/// Compact DNS server summary used by both dashboard layouts.
fn dns_section(ui: &mut egui::Ui, snapshot: &NetworkSnapshot) {
    section_heading(ui, &t!("overview.dns_servers"));
    if snapshot.dns_servers.is_empty() {
        ui.weak(t!("overview.none"));
        return;
    }
    for server in &snapshot.dns_servers {
        ui.monospace(server);
    }
}

fn interfaces_list(ui: &mut egui::Ui, snapshot: &NetworkSnapshot) {
    if snapshot.interfaces.is_empty() {
        ui.weak(t!("overview.none"));
        return;
    }
    let palette = Palette::from_ui(ui);
    for interface in &snapshot.interfaces {
        egui::Frame::new()
            .fill(palette.card_bg)
            .corner_radius(6.0)
            .inner_margin(egui::Margin::symmetric(8, 4))
            .show(ui, |ui| {
                let id = ui.make_persistent_id(("overview_interface", &interface.name));
                egui::collapsing_header::CollapsingState::load_with_default_open(
                    ui.ctx(),
                    id,
                    false,
                )
                .show_header(ui, |ui| {
                    ui.monospace(
                        egui::RichText::new(preview_interface_name(&interface.name)).strong(),
                    )
                    .on_hover_text(&interface.name);
                    status_label(ui, interface.up);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.monospace(format_link_speed(interface.link_speed_bps));
                    });
                })
                .body(|ui| interface_details(ui, interface));
            });
        ui.add_space(4.0);
    }
}

/// Keep long interface names readable in the narrow column. The full name is
/// shown in the tooltip and as the first line of the expanded details.
fn preview_interface_name(name: &str) -> String {
    let mut characters = name.chars();
    let preview: String = characters
        .by_ref()
        .take(INTERFACE_NAME_PREVIEW_CHARS)
        .collect();
    if characters.next().is_some() {
        format!("{preview}...")
    } else {
        name.to_string()
    }
}

/// Expanded interface details: link-layer address, MTU and every assigned
/// address on its own line.
fn interface_details(ui: &mut egui::Ui, interface: &NetworkInterface) {
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
    egui::Grid::new(("overview_interface_details", &interface.name))
        .num_columns(2)
        .spacing([10.0, 2.0])
        .show(ui, |ui| {
            ui.weak(t!("overview.name"));
            ui.monospace(&interface.name);
            ui.end_row();

            ui.weak(t!("overview.mac"));
            ui.monospace(interface.mac.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.weak(t!("overview.mtu"));
            ui.monospace(
                interface
                    .mtu
                    .map(|mtu| mtu.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.weak(t!("overview.ipv4"));
            addresses_cell(ui, &interface.ipv4);
            ui.end_row();

            ui.weak(t!("overview.ipv6"));
            addresses_cell(ui, &interface.ipv6);
            ui.end_row();
        });
}

/// Render one address per line, or a dash when the list is empty.
fn addresses_cell(ui: &mut egui::Ui, addresses: &[String]) {
    if addresses.is_empty() {
        ui.monospace("-");
        return;
    }
    ui.vertical(|ui| {
        for address in addresses {
            ui.monospace(address);
        }
    });
}

fn routes_table(ui: &mut egui::Ui, snapshot: &NetworkSnapshot) {
    let headers = [
        t!("overview.family").to_string(),
        t!("overview.destination").to_string(),
        t!("overview.gateway").to_string(),
        t!("overview.interface").to_string(),
        t!("overview.metric").to_string(),
    ];
    let visible_rows = snapshot
        .routes
        .len()
        .clamp(ROUTE_MIN_VISIBLE_ROWS, ROUTE_VISIBLE_ROWS);
    table_fixed_rows(
        ui,
        &headers,
        snapshot.routes.len(),
        visible_rows,
        |index, row| {
            let Some(route) = snapshot.routes.get(index) else {
                return;
            };
            row.col(|ui| {
                ui.label(&route.family);
            });
            row.col(|ui| {
                ui.monospace(&route.destination);
            });
            row.col(|ui| {
                ui.monospace(&route.gateway);
            });
            row.col(|ui| {
                ui.label(&route.interface);
            });
            row.col(|ui| {
                ui.monospace(
                    route
                        .metric
                        .map(|metric| metric.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                );
            });
        },
    );
}

fn status_label(ui: &mut egui::Ui, up: bool) {
    let palette = Palette::from_ui(ui);
    let (color, text) = if up {
        (palette.success_text, t!("overview.up"))
    } else {
        (palette.error_text, t!("overview.down"))
    };
    ui.colored_label(color, text);
}

fn section_heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(6.0);
    ui.heading(text);
    ui.add_space(2.0);
}

/// Format a bits-per-second link speed using decimal units.
fn format_link_speed(bits_per_second: Option<u64>) -> String {
    let Some(value) = bits_per_second else {
        return "-".to_string();
    };
    let value = value as f64;
    if value >= 1_000_000_000.0 {
        format!("{:.1} Gbps", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.0} Mbps", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.0} Kbps", value / 1_000.0)
    } else {
        format!("{value:.0} bps")
    }
}

/// Format a byte rate using decimal units.
fn format_bytes_rate(bytes_per_second: f64) -> String {
    let value = bytes_per_second.max(0.0);
    if value >= 1_000_000_000.0 {
        format!("{:.2} GB/s", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.2} MB/s", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1} KB/s", value / 1_000.0)
    } else {
        format!("{value:.0} B/s")
    }
}

/// Format a packet rate with decimal units.
fn format_packet_rate(packets_per_second: f64) -> String {
    let value = packets_per_second.max(0.0);
    if value >= 1_000_000.0 {
        format!("{:.2} Mpps", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1} Kpps", value / 1_000.0)
    } else {
        format!("{value:.0} pps")
    }
}

fn csv_row(out: &mut String, section: &str, item: &str, key: &str, value: &str) {
    out.push_str(&format!(
        "{},{},{},{}\n",
        crate::ui::export::csv_field(section),
        crate::ui::export::csv_field(item),
        crate::ui::export::csv_field(key),
        crate::ui::export::csv_field(value),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_tools_core::net::overview::InterfaceCounters;

    #[test]
    fn ui_handles_narrow_and_wide_windows() {
        use net_tools_core::net::overview::{DefaultGateway, NetworkRoute};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut tab = OverviewTab::new();
        tab.snapshot = Some(NetworkSnapshot {
            captured_at: "now".into(),
            interfaces: vec![NetworkInterface {
                name: "a-very-long-interface-name-for-layout".into(),
                mac: Some("00:11:22:33:44:55".into()),
                ipv4: vec!["192.0.2.10/24".into()],
                ipv6: vec!["2001:db8::1/64".into()],
                mtu: Some(1500),
                link_speed_bps: Some(1_000_000_000),
                up: true,
                counters: InterfaceCounters::default(),
            }],
            default_gateways: vec![DefaultGateway {
                family: "IPv4".into(),
                gateway: "192.0.2.1".into(),
                interface: "a-very-long-interface-name-for-layout".into(),
                metric: Some(1),
            }],
            dns_servers: vec!["1.1.1.1".into()],
            routes: vec![NetworkRoute {
                family: "IPv4".into(),
                destination: "default".into(),
                gateway: "192.0.2.1".into(),
                interface: "a-very-long-interface-name-for-layout".into(),
                metric: Some(1),
            }],
        });
        tab.public_egress = Some(PublicEgress::default());
        tab.selected_interface = Some(ALL_INTERFACES.to_string());

        for width in [1.0, 120.0, 320.0, 960.0, 1400.0] {
            let ctx = egui::Context::default();
            for _ in 0..4 {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::pos2(0.0, 0.0),
                        egui::vec2(width, 700.0),
                    )),
                    ..Default::default()
                };
                ctx.run_ui(input, |ui| {
                    egui::CentralPanel::default().show(ui, |ui| {
                        tab.ui(ui, runtime.handle(), true);
                    });
                })
                .textures_delta
                .clear();
            }
        }
    }

    #[test]
    fn rate_point_divides_counter_delta_by_elapsed_time() {
        let previous = InterfaceCounters {
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
        };
        let current = InterfaceCounters {
            rx_bytes: 3000,
            tx_bytes: 6000,
            rx_packets: 30,
            tx_packets: 60,
        };
        let point = rate_point(1.0, 2.0, previous, current);
        assert_eq!(point.rx_bytes, 1000.0);
        assert_eq!(point.tx_bytes, 2000.0);
        assert_eq!(point.rx_packets, 10.0);
        assert_eq!(point.tx_packets, 20.0);
    }

    #[test]
    fn counter_reset_does_not_underflow() {
        let point = rate_point(
            1.0,
            1.0,
            InterfaceCounters {
                rx_bytes: 100,
                ..InterfaceCounters::default()
            },
            InterfaceCounters::default(),
        );
        assert_eq!(point.rx_bytes, 0.0);
    }

    #[test]
    fn interface_names_are_truncated_for_the_collapsed_row() {
        assert_eq!(preview_interface_name("eth0"), "eth0");
        let long = "a".repeat(INTERFACE_NAME_PREVIEW_CHARS + 1);
        let preview = preview_interface_name(&long);
        assert!(preview.ends_with("..."));
        assert_eq!(
            preview.trim_end_matches('.').chars().count(),
            INTERFACE_NAME_PREVIEW_CHARS
        );
    }

    #[test]
    fn rate_formatting_uses_decimal_units() {
        assert_eq!(format_bytes_rate(1_500.0), "1.5 KB/s");
        assert_eq!(format_packet_rate(2_500.0), "2.5 Kpps");
        assert_eq!(format_link_speed(Some(1_000_000_000)), "1.0 Gbps");
        assert_eq!(format_link_speed(None), "-");
    }
}
