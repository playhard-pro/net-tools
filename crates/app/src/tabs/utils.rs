//! Utils tab: subnet calculator, Wake-on-LAN, port reference, MAC vendor
//! lookup and timestamp conversion.

use std::collections::HashMap;

use eframe::egui;
use net_tools_core::config::{InputHistory, UtilsSettings};
use net_tools_core::control::TaskController;
use net_tools_core::model::{
    MacVendorResult, MacVendorSource, PortReferenceView, PortTransportFilter, ProbeEvent,
    TimestampUnit, UtilsTool, WolResult,
};
use net_tools_core::net::{mac_vendor, wol};
use net_tools_core::utils::{port_reference, subnet, time_convert};
use rust_i18n::t;

use crate::ui::common::{copy_button, error_banner, state_badge};
use crate::ui::history_input;
use crate::ui::result_table::table;
use crate::ui::theme::Palette;

const SUBNET_HISTORY_KEY: &str = "utils.subnet.input";
const WOL_MAC_HISTORY_KEY: &str = "utils.wol.mac";
const WOL_BROADCAST_HISTORY_KEY: &str = "utils.wol.broadcast";
const MAC_HISTORY_KEY: &str = "utils.mac.mac";
const TIMESTAMP_HISTORY_KEY: &str = "utils.timestamp.input";

const MAC_ONLINE_TIMEOUT_MS: u64 = 10_000;
const MAX_TARGET_ZONES: usize = 8;

/// Cached filter inputs for the port reference table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PortFilterKey {
    query: String,
    transport: PortTransportFilter,
    view: PortReferenceView,
}

/// State owned by the Utils tab.
pub struct UtilsTab {
    wol_ctrl: TaskController<ProbeEvent>,
    mac_ctrl: TaskController<ProbeEvent>,
    wol_result: Option<WolResult>,
    wol_error: Option<(String, Option<String>)>,
    wol_notice: Option<String>,
    mac_result: Option<MacVendorResult>,
    mac_error: Option<(String, Option<String>)>,
    mac_notice: Option<String>,
    mac_cache: HashMap<String, MacVendorResult>,
    broadcasts: Vec<wol::LocalBroadcast>,
    port_matches: Vec<usize>,
    protocol_matches: Vec<usize>,
    port_filter_key: Option<PortFilterKey>,
    source_zone_search: String,
    target_zone_search: String,
    /// Whether this tab is currently rendered.
    visible: bool,
}

impl Default for UtilsTab {
    fn default() -> Self {
        Self::new()
    }
}

impl UtilsTab {
    pub fn new() -> Self {
        let mut tab = Self {
            wol_ctrl: TaskController::new(),
            mac_ctrl: TaskController::new(),
            wol_result: None,
            wol_error: None,
            wol_notice: None,
            mac_result: None,
            mac_error: None,
            mac_notice: None,
            mac_cache: HashMap::new(),
            broadcasts: wol::local_broadcasts(),
            port_matches: Vec::new(),
            protocol_matches: Vec::new(),
            port_filter_key: None,
            source_zone_search: String::new(),
            target_zone_search: String::new(),
            visible: false,
        };
        tab.refresh_port_filters("", PortTransportFilter::All, PortReferenceView::Ports);
        tab
    }

    /// Stop background tasks and drop live results when another tab is
    /// selected. Inputs stay in the configuration.
    pub fn clear_on_hide(&mut self) {
        self.visible = false;
        for ctrl in [&mut self.wol_ctrl, &mut self.mac_ctrl] {
            if ctrl.is_active() {
                ctrl.stop();
            }
            let _ = ctrl.drain();
        }
        self.wol_result = None;
        self.wol_error = None;
        self.wol_notice = None;
        self.mac_result = None;
        self.mac_error = None;
        self.mac_notice = None;
    }

    /// Render the Utils tab and return the shared settings expansion state.
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut UtilsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        self.drain_events();
        self.visible = true;
        if self.wol_ctrl.is_active() || self.mac_ctrl.is_active() {
            ui.ctx().request_repaint();
        }

        self.tool_selector(ui, settings);
        match settings.active_tool {
            UtilsTool::Subnet => self.subnet_ui(ui, settings, history, settings_expanded),
            UtilsTool::Wol => self.wol_ui(ui, settings, history, rt, settings_expanded),
            UtilsTool::PortReference => self.port_reference_ui(ui, settings, settings_expanded),
            UtilsTool::MacVendor => {
                self.mac_vendor_ui(ui, settings, history, rt, settings_expanded)
            }
            UtilsTool::Timestamp => self.timestamp_ui(ui, settings, history, settings_expanded),
        }
    }

    fn drain_events(&mut self) {
        for event in self.wol_ctrl.drain() {
            if !self.visible {
                continue;
            }
            match event {
                ProbeEvent::Wol(result) => {
                    self.wol_result = Some(result);
                    self.wol_error = None;
                    self.wol_notice = None;
                }
                ProbeEvent::Error { message, hint } => {
                    self.wol_error = Some((message, hint));
                    self.wol_result = None;
                }
                ProbeEvent::Info(message) => self.wol_notice = Some(message),
                _ => {}
            }
        }
        for event in self.mac_ctrl.drain() {
            if !self.visible {
                continue;
            }
            match event {
                ProbeEvent::MacVendor(result) => {
                    if let Some(prefix) = result.prefix.get(..6) {
                        self.mac_cache.insert(prefix.to_string(), result.clone());
                    }
                    self.mac_result = Some(result);
                    self.mac_error = None;
                    self.mac_notice = None;
                }
                ProbeEvent::Error { message, hint } => {
                    self.mac_error = Some((message, hint));
                    self.mac_result = None;
                }
                ProbeEvent::Info(message) => self.mac_notice = Some(message),
                _ => {}
            }
        }
    }

    fn tool_selector(&self, ui: &mut egui::Ui, settings: &mut UtilsSettings) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(
                &mut settings.active_tool,
                UtilsTool::Subnet,
                t!("utils.tools.subnet"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                UtilsTool::Wol,
                t!("utils.tools.wol"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                UtilsTool::PortReference,
                t!("utils.tools.ports"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                UtilsTool::MacVendor,
                t!("utils.tools.mac"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                UtilsTool::Timestamp,
                t!("utils.tools.timestamp"),
            );
        });
    }

    fn subnet_ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut UtilsSettings,
        history: &mut InputHistory,
        settings_expanded: bool,
    ) -> bool {
        let (_, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            egui::Grid::new("utils_subnet_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("utils.subnet.input"));
                    history_input::singleline(
                        ui,
                        SUBNET_HISTORY_KEY,
                        &mut settings.subnet.input,
                        history,
                        170.0,
                    );
                    ui.end_row();
                });
            ui.weak(t!("utils.subnet.hint"));
        });

        crate::ui::layout::results_panel(ui, |ui| {
            let input = settings.subnet.input.trim();
            if input.is_empty() {
                ui.weak(t!("utils.subnet.empty"));
                return;
            }
            match subnet::parse_subnet(input) {
                Ok(info) => {
                    let mut rows = vec![
                        (t!("utils.subnet.input_field").to_string(), info.input),
                        (
                            t!("utils.subnet.family").to_string(),
                            info.family.to_string(),
                        ),
                        (t!("utils.subnet.cidr").to_string(), info.cidr),
                        (t!("utils.subnet.network").to_string(), info.network),
                    ];
                    if let Some(value) = info.broadcast {
                        rows.push((t!("utils.subnet.broadcast").to_string(), value));
                    }
                    if let Some(value) = info.netmask {
                        rows.push((t!("utils.subnet.netmask").to_string(), value));
                    }
                    if let Some(value) = info.wildcard {
                        rows.push((t!("utils.subnet.wildcard").to_string(), value));
                    }
                    rows.push((t!("utils.subnet.first").to_string(), info.first));
                    rows.push((t!("utils.subnet.last").to_string(), info.last));
                    rows.push((t!("utils.subnet.total").to_string(), info.total));
                    rows.push((t!("utils.subnet.usable").to_string(), info.usable));
                    rows.push((t!("utils.subnet.scope").to_string(), info.scope));
                    if let Some(value) = info.address_binary {
                        rows.push((t!("utils.subnet.address_binary").to_string(), value));
                    }
                    if let Some(value) = info.mask_binary {
                        rows.push((t!("utils.subnet.mask_binary").to_string(), value));
                    }
                    if let Some(value) = info.expanded {
                        rows.push((t!("utils.subnet.expanded").to_string(), value));
                    }
                    if let Some(value) = info.interface_id {
                        rows.push((t!("utils.subnet.interface_id").to_string(), value));
                    }
                    copyable_grid(ui, "utils_subnet_result", &rows);
                    if info.family == "IPv6" {
                        ui.weak(t!("utils.subnet.ipv6_no_broadcast"));
                    }
                }
                Err(message) => error_banner(ui, &message, None),
            }
        });

        expanded
    }

    fn wol_ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut UtilsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        let (start, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            let mut start = false;
            egui::Grid::new("utils_wol_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("utils.wol.mac"));
                    if history_input::singleline(
                        ui,
                        WOL_MAC_HISTORY_KEY,
                        &mut settings.wol.mac,
                        history,
                        170.0,
                    ) {
                        start = true;
                    }
                    ui.end_row();

                    ui.label(t!("utils.wol.broadcast"));
                    ui.horizontal(|ui| {
                        history_input::singleline(
                            ui,
                            WOL_BROADCAST_HISTORY_KEY,
                            &mut settings.wol.broadcast,
                            history,
                            120.0,
                        );
                        ui.menu_button(t!("utils.wol.detect"), |ui| {
                            if self.broadcasts.is_empty() {
                                ui.weak(t!("utils.wol.no_broadcast"));
                            }
                            for local in &self.broadcasts {
                                let label = format!("{}  ({})", local.address, local.interface);
                                if ui.button(label).clicked() {
                                    settings.wol.broadcast = local.address.to_string();
                                    ui.close();
                                }
                            }
                        });
                    });
                    ui.end_row();

                    ui.label(t!("utils.wol.port"));
                    ui.horizontal(|ui| {
                        ui.add(egui::DragValue::new(&mut settings.wol.port).range(1..=65535));
                        ui.selectable_value(&mut settings.wol.port, 9, "9");
                        ui.selectable_value(&mut settings.wol.port, 7, "7");
                    });
                    ui.end_row();

                    ui.label(t!("utils.wol.repeat"));
                    ui.add(egui::DragValue::new(&mut settings.wol.repeat).range(1..=10));
                    ui.end_row();

                    ui.label(t!("utils.wol.interval"));
                    ui.add(
                        egui::DragValue::new(&mut settings.wol.interval_ms)
                            .range(10..=5_000)
                            .suffix(" ms"),
                    );
                    ui.end_row();

                    ui.label(t!("utils.wol.secure_on"));
                    ui.add(
                        egui::TextEdit::singleline(&mut settings.wol.secure_on)
                            .desired_width(170.0)
                            .hint_text("AA:BB:CC:DD:EE:FF"),
                    );
                    ui.end_row();
                });
            ui.weak(t!("utils.wol.hint"));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if self.wol_ctrl.is_active() {
                    if ui.button(t!("common.stop")).clicked() {
                        self.wol_ctrl.stop();
                    }
                } else if ui.button(t!("utils.wol.send")).clicked() {
                    start = true;
                }
                state_badge(ui, self.wol_ctrl.state);
            });
            if let Some((message, hint)) = &self.wol_error {
                error_banner(ui, message, hint.as_deref());
            }
            if let Some(notice) = &self.wol_notice {
                ui.colored_label(Palette::from_ui(ui).info_text, notice);
            }
            start
        });

        if start.unwrap_or(false) {
            history_input::record_fields(
                history,
                &[
                    (WOL_MAC_HISTORY_KEY, &settings.wol.mac),
                    (WOL_BROADCAST_HISTORY_KEY, &settings.wol.broadcast),
                ],
            );
            self.wol_result = None;
            self.wol_error = None;
            self.wol_notice = None;
            let settings = settings.wol.clone();
            self.wol_ctrl.start(rt, move |handle| async move {
                wol::run_wake(&handle, &settings).await;
            });
        }

        crate::ui::layout::results_panel(ui, |ui| {
            ui.heading(t!("utils.wol.result"));
            if let Some(result) = &self.wol_result {
                let rows = vec![
                    (t!("utils.wol.mac").to_string(), result.mac.clone()),
                    (
                        t!("utils.wol.broadcast").to_string(),
                        result.broadcast.clone(),
                    ),
                    (t!("utils.wol.port").to_string(), result.port.to_string()),
                    (
                        t!("utils.wol.packets").to_string(),
                        result.packets.to_string(),
                    ),
                    (t!("utils.wol.bytes").to_string(), result.bytes.to_string()),
                    (
                        t!("utils.wol.elapsed").to_string(),
                        format!("{:.1} ms", result.elapsed_ms),
                    ),
                    (
                        t!("utils.wol.secure_on").to_string(),
                        yes_no(result.secure_on),
                    ),
                ];
                copyable_grid(ui, "utils_wol_result", &rows);
            } else if !self.wol_ctrl.is_active() {
                ui.weak(t!("utils.wol.empty"));
            }
        });

        expanded
    }

    fn refresh_port_filters(
        &mut self,
        query: &str,
        transport: PortTransportFilter,
        view: PortReferenceView,
    ) {
        self.port_matches = port_reference::search_services(query, transport);
        self.protocol_matches = port_reference::search_ip_protocols(query);
        self.port_filter_key = Some(PortFilterKey {
            query: query.to_string(),
            transport,
            view,
        });
    }

    fn port_reference_ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut UtilsSettings,
        settings_expanded: bool,
    ) -> bool {
        let s = &mut settings.port_reference;
        let key = PortFilterKey {
            query: s.query.clone(),
            transport: s.transport,
            view: s.view,
        };
        if self.port_filter_key.as_ref() != Some(&key) {
            self.refresh_port_filters(&s.query, s.transport, s.view);
        }

        let (_, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            ui.label(t!("utils.ports.search"));
            ui.add(
                egui::TextEdit::singleline(&mut s.query)
                    .desired_width(220.0)
                    .hint_text(t!("utils.ports.search_hint")),
            );
            ui.add_space(6.0);
            egui::Grid::new("utils_port_filter")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("utils.ports.transport"));
                    egui::ComboBox::from_id_salt("utils_port_transport")
                        .selected_text(s.transport.label())
                        .width(160.0)
                        .show_ui(ui, |ui| {
                            for transport in [
                                PortTransportFilter::All,
                                PortTransportFilter::Tcp,
                                PortTransportFilter::Udp,
                                PortTransportFilter::Sctp,
                                PortTransportFilter::Dccp,
                            ] {
                                ui.selectable_value(&mut s.transport, transport, transport.label());
                            }
                        });
                    ui.end_row();

                    ui.label(t!("utils.ports.view"));
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut s.view,
                            PortReferenceView::Ports,
                            t!("utils.ports.ports_view"),
                        );
                        ui.selectable_value(
                            &mut s.view,
                            PortReferenceView::IpProtocols,
                            t!("utils.ports.protocols_view"),
                        );
                    });
                    ui.end_row();
                });
            ui.add_space(6.0);
            let count = match s.view {
                PortReferenceView::Ports => self.port_matches.len(),
                PortReferenceView::IpProtocols => self.protocol_matches.len(),
            };
            ui.weak(t!("utils.ports.count").replace("%{count}", &count.to_string()));
            ui.weak(t!("utils.ports.range_hint"));
        });

        crate::ui::layout::results_panel(ui, |ui| match s.view {
            PortReferenceView::Ports => self.port_table(ui),
            PortReferenceView::IpProtocols => self.protocol_table(ui),
        });

        expanded
    }

    fn port_table(&self, ui: &mut egui::Ui) {
        let headers = [
            t!("utils.ports.port").to_string(),
            t!("utils.ports.service").to_string(),
            t!("utils.ports.transport").to_string(),
            t!("utils.ports.description").to_string(),
            t!("common.copy").to_string(),
        ];
        let services = port_reference::iana_services();
        table(ui, &headers, self.port_matches.len(), |index, row| {
            let Some(service) = self
                .port_matches
                .get(index)
                .and_then(|service_index| services.get(*service_index))
            else {
                return;
            };
            row.col(|ui| {
                ui.monospace(&service.port_text);
            });
            row.col(|ui| {
                ui.label(display_or_dash(&service.service));
            });
            row.col(|ui| {
                ui.label(display_or_dash(&service.transport));
            });
            row.col(|ui| {
                ui.label(display_or_dash(&service.description))
                    .on_hover_text(&service.description);
            });
            row.col(|ui| {
                let text = format!(
                    "{}\t{}\t{}\t{}",
                    service.port_text, service.service, service.transport, service.description
                );
                copy_button(ui, &text);
            });
        });
    }

    fn protocol_table(&self, ui: &mut egui::Ui) {
        let headers = [
            t!("utils.ports.number").to_string(),
            t!("utils.ports.keyword").to_string(),
            t!("utils.ports.protocol").to_string(),
            t!("utils.ports.description").to_string(),
            t!("common.copy").to_string(),
        ];
        table(ui, &headers, self.protocol_matches.len(), |index, row| {
            let Some(protocol) = self
                .protocol_matches
                .get(index)
                .and_then(|protocol_index| port_reference::IP_PROTOCOLS.get(*protocol_index))
            else {
                return;
            };
            row.col(|ui| {
                ui.monospace(protocol.number.to_string());
            });
            row.col(|ui| {
                ui.label(protocol.keyword);
            });
            row.col(|ui| {
                ui.label(protocol.protocol);
            });
            row.col(|ui| {
                ui.label(protocol.description);
            });
            row.col(|ui| {
                let text = format!(
                    "{}\t{}\t{}\t{}",
                    protocol.number, protocol.keyword, protocol.protocol, protocol.description
                );
                copy_button(ui, &text);
            });
        });
    }

    fn mac_vendor_ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut UtilsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        let (query, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            let mut query = false;
            egui::Grid::new("utils_mac_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("utils.mac.input"));
                    if history_input::singleline(
                        ui,
                        MAC_HISTORY_KEY,
                        &mut settings.mac_vendor.mac,
                        history,
                        170.0,
                    ) {
                        query = true;
                    }
                    ui.end_row();

                    ui.label(t!("utils.mac.online"));
                    ui.checkbox(
                        &mut settings.mac_vendor.allow_online,
                        t!("utils.mac.allow_online"),
                    );
                    ui.end_row();
                });
            ui.weak(t!("utils.mac.privacy"));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if self.mac_ctrl.is_active() {
                    if ui.button(t!("common.stop")).clicked() {
                        self.mac_ctrl.stop();
                    }
                } else if ui.button(t!("utils.mac.query")).clicked() {
                    query = true;
                }
                state_badge(ui, self.mac_ctrl.state);
            });
            if let Some((message, hint)) = &self.mac_error {
                error_banner(ui, message, hint.as_deref());
            }
            if let Some(notice) = &self.mac_notice {
                ui.colored_label(Palette::from_ui(ui).info_text, notice);
            }
            ui.add_space(6.0);
            ui.weak(t!("utils.mac.source"));
            ui.hyperlink_to(mac_vendor::MAC_LOOKUP_SOURCE, mac_vendor::MAC_LOOKUP_SOURCE);
            ui.hyperlink_to(t!("utils.mac.terms"), mac_vendor::MAC_LOOKUP_TERMS);
            query
        });

        if query.unwrap_or(false) {
            history_input::record_fields(history, &[(MAC_HISTORY_KEY, &settings.mac_vendor.mac)]);
            self.start_mac_query(settings, rt);
        }

        crate::ui::layout::results_panel(ui, |ui| {
            ui.heading(t!("utils.mac.result"));
            if let Some(result) = &self.mac_result {
                let mut rows = vec![
                    (t!("utils.mac.input").to_string(), result.mac.clone()),
                    (t!("utils.mac.prefix").to_string(), result.prefix.clone()),
                    (t!("utils.mac.vendor").to_string(), result.vendor.clone()),
                    (
                        t!("utils.mac.block_type").to_string(),
                        result.block_type.clone().unwrap_or_else(|| "—".to_string()),
                    ),
                    (
                        t!("utils.mac.updated").to_string(),
                        result.updated.clone().unwrap_or_else(|| "—".to_string()),
                    ),
                    (
                        t!("utils.mac.country").to_string(),
                        result.country.clone().unwrap_or_else(|| "—".to_string()),
                    ),
                    (
                        t!("utils.mac.address").to_string(),
                        result.address.clone().unwrap_or_else(|| "—".to_string()),
                    ),
                    (
                        t!("utils.mac.result_source").to_string(),
                        match result.source {
                            MacVendorSource::Local => t!("utils.mac.local").to_string(),
                            MacVendorSource::Online => t!("utils.mac.online_source").to_string(),
                        },
                    ),
                ];
                if result.source == MacVendorSource::Online {
                    rows.push((
                        t!("utils.mac.source").to_string(),
                        t!("utils.mac.source_online").to_string(),
                    ));
                }
                copyable_grid(ui, "utils_mac_result", &rows);
            } else if !self.mac_ctrl.is_active() {
                ui.weak(t!("utils.mac.empty"));
            }
        });

        expanded
    }

    fn start_mac_query(&mut self, settings: &UtilsSettings, rt: &tokio::runtime::Handle) {
        self.mac_result = None;
        self.mac_error = None;
        self.mac_notice = None;

        match mac_vendor::lookup_local(&settings.mac_vendor.mac) {
            Ok(Some(result)) => {
                if let Some(prefix) = result.prefix.get(..6) {
                    self.mac_cache.insert(prefix.to_string(), result.clone());
                }
                self.mac_result = Some(result);
                return;
            }
            Ok(None) => {}
            Err(message) => {
                self.mac_error = Some((message, None));
                return;
            }
        }

        if !settings.mac_vendor.allow_online {
            self.mac_notice = Some(t!("utils.mac.not_found_local").to_string());
            return;
        }

        let oui = mac_vendor::normalize_mac(&settings.mac_vendor.mac)
            .map(|mac| mac.oui().to_string())
            .ok();
        if let Some(oui) = oui {
            if let Some(cached) = self.mac_cache.get(&oui) {
                self.mac_result = Some(cached.clone());
                return;
            }
        }

        let mac = settings.mac_vendor.mac.clone();
        self.mac_ctrl.start(rt, move |handle| async move {
            mac_vendor::run_online_lookup(&handle, &mac, MAC_ONLINE_TIMEOUT_MS).await;
        });
    }

    fn timestamp_ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut UtilsSettings,
        history: &mut InputHistory,
        settings_expanded: bool,
    ) -> bool {
        let s = &mut settings.timestamp;
        let (_, expanded) = crate::ui::layout::settings_panel(ui, settings_expanded, |ui| {
            ui.heading(t!("common.settings"));
            ui.label(t!("utils.timestamp.input"));
            ui.horizontal(|ui| {
                history_input::singleline(ui, TIMESTAMP_HISTORY_KEY, &mut s.input, history, 140.0);
                if ui.button(t!("utils.timestamp.now")).clicked() {
                    s.input = time_convert::now_unix_seconds().to_string();
                    s.unit = TimestampUnit::Seconds;
                }
            });
            ui.add_space(6.0);
            egui::Grid::new("utils_timestamp_settings")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t!("utils.timestamp.unit"));
                    egui::ComboBox::from_id_salt("utils_timestamp_unit")
                        .selected_text(timestamp_unit_label(s.unit))
                        .width(160.0)
                        .show_ui(ui, |ui| {
                            for unit in [
                                TimestampUnit::Auto,
                                TimestampUnit::Seconds,
                                TimestampUnit::Milliseconds,
                                TimestampUnit::Microseconds,
                                TimestampUnit::Nanoseconds,
                            ] {
                                ui.selectable_value(&mut s.unit, unit, timestamp_unit_label(unit));
                            }
                        });
                    ui.end_row();

                    ui.label(t!("utils.timestamp.source_zone"));
                    if let Some(zone) = zone_picker(
                        ui,
                        "utils_source_zone",
                        &mut self.source_zone_search,
                        &s.source_zone,
                    ) {
                        s.source_zone = zone;
                    }
                    ui.end_row();
                });
            ui.add_space(6.0);
            ui.label(t!("utils.timestamp.target_zones"));
            let mut remove = None;
            for (index, zone) in s.target_zones.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(zone);
                    if ui.small_button("x").clicked() {
                        remove = Some(index);
                    }
                });
            }
            if let Some(index) = remove {
                s.target_zones.remove(index);
            }
            if s.target_zones.len() < MAX_TARGET_ZONES {
                if let Some(zone) = zone_picker(
                    ui,
                    "utils_target_zone",
                    &mut self.target_zone_search,
                    t!("utils.timestamp.add_zone").as_ref(),
                ) {
                    if !s.target_zones.iter().any(|existing| existing == &zone) {
                        s.target_zones.push(zone);
                    }
                }
            } else {
                ui.weak(t!("utils.timestamp.zone_limit"));
            }
            ui.weak(t!("utils.timestamp.hint"));
        });

        crate::ui::layout::results_panel(ui, |ui| {
            let input = settings.timestamp.input.trim();
            if input.is_empty() {
                ui.weak(t!("utils.timestamp.empty"));
                return;
            }
            match time_convert::convert(
                input,
                settings.timestamp.unit,
                &settings.timestamp.source_zone,
                &settings.timestamp.target_zones,
            ) {
                Ok(result) => {
                    let mut zones = Vec::with_capacity(result.zones.len() + 2);
                    zones.push(&result.local);
                    zones.push(&result.utc);
                    zones.extend(result.zones.iter());
                    egui::ScrollArea::horizontal()
                        .id_salt("utils_timestamp_zones_scroll")
                        .show(ui, |ui| {
                            egui::Grid::new("utils_timestamp_zones")
                                .num_columns(5)
                                .striped(true)
                                .spacing([22.0, 6.0])
                                .show(ui, |ui| {
                                    for header in [
                                        t!("utils.timestamp.zone"),
                                        t!("utils.timestamp.date_time"),
                                        t!("utils.timestamp.offset"),
                                        t!("utils.timestamp.abbreviation"),
                                        t!("common.copy"),
                                    ] {
                                        ui.add(
                                            egui::Label::new(egui::RichText::new(header).strong())
                                                .wrap_mode(egui::TextWrapMode::Extend),
                                        );
                                    }
                                    ui.end_row();
                                    for zone in zones {
                                        ui.add(
                                            egui::Label::new(&zone.zone)
                                                .wrap_mode(egui::TextWrapMode::Extend),
                                        );
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&zone.date_time).monospace(),
                                            )
                                            .wrap_mode(egui::TextWrapMode::Extend),
                                        );
                                        ui.add(
                                            egui::Label::new(&zone.offset)
                                                .wrap_mode(egui::TextWrapMode::Extend),
                                        );
                                        ui.add(
                                            egui::Label::new(&zone.abbreviation)
                                                .wrap_mode(egui::TextWrapMode::Extend),
                                        );
                                        let text = format!(
                                            "{}\t{}\t{}\t{}",
                                            zone.zone,
                                            zone.date_time,
                                            zone.offset,
                                            zone.abbreviation
                                        );
                                        copy_button(ui, &text);
                                        ui.end_row();
                                    }
                                });
                        });
                    ui.add_space(10.0);
                    let rows = vec![
                        (
                            t!("utils.timestamp.used_unit").to_string(),
                            result.unit.to_string(),
                        ),
                        ("RFC 3339".to_string(), result.rfc3339),
                        ("Unix seconds".to_string(), result.unix_seconds.to_string()),
                        (
                            "Unix milliseconds".to_string(),
                            result.unix_millis.to_string(),
                        ),
                        (
                            "Unix microseconds".to_string(),
                            result.unix_micros.to_string(),
                        ),
                        (
                            "Unix nanoseconds".to_string(),
                            result.unix_nanos.to_string(),
                        ),
                        (t!("utils.timestamp.weekday").to_string(), result.weekday),
                        (t!("utils.timestamp.iso_week").to_string(), result.iso_week),
                        (t!("utils.timestamp.relative").to_string(), result.relative),
                    ];
                    copyable_grid(ui, "utils_timestamp_result", &rows);
                }
                Err(message) => error_banner(ui, &message, None),
            }
        });

        expanded
    }
}

fn timestamp_unit_label(unit: TimestampUnit) -> String {
    match unit {
        TimestampUnit::Auto => t!("utils.timestamp.unit_auto").to_string(),
        TimestampUnit::Seconds => t!("utils.timestamp.unit_seconds").to_string(),
        TimestampUnit::Milliseconds => t!("utils.timestamp.unit_milliseconds").to_string(),
        TimestampUnit::Microseconds => t!("utils.timestamp.unit_microseconds").to_string(),
        TimestampUnit::Nanoseconds => t!("utils.timestamp.unit_nanoseconds").to_string(),
    }
}

fn display_or_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "—"
    } else {
        value
    }
}

fn yes_no(value: bool) -> String {
    if value {
        t!("common.yes").to_string()
    } else {
        t!("common.no").to_string()
    }
}

/// Render a two-column key/value list with a copy button for each value.
///
/// Columns size to their content and the whole grid scrolls horizontally when a
/// value is wider than the results panel, so long IPv6 or MAC values are never
/// squeezed into a narrow wrapping column.
fn copyable_grid(ui: &mut egui::Ui, id: &str, rows: &[(String, String)]) {
    egui::ScrollArea::horizontal()
        .id_salt((id, "scroll"))
        .show(ui, |ui| {
            egui::Grid::new(id)
                .num_columns(3)
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    for (key, value) in rows {
                        ui.add(egui::Label::new(key).wrap_mode(egui::TextWrapMode::Extend));
                        ui.add(
                            egui::Label::new(egui::RichText::new(value).monospace())
                                .wrap_mode(egui::TextWrapMode::Extend),
                        );
                        copy_button(ui, value);
                        ui.end_row();
                    }
                });
        });
}

/// Searchable IANA timezone picker. Returns the chosen zone.
fn zone_picker(ui: &mut egui::Ui, id: &str, search: &mut String, current: &str) -> Option<String> {
    let mut chosen = None;
    egui::ComboBox::from_id_salt(id)
        .selected_text(current)
        .width(220.0)
        .show_ui(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(search)
                    .desired_width(200.0)
                    .hint_text(t!("utils.timestamp.zone_search")),
            );
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(ui, |ui| {
                    let needle = search.trim().to_ascii_lowercase();
                    for name in time_convert::timezone_names() {
                        if !needle.is_empty() && !name.to_ascii_lowercase().contains(&needle) {
                            continue;
                        }
                        if ui.selectable_label(current == name, name).clicked() {
                            chosen = Some(name.to_string());
                            ui.close();
                        }
                    }
                });
        });
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_utils_tool_renders_without_panic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut tab = UtilsTab::new();
        let mut settings = UtilsSettings::default();
        settings.subnet.input = "2001:db8::1/64".into();
        settings.wol.mac = "AA:BB:CC:DD:EE:FF".into();
        settings.mac_vendor.mac = "00:00:0C:12:34:56".into();
        settings.timestamp.input = "1700000000".into();
        let mut history = InputHistory::default();
        let ctx = egui::Context::default();

        for tool in [
            UtilsTool::Subnet,
            UtilsTool::Wol,
            UtilsTool::PortReference,
            UtilsTool::MacVendor,
            UtilsTool::Timestamp,
        ] {
            settings.active_tool = tool;
            for _ in 0..3 {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::pos2(0.0, 0.0),
                        egui::vec2(1100.0, 800.0),
                    )),
                    ..Default::default()
                };
                ctx.run_ui(input, |ui| {
                    let _ = tab.ui(ui, &mut settings, &mut history, runtime.handle(), true);
                })
                .textures_delta
                .clear();
            }
        }
    }
}
