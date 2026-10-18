//! Speedtest tab: LibreSpeed and iperf3 in one view.

use std::time::Duration;

use eframe::egui;
use net_tools_core::config::{InputHistory, Iperf3Settings, SpeedtestSettings};
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{
    Iperf3Protocol, Iperf3Server, LibreSpeedServer, ProbeEvent, SpeedPhase, SpeedProgress,
    SpeedResult, SpeedSample, SpeedtestTool,
};
use rust_i18n::t;

use crate::speedtest_worker;
use crate::tabs::iperf3_server::Iperf3ServerTab;
use crate::ui::common::{error_banner, result_toolbar, state_badge, ToolbarAction};
use crate::ui::history_input;
use crate::ui::result_table::table_fixed_rows;

/// History bucket for the custom LibreSpeed backend URL.
const LIBRESPEED_URL_KEY: &str = "speedtest.librespeed.custom_url";

/// History bucket for the iperf3 host field.
const IPERF3_HOST_KEY: &str = "speedtest.iperf3.host";

/// Maximum number of results kept in the in-memory session history per tool.
const HISTORY_LIMIT: usize = 20;

/// Number of history rows visible before the table scrolls.
const VISIBLE_HISTORY_ROWS: usize = 5;

/// Repaint cadence while a speed test or server list request is running.
const LIVE_REPAINT: Duration = Duration::from_millis(200);

/// Timeout for loading the public iperf3 server directory.
const IPERF3_LIST_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionChoice {
    Upload,
    Download,
    Bidirectional,
}

impl DirectionChoice {
    fn from_settings(settings: &Iperf3Settings) -> Self {
        if settings.bidir {
            Self::Bidirectional
        } else if settings.reverse {
            Self::Download
        } else {
            Self::Upload
        }
    }

    fn label(self) -> String {
        match self {
            Self::Upload => t!("speedtest.direction_upload").to_string(),
            Self::Download => t!("speedtest.direction_download").to_string(),
            Self::Bidirectional => t!("speedtest.direction_bidirectional").to_string(),
        }
    }

    fn apply(self, settings: &mut Iperf3Settings) {
        settings.reverse = matches!(self, Self::Download);
        settings.bidir = matches!(self, Self::Bidirectional);
    }
}

/// State shared by both sub-tools.
#[derive(Default)]
struct ToolState {
    result: Option<SpeedResult>,
    /// Samples of the current or most recent run, used by the live chart.
    samples: Vec<SpeedSample>,
    progress: Option<SpeedProgress>,
    error: Option<(String, Option<String>)>,
    notice: Option<String>,
    /// Completed runs from this application session only.
    history: Vec<SpeedResult>,
    /// Phase used for live iperf3 samples, derived from the configured
    /// direction when the test starts.
    live_phase: SpeedPhase,
}

impl ToolState {
    fn start(&mut self) {
        self.result = None;
        self.samples.clear();
        self.progress = None;
        self.error = None;
        self.notice = None;
    }

    fn apply_progress(&mut self, progress: SpeedProgress, live_phase: SpeedPhase) {
        if progress.current_mbps > 0.0 {
            let phase = if progress.phase == SpeedPhase::Testing {
                live_phase
            } else {
                progress.phase
            };
            if matches!(phase, SpeedPhase::Download | SpeedPhase::Upload) {
                self.samples.push(SpeedSample {
                    elapsed_s: progress.elapsed_s,
                    mbps: progress.current_mbps,
                    phase,
                });
            }
        }
        self.progress = Some(progress);
    }

    fn apply_result(&mut self, result: SpeedResult) {
        self.samples = result.samples.clone();
        self.result = Some(result.clone());
        self.history.insert(0, result);
        self.history.truncate(HISTORY_LIMIT);
        self.progress = None;
    }

    fn clear(&mut self) {
        self.result = None;
        self.samples.clear();
        self.progress = None;
        self.error = None;
        self.notice = None;
        self.history.clear();
    }
}

/// Speedtest tab with two independent one-shot tasks.
pub struct SpeedtestTab {
    librespeed_ctrl: TaskController<ProbeEvent>,
    server_ctrl: TaskController<ProbeEvent>,
    iperf3_ctrl: TaskController<ProbeEvent>,
    iperf3_server_ctrl: TaskController<ProbeEvent>,
    librespeed: ToolState,
    iperf3: ToolState,
    server: Iperf3ServerTab,
    servers: Vec<LibreSpeedServer>,
    iperf3_servers: Vec<Iperf3Server>,
    /// Filter text for the public iperf3 server drop-down.
    iperf3_filter: String,
    /// Whether an automatic server list request has already been attempted.
    servers_requested: bool,
    /// Whether an automatic iperf3 server list request has already been attempted.
    iperf3_servers_requested: bool,
    /// Whether this tab is currently rendered.
    visible: bool,
}

impl Default for SpeedtestTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SpeedtestTab {
    pub fn new() -> Self {
        Self {
            librespeed_ctrl: TaskController::new(),
            server_ctrl: TaskController::new(),
            iperf3_ctrl: TaskController::new(),
            iperf3_server_ctrl: TaskController::new(),
            librespeed: ToolState::default(),
            iperf3: ToolState::default(),
            server: Iperf3ServerTab::new(),
            servers: Vec::new(),
            iperf3_servers: Vec::new(),
            iperf3_filter: String::new(),
            servers_requested: false,
            iperf3_servers_requested: false,
            visible: false,
        }
    }

    /// Drop live progress when another top-level tab is selected. Completed
    /// results and the in-memory session history are kept.
    pub fn clear_on_hide(&mut self) {
        self.visible = false;
        for ctrl in [&mut self.librespeed_ctrl, &mut self.iperf3_ctrl] {
            if ctrl.is_active() {
                ctrl.stop();
            }
            let _ = ctrl.drain();
        }
        if self.server_ctrl.is_active() {
            self.server_ctrl.stop();
            // An interrupted initial load should be retried when the tab is
            // opened again; a cached list is kept as is.
            if self.servers.is_empty() {
                self.servers_requested = false;
            }
        }
        let _ = self.server_ctrl.drain();
        if self.iperf3_server_ctrl.is_active() {
            self.iperf3_server_ctrl.stop();
            if self.iperf3_servers.is_empty() {
                self.iperf3_servers_requested = false;
            }
        }
        let _ = self.iperf3_server_ctrl.drain();
        for state in [&mut self.librespeed, &mut self.iperf3] {
            state.progress = None;
            state.samples.clear();
        }
        self.server.clear_on_hide();
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut SpeedtestSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        self.drain();
        if !self.visible {
            self.visible = true;
        }
        match settings.active_tool {
            SpeedtestTool::LibreSpeed => self.ensure_servers(settings, rt),
            SpeedtestTool::Iperf3 => self.ensure_iperf3_servers(rt),
            SpeedtestTool::Iperf3Server => {}
        }
        if self.any_active()
            || self.server_ctrl.is_active()
            || self.iperf3_server_ctrl.is_active()
            || self.librespeed.progress.is_some()
            || self.iperf3.progress.is_some()
        {
            ui.ctx().request_repaint_after(LIVE_REPAINT);
        }

        let previous_tool = settings.active_tool;
        self.tool_selector(ui, settings);
        if previous_tool != settings.active_tool && previous_tool == SpeedtestTool::Iperf3Server {
            // The built-in server only runs while its sub-tab is selected.
            self.server.clear_on_hide();
        }
        if settings.active_tool == SpeedtestTool::Iperf3Server {
            self.server.ui(ui, &mut settings.iperf3_server, history, rt);
            return;
        }
        let (start_requested, refresh_requested) =
            egui::CollapsingHeader::new(t!("common.settings"))
                .default_open(true)
                .show(ui, |ui| match settings.active_tool {
                    SpeedtestTool::LibreSpeed => {
                        self.librespeed_settings(ui, settings, history, rt)
                    }
                    SpeedtestTool::Iperf3 => self.iperf3_settings(ui, settings, history),
                    SpeedtestTool::Iperf3Server => (false, false),
                })
                .body_returned
                .unwrap_or_default();
        if refresh_requested {
            match settings.active_tool {
                SpeedtestTool::LibreSpeed => self.refresh_servers(settings, rt),
                SpeedtestTool::Iperf3 => self.refresh_iperf3_servers(rt),
                SpeedtestTool::Iperf3Server => {}
            }
        }
        if start_requested {
            self.start_active(settings, history, rt);
        }

        self.controls(ui, settings, history, rt);
        self.toolbar(ui, settings.active_tool);

        let active_state = self.active_state(settings.active_tool);
        if let Some((message, hint)) = &active_state.error {
            error_banner(ui, message, hint.as_deref());
        }
        if let Some(notice) = &active_state.notice {
            ui.colored_label(egui::Color32::from_rgb(150, 200, 255), notice);
        }

        ui.separator();
        // Results and history can exceed the available height, especially when
        // the chart and a narrow window are combined, so keep them scrollable.
        egui::ScrollArea::vertical()
            .id_salt("speedtest_results_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.result_ui(ui, settings.active_tool);
                ui.add_space(10.0);
                self.history_ui(ui, settings.active_tool);
            });
    }

    fn any_active(&self) -> bool {
        self.librespeed_ctrl.is_active() || self.iperf3_ctrl.is_active()
    }

    fn active_state(&self, tool: SpeedtestTool) -> &ToolState {
        match tool {
            SpeedtestTool::LibreSpeed => &self.librespeed,
            SpeedtestTool::Iperf3 => &self.iperf3,
            SpeedtestTool::Iperf3Server => &self.librespeed,
        }
    }

    fn tool_selector(&mut self, ui: &mut egui::Ui, settings: &mut SpeedtestSettings) {
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut settings.active_tool,
                SpeedtestTool::LibreSpeed,
                t!("speedtest.librespeed"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                SpeedtestTool::Iperf3,
                t!("speedtest.iperf3"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                SpeedtestTool::Iperf3Server,
                t!("speedtest.iperf3_server"),
            );
        });
    }

    /// Load the public LibreSpeed list automatically once per session.
    fn ensure_servers(&mut self, settings: &SpeedtestSettings, rt: &tokio::runtime::Handle) {
        if self.servers_requested || self.server_ctrl.is_active() {
            return;
        }
        self.servers_requested = true;
        let timeout_ms = settings.librespeed.timeout_ms;
        let ip_version = settings.librespeed.ip_version;
        self.server_ctrl.start(rt, move |handle| async move {
            net_tools_core::net::librespeed::run_server_list(&handle, timeout_ms, ip_version).await;
        });
    }

    fn refresh_servers(&mut self, settings: &SpeedtestSettings, rt: &tokio::runtime::Handle) {
        if self.server_ctrl.is_active() {
            self.server_ctrl.stop();
        }
        self.servers_requested = false;
        self.ensure_servers(settings, rt);
    }

    /// Load the public iperf3 server directory automatically once per session.
    fn ensure_iperf3_servers(&mut self, rt: &tokio::runtime::Handle) {
        if self.iperf3_servers_requested || self.iperf3_server_ctrl.is_active() {
            return;
        }
        self.iperf3_servers_requested = true;
        self.iperf3_server_ctrl.start(rt, move |handle| async move {
            net_tools_core::net::iperf3::run_server_list(&handle, IPERF3_LIST_TIMEOUT_MS).await;
        });
    }

    fn refresh_iperf3_servers(&mut self, rt: &tokio::runtime::Handle) {
        if self.iperf3_server_ctrl.is_active() {
            self.iperf3_server_ctrl.stop();
        }
        self.iperf3_servers_requested = false;
        self.ensure_iperf3_servers(rt);
    }

    fn librespeed_settings(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut SpeedtestSettings,
        history: &mut InputHistory,
        _rt: &tokio::runtime::Handle,
    ) -> (bool, bool) {
        let mut submit = false;
        let mut refresh = false;
        let s = &mut settings.librespeed;
        egui::Grid::new("speedtest_librespeed_settings")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label(t!("speedtest.server"));
                ui.horizontal(|ui| {
                    let selected = if s.server == "auto" || s.server.is_empty() {
                        t!("speedtest.auto").to_string()
                    } else {
                        self.servers
                            .iter()
                            .find(|server| server.id.to_string() == s.server)
                            .map(|server| server.name.clone())
                            .unwrap_or_else(|| format!("#{}", s.server))
                    };
                    egui::ComboBox::from_id_salt("librespeed_server")
                        .selected_text(selected)
                        .width(320.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut s.server,
                                "auto".to_string(),
                                t!("speedtest.auto"),
                            );
                            for server in &self.servers {
                                ui.selectable_value(
                                    &mut s.server,
                                    server.id.to_string(),
                                    format!("{}  ({})", server.name, server.sponsor_name),
                                );
                            }
                        });
                    if ui.button(t!("speedtest.refresh_servers")).clicked() {
                        refresh = true;
                    }
                    if self.server_ctrl.is_active() {
                        ui.spinner();
                    }
                });
                ui.end_row();

                ui.label(t!("speedtest.custom_url"));
                if history_input::singleline(
                    ui,
                    LIBRESPEED_URL_KEY,
                    &mut s.custom_url,
                    history,
                    360.0,
                ) {
                    submit = true;
                }
                ui.end_row();

                ui.label(t!("speedtest.duration_s"));
                ui.add(
                    egui::DragValue::new(&mut s.duration_s)
                        .range(1..=300)
                        .suffix(" s"),
                );
                ui.end_row();

                ui.label(t!("speedtest.connections"));
                ui.add(egui::DragValue::new(&mut s.connections).range(1..=32));
                ui.end_row();

                ui.label(t!("common.timeout_ms"));
                ui.add(
                    egui::DragValue::new(&mut s.timeout_ms)
                        .range(1000..=120_000)
                        .suffix(" ms"),
                );
                ui.end_row();

                ui.label(t!("common.ip_version"));
                crate::ui::settings::ip_version_selector(ui, &mut s.ip_version);
                ui.end_row();

                ui.label(t!("speedtest.skip_download"));
                ui.checkbox(&mut s.skip_download, "");
                ui.end_row();

                ui.label(t!("speedtest.skip_upload"));
                ui.checkbox(&mut s.skip_upload, "");
                ui.end_row();
            });
        ui.weak(t!("speedtest.librespeed_hint"));
        (submit, refresh)
    }

    fn iperf3_settings(
        &mut self,
        ui: &mut egui::Ui,
        settings: &mut SpeedtestSettings,
        history: &mut InputHistory,
    ) -> (bool, bool) {
        let mut submit = false;
        let mut refresh = false;
        let s = &mut settings.iperf3;
        egui::Grid::new("speedtest_iperf3_settings")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label(t!("speedtest.server"));
                ui.horizontal(|ui| {
                    let selected = self
                        .iperf3_servers
                        .iter()
                        .find(|server| server.host.eq_ignore_ascii_case(s.host.trim()))
                        .map(Iperf3Server::label)
                        .unwrap_or_else(|| {
                            if s.host.trim().is_empty() {
                                t!("speedtest.select_server").to_string()
                            } else {
                                format!("{}:{}", s.host.trim(), s.port)
                            }
                        });
                    egui::ComboBox::from_id_salt("iperf3_public_server")
                        .selected_text(selected)
                        .width(460.0)
                        .show_ui(ui, |ui| {
                            let filter = self.iperf3_filter.trim().to_ascii_lowercase();
                            for server in &self.iperf3_servers {
                                if !filter.is_empty()
                                    && !server.label().to_ascii_lowercase().contains(&filter)
                                {
                                    continue;
                                }
                                if ui
                                    .selectable_label(
                                        server.host.eq_ignore_ascii_case(s.host.trim()),
                                        server.label(),
                                    )
                                    .clicked()
                                {
                                    s.host = server.host.clone();
                                    s.port = server.first_port();
                                }
                            }
                        });
                    if ui.button(t!("speedtest.refresh_servers")).clicked() {
                        refresh = true;
                    }
                    if self.iperf3_server_ctrl.is_active() {
                        ui.spinner();
                    } else if !self.iperf3_servers.is_empty() {
                        ui.weak(t!(
                            "speedtest.servers_loaded",
                            count = self.iperf3_servers.len()
                        ));
                    }
                });
                ui.end_row();

                ui.label(t!("speedtest.server_filter"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.iperf3_filter)
                        .hint_text(t!("speedtest.server_filter_hint"))
                        .desired_width(240.0),
                );
                ui.end_row();

                ui.label(t!("speedtest.host"));
                if history_input::singleline(ui, IPERF3_HOST_KEY, &mut s.host, history, 360.0) {
                    submit = true;
                }
                ui.end_row();

                ui.label(t!("speedtest.port"));
                ui.add(egui::DragValue::new(&mut s.port).range(1..=65_535));
                ui.end_row();

                ui.label(t!("speedtest.protocol"));
                egui::ComboBox::from_id_salt("iperf3_protocol")
                    .selected_text(s.protocol.label())
                    .show_ui(ui, |ui| {
                        for protocol in [Iperf3Protocol::Tcp, Iperf3Protocol::Udp] {
                            ui.selectable_value(&mut s.protocol, protocol, protocol.label());
                        }
                    });
                ui.end_row();

                ui.label(t!("speedtest.direction"));
                let mut direction = DirectionChoice::from_settings(s);
                egui::ComboBox::from_id_salt("iperf3_direction")
                    .selected_text(direction.label())
                    .show_ui(ui, |ui| {
                        for choice in [
                            DirectionChoice::Upload,
                            DirectionChoice::Download,
                            DirectionChoice::Bidirectional,
                        ] {
                            ui.selectable_value(&mut direction, choice, choice.label());
                        }
                    });
                direction.apply(s);
                ui.end_row();

                ui.label(t!("speedtest.duration_s"));
                ui.add(
                    egui::DragValue::new(&mut s.duration_s)
                        .range(1..=600)
                        .suffix(" s"),
                );
                ui.end_row();

                ui.label(t!("speedtest.omit_s"));
                ui.add(
                    egui::DragValue::new(&mut s.omit_s)
                        .range(0..=600)
                        .suffix(" s"),
                );
                ui.end_row();

                ui.label(t!("speedtest.streams"));
                ui.add(egui::DragValue::new(&mut s.streams).range(1..=64));
                ui.end_row();

                ui.label(t!("speedtest.block_size"));
                ui.add(
                    egui::DragValue::new(&mut s.block_size)
                        .range(0..=1_048_576)
                        .suffix(" B"),
                );
                ui.end_row();

                ui.label(t!("speedtest.bandwidth_mbps"));
                let mut bandwidth = s.bandwidth_bps as f64 / 1_000_000.0;
                if ui
                    .add(
                        egui::DragValue::new(&mut bandwidth)
                            .range(0.0..=100_000.0)
                            .suffix(" Mbps"),
                    )
                    .changed()
                {
                    s.bandwidth_bps = (bandwidth * 1_000_000.0).round() as u64;
                }
                ui.end_row();

                ui.label(t!("common.ip_version"));
                crate::ui::settings::ip_version_selector(ui, &mut s.ip_version);
                ui.end_row();
            });
        ui.weak(t!("speedtest.iperf3_hint"));
        (submit, refresh)
    }

    fn controls(
        &mut self,
        ui: &mut egui::Ui,
        settings: &SpeedtestSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        ui.horizontal(|ui| {
            let (state, active) = match settings.active_tool {
                SpeedtestTool::LibreSpeed => {
                    (self.librespeed_ctrl.state, self.librespeed_ctrl.is_active())
                }
                SpeedtestTool::Iperf3 => (self.iperf3_ctrl.state, self.iperf3_ctrl.is_active()),
                SpeedtestTool::Iperf3Server => (TaskState::Idle, false),
            };
            if !active {
                if ui.button(t!("common.start")).clicked() {
                    self.start_active(settings, history, rt);
                }
            } else if ui.button(t!("common.stop")).clicked() {
                match settings.active_tool {
                    SpeedtestTool::LibreSpeed => self.librespeed_ctrl.stop(),
                    SpeedtestTool::Iperf3 => self.iperf3_ctrl.stop(),
                    SpeedtestTool::Iperf3Server => {}
                }
            }
            state_badge(ui, state);
            if active {
                ui.spinner();
            }
        });
        ui.weak(t!("speedtest.authorized_hint"));
    }

    fn start_active(
        &mut self,
        settings: &SpeedtestSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
    ) {
        match settings.active_tool {
            SpeedtestTool::LibreSpeed => {
                if self.librespeed_ctrl.is_active() {
                    return;
                }
                history_input::record_fields(
                    history,
                    &[(LIBRESPEED_URL_KEY, &settings.librespeed.custom_url)],
                );
                self.librespeed.start();
                let settings = settings.librespeed.clone();
                self.librespeed_ctrl.start(rt, move |handle| async move {
                    net_tools_core::net::librespeed::run_test(&handle, &settings).await;
                });
            }
            SpeedtestTool::Iperf3Server => {}
            SpeedtestTool::Iperf3 => {
                if self.iperf3_ctrl.is_active() {
                    return;
                }
                if settings.iperf3.host.trim().is_empty() {
                    self.iperf3.error = Some((t!("speedtest.host_required").to_string(), None));
                    return;
                }
                history_input::record_fields(history, &[(IPERF3_HOST_KEY, &settings.iperf3.host)]);
                self.iperf3.start();
                self.iperf3.live_phase = if settings.iperf3.reverse {
                    SpeedPhase::Download
                } else {
                    SpeedPhase::Upload
                };
                let settings = settings.iperf3.clone();
                self.iperf3_ctrl.start(rt, move |handle| async move {
                    speedtest_worker::run_iperf3(&handle, &settings).await;
                });
            }
        }
    }

    fn drain(&mut self) {
        for event in self.server_ctrl.drain() {
            match event {
                ProbeEvent::LibreSpeedServers(servers) => {
                    self.servers = servers;
                    self.librespeed.error = None;
                }
                ProbeEvent::Error { message, hint } => {
                    self.librespeed.error = Some((message, hint));
                }
                _ => {}
            }
        }
        for event in self.librespeed_ctrl.drain() {
            match event {
                ProbeEvent::SpeedProgress(progress) => {
                    self.librespeed
                        .apply_progress(progress, SpeedPhase::Download);
                }
                ProbeEvent::SpeedResult(result) => self.librespeed.apply_result(result),
                ProbeEvent::Info(message) => self.librespeed.notice = Some(message),
                ProbeEvent::Error { message, hint } => {
                    self.librespeed.error = Some((message, hint))
                }
                _ => {}
            }
        }
        for event in self.iperf3_server_ctrl.drain() {
            match event {
                ProbeEvent::Iperf3Servers(servers) => {
                    self.iperf3_servers = servers;
                    self.iperf3.error = None;
                }
                ProbeEvent::Error { message, hint } => {
                    self.iperf3.error = Some((message, hint));
                }
                _ => {}
            }
        }
        for event in self.iperf3_ctrl.drain() {
            match event {
                ProbeEvent::SpeedProgress(progress) => {
                    self.iperf3.apply_progress(progress, self.iperf3.live_phase);
                }
                ProbeEvent::SpeedResult(result) => self.iperf3.apply_result(result),
                ProbeEvent::Info(message) => self.iperf3.notice = Some(message),
                ProbeEvent::Error { message, hint } => self.iperf3.error = Some((message, hint)),
                _ => {}
            }
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, tool: SpeedtestTool) {
        match result_toolbar(ui) {
            ToolbarAction::Copy => ui.ctx().copy_text(self.to_csv(tool)),
            ToolbarAction::ExportCsv => {
                crate::ui::export::save_file("speedtest", "csv", &self.to_csv(tool))
            }
            ToolbarAction::ExportJson => {
                crate::ui::export::save_file("speedtest", "json", &self.to_json(tool))
            }
            ToolbarAction::ExportHtml => {
                crate::ui::export::save_file("speedtest", "html", &self.to_html(tool))
            }
            ToolbarAction::Clear => match tool {
                SpeedtestTool::LibreSpeed => self.librespeed.clear(),
                SpeedtestTool::Iperf3 => self.iperf3.clear(),
                SpeedtestTool::Iperf3Server => {}
            },
            ToolbarAction::None => {}
        }
    }

    fn result_ui(&self, ui: &mut egui::Ui, tool: SpeedtestTool) {
        let state = match tool {
            SpeedtestTool::LibreSpeed => &self.librespeed,
            SpeedtestTool::Iperf3 => &self.iperf3,
            SpeedtestTool::Iperf3Server => &self.librespeed,
        };
        if state.result.is_none() && state.progress.is_none() {
            ui.vertical_centered(|ui| {
                ui.add_space(48.0);
                ui.weak(t!("speedtest.empty"));
            });
            return;
        }

        let (phase, elapsed, total) = if let Some(progress) = &state.progress {
            (progress.phase, progress.elapsed_s, progress.total_s)
        } else if let Some(result) = &state.result {
            (
                SpeedPhase::Done,
                result.elapsed_ms / 1000.0,
                result.elapsed_ms / 1000.0,
            )
        } else {
            (SpeedPhase::Idle, 0.0, 0.0)
        };

        ui.vertical_centered(|ui| {
            let phase_label = phase_label(phase);
            let elapsed_label = if total > 0.0 {
                format!("{} · {:.1}s / {:.1}s", phase_label, elapsed, total)
            } else {
                format!("{} · {:.1}s", phase_label, elapsed)
            };
            ui.label(egui::RichText::new(elapsed_label).small().weak());
        });

        ui.add_space(6.0);
        self.metrics_ui(ui, tool, state);
        if tool == SpeedtestTool::Iperf3 {
            ui.vertical_centered(|ui| {
                ui.weak(t!("speedtest.iperf3_metrics_hint"));
            });
        }

        let samples = if !state.samples.is_empty() {
            &state.samples
        } else if let Some(result) = &state.result {
            &result.samples
        } else {
            &state.samples
        };
        if !samples.is_empty() {
            ui.add_space(10.0);
            crate::ui::chart::throughput_chart(ui, "speedtest_throughput", samples, 180.0);
        }
    }

    fn metrics_ui(&self, ui: &mut egui::Ui, tool: SpeedtestTool, state: &ToolState) {
        let result = state.result.as_ref();
        let live = state.progress.as_ref().map(|progress| {
            let phase = if tool == SpeedtestTool::Iperf3 {
                state.live_phase
            } else {
                progress.phase
            };
            (progress.current_mbps, phase)
        });
        let live_download = live
            .filter(|(_, phase)| *phase == SpeedPhase::Download)
            .map(|(mbps, _)| mbps);
        let live_upload = live
            .filter(|(_, phase)| *phase == SpeedPhase::Upload)
            .map(|(mbps, _)| mbps);
        let download = result.and_then(|r| r.download_mbps).or(live_download);
        let upload = result.and_then(|r| r.upload_mbps).or(live_upload);
        let ping = result.and_then(|r| r.ping_ms);
        let jitter = result.and_then(|r| r.jitter_ms);
        let retransmits = result.and_then(|r| r.retransmits);
        let lost = result.and_then(|r| r.lost_percent);
        let direction = result.map(|r| r.direction.as_str()).unwrap_or("-");

        let ping_label = if tool == SpeedtestTool::Iperf3 {
            t!("speedtest.rtt")
        } else {
            t!("speedtest.ping")
        };
        let missing = if tool == SpeedtestTool::Iperf3 {
            t!("speedtest.not_available").to_string()
        } else {
            "-".to_string()
        };

        ui.columns(4, |columns| {
            metric_card(
                &mut columns[0],
                ping_label,
                &ping.map_or_else(|| missing.clone(), |v| format!("{v:.1} ms")),
            );
            metric_card(
                &mut columns[1],
                t!("speedtest.jitter"),
                &jitter.map_or_else(|| missing.clone(), |v| format!("{v:.1} ms")),
            );
            match tool {
                SpeedtestTool::Iperf3Server => {}
                SpeedtestTool::LibreSpeed => {
                    metric_card(
                        &mut columns[2],
                        t!("speedtest.download"),
                        &download.map_or("-".into(), |v| format!("{v:.1} Mbps")),
                    );
                    metric_card(
                        &mut columns[3],
                        t!("speedtest.upload"),
                        &upload.map_or("-".into(), |v| format!("{v:.1} Mbps")),
                    );
                }
                SpeedtestTool::Iperf3 => {
                    let protocol = result.map(|r| r.protocol.as_str()).unwrap_or("");
                    if protocol == "UDP" {
                        metric_card(
                            &mut columns[2],
                            t!("speedtest.lost"),
                            &lost.map_or("-".into(), |v| format!("{v:.2} %")),
                        );
                    } else {
                        metric_card(
                            &mut columns[2],
                            t!("speedtest.retransmits"),
                            &retransmits.map_or("-".into(), |v| v.to_string()),
                        );
                    }
                    metric_card(&mut columns[3], t!("speedtest.direction"), direction);
                }
            }
        });
    }

    fn history_ui(&self, ui: &mut egui::Ui, tool: SpeedtestTool) {
        let state = match tool {
            SpeedtestTool::LibreSpeed => &self.librespeed,
            SpeedtestTool::Iperf3 => &self.iperf3,
            SpeedtestTool::Iperf3Server => &self.librespeed,
        };
        ui.label(egui::RichText::new(t!("speedtest.history")).strong());
        if state.history.is_empty() {
            ui.weak(t!("speedtest.no_history"));
            return;
        }
        let ping_header = if tool == SpeedtestTool::Iperf3 {
            t!("speedtest.rtt")
        } else {
            t!("speedtest.ping")
        };
        let headers = [
            t!("common.time"),
            t!("speedtest.server"),
            ping_header,
            t!("speedtest.jitter"),
            t!("speedtest.download"),
            t!("speedtest.upload"),
            t!("speedtest.retransmits"),
            t!("speedtest.lost"),
            t!("speedtest.direction"),
        ];
        table_fixed_rows(
            ui,
            &headers,
            state.history.len(),
            VISIBLE_HISTORY_ROWS,
            |index, row| {
                let result = &state.history[index];
                row.col(|ui| {
                    ui.label(&result.started_at);
                });
                row.col(|ui| {
                    ui.label(&result.server);
                });
                row.col(|ui| {
                    ui.label(result.ping_ms.map_or("-".into(), |v| format!("{v:.1}")));
                });
                row.col(|ui| {
                    ui.label(result.jitter_ms.map_or("-".into(), |v| format!("{v:.2}")));
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .download_mbps
                            .map_or("-".into(), |v| format!("{v:.1}")),
                    );
                });
                row.col(|ui| {
                    ui.label(result.upload_mbps.map_or("-".into(), |v| format!("{v:.1}")));
                });
                row.col(|ui| {
                    ui.label(result.retransmits.map_or("-".into(), |v| v.to_string()));
                });
                row.col(|ui| {
                    ui.label(
                        result
                            .lost_percent
                            .map_or("-".into(), |v| format!("{v:.2}")),
                    );
                });
                row.col(|ui| {
                    ui.label(&result.direction);
                });
            },
        );
    }

    fn active_history(&self, tool: SpeedtestTool) -> &[SpeedResult] {
        match tool {
            SpeedtestTool::LibreSpeed => &self.librespeed.history,
            SpeedtestTool::Iperf3 => &self.iperf3.history,
            SpeedtestTool::Iperf3Server => &self.librespeed.history,
        }
    }

    pub fn to_csv(&self, tool: SpeedtestTool) -> String {
        let mut out = String::from(
            "time,tool,server,protocol,direction,ping_ms,jitter_ms,download_mbps,upload_mbps,retransmits,lost_percent,elapsed_ms\n",
        );
        for result in self.active_history(tool) {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{:.1}\n",
                crate::ui::export::csv_field(&result.started_at),
                crate::ui::export::csv_field(result.tool.label()),
                crate::ui::export::csv_field(&result.server),
                crate::ui::export::csv_field(&result.protocol),
                crate::ui::export::csv_field(&result.direction),
                result.ping_ms.map_or("-".into(), |v| format!("{v:.2}")),
                result.jitter_ms.map_or("-".into(), |v| format!("{v:.2}")),
                result
                    .download_mbps
                    .map_or("-".into(), |v| format!("{v:.2}")),
                result.upload_mbps.map_or("-".into(), |v| format!("{v:.2}")),
                result.retransmits.map_or("-".into(), |v| v.to_string()),
                result
                    .lost_percent
                    .map_or("-".into(), |v| format!("{v:.2}")),
                result.elapsed_ms,
            ));
        }
        out
    }

    pub fn to_json(&self, tool: SpeedtestTool) -> String {
        serde_json::to_string_pretty(self.active_history(tool)).unwrap_or_default()
    }

    pub fn to_html(&self, tool: SpeedtestTool) -> String {
        crate::ui::export::csv_to_html(&self.to_csv(tool))
    }
}

fn phase_label(phase: SpeedPhase) -> String {
    match phase {
        SpeedPhase::Idle => t!("speedtest.phase_idle").to_string(),
        SpeedPhase::Latency => t!("speedtest.phase_latency").to_string(),
        SpeedPhase::Download => t!("speedtest.phase_download").to_string(),
        SpeedPhase::Upload => t!("speedtest.phase_upload").to_string(),
        SpeedPhase::Connecting => t!("speedtest.phase_connecting").to_string(),
        SpeedPhase::Testing => t!("speedtest.phase_testing").to_string(),
        SpeedPhase::Done => t!("speedtest.phase_done").to_string(),
    }
}

pub(crate) fn metric_card(ui: &mut egui::Ui, label: impl ToString, value: &str) {
    let label = label.to_string();
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(32, 38, 48))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.set_min_width(120.0);
            ui.label(
                egui::RichText::new(label)
                    .small()
                    .color(egui::Color32::WHITE),
            );
            ui.label(
                egui::RichText::new(value)
                    .monospace()
                    .size(16.0)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
        });
}
