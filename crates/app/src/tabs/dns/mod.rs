//! DNS tab: structured query, propagation comparison, latency benchmark and
//! domain health checks.

mod benchmark;
mod health;
mod propagation;
mod query;
mod resolver_editor;

use eframe::egui;
use net_tools_core::config::{DnsSettings, InputHistory};
use net_tools_core::control::TaskController;
use net_tools_core::model::{
    DnsBenchmarkReport, DnsPropagationReport, DnsQueryResult, DnsRunProgress, DnsTool,
    DomainHealthReport, ProbeEvent,
};
use rust_i18n::t;

/// State owned by the DNS tab.
pub struct DnsTab {
    pub query_ctrl: TaskController<ProbeEvent>,
    pub propagation_ctrl: TaskController<ProbeEvent>,
    pub benchmark_ctrl: TaskController<ProbeEvent>,
    pub health_ctrl: TaskController<ProbeEvent>,
    pub query_result: Option<DnsQueryResult>,
    /// Raw text produced by the latest query or trace.
    pub output: String,
    pub error: Option<(String, Option<String>)>,
    pub progress: Option<DnsRunProgress>,
    pub propagation: Option<DnsPropagationReport>,
    pub benchmark: Option<DnsBenchmarkReport>,
    pub health: Option<DomainHealthReport>,
    pub propagation_selected: Option<usize>,
    pub benchmark_selected: Option<usize>,
    pub health_selected: Option<usize>,
}

impl Default for DnsTab {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTab {
    pub fn new() -> Self {
        Self {
            query_ctrl: TaskController::new(),
            propagation_ctrl: TaskController::new(),
            benchmark_ctrl: TaskController::new(),
            health_ctrl: TaskController::new(),
            query_result: None,
            output: String::new(),
            error: None,
            progress: None,
            propagation: None,
            benchmark: None,
            health: None,
            propagation_selected: None,
            benchmark_selected: None,
            health_selected: None,
        }
    }

    pub fn reset(&mut self) {
        self.query_result = None;
        self.output.clear();
        self.error = None;
        self.progress = None;
        self.propagation = None;
        self.benchmark = None;
        self.health = None;
        self.propagation_selected = None;
        self.benchmark_selected = None;
        self.health_selected = None;
    }

    /// Stop background work and drop live results when another tab is selected.
    pub fn clear_on_hide(&mut self) {
        for ctrl in [
            &mut self.query_ctrl,
            &mut self.propagation_ctrl,
            &mut self.benchmark_ctrl,
            &mut self.health_ctrl,
        ] {
            if ctrl.is_active() {
                ctrl.stop();
            }
            let _ = ctrl.drain();
        }
        self.reset();
    }

    pub fn drain(&mut self) {
        let events: Vec<ProbeEvent> = self
            .query_ctrl
            .drain()
            .into_iter()
            .chain(self.propagation_ctrl.drain())
            .chain(self.benchmark_ctrl.drain())
            .chain(self.health_ctrl.drain())
            .collect();
        for event in events {
            self.apply_event(event);
        }
    }

    fn apply_event(&mut self, event: ProbeEvent) {
        match event {
            ProbeEvent::DnsText(text) => self.output.push_str(&text),
            ProbeEvent::DnsQuery(result) => {
                self.output = result.raw.clone();
                self.query_result = Some(*result);
            }
            ProbeEvent::DnsProgress(progress) => self.progress = Some(progress),
            ProbeEvent::DnsPropagation(report) => {
                self.propagation_selected = if report.results.is_empty() {
                    None
                } else {
                    Some(0)
                };
                self.propagation = Some(*report);
                self.progress = None;
            }
            ProbeEvent::DnsBenchmark(report) => {
                self.benchmark_selected = if report.rows.is_empty() {
                    None
                } else {
                    Some(0)
                };
                self.benchmark = Some(*report);
                self.progress = None;
            }
            ProbeEvent::DnsHealth(report) => {
                self.health = Some(*report);
                self.progress = None;
            }
            ProbeEvent::Error { message, hint } => self.error = Some((message, hint)),
            _ => {}
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &mut DnsSettings,
        history: &mut InputHistory,
        rt: &tokio::runtime::Handle,
        settings_expanded: bool,
    ) -> bool {
        self.drain();
        if self.query_ctrl.is_active()
            || self.propagation_ctrl.is_active()
            || self.benchmark_ctrl.is_active()
            || self.health_ctrl.is_active()
        {
            ui.ctx().request_repaint();
        }

        let previous = s.active_tool;
        self.tool_selector(ui, s);
        if previous != s.active_tool {
            self.stop_tool(previous);
        }

        match s.active_tool {
            DnsTool::Query => query::ui(self, ui, s, history, rt, settings_expanded),
            DnsTool::Propagation => {
                propagation::ui(self, ui, &mut s.propagation, history, rt, settings_expanded)
            }
            DnsTool::Benchmark => {
                benchmark::ui(self, ui, &mut s.benchmark, history, rt, settings_expanded)
            }
            DnsTool::Health => health::ui(self, ui, &mut s.health, history, rt, settings_expanded),
        }
    }

    /// Secondary tab row shown above the settings/results columns.
    fn tool_selector(&self, ui: &mut egui::Ui, settings: &mut DnsSettings) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(
                &mut settings.active_tool,
                DnsTool::Query,
                t!("dns.tools.query"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                DnsTool::Propagation,
                t!("dns.tools.propagation"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                DnsTool::Benchmark,
                t!("dns.tools.benchmark"),
            );
            ui.selectable_value(
                &mut settings.active_tool,
                DnsTool::Health,
                t!("dns.tools.health"),
            );
        });
    }

    fn stop_tool(&mut self, tool: DnsTool) {
        let ctrl = match tool {
            DnsTool::Query => &mut self.query_ctrl,
            DnsTool::Propagation => &mut self.propagation_ctrl,
            DnsTool::Benchmark => &mut self.benchmark_ctrl,
            DnsTool::Health => &mut self.health_ctrl,
        };
        if ctrl.is_active() {
            ctrl.stop();
            let _ = ctrl.drain();
        }
        self.progress = None;
    }
}

/// Protocol selector shared by all DNS sub-tools.
///
/// The settings panel sets a large default interaction width for form fields.
/// Selectable labels inherit that width, which would spread the four protocol
/// buttons across the panel. Reset the local interaction width and spacing so
/// the buttons stay compact and grouped together.
pub(crate) fn protocol_selector(
    ui: &mut egui::Ui,
    protocol: &mut net_tools_core::model::DnsProtocol,
) {
    use net_tools_core::model::DnsProtocol;
    ui.horizontal(|ui| {
        ui.spacing_mut().interact_size.x = 0.0;
        ui.spacing_mut().item_spacing.x = 4.0;
        for value in [
            DnsProtocol::Udp,
            DnsProtocol::Tcp,
            DnsProtocol::Dot,
            DnsProtocol::Doh,
            DnsProtocol::Quic,
        ] {
            ui.selectable_value(protocol, value, value.label());
        }
    });
}
