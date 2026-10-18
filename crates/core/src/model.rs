//! Shared types: probe results, events, and enums.

use serde::{Deserialize, Serialize};

/// IP version selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum IpVersion {
    #[default]
    Auto,
    V4,
    V6,
}

impl IpVersion {
    pub fn label(&self) -> &'static str {
        match self {
            IpVersion::Auto => "Auto",
            IpVersion::V4 => "IPv4",
            IpVersion::V6 => "IPv6",
        }
    }
}

/// Probe mode for ping / mtr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProbeMode {
    #[default]
    Icmp,
    Udp,
}

impl ProbeMode {
    pub fn label(&self) -> &'static str {
        match self {
            ProbeMode::Icmp => "ICMP",
            ProbeMode::Udp => "UDP",
        }
    }
}

/// Port scanning technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ScanMode {
    #[default]
    TcpConnect,
    Syn,
    Udp,
}

impl ScanMode {
    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::TcpConnect => "TCP connect",
            ScanMode::Syn => "SYN",
            ScanMode::Udp => "UDP",
        }
    }
}

/// Port list preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PortPreset {
    #[default]
    Custom,
    Top100,
    Top1000,
    All,
}

impl PortPreset {
    pub fn label(&self) -> &'static str {
        match self {
            PortPreset::Custom => "custom",
            PortPreset::Top100 => "top 100",
            PortPreset::Top1000 => "top 1000",
            PortPreset::All => "all (1-65535)",
        }
    }
}

/// A single ping sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSample {
    pub seq: u64,
    /// Local wall-clock time of the probe, down to milliseconds.
    pub time: String,
    /// Round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// Reply TTL, when available.
    pub ttl: Option<u8>,
    /// Responder address.
    pub from: String,
    /// Reply payload size in bytes.
    pub size: usize,
}

/// One responder observed at an MTR hop.
///
/// A single hop can be answered by several routers (load balancing / ECMP), so
/// a hop owns a list of nodes instead of a single address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopNode {
    /// Address of the responder.
    pub addr: String,
    /// PTR name of `addr`, when reverse DNS is enabled and a name exists.
    pub reverse: Option<String>,
}

/// Per-hop statistics for MTR.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopStats {
    /// One-based hop index.
    pub hop: u8,
    /// Responders seen at this hop, in first-seen order.
    pub nodes: Vec<HopNode>,
    /// Number of probes sent.
    pub sent: u32,
    /// Number of probes lost.
    pub lost: u32,
    /// Most recent RTT in milliseconds.
    pub last_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub best_ms: Option<f64>,
    pub worst_ms: Option<f64>,
    pub stdev_ms: Option<f64>,
    /// Whether the target host was reached at this hop.
    pub reached: bool,
}

impl HopStats {
    /// Fraction of probes that were lost.
    pub fn loss_ratio(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            self.lost as f64 / self.sent as f64
        }
    }

    /// Number of probes that were answered.
    pub fn success_count(&self) -> u32 {
        self.sent.saturating_sub(self.lost)
    }

    /// All responder addresses as one comma separated string for display. A
    /// hop without any response is shown as a wildcard.
    pub fn addr_text(&self) -> String {
        if self.nodes.is_empty() {
            "*".to_string()
        } else {
            self.nodes
                .iter()
                .map(|n| n.addr.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    /// All PTR names as one comma separated string for display. Falls back to a
    /// dash when no name is known.
    pub fn reverse_text(&self) -> String {
        let names: Vec<&str> = self
            .nodes
            .iter()
            .filter_map(|n| n.reverse.as_deref())
            .collect();
        if names.is_empty() {
            "-".to_string()
        } else {
            names.join(", ")
        }
    }
}

/// Result of a single HTTP probe.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResult {
    pub seq: u64,
    /// Local wall-clock time of the probe, down to milliseconds.
    pub time: String,
    /// Whether the result matched the expectations (status / keyword).
    pub ok: bool,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub dns_ms: f64,
    pub connect_ms: f64,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: f64,
    pub total_ms: f64,
    pub body_bytes: usize,
    pub error: Option<String>,
}

/// Transport protocol of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl PortProtocol {
    pub fn label(&self) -> &'static str {
        match self {
            PortProtocol::Tcp => "TCP",
            PortProtocol::Udp => "UDP",
        }
    }
}

/// State of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
}

impl PortState {
    pub fn label(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenOrFiltered => "open|filtered",
        }
    }
}

/// Result of scanning a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub host: String,
    pub port: u16,
    pub protocol: PortProtocol,
    pub state: PortState,
    pub banner: Option<String>,
    pub service: Option<String>,
}

/// Progress of a running scan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scanned: u64,
    pub total: u64,
    pub open: u64,
}

/// Result of one IP insight API query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInsightResult {
    /// Display name of the API provider.
    pub provider: String,
    /// Full request URL.
    pub url: String,
    /// HTTP status code, when a response was received.
    pub status: Option<u16>,
    /// Request duration in milliseconds.
    pub elapsed_ms: f64,
    /// Parsed JSON body, when the response contained valid JSON.
    pub data: Option<serde_json::Value>,
    /// Raw response body, kept only when it could not be parsed as JSON.
    pub raw: Option<String>,
    /// Error message, when the query failed.
    pub error: Option<String>,
}

impl IpInsightResult {
    /// A placeholder for a provider that has not answered yet.
    pub fn pending(provider: &str) -> Self {
        Self {
            provider: provider.to_string(),
            url: String::new(),
            status: None,
            elapsed_ms: 0.0,
            data: None,
            raw: None,
            error: None,
        }
    }

    /// Whether the provider is still waiting for a response.
    pub fn is_pending(&self) -> bool {
        self.status.is_none() && self.error.is_none()
    }
}

/// Result of a single RDAP lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupResult {
    /// Target that actually produced this response (may be a parent domain when
    /// the original target returned no data).
    pub target: String,
    /// Original user supplied target (domain or IP).
    pub original_target: String,
    /// Object kind: `domain` or `ip`.
    pub kind: String,
    /// URL of the authoritative RDAP response after redirects.
    pub url: String,
    /// HTTP status code, when a response was received.
    pub status: Option<u16>,
    /// Request duration in milliseconds.
    pub elapsed_ms: f64,
    /// Parsed RDAP JSON document, when the response contained valid JSON.
    pub data: Option<serde_json::Value>,
    /// Raw response body, kept only when it could not be parsed as JSON.
    pub raw: Option<String>,
    /// Error message, when the query failed.
    pub error: Option<String>,
}

impl LookupResult {
    /// Build a failed result. The HTTP status is kept when a response was
    /// received, so callers can still tell a "not found" apart from a transport
    /// failure even when the body could not be read.
    pub fn failed(
        target: &str,
        kind: &str,
        url: &str,
        status: Option<u16>,
        elapsed_ms: f64,
        message: String,
    ) -> Self {
        Self {
            target: target.to_string(),
            original_target: target.to_string(),
            kind: kind.to_string(),
            url: url.to_string(),
            status,
            elapsed_ms,
            data: None,
            raw: None,
            error: Some(message),
        }
    }

    /// Build a "not found" result (HTTP 404 without a usable body).
    pub fn not_found(target: &str, kind: &str, url: &str, elapsed_ms: f64) -> Self {
        Self {
            target: target.to_string(),
            original_target: target.to_string(),
            kind: kind.to_string(),
            url: url.to_string(),
            status: Some(404),
            elapsed_ms,
            data: None,
            raw: None,
            error: None,
        }
    }
}

/// Result of a single NTP query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpResult {
    /// Target server as entered by the user.
    pub target: String,
    /// Resolved server address including the port.
    pub server_addr: String,
    pub stratum: u8,
    /// Leap indicator field (0 = synchronized, 3 = unsynchronized).
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    /// log2 of the server clock precision in seconds.
    pub precision: i8,
    pub root_delay_ms: f64,
    pub root_dispersion_ms: f64,
    pub reference_id: String,
    /// Reference timestamp formatted as UTC.
    pub reference_time: String,
    /// Estimated server-minus-local clock offset in milliseconds.
    pub offset_ms: f64,
    /// Round-trip delay in milliseconds.
    pub delay_ms: f64,
    /// Estimated server Unix time at the moment the response was received.
    /// The UI adds elapsed monotonic time to keep the clock running.
    pub server_time_unix: f64,
    /// Time spent on the request in milliseconds.
    pub elapsed_ms: f64,
}

/// Transport protocol used by the iperf3 tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Iperf3Protocol {
    #[default]
    Tcp,
    Udp,
}

impl Iperf3Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Iperf3Protocol::Tcp => "TCP",
            Iperf3Protocol::Udp => "UDP",
        }
    }
}

/// Speed test tool shown inside the Speedtest tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SpeedtestTool {
    #[default]
    LibreSpeed,
    Iperf3,
    Iperf3Server,
}

impl SpeedtestTool {
    pub fn label(&self) -> &'static str {
        match self {
            SpeedtestTool::LibreSpeed => "LibreSpeed",
            SpeedtestTool::Iperf3 => "iperf3",
            SpeedtestTool::Iperf3Server => "iperf3 server",
        }
    }
}

/// Phase of a speed test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SpeedPhase {
    #[default]
    Idle,
    Latency,
    Download,
    Upload,
    Connecting,
    Testing,
    Done,
}

impl SpeedPhase {
    pub fn label(&self) -> &'static str {
        match self {
            SpeedPhase::Idle => "idle",
            SpeedPhase::Latency => "latency",
            SpeedPhase::Download => "download",
            SpeedPhase::Upload => "upload",
            SpeedPhase::Connecting => "connecting",
            SpeedPhase::Testing => "testing",
            SpeedPhase::Done => "done",
        }
    }
}

/// A public iperf3 server entry from the online server list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Iperf3Server {
    #[serde(rename = "IP/HOST", default)]
    pub host: String,
    /// Port or port range as published by the list, for example `5201-5209`.
    #[serde(rename = "PORT", default)]
    pub port: String,
    /// Supported option flags published by the list, for example `-R,-u`.
    #[serde(rename = "OPTIONS", default)]
    pub options: String,
    #[serde(rename = "GB/S", default)]
    pub bandwidth: String,
    #[serde(rename = "CONTINENT", default)]
    pub continent: String,
    #[serde(rename = "COUNTRY", default)]
    pub country: String,
    #[serde(rename = "SITE", default)]
    pub site: String,
    #[serde(rename = "PROVIDER", default)]
    pub provider: String,
}

impl Iperf3Server {
    /// First concrete port of the published port field, falling back to the
    /// standard iperf3 port when the field cannot be parsed.
    pub fn first_port(&self) -> u16 {
        self.port
            .split('-')
            .next()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(5201)
    }

    /// Human readable label for the server drop-down.
    pub fn label(&self) -> String {
        let location = if self.site.is_empty() {
            self.country.clone()
        } else if self.country.is_empty() {
            self.site.clone()
        } else {
            format!("{}, {}", self.site, self.country)
        };
        let mut label = format!("{}:{}", self.host, self.port);
        if !self.provider.is_empty() || !location.is_empty() {
            let detail = [self.provider.as_str(), location.as_str()]
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
            if !detail.is_empty() {
                label.push_str(&format!("  ({detail})"));
            }
        }
        label
    }
}

/// One throughput sample plotted by the Speedtest tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedSample {
    /// Seconds since the test started.
    pub elapsed_s: f64,
    /// Throughput of this sample in megabits per second.
    pub mbps: f64,
    pub phase: SpeedPhase,
}

/// Live progress of a speed test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedProgress {
    pub tool: SpeedtestTool,
    pub phase: SpeedPhase,
    /// Current interval throughput in megabits per second.
    pub current_mbps: f64,
    /// Seconds elapsed in the current phase.
    pub elapsed_s: f64,
    /// Configured duration of the current phase in seconds.
    pub total_s: f64,
    /// Completion ratio in the range 0.0 to 1.0.
    pub progress: f32,
}

/// Final result of one speed test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedResult {
    pub tool: SpeedtestTool,
    /// Server name or address shown to the user.
    pub server: String,
    /// TCP, UDP, HTTP or another transport description.
    pub protocol: String,
    /// Direction description for iperf3, or a summary for LibreSpeed.
    pub direction: String,
    pub ping_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    /// TCP retransmissions reported by iperf3.
    pub retransmits: Option<u64>,
    /// UDP packet loss percentage reported by iperf3.
    pub lost_percent: Option<f64>,
    /// Local wall-clock start time.
    pub started_at: String,
    pub elapsed_ms: f64,
    /// Throughput samples collected during the run.
    pub samples: Vec<SpeedSample>,
    pub error: Option<String>,
}

/// Live metrics of a test currently served by the built-in iperf3 server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iperf3ServerProgress {
    pub peer: String,
    pub protocol: String,
    pub direction: String,
    pub elapsed_s: f64,
    pub total_s: f64,
    pub current_mbps: f64,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_percent: Option<f64>,
}

/// Result of one test served by the built-in iperf3 server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iperf3ServerResult {
    /// Local wall-clock time when the test finished.
    pub time: String,
    /// Client address reported on the control connection.
    pub peer: String,
    pub protocol: String,
    /// Direction from the server's point of view.
    pub direction: String,
    pub duration_s: f64,
    /// Throughput the server sent to the client.
    pub sent_mbps: Option<f64>,
    /// Throughput the server received from the client.
    pub received_mbps: Option<f64>,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_percent: Option<f64>,
    pub error: Option<String>,
}

/// A LibreSpeed backend server from the public server list or a custom URL.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LibreSpeedServer {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub server: String,
    #[serde(default, rename = "dlURL")]
    pub download_url: String,
    #[serde(default, rename = "ulURL")]
    pub upload_url: String,
    #[serde(default, rename = "pingURL")]
    pub ping_url: String,
    #[serde(default, rename = "getIpURL")]
    pub get_ip_url: String,
    #[serde(default, rename = "sponsorName")]
    pub sponsor_name: String,
    #[serde(default, rename = "sponsorURL")]
    pub sponsor_url: String,
}

/// Unified event streamed from a probe task back to the UI.
#[derive(Debug, Clone)]
pub enum ProbeEvent {
    /// Informational message (resolved address, etc.).
    Info(String),
    /// Error with an optional actionable hint.
    Error {
        message: String,
        hint: Option<String>,
    },
    /// A ping sample.
    Latency(ProbeSample),
    /// A ping timeout.
    Timeout { seq: u64 },
    /// Updated MTR hop statistics.
    Hop(HopStats),
    /// An HTTP result.
    Http(HttpResult),
    /// A port result.
    Port(PortResult),
    /// Scan progress update.
    ScanProgress(ScanProgress),
    /// An IP insight API result.
    IpInsight(IpInsightResult),
    /// An RDAP lookup result.
    Lookup(LookupResult),
    /// A block of text emitted by the DNS query / trace task.
    DnsText(String),
    /// An NTP query result.
    Ntp(NtpResult),
    /// A speed test result.
    SpeedResult(SpeedResult),
    /// Live speed test progress.
    SpeedProgress(SpeedProgress),
    /// A refreshed LibreSpeed server list.
    LibreSpeedServers(Vec<LibreSpeedServer>),
    /// A refreshed public iperf3 server list.
    Iperf3Servers(Vec<Iperf3Server>),
    /// A test completed by the built-in iperf3 server.
    Iperf3ServerResult(Iperf3ServerResult),
    /// Live metrics of a test running on the built-in iperf3 server.
    Iperf3ServerProgress(Iperf3ServerProgress),
    /// The task finished naturally.
    Finished,
}
