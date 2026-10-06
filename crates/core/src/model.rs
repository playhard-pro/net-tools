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
    /// The task finished naturally.
    Finished,
}
