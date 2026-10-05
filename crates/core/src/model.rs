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
    /// Round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// Reply TTL, when available.
    pub ttl: Option<u8>,
    /// Responder address.
    pub from: String,
    /// Reply payload size in bytes.
    pub size: usize,
}

/// Per-hop statistics for MTR.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopStats {
    /// One-based hop index.
    pub hop: u8,
    /// Address of this hop.
    pub addr: Option<String>,
    /// PTR name of this hop.
    pub reverse: Option<String>,
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
}

/// Result of a single HTTP probe.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResult {
    pub seq: u64,
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
    /// The task finished naturally.
    Finished,
}
