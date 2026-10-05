//! Per-feature settings structs and the global application configuration.

use serde::{Deserialize, Serialize};

use crate::model::{IpVersion, PortPreset, ProbeMode, ScanMode};

/// Settings shared by ping and mtr.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonProbe {
    pub target: String,
    pub ip_version: IpVersion,
    /// Timeout for a single probe, in milliseconds.
    pub timeout_ms: u64,
    /// Delay between probes, in milliseconds.
    pub interval_ms: u64,
    /// Packet payload size in bytes.
    pub packet_size: usize,
    /// Whether to perform a PTR (reverse DNS) lookup.
    pub reverse_dns: bool,
}

impl Default for CommonProbe {
    fn default() -> Self {
        Self {
            target: "1.1.1.1".into(),
            ip_version: IpVersion::Auto,
            timeout_ms: 1000,
            interval_ms: 1000,
            packet_size: 56,
            reverse_dns: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingSettings {
    pub common: CommonProbe,
    pub mode: ProbeMode,
    /// Destination UDP port used in UDP mode.
    pub udp_port: u16,
}

impl Default for PingSettings {
    fn default() -> Self {
        Self {
            common: CommonProbe::default(),
            mode: ProbeMode::Icmp,
            udp_port: 33434,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtrSettings {
    pub common: CommonProbe,
    pub mode: ProbeMode,
    /// Maximum number of hops to probe.
    pub max_hops: u8,
    pub udp_port: u16,
}

impl Default for MtrSettings {
    fn default() -> Self {
        Self {
            common: CommonProbe::default(),
            mode: ProbeMode::Icmp,
            max_hops: 30,
            udp_port: 33434,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSettings {
    /// Full request URL.
    pub target: String,
    pub ip_version: IpVersion,
    pub timeout_ms: u64,
    pub interval_ms: u64,
    /// HTTP method (GET/HEAD/POST/PUT/DELETE/OPTIONS/PATCH).
    pub method: String,
    /// Custom request headers, one "Name: Value" per line.
    pub headers: String,
    /// Request body (for methods that carry one).
    pub body: String,
    pub follow_redirects: bool,
    pub verify_tls: bool,
    /// Expected status code; `None` disables the check.
    pub expect_status: Option<u16>,
    /// Expected keyword in the response body.
    pub expect_keyword: Option<String>,
    pub reverse_dns: bool,
}

impl Default for HttpSettings {
    fn default() -> Self {
        Self {
            target: "https://example.com".into(),
            ip_version: IpVersion::Auto,
            timeout_ms: 5000,
            interval_ms: 1000,
            method: "GET".into(),
            headers: String::new(),
            body: String::new(),
            follow_redirects: true,
            verify_tls: true,
            expect_status: None,
            expect_keyword: None,
            reverse_dns: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanSettings {
    /// Target hosts (comma separated).
    pub targets: String,
    /// Port expression, e.g. single ports, ranges and comma lists.
    pub ports: String,
    pub preset: PortPreset,
    pub mode: ScanMode,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub grab_banner: bool,
    pub ip_version: IpVersion,
    pub reverse_dns: bool,
}

impl Default for PortScanSettings {
    fn default() -> Self {
        Self {
            targets: "127.0.0.1".into(),
            ports: "22,80,443,8000-8100".into(),
            preset: PortPreset::Custom,
            mode: ScanMode::TcpConnect,
            concurrency: 256,
            timeout_ms: 1000,
            grab_banner: true,
            ip_version: IpVersion::Auto,
            reverse_dns: false,
        }
    }
}

/// Settings for the IP insight tab: a target IP queried against several online
/// geolocation APIs at once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInsightSettings {
    /// Target IP address.
    pub target: String,
    /// Timeout for a single API request, in milliseconds.
    pub timeout_ms: u64,
}

impl Default for IpInsightSettings {
    fn default() -> Self {
        Self {
            target: "1.1.1.1".into(),
            timeout_ms: 10_000,
        }
    }
}

/// Global application configuration (persisted to disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub language: String,
    pub ping: PingSettings,
    pub mtr: MtrSettings,
    pub http: HttpSettings,
    pub port_scan: PortScanSettings,
    /// Added after the first release, so older config files still load.
    #[serde(default)]
    pub ip_insight: IpInsightSettings,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            language: "en".into(),
            ping: PingSettings::default(),
            mtr: MtrSettings::default(),
            http: HttpSettings::default(),
            port_scan: PortScanSettings::default(),
            ip_insight: IpInsightSettings::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_config_roundtrip() {
        let cfg = AppConfig::default();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: AppConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.language, cfg.language);
        assert_eq!(back.ping.udp_port, cfg.ping.udp_port);
        assert_eq!(back.mtr.max_hops, cfg.mtr.max_hops);
        assert_eq!(back.http.method, cfg.http.method);
        assert_eq!(back.port_scan.concurrency, cfg.port_scan.concurrency);
        assert_eq!(back.ip_insight.target, cfg.ip_insight.target);
    }

    #[test]
    fn settings_defaults_sane() {
        let p = PingSettings::default();
        assert!(p.common.timeout_ms > 0);
        assert!(p.common.interval_ms > 0);
        let m = MtrSettings::default();
        assert!(m.max_hops > 0);
        let ps = PortScanSettings::default();
        assert!(ps.concurrency > 0);
        let ii = IpInsightSettings::default();
        assert!(!ii.target.is_empty());
        assert!(ii.timeout_ms > 0);
    }
}
