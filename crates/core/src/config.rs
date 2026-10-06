//! Per-feature settings structs and the global application configuration.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{IpVersion, PortPreset, ProbeMode, ScanMode};

/// Maximum number of remembered values kept for each input field. Older entries
/// are dropped once this many values are stored.
const HISTORY_LIMIT: usize = 20;

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

/// Settings for the Lookup tab: a single domain or IP queried through RDAP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupSettings {
    /// Target domain name or IP address.
    pub target: String,
    /// Timeout for the RDAP request, in milliseconds.
    pub timeout_ms: u64,
}

impl Default for LookupSettings {
    fn default() -> Self {
        Self {
            target: "example.com".into(),
            timeout_ms: 15_000,
        }
    }
}

/// Settings for the DNS tab: a dig-like query and an optional iterative trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    /// Domain name, or an IP address when querying PTR records.
    pub target: String,
    /// Record type as text, e.g. `A` or `MX`.
    pub record_type: String,
    /// Custom DNS server; empty means use the system resolver.
    pub server: String,
    /// Timeout for a single query, in milliseconds.
    pub timeout_ms: u64,
    /// Use TCP instead of UDP.
    pub force_tcp: bool,
    /// Run a full iterative trace from the root servers.
    pub trace: bool,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            target: "example.com".into(),
            record_type: "A".into(),
            server: String::new(),
            timeout_ms: 5000,
            force_tcp: false,
            trace: false,
        }
    }
}

/// Recently entered values for the editable text inputs, keyed by a stable
/// field id such as `ping.target`. Values are stored most recent first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InputHistory {
    #[serde(default)]
    fields: BTreeMap<String, Vec<String>>,
    /// Monotonic change counter; not persisted, only used to detect when the
    /// in-memory history changed and should be written back to disk.
    #[serde(skip)]
    revision: u64,
}

impl InputHistory {
    /// Values remembered for `key`, most recent first.
    pub fn entries(&self, key: &str) -> &[String] {
        self.fields.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Remember `value` for `key`. Surrounding whitespace is trimmed, empty
    /// values are ignored, duplicates move to the front, and the list is
    /// trimmed to the per-field limit.
    pub fn record(&mut self, key: &str, value: &str) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        let list = self.fields.entry(key.to_owned()).or_default();
        // Nothing to do when the value is already the most recent entry.
        if list.first().map(String::as_str) == Some(value) {
            return;
        }
        list.retain(|v| v != value);
        list.insert(0, value.to_owned());
        list.truncate(HISTORY_LIMIT);
        self.revision = self.revision.wrapping_add(1);
    }

    /// Remove a single remembered value at `index` for `key`.
    pub fn remove(&mut self, key: &str, index: usize) {
        if let Some(list) = self.fields.get_mut(key) {
            if index < list.len() {
                list.remove(index);
                self.revision = self.revision.wrapping_add(1);
            }
        }
    }

    /// Forget every value remembered for `key`.
    pub fn clear(&mut self, key: &str) {
        if let Some(list) = self.fields.get_mut(key) {
            if !list.is_empty() {
                list.clear();
                self.revision = self.revision.wrapping_add(1);
            }
        }
    }

    /// Current change counter. Compare a value captured at the start of a frame
    /// with the value afterwards to know whether persistence is needed.
    pub fn revision(&self) -> u64 {
        self.revision
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
    /// Added after the first release, so older config files still load.
    #[serde(default)]
    pub lookup: LookupSettings,
    /// Recently entered values for the editable text inputs.
    #[serde(default)]
    pub history: InputHistory,
    /// Added after the first release, so older config files still load.
    #[serde(default)]
    pub dns: DnsSettings,
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
            lookup: LookupSettings::default(),
            history: InputHistory::default(),
            dns: DnsSettings::default(),
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
        assert_eq!(back.lookup.target, cfg.lookup.target);
        assert_eq!(
            back.history.entries("ping.target"),
            cfg.history.entries("ping.target")
        );
        assert_eq!(back.dns.record_type, cfg.dns.record_type);
        assert_eq!(back.dns.force_tcp, cfg.dns.force_tcp);
    }

    #[test]
    fn history_records_dedupes_and_caps() {
        let mut history = InputHistory::default();
        // Duplicates are moved to the front instead of stored twice.
        history.record("k", "a");
        history.record("k", "b");
        history.record("k", "a");
        assert_eq!(history.entries("k"), &["a".to_string(), "b".to_string()]);
        // Whitespace-only values are ignored and values are trimmed.
        history.record("k", "   ");
        history.record("k", "  c  ");
        assert_eq!(history.entries("k")[0], "c");
        // Repeating more values than the limit keeps only the newest entries.
        for i in 0..HISTORY_LIMIT + 5 {
            history.record("k", &format!("v{i}"));
        }
        assert_eq!(history.entries("k").len(), HISTORY_LIMIT);
    }

    #[test]
    fn history_remove_and_clear() {
        let mut history = InputHistory::default();
        history.record("k", "a");
        history.record("k", "b");
        history.remove("k", 0);
        assert_eq!(history.entries("k"), &["a".to_string()]);
        history.clear("k");
        assert!(history.entries("k").is_empty());
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
        let lk = LookupSettings::default();
        assert!(!lk.target.is_empty());
        assert!(lk.timeout_ms > 0);
    }
}
