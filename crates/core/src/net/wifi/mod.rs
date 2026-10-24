//! Wi-Fi monitoring, platform adapters and channel analysis.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::WifiSettings;
use crate::control::ProbeHandle;
use crate::model::{
    ProbeEvent, WifiCurrentConnection, WifiCurrentSnapshot, WifiNetwork, WifiScanSnapshot,
    WifiSignalSample,
};
use crate::net::mac_vendor;

pub mod analysis;
pub mod ie;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(windows)]
use windows as platform;

/// Number of current-link samples retained for trend and stability analysis.
const MAX_HISTORY_SAMPLES: usize = 300;

/// Number of scan rounds an access point may be missing before it is dropped.
const MAX_MISSING_SCANS: u64 = 10;

/// Smallest accepted sample delay.
const MIN_SAMPLE_INTERVAL_MS: u64 = 200;

/// Smallest accepted full-scan delay.
const MIN_SCAN_INTERVAL_MS: u64 = 5_000;

/// Platform error with optional actionable hint.
#[derive(Debug, Clone)]
pub struct WifiError {
    pub message: String,
    pub hint: Option<String>,
}

impl WifiError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: Some(hint.into()),
        }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(message)
    }
}

/// Monitor state owned by the background task.
struct MonitorState {
    started: Instant,
    current: Option<WifiCurrentConnection>,
    last_bssid: String,
    history: Vec<WifiSignalSample>,
    access_points: HashMap<String, WifiNetwork>,
    scan_count: u64,
}

impl MonitorState {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            current: None,
            last_bssid: String::new(),
            history: Vec::new(),
            access_points: HashMap::new(),
            scan_count: 0,
        }
    }

    fn observe_current(
        &mut self,
        connection: Option<WifiCurrentConnection>,
        warnings: Vec<String>,
    ) -> WifiCurrentSnapshot {
        let bssid = connection
            .as_ref()
            .map(|connection| connection.bssid.clone())
            .unwrap_or_default();
        if bssid != self.last_bssid {
            self.history.clear();
            self.last_bssid = bssid;
        }

        if let Some(connection) = &connection {
            let sample = WifiSignalSample {
                elapsed_s: self.started.elapsed().as_secs_f64(),
                signal_dbm: connection.signal_dbm,
                signal_quality: connection.signal_quality,
                rx_rate_mbps: connection.rx_rate_mbps,
                tx_rate_mbps: connection.tx_rate_mbps,
            };
            self.history.push(sample);
            if self.history.len() > MAX_HISTORY_SAMPLES {
                self.history.remove(0);
            }
        } else {
            self.history.clear();
        }

        self.current = connection.clone();
        let stats = analysis::signal_stats(&self.history);
        WifiCurrentSnapshot {
            connection,
            history: self.history.clone(),
            stats,
            captured_at: crate::net::overview::captured_at_now(),
            warnings,
        }
    }

    fn observe_scan(
        &mut self,
        mut scanned: Vec<WifiNetwork>,
        warnings: Vec<String>,
    ) -> WifiScanSnapshot {
        self.scan_count = self.scan_count.saturating_add(1);
        let scan_count = self.scan_count;
        let current_bssid = self
            .current
            .as_ref()
            .map(|connection| connection.bssid.clone())
            .unwrap_or_default();

        let observed = scanned.clone();
        for network in &mut scanned {
            let bssid = network.bssid.clone();
            let existing = self.access_points.remove(&bssid);
            let mut entry = merge_observed(existing, network.clone(), scan_count, &current_bssid);
            if entry.vendor.is_none() {
                entry.vendor = lookup_vendor(&entry.bssid);
            }
            self.access_points.insert(bssid, entry);
        }

        // Drop access points that have not been seen for several scan rounds.
        self.access_points.retain(|_, network| {
            scan_count.saturating_sub(network.last_seen_scan) <= MAX_MISSING_SCANS
        });

        let mut networks = self.access_points.values().cloned().collect::<Vec<_>>();
        networks.sort_by(|left, right| {
            right
                .signal_dbm
                .unwrap_or(i32::MIN)
                .cmp(&left.signal_dbm.unwrap_or(i32::MIN))
                .then_with(|| left.ssid.cmp(&right.ssid))
                .then_with(|| left.bssid.cmp(&right.bssid))
        });

        if let Some(current) = self.current.as_mut() {
            if let Some(observed_current) = observed
                .iter()
                .find(|network| network.bssid == current.bssid)
            {
                merge_current_from_network(current, observed_current);
            }
        }

        let analysis = analysis::analyze(&observed, self.current.as_ref());
        WifiScanSnapshot {
            networks,
            channel_usage: analysis.channel_usage,
            recommendations: analysis.recommendations,
            summary: analysis.summary,
            scan_count,
            duration_ms: 0,
            captured_at: crate::net::overview::captured_at_now(),
            warnings,
        }
    }
}

fn merge_observed(
    existing: Option<WifiNetwork>,
    mut scanned: WifiNetwork,
    scan_count: u64,
    current_bssid: &str,
) -> WifiNetwork {
    let previous = existing.unwrap_or_else(|| WifiNetwork::new(scanned.bssid.clone()));
    let seen_scans = previous.seen_scans;
    let average_signal = previous.average_signal_dbm;
    let last_seen = previous.last_seen_scan;
    let previous_vendor = previous.vendor;

    if scanned.vendor.is_none() {
        scanned.vendor = previous_vendor;
    }
    scanned.seen_scans = seen_scans;
    scanned.average_signal_dbm = average_signal;
    scanned.last_seen_scan = last_seen;
    scanned.is_current = !current_bssid.is_empty() && scanned.bssid == current_bssid;
    scanned.observe(scan_count);
    scanned
}

fn merge_current_from_network(current: &mut WifiCurrentConnection, network: &WifiNetwork) {
    if current.frequency_mhz.is_none() {
        current.frequency_mhz = network.frequency_mhz;
    }
    if current.channel.is_none() {
        current.channel = network.channel;
    }
    if current.band == crate::model::WifiBand::Unknown {
        current.band = network.band;
    }
    if current.width_mhz.is_none() {
        current.width_mhz = network.width_mhz;
    }
    if current.standard == crate::model::WifiStandard::Unknown {
        current.standard = network.standard;
    }
    if current.security == crate::model::WifiSecurity::Unknown {
        current.security = network.security;
        current.security_detail = network.security_detail.clone();
    }
    current.snr_db = analysis::snr_db(current.signal_dbm, current.noise_dbm);
}

fn lookup_vendor(bssid: &str) -> Option<String> {
    mac_vendor::lookup_local(bssid)
        .ok()
        .flatten()
        .map(|result| result.vendor)
}

fn emit_error_once(
    handle: &ProbeHandle<ProbeEvent>,
    last_error: &mut Option<String>,
    error: WifiError,
) {
    if last_error.as_deref() == Some(error.message.as_str()) {
        return;
    }
    *last_error = Some(error.message.clone());
    handle.send(ProbeEvent::Error {
        message: error.message,
        hint: error.hint,
    });
}

/// Run the continuous Wi-Fi monitor until the task is cancelled.
pub async fn run_monitor(handle: ProbeHandle<ProbeEvent>, settings: WifiSettings) {
    let capabilities = platform::capabilities().await;
    let scan_supported = capabilities.scan_supported;
    handle.send(ProbeEvent::WifiCapabilities(capabilities));

    let sample_interval =
        Duration::from_millis(settings.sample_interval_ms.max(MIN_SAMPLE_INTERVAL_MS));
    let scan_interval = Duration::from_millis(settings.scan_interval_ms.max(MIN_SCAN_INTERVAL_MS));
    let mut state = MonitorState::new();
    let mut last_error = None;
    let mut next_scan = Instant::now();

    loop {
        if handle.is_cancelled() {
            break;
        }

        match platform::sample_current().await {
            Ok((connection, warnings)) => {
                let snapshot = state.observe_current(connection, warnings);
                handle.send(ProbeEvent::WifiCurrent(Box::new(snapshot)));
            }
            Err(error) => emit_error_once(&handle, &mut last_error, error),
        }

        if scan_supported && Instant::now() >= next_scan {
            let started = Instant::now();
            match platform::scan_networks().await {
                Ok((networks, warnings)) => {
                    let mut snapshot = state.observe_scan(networks, warnings);
                    snapshot.duration_ms = started.elapsed().as_millis() as u64;
                    handle.send(ProbeEvent::WifiScan(Box::new(snapshot)));
                }
                Err(error) => emit_error_once(&handle, &mut last_error, error),
            }
            next_scan = Instant::now() + scan_interval;
        }

        if handle.sleep(sample_interval).await {
            break;
        }
    }

    handle.send(ProbeEvent::Finished);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{WifiBand, WifiStandard};

    fn network(bssid: &str, signal: i32, scan: u64) -> WifiNetwork {
        let mut network = WifiNetwork::new(bssid);
        network.ssid = "test".into();
        network.signal_dbm = Some(signal);
        network.frequency_mhz = Some(2_437);
        network.band = WifiBand::Ghz24;
        network.channel = Some(6);
        network.standard = WifiStandard::Wifi4;
        network.last_seen_scan = scan;
        network
    }

    #[test]
    fn observations_update_history_and_seen_count() {
        let mut state = MonitorState::new();
        state.observe_scan(vec![network("aa", -60, 0)], Vec::new());
        state.observe_scan(vec![network("aa", -50, 0)], Vec::new());
        let snapshot = state.observe_scan(Vec::new(), Vec::new());
        let entry = snapshot
            .networks
            .iter()
            .find(|entry| entry.bssid == "aa")
            .unwrap();
        assert_eq!(entry.seen_scans, 2);
        assert_eq!(entry.last_seen_scan, 2);
        assert!((entry.average_signal_dbm.unwrap() + 55.0).abs() < f64::EPSILON);
    }

    #[test]
    fn missing_access_points_are_dropped_after_limit() {
        let mut state = MonitorState::new();
        state.observe_scan(vec![network("aa", -60, 0)], Vec::new());
        for _ in 0..=MAX_MISSING_SCANS {
            state.observe_scan(Vec::new(), Vec::new());
        }
        let snapshot = state.observe_scan(Vec::new(), Vec::new());
        assert!(snapshot.networks.iter().all(|entry| entry.bssid != "aa"));
    }

    #[test]
    fn current_bssid_is_marked_in_scan_results() {
        let mut state = MonitorState::new();
        state.observe_current(
            Some(WifiCurrentConnection {
                bssid: "aa".into(),
                ssid: "test".into(),
                band: WifiBand::Ghz24,
                channel: Some(6),
                ..WifiCurrentConnection::default()
            }),
            Vec::new(),
        );
        let snapshot = state.observe_scan(vec![network("aa", -60, 0)], Vec::new());
        assert!(snapshot
            .networks
            .iter()
            .any(|entry| entry.bssid == "aa" && entry.is_current));
    }

    #[test]
    fn signal_history_resets_when_bssid_changes() {
        let mut state = MonitorState::new();
        let first = WifiCurrentConnection {
            bssid: "aa".into(),
            ssid: "first".into(),
            signal_dbm: Some(-50),
            ..WifiCurrentConnection::default()
        };
        state.observe_current(Some(first), Vec::new());
        let second = WifiCurrentConnection {
            bssid: "bb".into(),
            ssid: "second".into(),
            signal_dbm: Some(-70),
            ..WifiCurrentConnection::default()
        };
        let snapshot = state.observe_current(Some(second), Vec::new());
        assert_eq!(snapshot.history.len(), 1);
        assert_eq!(snapshot.stats.samples, 1);
        assert_eq!(snapshot.stats.average_signal_dbm, Some(-70.0));
    }

    #[test]
    fn empty_snapshot_has_no_samples() {
        let mut state = MonitorState::new();
        let snapshot = state.observe_current(None, Vec::new());
        assert!(snapshot.history.is_empty());
        assert_eq!(snapshot.stats, crate::model::WifiSignalStats::default());
    }
}
