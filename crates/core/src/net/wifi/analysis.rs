//! Frequency/channel analysis for Wi-Fi scan results.

use std::collections::HashSet;

use crate::model::{
    WifiBand, WifiBandCount, WifiBusiestChannel, WifiChannelRecommendation, WifiChannelUsage,
    WifiCurrentConnection, WifiNetwork, WifiScanSummary, WifiSecurity, WifiSignalSample,
    WifiSignalStats,
};

/// Number of recommendations returned per band.
const MAX_RECOMMENDATIONS_PER_BAND: usize = 3;

/// Assumed channel width when the platform did not report one.
const DEFAULT_WIDTH_MHZ: u32 = 20;

/// Result of analyzing one scan round.
#[derive(Debug, Clone, Default)]
pub struct WifiAnalysis {
    pub channel_usage: Vec<WifiChannelUsage>,
    pub recommendations: Vec<WifiChannelRecommendation>,
    pub summary: WifiScanSummary,
}

/// Map a center frequency to its band.
pub fn band_for_frequency(frequency_mhz: u32) -> WifiBand {
    match frequency_mhz {
        2_400..=2_500 => WifiBand::Ghz24,
        5_000..=5_924 => WifiBand::Ghz5,
        5_925..=7_125 => WifiBand::Ghz6,
        _ => WifiBand::Unknown,
    }
}

/// Map a center frequency to its channel number.
pub fn channel_for_frequency(frequency_mhz: u32) -> Option<u32> {
    match frequency_mhz {
        2_484 => Some(14),
        2_400..=2_500 => Some((frequency_mhz.saturating_sub(2_407)) / 5),
        5_000..=5_924 => Some((frequency_mhz.saturating_sub(5_000)) / 5),
        5_925..=7_125 => Some((frequency_mhz.saturating_sub(5_950)) / 5),
        _ => None,
    }
}

/// Return the center frequency of a channel in the given band.
pub fn frequency_for_channel(band: WifiBand, channel: u32) -> Option<u32> {
    let frequency = match band {
        WifiBand::Ghz24 if channel == 14 => 2_484,
        WifiBand::Ghz24 if (1..=13).contains(&channel) => 2_407 + channel * 5,
        WifiBand::Ghz5 if (1..=200).contains(&channel) => 5_000 + channel * 5,
        WifiBand::Ghz6 if (1..=233).contains(&channel) => 5_950 + channel * 5,
        _ => return None,
    };
    Some(frequency)
}

/// Normalize RSSI or an existing quality value to a percentage.
pub fn signal_quality(signal_dbm: Option<i32>, quality: Option<u8>) -> Option<u8> {
    if let Some(quality) = quality {
        return Some(quality.min(100));
    }
    let dbm = signal_dbm?;
    let percent = ((dbm + 100) * 2).clamp(0, 100);
    Some(percent as u8)
}

/// Compute signal-to-noise ratio when both values are available.
pub fn snr_db(signal_dbm: Option<i32>, noise_dbm: Option<i32>) -> Option<i32> {
    Some(signal_dbm? - noise_dbm?)
}

/// Derive a dBm-like value for an AP that only reported link quality.
fn effective_signal_dbm(network: &WifiNetwork) -> Option<f64> {
    if let Some(dbm) = network.signal_dbm {
        return Some(dbm as f64);
    }
    network
        .signal_quality
        .map(|quality| (quality as f64 / 2.0) - 100.0)
}

/// Frequency range occupied by a network.
fn occupied_range(network: &WifiNetwork) -> Option<(f64, f64)> {
    let center = network.frequency_mhz? as f64;
    let width = network.width_mhz.unwrap_or(DEFAULT_WIDTH_MHZ) as f64;
    Some((center - width / 2.0, center + width / 2.0))
}

/// Linear power sum used when several access points overlap one channel.
fn interference_at(
    networks: &[&WifiNetwork],
    candidate_low: f64,
    candidate_high: f64,
) -> (Option<f64>, Option<i32>, u32) {
    let candidate_width = (candidate_high - candidate_low).max(1.0);
    let mut power = 0.0;
    let mut strongest: Option<i32> = None;
    let mut count = 0_u32;

    for network in networks {
        let Some((low, high)) = occupied_range(network) else {
            continue;
        };
        let overlap = high.min(candidate_high) - low.max(candidate_low);
        if overlap <= 0.0 {
            continue;
        }
        count = count.saturating_add(1);
        if let Some(signal) = network.signal_dbm {
            strongest = Some(strongest.map_or(signal, |current| current.max(signal)));
        }
        if let Some(signal) = effective_signal_dbm(network) {
            let overlap_ratio = (overlap / candidate_width).clamp(0.0, 1.0);
            power += 10_f64.powf(signal / 10.0) * overlap_ratio;
        }
    }

    let interference = (power > 0.0).then(|| 10.0 * power.log10());
    (interference, strongest, count)
}

/// Convert interference into a bounded score for charts and sorting.
fn occupancy_score(interference_dbm: Option<f64>, access_points: u32) -> f64 {
    match interference_dbm {
        Some(dbm) => ((dbm + 100.0) / 70.0 * 100.0).clamp(0.0, 100.0),
        None => (access_points as f64 * 10.0).min(100.0),
    }
}

/// Candidate channels used for usage charts and recommendations.
fn candidate_channels(band: WifiBand) -> Vec<u32> {
    match band {
        WifiBand::Ghz24 => (1..=14).collect(),
        WifiBand::Ghz5 => vec![
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
            144, 149, 153, 157, 161, 165,
        ],
        WifiBand::Ghz6 => (1..=233).step_by(4).collect(),
        WifiBand::Unknown => Vec::new(),
    }
}

/// Channels that may be recommended for a band.
fn recommendation_channels(band: WifiBand) -> Vec<u32> {
    match band {
        WifiBand::Ghz24 => vec![1, 6, 11],
        WifiBand::Ghz5 | WifiBand::Ghz6 => candidate_channels(band),
        WifiBand::Unknown => Vec::new(),
    }
}

/// Compute usage for every candidate channel in the bands present in the scan.
pub fn channel_usage(
    networks: &[WifiNetwork],
    current: Option<&WifiCurrentConnection>,
) -> Vec<WifiChannelUsage> {
    let bands = [
        WifiBand::Ghz24,
        WifiBand::Ghz5,
        WifiBand::Ghz6,
        WifiBand::Unknown,
    ];
    let mut usage = Vec::new();

    for band in bands {
        let band_networks = networks
            .iter()
            .filter(|network| {
                network.band == band
                    || (network.band == WifiBand::Unknown && band == WifiBand::Unknown)
            })
            .collect::<Vec<_>>();
        for channel in candidate_channels(band) {
            let Some(frequency) = frequency_for_channel(band, channel) else {
                continue;
            };
            let width = DEFAULT_WIDTH_MHZ;
            let low = frequency as f64 - width as f64 / 2.0;
            let high = frequency as f64 + width as f64 / 2.0;
            let (interference, strongest, access_points) =
                interference_at(&band_networks, low, high);
            let is_current = current
                .is_some_and(|current| current.band == band && current.channel == Some(channel));
            usage.push(WifiChannelUsage {
                band,
                channel,
                frequency_mhz: frequency,
                width_mhz: width,
                access_points,
                strongest_signal_dbm: strongest,
                interference_dbm: interference,
                occupancy: occupancy_score(interference, access_points),
                is_current,
            });
        }
    }

    usage
}

/// Pick the least contended channels for each band.
pub fn recommendations(
    usage: &[WifiChannelUsage],
    current: Option<&WifiCurrentConnection>,
) -> Vec<WifiChannelRecommendation> {
    let mut out = Vec::new();
    for band in [WifiBand::Ghz24, WifiBand::Ghz5, WifiBand::Ghz6] {
        let allowed = recommendation_channels(band);
        let mut candidates = usage
            .iter()
            .filter(|entry| entry.band == band && allowed.contains(&entry.channel))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.access_points
                .cmp(&right.access_points)
                .then_with(|| {
                    left.interference_dbm
                        .unwrap_or(f64::NEG_INFINITY)
                        .total_cmp(&right.interference_dbm.unwrap_or(f64::NEG_INFINITY))
                })
                .then_with(|| left.channel.cmp(&right.channel))
        });
        for entry in candidates.into_iter().take(MAX_RECOMMENDATIONS_PER_BAND) {
            out.push(WifiChannelRecommendation {
                band,
                channel: entry.channel,
                interference_dbm: entry.interference_dbm,
                occupancy: entry.occupancy,
                overlapping_aps: entry.access_points,
                is_current: current.is_some_and(|current| {
                    current.band == entry.band && current.channel == Some(entry.channel)
                }),
            });
        }
    }
    out
}

/// Build the high-level scan summary.
pub fn summary(networks: &[WifiNetwork], usage: &[WifiChannelUsage]) -> WifiScanSummary {
    let mut unique_ssids = HashSet::new();
    let mut band_counts = Vec::new();
    let mut open_networks = 0_u32;
    let mut wep_networks = 0_u32;
    let mut hidden_networks = 0_u32;
    let mut strongest: Option<&WifiNetwork> = None;

    for network in networks {
        if !network.is_hidden && !network.ssid.is_empty() {
            unique_ssids.insert(network.ssid.clone());
        }
        if network.is_hidden || network.ssid.is_empty() {
            hidden_networks = hidden_networks.saturating_add(1);
        }
        if network.security == WifiSecurity::Open {
            open_networks = open_networks.saturating_add(1);
        }
        if network.security == WifiSecurity::Wep {
            wep_networks = wep_networks.saturating_add(1);
        }
        if strongest
            .map(|current| {
                network.signal_dbm.unwrap_or(i32::MIN) > current.signal_dbm.unwrap_or(i32::MIN)
            })
            .unwrap_or(true)
        {
            strongest = Some(network);
        }
    }

    for band in [
        WifiBand::Ghz24,
        WifiBand::Ghz5,
        WifiBand::Ghz6,
        WifiBand::Unknown,
    ] {
        let count = networks
            .iter()
            .filter(|network| network.band == band)
            .count() as u32;
        band_counts.push(WifiBandCount { band, count });
    }

    let mut busiest_channels = Vec::new();
    for band in [WifiBand::Ghz24, WifiBand::Ghz5, WifiBand::Ghz6] {
        if let Some(entry) = usage
            .iter()
            .filter(|entry| entry.band == band && entry.access_points > 0)
            .max_by(|left, right| {
                left.access_points.cmp(&right.access_points).then_with(|| {
                    left.interference_dbm
                        .unwrap_or(f64::NEG_INFINITY)
                        .total_cmp(&right.interference_dbm.unwrap_or(f64::NEG_INFINITY))
                })
            })
        {
            busiest_channels.push(WifiBusiestChannel {
                band,
                channel: entry.channel,
                access_points: entry.access_points,
            });
        }
    }

    WifiScanSummary {
        access_points: networks.len() as u32,
        unique_ssids: unique_ssids.len() as u32,
        band_counts,
        open_networks,
        wep_networks,
        hidden_networks,
        strongest_ssid: strongest.map(|network| network.ssid.clone()),
        strongest_bssid: strongest.map(|network| network.bssid.clone()),
        strongest_signal_dbm: strongest.and_then(|network| network.signal_dbm),
        busiest_channels,
    }
}

/// Analyze a completed scan in one call.
pub fn analyze(networks: &[WifiNetwork], current: Option<&WifiCurrentConnection>) -> WifiAnalysis {
    let channel_usage = channel_usage(networks, current);
    let recommendations = recommendations(&channel_usage, current);
    let summary = summary(networks, &channel_usage);
    WifiAnalysis {
        channel_usage,
        recommendations,
        summary,
    }
}

/// Compute aggregate signal and rate statistics from the sample history.
pub fn signal_stats(samples: &[WifiSignalSample]) -> WifiSignalStats {
    let signals = samples
        .iter()
        .filter_map(|sample| sample.signal_dbm)
        .collect::<Vec<_>>();
    let rates_rx = samples
        .iter()
        .filter_map(|sample| sample.rx_rate_mbps)
        .collect::<Vec<_>>();
    let rates_tx = samples
        .iter()
        .filter_map(|sample| sample.tx_rate_mbps)
        .collect::<Vec<_>>();

    let average = |values: &[f64]| {
        (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
    };

    let average_signal = if signals.is_empty() {
        None
    } else {
        Some(signals.iter().map(|value| *value as f64).sum::<f64>() / signals.len() as f64)
    };
    let stddev = average_signal.map(|mean| {
        let variance = signals
            .iter()
            .map(|value| {
                let delta = *value as f64 - mean;
                delta * delta
            })
            .sum::<f64>()
            / signals.len() as f64;
        variance.sqrt()
    });

    WifiSignalStats {
        samples: samples.len() as u32,
        min_signal_dbm: signals.iter().copied().min(),
        max_signal_dbm: signals.iter().copied().max(),
        average_signal_dbm: average_signal,
        stddev_db: stddev,
        average_rx_rate_mbps: average(&rates_rx),
        average_tx_rate_mbps: average(&rates_tx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::WifiStandard;

    fn network(ssid: &str, bssid: &str, frequency: u32, signal: i32) -> WifiNetwork {
        let band = band_for_frequency(frequency);
        let channel = channel_for_frequency(frequency);
        WifiNetwork {
            ssid: ssid.to_string(),
            bssid: bssid.to_string(),
            band,
            channel,
            frequency_mhz: Some(frequency),
            signal_dbm: Some(signal),
            signal_quality: signal_quality(Some(signal), None),
            security: WifiSecurity::Wpa2,
            standard: WifiStandard::Wifi5,
            ..WifiNetwork::new(bssid)
        }
    }

    #[test]
    fn frequency_channel_mapping_covers_common_bands() {
        assert_eq!(band_for_frequency(2_412), WifiBand::Ghz24);
        assert_eq!(channel_for_frequency(2_412), Some(1));
        assert_eq!(channel_for_frequency(2_484), Some(14));
        assert_eq!(band_for_frequency(5_180), WifiBand::Ghz5);
        assert_eq!(channel_for_frequency(5_180), Some(36));
        assert_eq!(band_for_frequency(5_955), WifiBand::Ghz6);
        assert_eq!(channel_for_frequency(5_955), Some(1));
        assert_eq!(frequency_for_channel(WifiBand::Ghz5, 36), Some(5_180));
        assert_eq!(frequency_for_channel(WifiBand::Ghz24, 14), Some(2_484));
    }

    #[test]
    fn two_point_four_recommendations_use_non_overlapping_channels() {
        let networks = vec![network("a", "aa", 2_437, -50)];
        let analysis = analyze(&networks, None);
        let recommended = analysis
            .recommendations
            .iter()
            .filter(|entry| entry.band == WifiBand::Ghz24)
            .map(|entry| entry.channel)
            .collect::<Vec<_>>();
        assert_eq!(recommended, vec![1, 11, 6]);
    }

    #[test]
    fn overlapping_channels_accumulate_interference() {
        let networks = vec![
            network("a", "aa", 2_437, -50),
            network("b", "bb", 2_437, -60),
        ];
        let usage = channel_usage(&networks, None);
        let channel_six = usage
            .iter()
            .find(|entry| entry.band == WifiBand::Ghz24 && entry.channel == 6)
            .unwrap();
        let channel_eleven = usage
            .iter()
            .find(|entry| entry.band == WifiBand::Ghz24 && entry.channel == 11)
            .unwrap();
        assert_eq!(channel_six.access_points, 2);
        assert_eq!(channel_eleven.access_points, 0);
        assert!(
            channel_six.interference_dbm.unwrap()
                > channel_eleven.interference_dbm.unwrap_or(-100.0)
        );
    }

    #[test]
    fn summary_counts_security_and_hidden_networks() {
        let mut hidden = network("", "cc", 5_180, -70);
        hidden.is_hidden = true;
        hidden.security = WifiSecurity::Open;
        let mut open = network("open", "dd", 2_412, -40);
        open.security = WifiSecurity::Open;
        let networks = vec![network("home", "aa", 2_437, -50), hidden, open];
        let analysis = analyze(&networks, None);
        assert_eq!(analysis.summary.access_points, 3);
        assert_eq!(analysis.summary.unique_ssids, 2);
        assert_eq!(analysis.summary.open_networks, 2);
        assert_eq!(analysis.summary.hidden_networks, 1);
        assert_eq!(analysis.summary.strongest_bssid.as_deref(), Some("dd"));
    }

    #[test]
    fn signal_stats_ignore_missing_values() {
        let samples = vec![
            WifiSignalSample {
                signal_dbm: Some(-60),
                rx_rate_mbps: Some(100.0),
                ..WifiSignalSample::default()
            },
            WifiSignalSample {
                signal_dbm: Some(-40),
                rx_rate_mbps: None,
                ..WifiSignalSample::default()
            },
            WifiSignalSample::default(),
        ];
        let stats = signal_stats(&samples);
        assert_eq!(stats.samples, 3);
        assert_eq!(stats.min_signal_dbm, Some(-60));
        assert_eq!(stats.max_signal_dbm, Some(-40));
        assert_eq!(stats.average_signal_dbm, Some(-50.0));
        assert_eq!(stats.stddev_db, Some(10.0));
        assert_eq!(stats.average_rx_rate_mbps, Some(100.0));
    }
}
