//! Linux Wi-Fi collection through NetworkManager and the `iw` tools.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::model::{
    WifiBand, WifiCapabilities, WifiCurrentConnection, WifiNetwork, WifiSecurity, WifiStandard,
};
use crate::net::mac_vendor;

use super::analysis;
use super::WifiError;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Detect whether a command is available on `PATH`.
fn command_exists(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| {
        let candidate = directory.join(name);
        candidate.is_file()
    })
}

/// Return names of interfaces that expose a wireless directory or phy link.
fn wireless_interfaces() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut names = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let base = entry.path();
            (base.join("wireless").exists() || base.join("phy80211").exists()).then_some(name)
        })
        .filter(|name| valid_interface_name(name))
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.:-".contains(character))
}

fn primary_interface() -> Option<String> {
    wireless_interfaces().into_iter().next()
}

/// Run a command with a hard timeout and bounded output.
async fn run_command(program: &str, args: &[&str]) -> Result<String, WifiError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = tokio::time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| WifiError::new(format!("{program} timed out")))?
        .map_err(|error| WifiError::new(format!("failed to run {program}: {error}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr.trim();
        let hint = if message.to_ascii_lowercase().contains("permission")
            || message
                .to_ascii_lowercase()
                .contains("operation not permitted")
        {
            Some(
                "Wireless scanning may require NetworkManager or additional privileges."
                    .to_string(),
            )
        } else {
            None
        };
        return Err(WifiError {
            message: if message.is_empty() {
                format!("{program} exited with {}", output.status)
            } else {
                format!("{program}: {message}")
            },
            hint,
        });
    }
    if stdout.len() > MAX_OUTPUT_BYTES {
        return Err(WifiError::new(format!(
            "{program} returned more output than expected"
        )));
    }
    Ok(stdout)
}

pub async fn capabilities() -> WifiCapabilities {
    let interfaces = wireless_interfaces();
    let has_nmcli = command_exists("nmcli");
    let has_iw = command_exists("iw");
    let has_iwlist = command_exists("iwlist");
    let current_supported = has_nmcli || has_iw || has_iwlist;
    let scan_supported = current_supported;
    let note = if interfaces.is_empty() {
        Some("No wireless interface was found.".to_string())
    } else if has_nmcli {
        Some(format!(
            "Using NetworkManager on {}.",
            interfaces.join(", ")
        ))
    } else if has_iw {
        Some(
            "NetworkManager is unavailable; using iw. Some scans may require privileges."
                .to_string(),
        )
    } else if has_iwlist {
        Some("Using iwlist. Detail fields may be limited.".to_string())
    } else {
        Some("Install NetworkManager (nmcli) or iw to scan Wi-Fi networks.".to_string())
    };

    WifiCapabilities {
        platform: "Linux".to_string(),
        current_supported: current_supported && !interfaces.is_empty(),
        scan_supported: scan_supported && !interfaces.is_empty(),
        note,
    }
}

pub async fn sample_current() -> Result<(Option<WifiCurrentConnection>, Vec<String>), WifiError> {
    let Some(interface) = primary_interface() else {
        return Ok((None, vec!["No wireless interface was found.".to_string()]));
    };
    let mut warnings = Vec::new();
    let mut connection = None;

    if command_exists("nmcli") {
        match current_from_nmcli(&interface).await {
            Ok(value) => connection = value,
            Err(error) => warnings.push(error.message),
        }
    }

    let iw = if command_exists("iw") {
        match iw_link(&interface).await {
            Ok(value) => value,
            Err(error) => {
                warnings.push(error.message);
                None
            }
        }
    } else {
        None
    };

    match (connection.as_mut(), iw) {
        (Some(current), Some(link)) => merge_current(current, link),
        (None, Some(link)) => connection = Some(link),
        _ => {}
    }

    Ok((connection, warnings))
}

async fn current_from_nmcli(interface: &str) -> Result<Option<WifiCurrentConnection>, WifiError> {
    let output = run_command(
        "nmcli",
        &[
            "-t",
            "-f",
            "IN-USE,SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
            "ifname",
            interface,
            "--rescan",
            "no",
        ],
    )
    .await?;
    let networks = parse_nmcli_networks(&output);
    Ok(networks
        .into_iter()
        .find(|network| network.is_current)
        .map(current_from_network))
}

fn current_from_network(network: WifiNetwork) -> WifiCurrentConnection {
    WifiCurrentConnection {
        interface: String::new(),
        ssid: network.ssid,
        bssid: network.bssid,
        vendor: network.vendor,
        signal_dbm: network.signal_dbm,
        signal_quality: network.signal_quality,
        noise_dbm: network.noise_dbm,
        snr_db: network.snr_db,
        channel: network.channel,
        frequency_mhz: network.frequency_mhz,
        width_mhz: network.width_mhz,
        band: network.band,
        security: network.security,
        security_detail: network.security_detail,
        standard: network.standard,
        rx_rate_mbps: None,
        tx_rate_mbps: network.max_rate_mbps,
    }
}

fn merge_current(current: &mut WifiCurrentConnection, link: WifiCurrentConnection) {
    if current.signal_dbm.is_none() {
        current.signal_dbm = link.signal_dbm;
    }
    if current.signal_quality.is_none() {
        current.signal_quality = link.signal_quality;
    }
    if current.channel.is_none() {
        current.channel = link.channel;
    }
    if current.frequency_mhz.is_none() {
        current.frequency_mhz = link.frequency_mhz;
    }
    if current.band == WifiBand::Unknown {
        current.band = link.band;
    }
    if current.width_mhz.is_none() {
        current.width_mhz = link.width_mhz;
    }
    if current.standard == WifiStandard::Unknown {
        current.standard = link.standard;
    }
    if current.rx_rate_mbps.is_none() {
        current.rx_rate_mbps = link.rx_rate_mbps;
    }
    if current.tx_rate_mbps.is_none() {
        current.tx_rate_mbps = link.tx_rate_mbps;
    }
    if current.interface.is_empty() {
        current.interface = link.interface;
    }
    current.snr_db = analysis::snr_db(current.signal_dbm, current.noise_dbm);
}

pub async fn scan_networks() -> Result<(Vec<WifiNetwork>, Vec<String>), WifiError> {
    let Some(interface) = primary_interface() else {
        return Err(WifiError::new("No wireless interface was found"));
    };
    let mut warnings = Vec::new();
    let mut networks = Vec::new();
    let mut command_failed = None;

    if command_exists("nmcli") {
        match run_command(
            "nmcli",
            &[
                "-t",
                "-f",
                "IN-USE,SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                "device",
                "wifi",
                "list",
                "ifname",
                interface.as_str(),
                "--rescan",
                "yes",
            ],
        )
        .await
        {
            Ok(output) => networks = parse_nmcli_networks(&output),
            Err(error) => command_failed = Some(error),
        }
    }

    if command_exists("iw") {
        let iw_output = if networks.is_empty() {
            "scan"
        } else {
            "scan dump"
        };
        let args = if iw_output == "scan" {
            vec!["dev", interface.as_str(), "scan"]
        } else {
            vec!["dev", interface.as_str(), "scan", "dump"]
        };
        match run_command("iw", &args).await {
            Ok(output) => {
                let detailed = parse_iw_scan(&output);
                networks = merge_scan(networks, detailed);
            }
            Err(error) => {
                if networks.is_empty() {
                    command_failed = Some(error);
                } else {
                    warnings.push(error.message);
                }
            }
        }
    }

    if networks.is_empty() && command_exists("iwlist") {
        match run_command("iwlist", &[&interface, "scan"]).await {
            Ok(output) => networks = parse_iwlist(&output),
            Err(error) => command_failed = Some(error),
        }
    }

    if networks.is_empty() {
        if let Some(error) = command_failed {
            return Err(error);
        }
        return Err(WifiError::new("The Wi-Fi scan returned no usable results"));
    }
    if let Some(error) = command_failed {
        warnings.push(error.message);
    }

    for network in &mut networks {
        if network.vendor.is_none() {
            network.vendor = mac_vendor::lookup_local(&network.bssid)
                .ok()
                .flatten()
                .map(|result| result.vendor);
        }
    }
    Ok((networks, warnings))
}

fn merge_scan(primary: Vec<WifiNetwork>, detailed: Vec<WifiNetwork>) -> Vec<WifiNetwork> {
    if primary.is_empty() {
        return detailed;
    }
    let mut by_bssid = primary
        .into_iter()
        .map(|network| (network.bssid.clone(), network))
        .collect::<std::collections::HashMap<_, _>>();
    for detail in detailed {
        if let Some(existing) = by_bssid.get_mut(&detail.bssid) {
            merge_network(existing, detail);
        } else {
            by_bssid.insert(detail.bssid.clone(), detail);
        }
    }
    by_bssid.into_values().collect()
}

fn merge_network(target: &mut WifiNetwork, detail: WifiNetwork) {
    if target.ssid.is_empty() {
        target.ssid = detail.ssid;
    }
    if target.signal_dbm.is_none() {
        target.signal_dbm = detail.signal_dbm;
    }
    if target.signal_quality.is_none() {
        target.signal_quality = detail.signal_quality;
    }
    if target.noise_dbm.is_none() {
        target.noise_dbm = detail.noise_dbm;
    }
    if target.channel.is_none() {
        target.channel = detail.channel;
    }
    if target.frequency_mhz.is_none() {
        target.frequency_mhz = detail.frequency_mhz;
    }
    if target.band == WifiBand::Unknown {
        target.band = detail.band;
    }
    if target.width_mhz.is_none() {
        target.width_mhz = detail.width_mhz;
    }
    if target.security == WifiSecurity::Unknown {
        target.security = detail.security;
    }
    if target.security_detail.is_empty() {
        target.security_detail = detail.security_detail;
    }
    if target.standard == WifiStandard::Unknown {
        target.standard = detail.standard;
    }
    if target.max_rate_mbps.is_none() {
        target.max_rate_mbps = detail.max_rate_mbps;
    }
    target.snr_db = analysis::snr_db(target.signal_dbm, target.noise_dbm);
}

/// Split one NetworkManager terse line, honouring backslash escapes.
fn split_terse(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    fields.push(current);
    fields
}

fn parse_nmcli_networks(text: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_terse(line);
        if fields.len() < 9 {
            continue;
        }
        let bssid = normalize_bssid(&fields[2]);
        if bssid.is_empty() {
            continue;
        }
        let mut network = WifiNetwork::new(bssid);
        network.ssid = fields[1].clone();
        network.is_hidden = network.ssid.is_empty();
        network.is_current = fields[0].trim() == "*";
        network.channel = fields[4].trim().parse().ok();
        network.frequency_mhz = parse_first_u32(&fields[5]);
        network.band = network
            .frequency_mhz
            .map(analysis::band_for_frequency)
            .unwrap_or_default();
        network.max_rate_mbps = parse_first_f64(&fields[6]);
        network.signal_quality = fields[7].trim().parse().ok();
        network.signal_dbm = None;
        network.security = security_from_text(&fields[8]);
        network.security_detail = fields[8].trim().to_string();
        network.standard = WifiStandard::Unknown;
        networks.push(network);
    }
    networks
}

fn parse_first_u32(value: &str) -> Option<u32> {
    value
        .split_whitespace()
        .find_map(|part| part.parse::<u32>().ok())
}

fn parse_first_f64(value: &str) -> Option<f64> {
    value
        .split_whitespace()
        .find_map(|part| part.parse::<f64>().ok())
}

fn parse_frequency_mhz(value: &str) -> Option<u32> {
    for part in value.split_whitespace() {
        if part.contains("GHz") {
            return part
                .trim_end_matches("GHz")
                .parse::<f64>()
                .ok()
                .map(|ghz| (ghz * 1_000.0) as u32);
        }
        if part.contains("MHz") {
            return part.trim_end_matches("MHz").parse::<u32>().ok();
        }
    }
    value.parse::<u32>().ok().filter(|value| *value >= 1_000)
}

fn normalize_bssid(value: &str) -> String {
    mac_vendor::normalize_mac(value.trim())
        .ok()
        .map(|mac| mac.display.to_ascii_lowercase())
        .unwrap_or_default()
}

fn security_from_text(value: &str) -> WifiSecurity {
    let lower = value.to_ascii_lowercase();
    if lower.contains("owe") {
        return WifiSecurity::Owe;
    }
    if lower.contains("wpa3") && lower.contains("wpa2") {
        return WifiSecurity::Wpa2Wpa3;
    }
    if lower.contains("wpa3") {
        return WifiSecurity::Wpa3;
    }
    if lower.contains("802.1x") || lower.contains("enterprise") {
        return WifiSecurity::Enterprise;
    }
    if lower.contains("wpa2") {
        return WifiSecurity::Wpa2;
    }
    if lower.contains("wpa") {
        return WifiSecurity::Wpa;
    }
    if lower.contains("wep") {
        return WifiSecurity::Wep;
    }
    if lower.trim().is_empty() || lower.trim() == "--" || lower.contains("open") {
        return WifiSecurity::Open;
    }
    WifiSecurity::Unknown
}

async fn iw_link(interface: &str) -> Result<Option<WifiCurrentConnection>, WifiError> {
    let output = run_command("iw", &["dev", interface, "link"]).await?;
    let mut connection = WifiCurrentConnection {
        interface: interface.to_string(),
        ..WifiCurrentConnection::default()
    };
    let mut connected = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Connected to ") {
            connected = true;
            connection.bssid = normalize_bssid(rest.split_whitespace().next().unwrap_or_default());
        } else if let Some(value) = trimmed.strip_prefix("SSID: ") {
            connection.ssid = value.trim().to_string();
        } else if let Some(value) = trimmed.strip_prefix("freq: ") {
            connection.frequency_mhz = value.trim().parse().ok();
            connection.band = connection
                .frequency_mhz
                .map(analysis::band_for_frequency)
                .unwrap_or_default();
            connection.channel = connection
                .frequency_mhz
                .and_then(analysis::channel_for_frequency);
        } else if let Some(value) = trimmed.strip_prefix("signal: ") {
            connection.signal_dbm = parse_first_i32(value);
            connection.signal_quality = analysis::signal_quality(connection.signal_dbm, None);
        } else if let Some(value) = trimmed.strip_prefix("rx bitrate: ") {
            connection.rx_rate_mbps = parse_first_f64(value);
            connection.width_mhz = parse_width(value);
        } else if let Some(value) = trimmed.strip_prefix("tx bitrate: ") {
            connection.tx_rate_mbps = parse_first_f64(value);
            if connection.width_mhz.is_none() {
                connection.width_mhz = parse_width(value);
            }
        }
    }
    if !connected && connection.ssid.is_empty() {
        return Ok(None);
    }
    connection.snr_db = analysis::snr_db(connection.signal_dbm, connection.noise_dbm);
    Ok(Some(connection))
}

fn parse_first_i32(value: &str) -> Option<i32> {
    value.split_whitespace().find_map(|part| {
        part.parse::<i32>()
            .ok()
            .or_else(|| part.parse::<f64>().ok().map(|value| value as i32))
    })
}

fn parse_width(value: &str) -> Option<u32> {
    value.split_whitespace().find_map(|part| {
        part.strip_suffix("MHz")
            .and_then(|width| width.parse().ok())
    })
}

/// Parse human-readable `iw dev ... scan` output.
fn parse_iw_scan(text: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut current: Option<WifiNetwork> = None;
    let mut rsn = false;
    let mut wpa = false;
    let mut privacy = false;
    let mut rsn_akms = String::new();

    let flush = |current: &mut Option<WifiNetwork>,
                 networks: &mut Vec<WifiNetwork>,
                 rsn: bool,
                 wpa: bool,
                 privacy: bool,
                 rsn_akms: &str| {
        if let Some(mut network) = current.take() {
            if network.ssid.is_empty() {
                network.is_hidden = true;
            }
            network.security = security_from_iw(rsn, wpa, privacy, rsn_akms);
            network.security_detail = network.security.label().to_string();
            if network.width_mhz.is_none() {
                network.width_mhz = Some(20);
            }
            network.snr_db = analysis::snr_db(network.signal_dbm, network.noise_dbm);
            networks.push(network);
        }
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("BSS ") {
            flush(&mut current, &mut networks, rsn, wpa, privacy, &rsn_akms);
            rsn = false;
            wpa = false;
            privacy = false;
            rsn_akms.clear();
            let bssid = normalize_bssid(rest.split_whitespace().next().unwrap_or_default());
            if !bssid.is_empty() {
                current = Some(WifiNetwork::new(bssid));
            }
            continue;
        }
        let Some(network) = current.as_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("freq: ") {
            network.frequency_mhz = value.trim().parse().ok();
            network.band = network
                .frequency_mhz
                .map(analysis::band_for_frequency)
                .unwrap_or_default();
            network.channel = network
                .frequency_mhz
                .and_then(analysis::channel_for_frequency);
        } else if let Some(value) = trimmed.strip_prefix("signal: ") {
            network.signal_dbm = parse_first_i32(value);
            network.signal_quality = analysis::signal_quality(network.signal_dbm, None);
        } else if let Some(value) = trimmed.strip_prefix("SSID: ") {
            network.ssid = value.to_string();
            network.is_hidden = network.ssid.is_empty();
        } else if let Some(value) = trimmed.strip_prefix("DS Parameter set: channel ") {
            network.channel = value.trim().parse().ok();
            if network.frequency_mhz.is_none() {
                if let Some(channel) = network.channel {
                    network.frequency_mhz = analysis::frequency_for_channel(network.band, channel);
                }
            }
        } else if trimmed.starts_with("capability:") && trimmed.contains("Privacy") {
            privacy = true;
        } else if trimmed == "RSN:" {
            rsn = true;
        } else if trimmed == "WPA:" {
            wpa = true;
        } else if let Some(value) = trimmed
            .strip_prefix("* ")
            .unwrap_or(trimmed)
            .strip_prefix("Authentication suites:")
        {
            rsn_akms.push_str(value);
            rsn_akms.push(' ');
        } else if trimmed.starts_with("HT operation:") || trimmed == "HT capabilities:" {
            network.standard = max_standard(network.standard, WifiStandard::Wifi4);
            if network.width_mhz.is_none() {
                network.width_mhz = Some(20);
            }
        } else if trimmed.starts_with("VHT operation:") || trimmed == "VHT capabilities:" {
            network.standard = max_standard(network.standard, WifiStandard::Wifi5);
        } else if trimmed.starts_with("HE operation:") || trimmed == "HE capabilities:" {
            network.standard = max_standard(network.standard, WifiStandard::Wifi6);
        } else if trimmed.starts_with("EHT operation:") || trimmed == "EHT capabilities:" {
            network.standard = max_standard(network.standard, WifiStandard::Wifi7);
        } else if let Some(width) = trimmed.strip_prefix("* channel width: ") {
            if let Some(value) = parse_parenthesized_mhz(width) {
                network.width_mhz = Some(network.width_mhz.unwrap_or(0).max(value));
            }
        } else if let Some(width) = trimmed.strip_prefix("* STA channel width: ") {
            if width.contains("any") {
                network.width_mhz = Some(network.width_mhz.unwrap_or(0).max(40));
            }
        } else if trimmed.starts_with("Supported rates:")
            || trimmed.starts_with("Extended supported rates:")
        {
            // Rates are human-readable and only used as a fallback.
            if let Some(value) = trimmed
                .split_whitespace()
                .find_map(|part| part.parse::<f64>().ok())
            {
                let rate = network.max_rate_mbps.map_or(value, |old| old.max(value));
                network.max_rate_mbps = Some(rate);
            }
        }
    }
    flush(&mut current, &mut networks, rsn, wpa, privacy, &rsn_akms);
    networks
}

fn parse_parenthesized_mhz(value: &str) -> Option<u32> {
    let start = value.find('(')? + 1;
    let end = value[start..].find("MHz")? + start;
    value[start..end].trim().parse().ok()
}

fn max_standard(current: WifiStandard, candidate: WifiStandard) -> WifiStandard {
    use WifiStandard::*;
    let rank = |standard| match standard {
        Unknown => 0,
        Legacy => 1,
        Wifi4 => 2,
        Wifi5 => 3,
        Wifi6 => 4,
        Wifi6E => 5,
        Wifi7 => 6,
    };
    if rank(candidate) >= rank(current) {
        candidate
    } else {
        current
    }
}

fn security_from_iw(rsn: bool, wpa: bool, privacy: bool, akms: &str) -> WifiSecurity {
    let upper = akms.to_ascii_uppercase();
    if upper.contains("OWE") {
        return WifiSecurity::Owe;
    }
    if upper.contains("SAE") && upper.contains("PSK") {
        return WifiSecurity::Wpa2Wpa3;
    }
    if upper.contains("SAE") {
        return WifiSecurity::Wpa3;
    }
    if upper.contains("802.1X") {
        return WifiSecurity::Enterprise;
    }
    if rsn {
        return WifiSecurity::Wpa2;
    }
    if wpa {
        return WifiSecurity::Wpa;
    }
    if privacy {
        return WifiSecurity::Wep;
    }
    WifiSecurity::Open
}

/// Parse the older `iwlist scan` output as a final fallback.
fn parse_iwlist(text: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut current: Option<WifiNetwork> = None;
    let mut encrypted = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Cell ") {
            if let Some(mut network) = current.take() {
                if network.security == WifiSecurity::Unknown {
                    network.security = if encrypted {
                        WifiSecurity::Wep
                    } else {
                        WifiSecurity::Open
                    };
                }
                networks.push(network);
            }
            encrypted = false;
            let bssid = rest
                .split_once("Address: ")
                .map(|(_, bssid)| normalize_bssid(bssid))
                .unwrap_or_default();
            if !bssid.is_empty() {
                current = Some(WifiNetwork::new(bssid));
            }
            continue;
        }
        let Some(network) = current.as_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("Channel:") {
            network.channel = value.trim().parse().ok();
        } else if let Some(value) = trimmed.strip_prefix("Frequency:") {
            network.frequency_mhz = parse_frequency_mhz(value);
            network.band = network
                .frequency_mhz
                .map(analysis::band_for_frequency)
                .unwrap_or_default();
            if network.channel.is_none() {
                network.channel = parse_parenthesized_channel(value);
            }
        } else if let Some(value) = trimmed.strip_prefix("Quality=") {
            let parts = value.split_whitespace().collect::<Vec<_>>();
            if let Some(quality) = parts.first().and_then(|value| value.split('/').next()) {
                network.signal_quality = quality.parse().ok();
            }
            if let Some(value) = parts.iter().find_map(|part| part.strip_prefix("level=")) {
                network.signal_dbm = parse_first_i32(value);
            }
        } else if let Some(value) = trimmed.strip_prefix("ESSID:") {
            network.ssid = value.trim_matches('"').to_string();
            network.is_hidden = network.ssid.is_empty();
        } else if trimmed.starts_with("Encryption key:") {
            encrypted = trimmed.ends_with("on");
        } else if trimmed.contains("IEEE 802.11i/WPA2") {
            network.security = WifiSecurity::Wpa2;
            network.standard = max_standard(network.standard, WifiStandard::Wifi4);
        } else if trimmed.contains("WPA2") {
            network.security = WifiSecurity::Wpa2;
        } else if trimmed.contains("WPA") {
            network.security = WifiSecurity::Wpa;
        } else if trimmed.contains("802.11n") {
            network.standard = max_standard(network.standard, WifiStandard::Wifi4);
        } else if trimmed.contains("802.11ac") {
            network.standard = max_standard(network.standard, WifiStandard::Wifi5);
        } else if trimmed.contains("802.11ax") {
            network.standard = max_standard(network.standard, WifiStandard::Wifi6);
        }
    }
    if let Some(mut network) = current {
        if network.security == WifiSecurity::Unknown {
            network.security = if encrypted {
                WifiSecurity::Wep
            } else {
                WifiSecurity::Open
            };
        }
        networks.push(network);
    }
    networks
}

fn parse_parenthesized_channel(value: &str) -> Option<u32> {
    let start = value.find("Channel ")? + "Channel ".len();
    value[start..]
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .and_then(|channel| channel.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NMCLI: &str = "*:Home\\:WiFi:AA\\:BB\\:CC\\:DD\\:EE\\:FF:Infra:6:2437 MHz:130 MBit/s:82:WPA2\n:Guest:11\\:22\\:33\\:44\\:55\\:66:Infra:11:2462 MHz:54 MBit/s:40:--\n";

    #[test]
    fn parses_escaped_nmcli_fields() {
        let networks = parse_nmcli_networks(NMCLI);
        assert_eq!(networks.len(), 2);
        assert_eq!(networks[0].ssid, "Home:WiFi");
        assert_eq!(networks[0].bssid, "aa:bb:cc:dd:ee:ff");
        assert!(networks[0].is_current);
        assert_eq!(networks[0].channel, Some(6));
        assert_eq!(networks[0].signal_quality, Some(82));
        assert_eq!(networks[0].security, WifiSecurity::Wpa2);
        assert_eq!(networks[1].security, WifiSecurity::Open);
    }

    #[test]
    fn nmcli_size_parser_handles_empty_ssid() {
        let networks = parse_nmcli_networks(
            "::AA\\:BB\\:CC\\:DD\\:EE\\:FF:Infra:1:2412 MHz:54 MBit/s:20:WPA3\n",
        );
        assert_eq!(networks.len(), 1);
        assert!(networks[0].ssid.is_empty());
    }

    #[test]
    fn parses_iw_scan_blocks() {
        let text = r#"BSS aa:bb:cc:dd:ee:ff (on wlan0)
	freq: 5180
	signal: -47.00 dBm
	SSID: Office
	RSN:
		* Authentication suites: PSK SAE
	HT operation:
		* primary channel: 36
		* STA channel width: any
	VHT operation:
		* channel width: 2 (160 MHz)
	HE capabilities:
"#;
        let networks = parse_iw_scan(text);
        assert_eq!(networks.len(), 1);
        let network = &networks[0];
        assert_eq!(network.ssid, "Office");
        assert_eq!(network.band, WifiBand::Ghz5);
        assert_eq!(network.channel, Some(36));
        assert_eq!(network.signal_dbm, Some(-47));
        assert_eq!(network.security, WifiSecurity::Wpa2Wpa3);
        assert_eq!(network.standard, WifiStandard::Wifi6);
        assert_eq!(network.width_mhz, Some(160));
    }

    #[test]
    fn parses_iwlist_fallback() {
        let text = r#"Cell 01 - Address: AA:BB:CC:DD:EE:FF
          Channel:6
          Frequency:2.437 GHz (Channel 6)
          Quality=70/70  Signal level=-40 dBm
          Encryption key:on
          ESSID:"Home"
          IE: IEEE 802.11i/WPA2 Version 1
"#;
        let networks = parse_iwlist(text);
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].ssid, "Home");
        assert_eq!(networks[0].channel, Some(6));
        assert_eq!(networks[0].signal_dbm, Some(-40));
        assert_eq!(networks[0].security, WifiSecurity::Wpa2);
    }

    #[test]
    fn split_terse_handles_backslashes() {
        assert_eq!(
            split_terse("*:A\\:B:AA\\:BB\\:CC\\:DD\\:EE\\:FF"),
            vec!["*", "A:B", "AA:BB:CC:DD:EE:FF"]
        );
    }
}
