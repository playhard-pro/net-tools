//! macOS Wi-Fi current-connection support through `wdutil`.
//!
//! macOS does not expose nearby-network scanning through the supported command
//! line tools on current releases, so this backend intentionally reports the
//! current association only.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::model::{
    WifiBand, WifiCapabilities, WifiCurrentConnection, WifiNetwork, WifiSecurity, WifiStandard,
};

use super::analysis;
use super::WifiError;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

fn command_exists(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| directory.join(name).is_file())
}

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
            || message.to_ascii_lowercase().contains("root")
            || message.to_ascii_lowercase().contains("sudo")
        {
            Some(
                "wdutil may require elevated privileges or Location Services permission."
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
        return Err(WifiError::new("wdutil returned more output than expected"));
    }
    Ok(stdout)
}

pub async fn capabilities() -> WifiCapabilities {
    let available = command_exists("wdutil");
    WifiCapabilities {
        platform: "macOS".to_string(),
        current_supported: available,
        scan_supported: false,
        note: if available {
            Some(
                "macOS shows current connection details through wdutil; nearby scanning is not available."
                    .to_string(),
            )
        } else {
            Some("wdutil is not available on this system.".to_string())
        },
    }
}

pub async fn sample_current() -> Result<(Option<WifiCurrentConnection>, Vec<String>), WifiError> {
    if !command_exists("wdutil") {
        return Err(WifiError::new("wdutil is not available on this system"));
    }
    let output = run_command("wdutil", &["info"]).await?;
    Ok((parse_wdutil(&output), Vec::new()))
}

pub async fn scan_networks() -> Result<(Vec<WifiNetwork>, Vec<String>), WifiError> {
    Err(WifiError::unsupported(
        "macOS only exposes the current connection through wdutil; nearby scanning is not available",
    ))
}

/// Parse the key/value output of `wdutil info`.
fn parse_wdutil(text: &str) -> Option<WifiCurrentConnection> {
    let mut connection = WifiCurrentConnection::default();
    let mut channel_width = None;

    for line in text.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = normalize_key(key);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        if key.contains("interfacename") {
            connection.interface = value.to_string();
        } else if key.ends_with("bssid") {
            connection.bssid = normalize_bssid(value);
        } else if key.ends_with("ssid") {
            connection.ssid = value.to_string();
        } else if key.contains("rssi") || key.contains("signal") {
            connection.signal_dbm = parse_first_i32(value);
            connection.signal_quality = analysis::signal_quality(connection.signal_dbm, None);
        } else if key.contains("noise") {
            connection.noise_dbm = parse_first_i32(value);
        } else if key.contains("channelwidth") {
            channel_width = parse_first_u32(value);
        } else if key.contains("channel") {
            let (channel, frequency) = parse_channel(value);
            connection.channel = channel;
            connection.frequency_mhz = frequency;
        } else if key.contains("band") {
            connection.band = band_from_text(value);
        } else if key.contains("security") {
            connection.security = security_from_text(value);
            connection.security_detail = value.to_string();
        } else if key.contains("txrate") {
            connection.tx_rate_mbps = parse_first_f64(value);
        } else if key.contains("rxrate") {
            connection.rx_rate_mbps = parse_first_f64(value);
        } else if key.contains("phymode") || key.contains("phy") {
            connection.standard = standard_from_text(value);
        }
    }

    if !connection.is_connected() {
        return None;
    }
    if connection.band == WifiBand::Unknown {
        connection.band = connection
            .frequency_mhz
            .map(analysis::band_for_frequency)
            .unwrap_or_default();
    }
    if connection.channel.is_none() {
        connection.channel = connection
            .frequency_mhz
            .and_then(analysis::channel_for_frequency);
    }
    if connection.frequency_mhz.is_none() {
        connection.frequency_mhz = connection
            .channel
            .and_then(|channel| analysis::frequency_for_channel(connection.band, channel));
    }
    if connection.standard == WifiStandard::Wifi6 && connection.band == WifiBand::Ghz6 {
        connection.standard = WifiStandard::Wifi6E;
    }
    connection.width_mhz = channel_width;
    connection.snr_db = analysis::snr_db(connection.signal_dbm, connection.noise_dbm);
    Some(connection)
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|character| !character.is_whitespace() && *character != '_' && *character != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn parse_first_i32(value: &str) -> Option<i32> {
    value
        .split_whitespace()
        .find_map(|part| part.trim_end_matches("dBm").parse::<i32>().ok())
}

fn parse_first_u32(value: &str) -> Option<u32> {
    value
        .split_whitespace()
        .find_map(|part| part.trim_end_matches("MHz").parse::<u32>().ok())
}

fn parse_first_f64(value: &str) -> Option<f64> {
    value
        .split_whitespace()
        .find_map(|part| part.trim_end_matches("Mbps").parse::<f64>().ok())
}

fn parse_channel(value: &str) -> (Option<u32>, Option<u32>) {
    let channel = value
        .split_whitespace()
        .next()
        .and_then(|part| part.trim_end_matches(',').parse::<u32>().ok());
    let frequency = value
        .find('(')
        .and_then(|start| {
            let rest = &value[start + 1..];
            let end = rest.find("MHz")?;
            rest[..end].trim().parse::<u32>().ok()
        })
        .or_else(|| {
            value
                .split_whitespace()
                .find_map(|part| part.trim_end_matches("MHz").parse::<u32>().ok())
        });
    (channel, frequency)
}

fn normalize_bssid(value: &str) -> String {
    crate::net::mac_vendor::normalize_mac(value)
        .ok()
        .map(|mac| mac.display.to_ascii_lowercase())
        .unwrap_or_default()
}

fn band_from_text(value: &str) -> WifiBand {
    let lower = value.to_ascii_lowercase();
    if lower.contains("6") {
        WifiBand::Ghz6
    } else if lower.contains("5") {
        WifiBand::Ghz5
    } else if lower.contains("2.4") || lower.contains("2,4") {
        WifiBand::Ghz24
    } else {
        WifiBand::Unknown
    }
}

fn security_from_text(value: &str) -> WifiSecurity {
    let lower = value.to_ascii_lowercase();
    if lower.contains("owe") {
        WifiSecurity::Owe
    } else if lower.contains("wpa3") && lower.contains("wpa2") {
        WifiSecurity::Wpa2Wpa3
    } else if lower.contains("wpa3") {
        WifiSecurity::Wpa3
    } else if lower.contains("enterprise") || lower.contains("802.1x") {
        WifiSecurity::Enterprise
    } else if lower.contains("wpa2") {
        WifiSecurity::Wpa2
    } else if lower.contains("wpa") {
        WifiSecurity::Wpa
    } else if lower.contains("wep") {
        WifiSecurity::Wep
    } else if lower.contains("none") || lower.contains("open") {
        WifiSecurity::Open
    } else {
        WifiSecurity::Unknown
    }
}

fn standard_from_text(value: &str) -> WifiStandard {
    let lower = value.to_ascii_lowercase();
    if lower.contains("be") || lower.contains("802.11be") {
        WifiStandard::Wifi7
    } else if lower.contains("ax") || lower.contains("802.11ax") {
        WifiStandard::Wifi6
    } else if lower.contains("ac") || lower.contains("802.11ac") {
        WifiStandard::Wifi5
    } else if lower.contains("n") || lower.contains("802.11n") {
        WifiStandard::Wifi4
    } else if lower.contains("a")
        || lower.contains("b")
        || lower.contains("g")
        || lower.contains("802.11")
    {
        WifiStandard::Legacy
    } else {
        WifiStandard::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WDUTIL: &str = r#"Wi-Fi:
    Interface Name : en0
    Current SSID : Home
    Current BSSID : AA:BB:CC:DD:EE:FF
    Current RSSI : -52 dBm
    Current Noise : -92 dBm
    Current Channel : 36 (5180 MHz)
    Current Band : 5GHz
    Current Security : WPA3 Personal
    Current Tx Rate : 866 Mbps
    Current Rx Rate : 780 Mbps
    Current PHY Mode : 802.11ax
"#;

    #[test]
    fn parses_current_connection() {
        let connection = parse_wdutil(WDUTIL).unwrap();
        assert_eq!(connection.interface, "en0");
        assert_eq!(connection.ssid, "Home");
        assert_eq!(connection.bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(connection.signal_dbm, Some(-52));
        assert_eq!(connection.noise_dbm, Some(-92));
        assert_eq!(connection.snr_db, Some(40));
        assert_eq!(connection.channel, Some(36));
        assert_eq!(connection.frequency_mhz, Some(5_180));
        assert_eq!(connection.band, WifiBand::Ghz5);
        assert_eq!(connection.security, WifiSecurity::Wpa3);
        assert_eq!(connection.standard, WifiStandard::Wifi6);
        assert_eq!(connection.tx_rate_mbps, Some(866.0));
    }

    #[test]
    fn missing_connection_returns_none() {
        assert!(parse_wdutil("Wi-Fi:\n    Interface Name : en0\n").is_none());
    }
}
