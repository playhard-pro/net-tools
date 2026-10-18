//! Local network overview: interface inventory, addressing, routing and
//! counters, plus the public egress address.
//!
//! The data is collected through native platform APIs where possible. macOS
//! uses the standard system utilities because the public BSD interfaces do not
//! expose every field this view needs.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::OffsetDateTime;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// A point-in-time view of the host's network configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    /// Local wall-clock time when the snapshot was collected.
    pub captured_at: String,
    /// Interfaces in stable name order, including loopback and down links.
    pub interfaces: Vec<NetworkInterface>,
    /// Default routes for each address family, ordered by metric.
    pub default_gateways: Vec<DefaultGateway>,
    /// System DNS servers in resolver order.
    pub dns_servers: Vec<String>,
    /// Full routing table entries.
    pub routes: Vec<NetworkRoute>,
}

/// One network interface and its cumulative counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    /// Hardware address in colon-separated form, when the link layer has one.
    pub mac: Option<String>,
    /// IPv4 addresses with their prefix length, e.g. `192.0.2.10/24`.
    pub ipv4: Vec<String>,
    /// IPv6 addresses with their prefix length.
    pub ipv6: Vec<String>,
    pub mtu: Option<u32>,
    /// Negotiated link speed in bits per second.
    pub link_speed_bps: Option<u64>,
    /// Whether the interface is operationally up.
    pub up: bool,
    /// Cumulative counters since the interface was created.
    pub counters: InterfaceCounters,
}

/// Cumulative packet and byte counters for one interface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// The route selected for traffic that has no more specific match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultGateway {
    /// `IPv4` or `IPv6`.
    pub family: String,
    pub gateway: String,
    pub interface: String,
    pub metric: Option<u32>,
}

/// One entry of the routing table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkRoute {
    /// `IPv4` or `IPv6`.
    pub family: String,
    /// Destination in CIDR notation, or `default`.
    pub destination: String,
    /// Next hop, or `-` for an on-link route.
    pub gateway: String,
    pub interface: String,
    pub metric: Option<u32>,
}

/// Public address and the geographic/network details returned for it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublicIp {
    /// `IPv4` or `IPv6`.
    pub family: String,
    pub address: String,
    /// Endpoint that supplied the response.
    pub source: String,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub postal_code: Option<String>,
    pub continent_code: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    /// UTC offset in seconds.
    pub offset: Option<i64>,
    pub asn: Option<u64>,
    pub asn_organization: Option<String>,
    pub isp: Option<String>,
    pub organization: Option<String>,
}

/// IPv4 and IPv6 public egress results. A family that cannot be reached is
/// represented by `None`, with the failure recorded in `errors`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublicEgress {
    pub ipv4: Option<PublicIp>,
    pub ipv6: Option<PublicIp>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Collect a fresh snapshot using the current platform's data sources.
pub fn collect() -> Result<NetworkSnapshot, String> {
    #[cfg(target_os = "linux")]
    {
        linux::collect()
    }
    #[cfg(windows)]
    {
        windows::collect()
    }
    #[cfg(target_os = "macos")]
    {
        macos::collect()
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        Err("network overview is not supported on this platform".to_string())
    }
}

/// Resolve the public IPv4 and IPv6 egress addresses through the IP.SB
/// geolocation API.
///
/// The two families are queried independently so an IPv4-only or IPv6-only
/// network still shows the reachable side. Both requests share one client and
/// therefore the caller-provided timeout.
pub async fn public_egress(timeout: Duration) -> PublicEgress {
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("net-tools")
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return PublicEgress {
                errors: vec![format!("failed to create HTTP client: {err}")],
                ..PublicEgress::default()
            };
        }
    };

    let (ipv4, ipv6) = tokio::join!(
        fetch_public_ip(&client, "https://api.ip.sb/geoip", "IPv4", |address| {
            address.is_ipv4()
        },),
        fetch_public_ip(&client, "https://api-ipv6.ip.sb/geoip", "IPv6", |address| {
            address.is_ipv6()
        },),
    );

    let mut result = PublicEgress::default();
    match ipv4 {
        Ok(value) => result.ipv4 = Some(value),
        Err(error) => result.errors.push(error),
    }
    match ipv6 {
        Ok(value) => result.ipv6 = Some(value),
        Err(error) => result.errors.push(error),
    }
    result
}

/// Query one IP.SB endpoint and turn its response into a [`PublicIp`].
async fn fetch_public_ip(
    client: &reqwest::Client,
    url: &str,
    family: &str,
    expected_family: impl Fn(IpAddr) -> bool,
) -> Result<PublicIp, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("{family} lookup failed: {err}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("{family} lookup failed: {err}"))?;
    if !status.is_success() {
        return Err(format!("{family} lookup failed with HTTP {status}"));
    }
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|err| format!("{family} response is not valid JSON: {err}"))?;
    let address = value
        .get("ip")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{family} response does not contain an IP address"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("{family} response contains an invalid IP address"))?;
    if !expected_family(address) {
        return Err(format!(
            "{family} endpoint returned the wrong address family"
        ));
    }
    Ok(parse_public_ip(&value, url, family, address))
}

/// Map the available IP.SB JSON fields onto the typed result. Missing fields
/// stay `None` instead of becoming empty strings.
fn parse_public_ip(
    value: &serde_json::Value,
    source: &str,
    family: &str,
    address: IpAddr,
) -> PublicIp {
    PublicIp {
        family: family.to_string(),
        address: address.to_string(),
        source: source.to_string(),
        country_code: string_field(value, "country_code"),
        country: string_field(value, "country"),
        region_code: string_field(value, "region_code"),
        region: string_field(value, "region"),
        city: string_field(value, "city"),
        postal_code: string_field(value, "postal_code"),
        continent_code: string_field(value, "continent_code"),
        latitude: number_field(value, "latitude"),
        longitude: number_field(value, "longitude"),
        timezone: string_field(value, "timezone"),
        offset: value.get("offset").and_then(serde_json::Value::as_i64),
        asn: value
            .get("asn")
            .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok())),
        asn_organization: string_field(value, "asn_organization"),
        isp: string_field(value, "isp"),
        organization: string_field(value, "organization"),
    }
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn number_field(value: &serde_json::Value, key: &str) -> Option<f64> {
    value.get(key).and_then(serde_json::Value::as_f64)
}

/// Format the current local time for the snapshot header.
pub(crate) fn captured_at_now() -> String {
    const FORMAT: &[time::format_description::FormatItem<'_>] =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(FORMAT)
        .unwrap_or_default()
}

/// Format an address as `address/prefix` for display and export.
pub(crate) fn with_prefix(address: impl std::fmt::Display, prefix: u8) -> String {
    format!("{address}/{prefix}")
}

/// Format a MAC address from raw bytes.
pub(crate) fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formatting_skips_empty_addresses() {
        assert_eq!(format_mac(&[]), None);
        assert_eq!(format_mac(&[0, 0, 0, 0, 0, 0]), None);
        assert_eq!(
            format_mac(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            Some("00:1a:2b:3c:4d:5e".to_string())
        );
    }

    #[test]
    fn prefix_notation_is_stable() {
        assert_eq!(with_prefix("192.0.2.10", 24), "192.0.2.10/24");
        assert_eq!(with_prefix("2001:db8::1", 64), "2001:db8::1/64");
    }

    #[test]
    fn ip_sb_response_maps_optional_fields() {
        let value = serde_json::json!({
            "ip": "172.225.7.7",
            "country_code": "US",
            "country": "United States",
            "region_code": "NY",
            "region": "New York",
            "city": "New York",
            "postal_code": "10118",
            "continent_code": "NA",
            "latitude": 40.7126,
            "longitude": -74.0066,
            "timezone": "America/New_York",
            "offset": -18000,
            "asn": 36183,
            "asn_organization": "Akamai Technologies, Inc.",
            "isp": "iCloud Private Relay",
            "organization": "iCloud Private Relay"
        });
        let result = parse_public_ip(
            &value,
            "https://api.ip.sb/geoip",
            "IPv4",
            "172.225.7.7".parse().unwrap(),
        );
        assert_eq!(result.address, "172.225.7.7");
        assert_eq!(result.country.as_deref(), Some("United States"));
        assert_eq!(result.asn, Some(36183));
        assert_eq!(result.offset, Some(-18000));
        assert_eq!(result.latitude, Some(40.7126));
    }

    #[test]
    fn missing_ip_sb_fields_stay_none() {
        let value = serde_json::json!({ "ip": "2001:db8::1" });
        let result = parse_public_ip(
            &value,
            "https://api-ipv6.ip.sb/geoip",
            "IPv6",
            "2001:db8::1".parse().unwrap(),
        );
        assert!(result.country.is_none());
        assert!(result.asn.is_none());
        assert!(result.city.is_none());
    }
}
