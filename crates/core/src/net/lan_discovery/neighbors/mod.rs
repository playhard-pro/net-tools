//! System neighbor table reading.
//!
//! The platform modules expose every usable address-to-MAC mapping and the
//! shared code applies the LAN-only address policy before returning the rows.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// One neighbor table row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: Option<String>,
}

/// Read the current neighbor table and keep only valid LAN entries.
pub fn collect() -> Result<Vec<NeighborEntry>, String> {
    #[cfg(target_os = "linux")]
    let entries = linux::collect();
    #[cfg(target_os = "macos")]
    let entries = macos::collect();
    #[cfg(windows)]
    let entries = windows::collect();
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let entries: Result<Vec<NeighborEntry>, String> =
        Err("neighbor table discovery is not supported on this platform".to_string());

    let mut entries = entries?;
    entries.retain(|entry| is_allowed_ip(entry.ip) && is_valid_mac(&entry.mac));
    entries.sort_by_key(|entry| entry.ip);
    entries.dedup_by_key(|entry| entry.ip);
    Ok(entries)
}

/// Whether an address belongs to an allowed private or link-local range.
pub fn is_allowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // fc00::/7 unique local addresses.
            (segments[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local addresses.
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_valid_mac(mac: &str) -> bool {
    let compact: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    compact.len() == 12 && compact.chars().any(|c| c != '0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_link_local_ranges_are_allowed() {
        for value in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.10.20",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
        ] {
            assert!(is_allowed_ip(value.parse().unwrap()), "{value}");
        }
    }

    #[test]
    fn public_and_special_ranges_are_rejected() {
        for value in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.64.0.1",
            "224.0.0.1",
            "2001:db8::1",
            "2400::1",
            "ff02::1",
        ] {
            assert!(!is_allowed_ip(value.parse().unwrap()), "{value}");
        }
    }

    #[test]
    fn all_zero_mac_is_rejected() {
        assert!(!is_valid_mac("00:00:00:00:00:00"));
        assert!(is_valid_mac("00:11:22:33:44:55"));
    }
}
