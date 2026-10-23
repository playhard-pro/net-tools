//! Linux neighbor table reader.
//!
//! IPv4 entries come from the stable `/proc/net/arp` interface. IPv6 entries
//! are read through `ip -6 neigh` when iproute2 is installed; a missing tool
//! only drops the IPv6 side.

use std::fs;
use std::net::IpAddr;
use std::process::Command;

use super::NeighborEntry;

pub(super) fn collect() -> Result<Vec<NeighborEntry>, String> {
    let mut entries = read_arp();
    entries.extend(read_ipv6_neighbors());
    Ok(entries)
}

fn read_arp() -> Vec<NeighborEntry> {
    fs::read_to_string("/proc/net/arp")
        .map(|text| parse_arp(&text))
        .unwrap_or_default()
}

fn parse_arp(text: &str) -> Vec<NeighborEntry> {
    let mut entries = Vec::new();
    for line in text.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 6 {
            continue;
        }
        let Ok(ip) = columns[0].parse::<IpAddr>() else {
            continue;
        };
        let mac = columns[3].to_ascii_uppercase().replace('-', ":");
        entries.push(NeighborEntry {
            ip,
            mac,
            interface: Some(columns[5].to_string()),
        });
    }
    entries
}

fn read_ipv6_neighbors() -> Vec<NeighborEntry> {
    let output = match Command::new("ip").args(["-6", "neigh", "show"]).output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_ip_neigh(&String::from_utf8_lossy(&output.stdout))
}

fn parse_ip_neigh(text: &str) -> Vec<NeighborEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(ip) = tokens
            .first()
            .and_then(|value| value.parse::<IpAddr>().ok())
        else {
            continue;
        };
        let mac = tokens
            .iter()
            .position(|token| *token == "lladdr")
            .and_then(|index| tokens.get(index + 1))
            .map(|value| value.to_ascii_uppercase().replace('-', ":"));
        let Some(mac) = mac else {
            continue;
        };
        let interface = tokens
            .iter()
            .position(|token| *token == "dev")
            .and_then(|index| tokens.get(index + 1))
            .map(|value| (*value).to_string());
        entries.push(NeighborEntry { ip, mac, interface });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_fixture_is_parsed() {
        let text =
            "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let entries = parse_arp(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(entries[0].interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn ipv6_neighbor_fixture_is_parsed() {
        let text = "fe80::1 dev eth0 lladdr AA:BB:CC:DD:EE:FF router REACHABLE\n\
fe80::2 dev eth0  FAILED\n";
        let entries = parse_ip_neigh(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].mac, "AA:BB:CC:DD:EE:FF");
    }
}
