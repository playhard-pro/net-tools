//! Linux implementation backed by `/proc` and `/sys`.
//!
//! These interfaces are part of the kernel's stable user-space ABI, so no
//! external command or additional dependency is needed.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    captured_at_now, format_mac, with_prefix, DefaultGateway, InterfaceCounters, NetworkInterface,
    NetworkRoute, NetworkSnapshot,
};

/// Routing table flag for an usable route.
const RTF_UP: u32 = 0x0001;

/// Collect interfaces, addresses, routes and DNS servers.
pub(super) fn collect() -> Result<NetworkSnapshot, String> {
    let mut interfaces = read_sysfs_interfaces();
    merge_if_addrs(&mut interfaces);
    for (name, interface) in &mut interfaces {
        fill_sysfs_details(name, interface);
    }

    let mut routes = read_ipv4_routes();
    routes.extend(read_ipv6_routes());
    routes.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.destination.cmp(&b.destination))
            .then_with(|| a.metric.cmp(&b.metric))
    });

    let default_gateways = default_gateways(&routes);

    Ok(NetworkSnapshot {
        captured_at: captured_at_now(),
        interfaces: interfaces.into_values().collect(),
        default_gateways,
        dns_servers: read_dns_servers(),
        routes,
    })
}

/// Start from the kernel's interface directory so down links without an
/// address are still listed.
fn read_sysfs_interfaces() -> BTreeMap<String, NetworkInterface> {
    let mut interfaces = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return interfaces;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        interfaces.insert(
            name.clone(),
            NetworkInterface {
                name,
                ..NetworkInterface::default()
            },
        );
    }
    interfaces
}

/// Add the addresses reported by `getifaddrs` and fold the operational state
/// into each interface.
fn merge_if_addrs(interfaces: &mut BTreeMap<String, NetworkInterface>) {
    let Ok(addresses) = if_addrs::get_if_addrs() else {
        return;
    };
    for address in addresses {
        let interface =
            interfaces
                .entry(address.name.clone())
                .or_insert_with(|| NetworkInterface {
                    name: address.name.clone(),
                    ..NetworkInterface::default()
                });
        interface.up |= address.is_oper_up();
        match address.addr {
            if_addrs::IfAddr::V4(v4) => {
                let text = with_prefix(v4.ip, v4.prefixlen);
                if !interface.ipv4.contains(&text) {
                    interface.ipv4.push(text);
                }
            }
            if_addrs::IfAddr::V6(v6) => {
                let text = with_prefix(v6.ip, v6.prefixlen);
                if !interface.ipv6.contains(&text) {
                    interface.ipv6.push(text);
                }
            }
        }
    }
}

/// Read the per-interface attributes that `getifaddrs` does not provide.
fn fill_sysfs_details(name: &str, interface: &mut NetworkInterface) {
    let base = format!("/sys/class/net/{name}");

    interface.mac = read_trim(&format!("{base}/address"))
        .as_deref()
        .and_then(parse_mac);
    interface.mtu = read_trim(&format!("{base}/mtu")).and_then(|value| value.parse().ok());

    let state = read_trim(&format!("{base}/operstate"));
    if state.as_deref() == Some("up") {
        interface.up = true;
    }

    interface.link_speed_bps = read_trim(&format!("{base}/speed"))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|mbps| mbps.saturating_mul(1_000_000));

    interface.counters = InterfaceCounters {
        rx_bytes: read_counter(&format!("{base}/statistics/rx_bytes")),
        tx_bytes: read_counter(&format!("{base}/statistics/tx_bytes")),
        rx_packets: read_counter(&format!("{base}/statistics/rx_packets")),
        tx_packets: read_counter(&format!("{base}/statistics/tx_packets")),
    };
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn read_counter(path: &str) -> u64 {
    read_trim(path)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn parse_mac(value: &str) -> Option<String> {
    let bytes: Vec<u8> = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    format_mac(&bytes)
}

/// Parse the IPv4 routing table from `/proc/net/route`.
fn read_ipv4_routes() -> Vec<NetworkRoute> {
    let Ok(text) = fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    parse_ipv4_routes(&text)
}

fn parse_ipv4_routes(text: &str) -> Vec<NetworkRoute> {
    let mut routes = Vec::new();
    for line in text.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 8 {
            continue;
        }
        let Some(destination) = parse_hex_ipv4(columns[1]) else {
            continue;
        };
        let Some(gateway) = parse_hex_ipv4(columns[2]) else {
            continue;
        };
        let flags = u32::from_str_radix(columns[3], 16).unwrap_or(0);
        if flags & RTF_UP == 0 {
            continue;
        }
        let Some(mask) = parse_hex_ipv4(columns[7]) else {
            continue;
        };
        let prefix = mask
            .octets()
            .iter()
            .map(|byte| byte.count_ones())
            .sum::<u32>();
        let destination = if destination.is_unspecified() && prefix == 0 {
            "default".to_string()
        } else {
            with_prefix(destination, prefix as u8)
        };
        routes.push(NetworkRoute {
            family: "IPv4".to_string(),
            destination,
            gateway: gateway_text(gateway.is_unspecified(), gateway.to_string()),
            interface: columns[0].to_string(),
            metric: columns[6].parse::<u32>().ok(),
        });
    }
    routes
}

/// Parse the IPv6 routing table from `/proc/net/ipv6_route`.
fn read_ipv6_routes() -> Vec<NetworkRoute> {
    let Ok(text) = fs::read_to_string("/proc/net/ipv6_route") else {
        return Vec::new();
    };
    parse_ipv6_routes(&text)
}

fn parse_ipv6_routes(text: &str) -> Vec<NetworkRoute> {
    let mut routes = Vec::new();
    for line in text.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 10 {
            continue;
        }
        let Some(destination) = parse_hex_ipv6(columns[0]) else {
            continue;
        };
        let Some(gateway) = parse_hex_ipv6(columns[4]) else {
            continue;
        };
        let Ok(prefix) = u8::from_str_radix(columns[1], 16) else {
            continue;
        };
        let flags = u32::from_str_radix(columns[8], 16).unwrap_or(0);
        if flags & RTF_UP == 0 {
            continue;
        }
        let destination = if destination.is_unspecified() && prefix == 0 {
            "default".to_string()
        } else {
            with_prefix(destination, prefix)
        };
        routes.push(NetworkRoute {
            family: "IPv6".to_string(),
            destination,
            gateway: gateway_text(gateway.is_unspecified(), gateway.to_string()),
            interface: columns[9].to_string(),
            metric: u32::from_str_radix(columns[5], 16).ok(),
        });
    }
    routes
}

/// `/proc/net/route` stores IPv4 addresses as little-endian hexadecimal words.
fn parse_hex_ipv4(value: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(value, 16).ok()?;
    Some(Ipv4Addr::from(raw.to_le_bytes()))
}

/// `/proc/net/ipv6_route` stores IPv6 addresses as hexadecimal groups.
fn parse_hex_ipv6(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut groups = [0u16; 8];
    for (index, group) in groups.iter_mut().enumerate() {
        *group = u16::from_str_radix(&value[index * 4..index * 4 + 4], 16).ok()?;
    }
    Some(Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
    ))
}

fn gateway_text(unspecified: bool, value: String) -> String {
    if unspecified {
        "-".to_string()
    } else {
        value
    }
}

fn default_gateways(routes: &[NetworkRoute]) -> Vec<DefaultGateway> {
    let mut gateways: Vec<DefaultGateway> = routes
        .iter()
        .filter(|route| route.destination == "default")
        .map(|route| DefaultGateway {
            family: route.family.clone(),
            gateway: route.gateway.clone(),
            interface: route.interface.clone(),
            metric: route.metric,
        })
        .collect();
    gateways.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.metric.cmp(&b.metric))
    });
    gateways
}

/// Read DNS servers from the resolver configuration. When the stub resolver is
/// in use, fall back to systemd's upstream list if the stub file has none.
fn read_dns_servers() -> Vec<String> {
    let mut servers =
        parse_resolv_conf(&fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
    if servers.is_empty() {
        servers = parse_resolv_conf(
            &fs::read_to_string("/run/systemd/resolve/resolv.conf").unwrap_or_default(),
        );
    }
    servers
}

fn parse_resolv_conf(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let Some(server) = rest.split_whitespace().next() else {
            continue;
        };
        if !servers.iter().any(|known| known == server) {
            servers.push(server.to_string());
        }
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_route_parsing_handles_hex_byte_order() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let routes = parse_ipv4_routes(text);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[0].gateway, "192.168.0.1");
        assert_eq!(routes[0].interface, "eth0");
        assert_eq!(routes[0].metric, Some(100));
    }

    #[test]
    fn ipv6_route_parsing_reads_prefix_and_metric() {
        let text = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000000 00000000 00000001 eth0\n";
        let routes = parse_ipv6_routes(text);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[0].gateway, "-");
        assert_eq!(routes[0].metric, Some(100));
    }

    #[test]
    fn resolv_conf_keeps_order_and_deduplicates() {
        let text = "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }
}
