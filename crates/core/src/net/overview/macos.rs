//! macOS implementation.
//!
//! Interface attributes and counters are read from the standard `ifconfig` and
//! `netstat` tools, routes from `netstat -rn`, and DNS servers from `scutil`.
//! The outputs are parsed defensively so a missing or reworded field only drops
//! that field instead of failing the whole overview.

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

use super::{
    captured_at_now, with_prefix, DefaultGateway, InterfaceCounters, NetworkInterface,
    NetworkRoute, NetworkSnapshot,
};

/// Collect interfaces, addresses, routes and DNS servers.
pub(super) fn collect() -> Result<NetworkSnapshot, String> {
    let mut interfaces = read_ifconfig();
    merge_if_addrs(&mut interfaces);
    let counters = read_counters();
    for (name, interface) in &mut interfaces {
        if let Some(value) = counters.get(name) {
            interface.counters = *value;
        }
    }

    let routes = read_routes();
    let default_gateways = default_gateways(&routes);

    Ok(NetworkSnapshot {
        captured_at: captured_at_now(),
        interfaces: interfaces.into_values().collect(),
        default_gateways,
        dns_servers: read_dns_servers(),
        routes,
    })
}

/// Run a system utility and return its standard output.
fn output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse `ifconfig -a` for names, link state, MAC, MTU and media speed.
fn read_ifconfig() -> BTreeMap<String, NetworkInterface> {
    output("ifconfig", &["-a"])
        .map(|text| parse_ifconfig(&text))
        .unwrap_or_default()
}

fn parse_ifconfig(text: &str) -> BTreeMap<String, NetworkInterface> {
    let mut interfaces = BTreeMap::new();
    let mut current: Option<NetworkInterface> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        let starts_block = line
            .chars()
            .next()
            .is_some_and(|character| !character.is_whitespace());
        if starts_block {
            if let Some(interface) = current.take() {
                interfaces.insert(interface.name.clone(), interface);
            }
            let Some(name) = line.split(':').next() else {
                continue;
            };
            let mut interface = NetworkInterface {
                name: name.to_string(),
                ..NetworkInterface::default()
            };
            interface.up = flags(line).is_some_and(|flags| flags.contains("UP"));
            interface.mtu = token_after(line, "mtu ").and_then(|value| value.parse().ok());
            current = Some(interface);
            continue;
        }

        let Some(interface) = current.as_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("ether ") {
            interface.mac = value
                .split_whitespace()
                .next()
                .and_then(|value| super::format_mac(&parse_mac_bytes(value)));
        } else if let Some(value) = trimmed.strip_prefix("status: ") {
            interface.up = value.trim() == "active";
        } else if let Some(value) = trimmed.strip_prefix("media: ") {
            interface.link_speed_bps = parse_media_speed(value);
        }
    }

    if let Some(interface) = current {
        interfaces.insert(interface.name.clone(), interface);
    }
    interfaces
}

/// Extract the `<...>` flag list from an `ifconfig` block header.
fn flags(line: &str) -> Option<&str> {
    let start = line.find('<')?;
    let end = line[start..].find('>')? + start;
    Some(&line[start + 1..end])
}

/// Return the first whitespace-delimited token after `marker`.
fn token_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker)?.1.split_whitespace().next()
}

/// Parse a colon-separated MAC address into bytes.
fn parse_mac_bytes(value: &str) -> Vec<u8> {
    value
        .split(':')
        .filter_map(|part| u8::from_str_radix(part, 16).ok())
        .collect()
}

/// Read media speed such as `1000baseT` or `10Gbase-T` into bits per second.
fn parse_media_speed(value: &str) -> Option<u64> {
    let lower = value.to_ascii_lowercase();
    let base = lower.find("base")?;
    let prefix = &lower[..base];
    let digits: String = prefix
        .chars()
        .rev()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let mut mbps = digits.parse::<u64>().ok()?;
    if prefix.ends_with('g') {
        mbps = mbps.saturating_mul(1000);
    }
    (mbps > 0).then_some(mbps.saturating_mul(1_000_000))
}

/// Add IP addresses from `getifaddrs`.
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

/// Read cumulative counters from `netstat -ibn`.
fn read_counters() -> BTreeMap<String, InterfaceCounters> {
    output("netstat", &["-ibn"])
        .map(|text| parse_netstat_counters(&text))
        .unwrap_or_default()
}

fn parse_netstat_counters(text: &str) -> BTreeMap<String, InterfaceCounters> {
    let mut counters: BTreeMap<String, InterfaceCounters> = BTreeMap::new();
    let mut lines = text.lines();

    let Some(header_line) = lines.find(|line| line.split_whitespace().next() == Some("Name"))
    else {
        return counters;
    };
    let headers: Vec<&str> = header_line.split_whitespace().collect();
    let column = |name: &str| headers.iter().position(|header| *header == name);
    let (Some(ipkts), Some(ibytes), Some(opkts), Some(obytes)) = (
        column("Ipkts"),
        column("Ibytes"),
        column("Opkts"),
        column("Obytes"),
    ) else {
        return counters;
    };

    for line in lines {
        let columns: Vec<&str> = line.split_whitespace().collect();
        let name = columns.first().copied().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let value = |index: usize| -> u64 {
            columns
                .get(index)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
        };
        let entry = counters.entry(name.to_string()).or_default();
        // A link can appear once per address; the largest sample is the
        // interface-wide counter and avoids double counting alias rows.
        entry.rx_packets = entry.rx_packets.max(value(ipkts));
        entry.rx_bytes = entry.rx_bytes.max(value(ibytes));
        entry.tx_packets = entry.tx_packets.max(value(opkts));
        entry.tx_bytes = entry.tx_bytes.max(value(obytes));
    }
    counters
}

/// Read IPv4 and IPv6 routes from `netstat -rn`.
fn read_routes() -> Vec<NetworkRoute> {
    let mut routes = Vec::new();
    for (family, flag) in [("IPv4", "inet"), ("IPv6", "inet6")] {
        if let Some(text) = output("netstat", &["-rn", "-f", flag]) {
            routes.extend(parse_routes(&text, family));
        }
    }
    routes.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.destination.cmp(&b.destination))
            .then_with(|| a.metric.cmp(&b.metric))
    });
    routes
}

fn parse_routes(text: &str, family: &str) -> Vec<NetworkRoute> {
    let mut routes = Vec::new();
    for line in text.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 4 {
            continue;
        }
        let destination = columns[0];
        if destination == "Destination"
            || destination == "Routing"
            || destination.ends_with(':')
            || destination == "Internet"
            || destination == "Internet6"
        {
            continue;
        }
        let gateway = columns[1];
        // A local route names its gateway as `link#N`; show it as on-link.
        let gateway = if gateway.starts_with("link#") {
            "-".to_string()
        } else {
            gateway.to_string()
        };
        routes.push(NetworkRoute {
            family: family.to_string(),
            destination: destination.to_string(),
            gateway,
            interface: columns[3].to_string(),
            metric: None,
        });
    }
    routes
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

/// Read DNS servers from `scutil --dns`, with `/etc/resolv.conf` as fallback.
fn read_dns_servers() -> Vec<String> {
    let mut servers = output("scutil", &["--dns"])
        .map(|text| parse_scutil_dns(&text))
        .unwrap_or_default();
    if servers.is_empty() {
        servers = fs::read_to_string("/etc/resolv.conf")
            .map(|text| parse_resolv_conf(&text))
            .unwrap_or_default();
    }
    servers
}

fn parse_scutil_dns(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("nameserver[") else {
            continue;
        };
        let Some((_, server)) = rest.split_once(':') else {
            continue;
        };
        let server = server.trim();
        if !server.is_empty() && !servers.iter().any(|known| known == server) {
            servers.push(server.to_string());
        }
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
    fn ifconfig_parsing_reads_link_fields() {
        let text = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500\n\
                    \tether 00:11:22:33:44:55\n\
                    \tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n\
                    \tmedia: autoselect (1000baseT <full-duplex>)\n\
                    \tstatus: active\n";
        let interfaces = parse_ifconfig(text);
        let interface = &interfaces["en0"];
        assert!(interface.up);
        assert_eq!(interface.mtu, Some(1500));
        assert_eq!(interface.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(interface.link_speed_bps, Some(1_000_000_000));
    }

    #[test]
    fn netstat_counters_take_largest_alias_row() {
        let text = "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\n\
                    en0       1500  <Link#4>      aa:bb:cc:dd:ee:ff    10     0        100       20     0        200     0\n\
                    en0       1500  192.0.2/24    192.0.2.10           12     0        120       22     0        220     0\n";
        let counters = parse_netstat_counters(text);
        let counters = &counters["en0"];
        assert_eq!(counters.rx_packets, 12);
        assert_eq!(counters.rx_bytes, 120);
        assert_eq!(counters.tx_packets, 22);
        assert_eq!(counters.tx_bytes, 220);
    }

    #[test]
    fn route_parsing_skips_headers_and_marks_on_link() {
        let text = "Routing tables\n\nInternet:\n\
                    Destination        Gateway            Flags        Netif Expire\n\
                    default            192.0.2.1          UGScg          en0\n\
                    192.0.2/24         link#4             UCS            en0\n";
        let routes = parse_routes(text, "IPv4");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[1].gateway, "-");
    }

    #[test]
    fn scutil_dns_deduplicates_nameservers() {
        let text = "resolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 8.8.8.8\n\
                    resolver #2\n  nameserver[0] : 1.1.1.1\n";
        assert_eq!(
            parse_scutil_dns(text),
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }

    #[test]
    fn media_speed_handles_megabit_and_gigabit_values() {
        assert_eq!(
            parse_media_speed("1000baseT <full-duplex>"),
            Some(1_000_000_000)
        );
        assert_eq!(parse_media_speed("10Gbase-T"), Some(10_000_000_000));
        assert_eq!(parse_media_speed("autoselect"), None);
    }
}
