//! macOS neighbor table reader backed by `arp` and `ndp`.

use std::net::IpAddr;
use std::process::Command;

use super::NeighborEntry;

pub(super) fn collect() -> Result<Vec<NeighborEntry>, String> {
    let mut entries = read_command("arp", &["-an"], parse_arp);
    entries.extend(read_command("ndp", &["-an"], parse_ndp));
    Ok(entries)
}

fn read_command(
    program: &str,
    args: &[&str],
    parse: fn(&str) -> Vec<NeighborEntry>,
) -> Vec<NeighborEntry> {
    let output = match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse(&String::from_utf8_lossy(&output.stdout))
}

fn parse_arp(text: &str) -> Vec<NeighborEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let Some((ip, rest)) = line
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
        else {
            continue;
        };
        let Ok(ip) = ip.parse::<IpAddr>() else {
            continue;
        };
        let Some((_, after_at)) = rest.split_once(" at ") else {
            continue;
        };
        let mac = after_at
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if mac == "(INCOMPLETE)" || !mac.contains(':') {
            continue;
        }
        let interface = rest
            .split_once(" on ")
            .and_then(|(_, value)| value.split_whitespace().next())
            .map(|value| value.to_string());
        entries.push(NeighborEntry { ip, mac, interface });
    }
    entries
}

fn parse_ndp(text: &str) -> Vec<NeighborEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let (address, zone) = tokens[0]
            .split_once('%')
            .map_or((tokens[0], None), |(address, zone)| (address, Some(zone)));
        let Ok(ip) = address.parse::<IpAddr>() else {
            continue;
        };
        let mac = tokens[1].to_ascii_uppercase();
        if !mac.contains(':') {
            continue;
        }
        entries.push(NeighborEntry {
            ip,
            mac,
            interface: zone.map(|value| value.to_string()),
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_fixture_is_parsed() {
        let text = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n\
? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n";
        let entries = parse_arp(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].interface.as_deref(), Some("en0"));
    }

    #[test]
    fn ndp_fixture_is_parsed() {
        let text = "fe80::1%en0 aa:bb:cc:dd:ee:ff 23 en0 23h S R\n";
        let entries = parse_ndp(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].interface.as_deref(), Some("en0"));
    }
}
