//! macOS socket collection through the standard `lsof` utility.
//!
//! The public libproc interfaces do not provide a complete, stable socket table
//! with owner information, so this view reuses the same defensive command
//! parsing approach as the macOS network overview.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

use super::{
    sort_entries, ConnectionEntry, ConnectionProtocol, ConnectionSnapshot, ConnectionState,
};

/// Collect TCP and UDP sockets reported by `lsof`.
pub(super) fn collect() -> Result<ConnectionSnapshot, String> {
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", "-iUDP"])
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "the `lsof` command was not found; it is required for the connection viewer"
                    .to_string()
            } else {
                format!("failed to run lsof: {error}")
            }
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut entries = parse_lsof(&stdout);

    if entries.is_empty() && !output.status.success() {
        return Err(if stderr.is_empty() {
            "lsof could not read the socket table".to_string()
        } else {
            stderr
        });
    }

    sort_entries(&mut entries);
    let mut warnings = Vec::new();
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") {
        warnings.push(
            "some socket owners are hidden by file permissions; run with elevated privileges to see every process"
                .to_string(),
        );
    }

    Ok(ConnectionSnapshot {
        captured_at: super::super::overview::captured_at_now(),
        entries,
        warnings,
    })
}

/// Parse the columns printed by `lsof -nP -iTCP -iUDP`.
fn parse_lsof(text: &str) -> Vec<ConnectionEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 9 || columns[0] == "COMMAND" {
            continue;
        }
        let pid = columns[1].parse::<u32>().ok();
        let family = match columns[4] {
            "IPv4" => Family::V4,
            "IPv6" => Family::V6,
            _ => continue,
        };
        // The NODE column carries the protocol token and NAME starts right
        // after it. Joining from NODE keeps the rest of the NAME intact when it
        // contains spaces around the state marker.
        let name = columns[7..].join(" ");
        let Some((protocol, endpoint)) = split_protocol_token(&name) else {
            continue;
        };
        let (state, endpoint) = split_state(endpoint);
        let (local, remote) = endpoint
            .split_once("->")
            .map_or((endpoint, None), |(a, b)| (a, Some(b)));
        let Some((local_addr, local_port)) = parse_lsof_endpoint(local.trim(), family) else {
            continue;
        };
        let peer = remote
            .and_then(|value| parse_lsof_endpoint(value.trim(), family))
            .filter(|(_, port)| *port != 0);

        entries.push(ConnectionEntry {
            protocol,
            local_addr,
            local_port,
            remote_addr: peer.map(|(address, _)| address),
            remote_port: peer.map(|(_, port)| port),
            state: if protocol == ConnectionProtocol::Udp && peer.is_none() {
                ConnectionState::Unconnected
            } else {
                state.unwrap_or(ConnectionState::Unknown)
            },
            pid,
            process: Some(columns[0].to_string()),
            uid: None,
        });
    }
    entries
}

/// Address family used to interpret wildcard addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Split a trailing `(STATE)` marker from the endpoint text.
fn split_state(value: &str) -> (Option<ConnectionState>, &str) {
    let trimmed = value.trim();
    let Some(open) = trimmed.rfind(" (") else {
        return (None, trimmed);
    };
    let Some(close) = trimmed[open..].find(')').map(|index| open + index) else {
        return (None, trimmed);
    };
    let label = &trimmed[open + 2..close];
    let state = match label {
        "LISTEN" => Some(ConnectionState::Listen),
        "ESTABLISHED" => Some(ConnectionState::Established),
        "SYN_SENT" => Some(ConnectionState::SynSent),
        "SYN_RCVD" | "SYN_RECV" => Some(ConnectionState::SynReceived),
        "FIN_WAIT_1" | "FIN_WAIT1" => Some(ConnectionState::FinWait1),
        "FIN_WAIT_2" | "FIN_WAIT2" => Some(ConnectionState::FinWait2),
        "CLOSE_WAIT" => Some(ConnectionState::CloseWait),
        "CLOSING" => Some(ConnectionState::Closing),
        "LAST_ACK" => Some(ConnectionState::LastAck),
        "TIME_WAIT" => Some(ConnectionState::TimeWait),
        "CLOSED" => Some(ConnectionState::Closed),
        _ => Some(ConnectionState::Unknown),
    };
    (state, trimmed[..open].trim())
}

/// Parse `address:port`, `*:port` or `[address]:port` as printed by lsof.
fn parse_lsof_endpoint(value: &str, family: Family) -> Option<(IpAddr, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest.get(end + 1..)?.strip_prefix(':')?;
        (host, port)
    } else {
        value.rsplit_once(':')?
    };
    let port = if port == "*" {
        0
    } else {
        port.parse::<u16>().ok()?
    };
    let address = if host == "*" {
        match family {
            Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Family::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    } else {
        host.parse::<IpAddr>().ok()?
    };
    Some((address, port))
}

/// Split the NAME column into a protocol and endpoint text.
///
/// lsof prints either `TCP ...`, `UDP ...`, or a `TCP6 ...`/`UDP6 ...` variant
/// depending on its version. The protocol token always starts with `TCP` or
/// `UDP`.
fn split_protocol_token(name: &str) -> Option<(ConnectionProtocol, &str)> {
    let mut parts = name.splitn(2, ' ');
    let token = parts.next()?;
    let rest = parts.next().unwrap_or_default().trim();
    if token.starts_with("TCP") {
        Some((ConnectionProtocol::Tcp, rest))
    } else if token.starts_with("UDP") {
        Some((ConnectionProtocol::Udp, rest))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listener_and_established_rows() {
        let text = "\
COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
python3    4321 rex    3u  IPv4 0x1234567890      0t0  TCP *:8080 (LISTEN)
Google     4322 rex   45u  IPv6 0x1234567891      0t0  TCP [::1]:5000->[::1]:443 (ESTABLISHED)
mDNSRespo   123 _mdns 4u  IPv4 0x1234567892      0t0  UDP *:5353
";
        let entries = parse_lsof(text);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].local_port, 8080);
        assert_eq!(entries[0].state, ConnectionState::Listen);
        assert_eq!(entries[0].pid, Some(4321));
        assert_eq!(entries[0].process.as_deref(), Some("python3"));
        assert_eq!(entries[1].state, ConnectionState::Established);
        assert_eq!(entries[1].remote_endpoint(), "[::1]:443");
        assert_eq!(entries[2].state, ConnectionState::Unconnected);
        assert!(!entries[2].has_remote());
    }

    #[test]
    fn splits_protocol_tokens() {
        let (protocol, rest) =
            split_protocol_token("TCP6 [::1]:443->[::1]:80 (ESTABLISHED)").unwrap();
        assert_eq!(protocol, ConnectionProtocol::Tcp);
        assert_eq!(rest, "[::1]:443->[::1]:80 (ESTABLISHED)");
    }

    #[test]
    fn parses_wildcard_and_bracketed_endpoints() {
        assert_eq!(
            parse_lsof_endpoint("*:80", Family::V4),
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80))
        );
        assert_eq!(
            parse_lsof_endpoint("[::1]:443", Family::V6),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 443))
        );
        assert_eq!(
            parse_lsof_endpoint("*:*", Family::V6),
            Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        );
    }
}
