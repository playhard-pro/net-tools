//! Linux socket collection from `/proc` and best-effort socket destruction.
//!
//! `/proc/net` is part of the kernel's stable user-space ABI. The process owner
//! mapping additionally walks `/proc/<pid>/fd`, which the kernel restricts to
//! the current user unless the process runs with elevated privileges.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

use super::{
    sort_entries, ConnectionEntry, ConnectionProtocol, ConnectionSnapshot, ConnectionState,
};

/// Socket files that make up the IPv4 and IPv6 inventories.
const SOCKET_FILES: [(&str, ConnectionProtocol); 4] = [
    ("/proc/net/tcp", ConnectionProtocol::Tcp),
    ("/proc/net/tcp6", ConnectionProtocol::Tcp),
    ("/proc/net/udp", ConnectionProtocol::Udp),
    ("/proc/net/udp6", ConnectionProtocol::Udp),
];

/// Process owner chosen for a socket inode.
#[derive(Debug, Clone)]
struct ProcessOwner {
    pid: u32,
    name: Option<String>,
}

/// Collect every TCP and UDP socket visible in `/proc`.
pub(super) fn collect() -> Result<ConnectionSnapshot, String> {
    let (owners, hidden_owners) = build_process_map();
    let mut entries = Vec::new();
    let mut read_any = false;

    for (path, protocol) in SOCKET_FILES {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        read_any = true;
        parse_net_file(&text, protocol, &owners, &mut entries);
    }

    if !read_any {
        return Err("could not read the kernel socket tables from /proc/net".to_string());
    }

    sort_entries(&mut entries);
    let mut warnings = Vec::new();
    if hidden_owners {
        warnings.push(
            "some socket owners are hidden by file permissions; run as root to see every process"
                .to_string(),
        );
    }

    Ok(ConnectionSnapshot {
        captured_at: super::super::overview::captured_at_now(),
        entries,
        warnings,
    })
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}` table.
fn parse_net_file(
    text: &str,
    protocol: ConnectionProtocol,
    owners: &HashMap<u32, ProcessOwner>,
    entries: &mut Vec<ConnectionEntry>,
) {
    for line in text.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 10 {
            continue;
        }
        let Some((local_addr, local_port)) = parse_proc_endpoint(columns[1]) else {
            continue;
        };
        let Some((remote_addr, remote_port)) = parse_proc_endpoint(columns[2]) else {
            continue;
        };
        let Ok(state_code) = u8::from_str_radix(columns[3], 16) else {
            continue;
        };
        let uid = columns[7].parse::<u32>().ok();
        let inode = columns[9].parse::<u32>().ok();

        // A zero remote port means the socket has no peer. This covers both
        // listening TCP sockets and unconnected UDP sockets.
        let peer = (remote_port != 0).then_some((remote_addr, remote_port));
        let state = if protocol == ConnectionProtocol::Udp && peer.is_none() {
            ConnectionState::Unconnected
        } else {
            state_from_hex(state_code)
        };
        let owner = inode.and_then(|inode| owners.get(&inode));

        entries.push(ConnectionEntry {
            protocol,
            local_addr,
            local_port,
            remote_addr: peer.map(|(address, _)| address),
            remote_port: peer.map(|(_, port)| port),
            state,
            pid: owner.map(|owner| owner.pid),
            process: owner.and_then(|owner| owner.name.clone()),
            uid,
        });
    }
}

/// Map one `/proc/net` endpoint field into an address and port.
fn parse_proc_endpoint(value: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = match address.len() {
        8 => {
            let raw = u32::from_str_radix(address, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
        }
        32 => {
            // `/proc/net/tcp6` stores four little-endian 32-bit words.
            let mut bytes = [0u8; 16];
            for (index, chunk) in address.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((address, port))
}

/// Translate the kernel's TCP state code into the shared state type.
fn state_from_hex(code: u8) -> ConnectionState {
    match code {
        0x01 => ConnectionState::Established,
        0x02 => ConnectionState::SynSent,
        0x03 => ConnectionState::SynReceived,
        0x04 => ConnectionState::FinWait1,
        0x05 => ConnectionState::FinWait2,
        0x06 => ConnectionState::TimeWait,
        0x07 => ConnectionState::Closed,
        0x08 => ConnectionState::CloseWait,
        0x09 => ConnectionState::LastAck,
        0x0A => ConnectionState::Listen,
        0x0B => ConnectionState::Closing,
        0x0C => ConnectionState::SynReceived,
        _ => ConnectionState::Unknown,
    }
}

/// Build an inode-to-owner map by walking every readable process descriptor.
///
/// Returns whether any descriptor was hidden by permissions so the caller can
/// explain incomplete process information.
fn build_process_map() -> (HashMap<u32, ProcessOwner>, bool) {
    let mut owners: HashMap<u32, ProcessOwner> = HashMap::new();
    let mut hidden = false;
    let Ok(processes) = fs::read_dir("/proc") else {
        return (owners, hidden);
    };

    for process in processes.flatten() {
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        let fd_dir = process.path().join("fd");
        let descriptors = match fs::read_dir(&fd_dir) {
            Ok(descriptors) => descriptors,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    hidden = true;
                }
                continue;
            }
        };
        let name = fs::read_to_string(process.path().join("comm"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        for descriptor in descriptors {
            let Ok(descriptor) = descriptor else {
                hidden = true;
                continue;
            };
            let target = match fs::read_link(descriptor.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    hidden = true;
                    continue;
                }
                Err(_) => continue,
            };
            let Some(inode) = target
                .to_str()
                .and_then(|value| value.strip_prefix("socket:["))
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };

            // A socket may be shared by several processes. Keep the lowest PID
            // so the visible owner is deterministic across snapshots.
            let replace = owners.get(&inode).is_none_or(|existing| pid < existing.pid);
            if replace {
                owners.insert(
                    inode,
                    ProcessOwner {
                        pid,
                        name: name.clone(),
                    },
                );
            }
        }
    }

    (owners, hidden)
}

/// Destroy a TCP or UDP socket through `ss -K`.
///
/// The filter matches the full local/remote tuple so unrelated connections are
/// not affected. `SOCK_DESTROY` requires root and a kernel that supports it.
pub(super) fn close_connection(entry: &ConnectionEntry) -> Result<(), String> {
    let (Some(remote_addr), Some(remote_port)) = (entry.remote_addr, entry.remote_port) else {
        return Err("the socket has no remote endpoint".to_string());
    };
    let protocol = match entry.protocol {
        ConnectionProtocol::Tcp => "-t",
        ConnectionProtocol::Udp => "-u",
    };
    let local_port = format!(":{}", entry.local_port);
    let remote_port = format!(":{}", remote_port);
    let local_addr = entry.local_addr.to_string();
    let remote_addr = remote_addr.to_string();

    let output = Command::new("ss")
        .args([
            "-K",
            "-n",
            protocol,
            "src",
            &local_addr,
            "sport",
            "=",
            &local_port,
            "dst",
            &remote_addr,
            "dport",
            "=",
            &remote_port,
        ])
        .output();

    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            Err(if detail.is_empty() {
                "ss -K could not destroy the connection".to_string()
            } else {
                detail
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
            "the `ss` command was not found; install iproute2 or close the connection by ending the process"
                .to_string(),
        ),
        Err(error) => Err(format!("failed to run ss: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_listener() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n";
        let mut entries = Vec::new();
        parse_net_file(text, ConnectionProtocol::Tcp, &HashMap::new(), &mut entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(entries[0].local_port, 8080);
        assert_eq!(entries[0].state, ConnectionState::Listen);
        assert!(!entries[0].has_remote());
        assert_eq!(entries[0].uid, Some(1000));
    }

    #[test]
    fn parses_ipv6_established_connection() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0\n";
        let mut entries = Vec::new();
        parse_net_file(text, ConnectionProtocol::Tcp, &HashMap::new(), &mut entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(entries[0].local_port, 443);
        assert_eq!(entries[0].state, ConnectionState::Established);
    }

    #[test]
    fn unconnected_udp_has_no_peer() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    53        0 999 1 0000000000000000 0\n";
        let mut entries = Vec::new();
        parse_net_file(text, ConnectionProtocol::Udp, &HashMap::new(), &mut entries);
        assert_eq!(entries[0].state, ConnectionState::Unconnected);
        assert!(!entries[0].has_remote());
    }

    #[test]
    fn collects_current_process_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let snapshot = collect().unwrap();
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| entry.local_port == port && entry.state == ConnectionState::Listen)
            .expect("the test listener should appear in the socket table");
        assert_eq!(entry.pid, Some(std::process::id()));
        assert!(entry.process.is_some());
    }

    #[test]
    fn maps_kernel_states() {
        assert_eq!(state_from_hex(0x01), ConnectionState::Established);
        assert_eq!(state_from_hex(0x06), ConnectionState::TimeWait);
        assert_eq!(state_from_hex(0x0A), ConnectionState::Listen);
        assert_eq!(state_from_hex(0xFF), ConnectionState::Unknown);
    }
}
