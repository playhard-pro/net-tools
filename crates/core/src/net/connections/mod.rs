//! Local socket inventory and connection control.
//!
//! The collector returns a unified view of the host's TCP and UDP sockets,
//! including the owning process where the operating system exposes it. The
//! platform modules keep all native access out of the UI.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// Transport protocol of one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionProtocol {
    Tcp,
    Udp,
}

impl ConnectionProtocol {
    /// Stable display label used by the table and exports.
    pub fn label(self) -> &'static str {
        match self {
            ConnectionProtocol::Tcp => "TCP",
            ConnectionProtocol::Udp => "UDP",
        }
    }
}

/// Normalized socket state across the platform data sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    Listen,
    Established,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
    /// A bound UDP socket without a peer.
    Unconnected,
    Unknown,
}

impl ConnectionState {
    /// Stable display label independent of the platform spelling.
    pub fn label(self) -> &'static str {
        match self {
            ConnectionState::Listen => "LISTEN",
            ConnectionState::Established => "ESTABLISHED",
            ConnectionState::SynSent => "SYN_SENT",
            ConnectionState::SynReceived => "SYN_RECV",
            ConnectionState::FinWait1 => "FIN_WAIT1",
            ConnectionState::FinWait2 => "FIN_WAIT2",
            ConnectionState::CloseWait => "CLOSE_WAIT",
            ConnectionState::Closing => "CLOSING",
            ConnectionState::LastAck => "LAST_ACK",
            ConnectionState::TimeWait => "TIME_WAIT",
            ConnectionState::Closed => "CLOSED",
            ConnectionState::Unconnected => "UNCONN",
            ConnectionState::Unknown => "UNKNOWN",
        }
    }

    /// Whether the socket is waiting for incoming traffic.
    pub fn is_listening(self) -> bool {
        matches!(self, ConnectionState::Listen | ConnectionState::Unconnected)
    }

    /// Rank used to put listening sockets before active connections.
    fn rank(self) -> u8 {
        if self.is_listening() {
            0
        } else if self == ConnectionState::Established {
            1
        } else {
            2
        }
    }
}

/// One TCP or UDP socket as reported by the operating system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub protocol: ConnectionProtocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    /// Peer address; `None` for listening and unconnected sockets.
    pub remote_addr: Option<IpAddr>,
    /// Peer port; `None` for listening and unconnected sockets.
    pub remote_port: Option<u16>,
    pub state: ConnectionState,
    /// Owning process when the platform exposes it.
    pub pid: Option<u32>,
    /// Process name or executable base name when available.
    pub process: Option<String>,
    /// Owner UID; only Linux reports it in this view.
    pub uid: Option<u32>,
}

impl ConnectionEntry {
    /// Local endpoint formatted with brackets around IPv6 addresses.
    pub fn local_endpoint(&self) -> String {
        endpoint(self.local_addr, self.local_port)
    }

    /// Remote endpoint, or `-` when the socket has no peer.
    pub fn remote_endpoint(&self) -> String {
        match (self.remote_addr, self.remote_port) {
            (Some(address), Some(port)) => endpoint(address, port),
            _ => "-".to_string(),
        }
    }

    /// Whether this entry describes a usable peer connection.
    pub fn has_remote(&self) -> bool {
        self.remote_addr.is_some() && self.remote_port.is_some()
    }
}

/// Point-in-time result of a local socket collection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    /// Local wall-clock time when the snapshot was collected.
    pub captured_at: String,
    pub entries: Vec<ConnectionEntry>,
    /// Non-fatal limitations, such as sockets whose owner is invisible.
    pub warnings: Vec<String>,
}

/// Format an address and port for display, adding IPv6 brackets.
pub(crate) fn endpoint(address: IpAddr, port: u16) -> String {
    SocketAddr::new(address, port).to_string()
}

/// Collect the current socket table using the platform data source.
pub fn collect() -> Result<ConnectionSnapshot, String> {
    #[cfg(target_os = "linux")]
    {
        linux::collect()
    }
    #[cfg(target_os = "macos")]
    {
        macos::collect()
    }
    #[cfg(windows)]
    {
        windows::collect()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err("the connection viewer is not supported on this platform".to_string())
    }
}

/// Sort entries into the stable order used by the table.
pub(crate) fn sort_entries(entries: &mut [ConnectionEntry]) {
    entries.sort_by(|a, b| {
        a.state
            .rank()
            .cmp(&b.state.rank())
            .then_with(|| a.local_port.cmp(&b.local_port))
            .then_with(|| a.protocol.label().cmp(b.protocol.label()))
            .then_with(|| a.local_addr.cmp(&b.local_addr))
            .then_with(|| a.remote_addr.cmp(&b.remote_addr))
            .then_with(|| a.remote_port.cmp(&b.remote_port))
            .then_with(|| a.pid.cmp(&b.pid))
    });
}

/// Whether the current platform can close this entry's socket.
pub fn close_connection_supported(entry: &ConnectionEntry) -> bool {
    if !entry.has_remote() || entry.state.is_listening() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        true
    }
    #[cfg(windows)]
    {
        entry.protocol == ConnectionProtocol::Tcp
            && entry.remote_addr.is_some_and(|address| address.is_ipv4())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = entry;
        false
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        false
    }
}

/// Terminate a process.
///
/// On Unix `force` selects `SIGKILL` instead of `SIGTERM`. Windows always uses
/// `TerminateProcess`, which has no graceful equivalent.
pub fn terminate_process(pid: u32, force: bool) -> Result<(), String> {
    if pid == 0 {
        return Err("refusing to terminate the system idle process".to_string());
    }
    #[cfg(unix)]
    {
        let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
        let result = unsafe { libc::kill(pid as libc::pid_t, signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().to_string())
        }
    }
    #[cfg(windows)]
    {
        windows::terminate_process(pid, force)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, force);
        Err("terminating a process is not supported on this platform".to_string())
    }
}

/// Close a socket that belongs to a local connection.
///
/// This is a best-effort operation: Linux uses `ss -K`, Windows supports IPv4
/// TCP only, and macOS has no public interface for destroying another process's
/// socket.
pub fn close_connection(entry: &ConnectionEntry) -> Result<(), String> {
    if !close_connection_supported(entry) {
        return Err("closing this connection is not supported on this platform".to_string());
    }
    #[cfg(target_os = "linux")]
    {
        linux::close_connection(entry)
    }
    #[cfg(windows)]
    {
        windows::close_connection(entry)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = entry;
        Err("closing another process's connection is not supported on macOS".to_string())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = entry;
        Err("closing a connection is not supported on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn entry(
        protocol: ConnectionProtocol,
        local_port: u16,
        state: ConnectionState,
    ) -> ConnectionEntry {
        ConnectionEntry {
            protocol,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port,
            remote_addr: None,
            remote_port: None,
            state,
            pid: None,
            process: None,
            uid: None,
        }
    }

    #[test]
    fn state_labels_are_stable() {
        assert_eq!(ConnectionState::Listen.label(), "LISTEN");
        assert_eq!(ConnectionState::Unconnected.label(), "UNCONN");
        assert_eq!(ConnectionState::TimeWait.label(), "TIME_WAIT");
        assert!(ConnectionState::Unconnected.is_listening());
        assert!(!ConnectionState::Established.is_listening());
    }

    #[test]
    fn endpoint_formatting_brackets_ipv6() {
        assert_eq!(endpoint(IpAddr::V6(Ipv6Addr::LOCALHOST), 443), "[::1]:443");
        assert_eq!(
            endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            "127.0.0.1:80"
        );
    }

    #[test]
    fn entries_sort_listening_first_then_by_port() {
        let mut entries = vec![
            entry(ConnectionProtocol::Tcp, 9000, ConnectionState::Established),
            entry(ConnectionProtocol::Tcp, 8080, ConnectionState::Listen),
            entry(ConnectionProtocol::Udp, 53, ConnectionState::Unconnected),
            entry(ConnectionProtocol::Tcp, 1000, ConnectionState::TimeWait),
        ];
        sort_entries(&mut entries);
        assert_eq!(entries[0].local_port, 53);
        assert_eq!(entries[1].local_port, 8080);
        assert_eq!(entries[2].local_port, 9000);
        assert_eq!(entries[3].local_port, 1000);
    }

    #[test]
    fn missing_peer_disables_close_support() {
        let listen = entry(ConnectionProtocol::Tcp, 8080, ConnectionState::Listen);
        assert!(!listen.has_remote());
        assert_eq!(listen.remote_endpoint(), "-");
        assert!(!close_connection_supported(&listen));
    }

    #[test]
    fn active_remote_connection_has_endpoint() {
        let mut entry = entry(ConnectionProtocol::Tcp, 5000, ConnectionState::Established);
        entry.remote_addr = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        entry.remote_port = Some(443);
        assert!(entry.has_remote());
        assert_eq!(entry.remote_endpoint(), "1.1.1.1:443");
    }
}
