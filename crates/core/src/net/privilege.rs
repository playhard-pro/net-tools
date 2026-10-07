//! Privilege probing and platform-specific guidance.

use socket2::{Domain, Protocol, Socket, Type};

/// Socket capabilities the probing engines need, as far as they can be detected
/// without actually running a probe.
#[derive(Debug, Clone, Default)]
pub struct PrivilegeStatus {
    /// Whether an ICMP probe can open its socket. Linux offers ICMP to
    /// unprivileged users through the ICMP datagram ("ping") socket, which the
    /// dedicated Linux engine uses, so this is commonly true for a normal user;
    /// on platforms without that socket the engines fall back to a raw socket
    /// and need elevation.
    pub icmp: bool,
    /// Whether a raw socket can be created, which the SYN scan and the UDP MTR
    /// mode require.
    pub raw: bool,
    /// Copyable command shown when a capability is missing.
    pub hint: Option<String>,
}

/// Probe the available socket capabilities (best effort; a negative result does
/// not necessarily mean that every feature is unusable).
pub fn probe() -> PrivilegeStatus {
    let icmp = can_icmp();
    let raw = can_raw();
    PrivilegeStatus {
        icmp,
        raw,
        hint: if icmp && raw { None } else { Some(guidance()) },
    }
}

/// Whether the ICMP engines can open a socket.
///
/// Both the Linux datagram engine and surge-ping try the ICMP datagram
/// ("ping") socket first and only fall back to a raw socket, so the report
/// matches the socket the probes really use instead of always demanding
/// raw-socket privileges.
fn can_icmp() -> bool {
    icmp_socket_available(Domain::IPV4, Protocol::ICMPV4)
        || icmp_socket_available(Domain::IPV6, Protocol::ICMPV6)
        || raw_socket_available(Domain::IPV4, Protocol::ICMPV4)
        || raw_socket_available(Domain::IPV6, Protocol::ICMPV6)
}

/// Whether a raw socket can be created, which the SYN scan (raw TCP) and the
/// UDP MTR mode (raw ICMP) need. Neither ICMP ping nor ICMP MTR needs it on
/// Linux, where the datagram socket is enough.
fn can_raw() -> bool {
    raw_socket_available(Domain::IPV4, Protocol::TCP)
        || raw_socket_available(Domain::IPV4, Protocol::ICMPV4)
        || raw_socket_available(Domain::IPV6, Protocol::ICMPV6)
}

fn icmp_socket_available(domain: Domain, protocol: Protocol) -> bool {
    Socket::new(domain, Type::DGRAM, Some(protocol)).is_ok()
}

fn raw_socket_available(domain: Domain, protocol: Protocol) -> bool {
    Socket::new(domain, Type::RAW, Some(protocol)).is_ok()
}

/// Elevation hint for a failed operation, or `None` when the failure has
/// nothing to do with missing privileges (wrong address family, unreachable
/// network, ...) and pointing the user at administrator rights would be wrong.
pub fn hint_for(permission_denied: bool) -> Option<String> {
    if permission_denied {
        Some(guidance())
    } else {
        None
    }
}

/// Platform-specific guidance for obtaining the required privileges.
pub fn guidance() -> String {
    #[cfg(target_os = "linux")]
    {
        "sudo setcap cap_net_raw+ep \"$(readlink -f \"$(which net-tools)\")\"".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "sudo ./net-tools".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Run net-tools as administrator".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "run with elevated privileges".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_only_for_permission_errors() {
        assert!(hint_for(true).is_some());
        assert!(hint_for(false).is_none());
    }

    #[test]
    fn probe_does_not_panic() {
        // The reported capabilities depend on the host, so only assert that the
        // probe runs and reports a hint whenever something is missing.
        let status = probe();
        assert_eq!(status.hint.is_some(), !(status.icmp && status.raw));
    }
}
