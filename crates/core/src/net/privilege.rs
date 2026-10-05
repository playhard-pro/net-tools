//! Privilege probing and platform-specific guidance.

/// Result of the privilege probe.
#[derive(Debug, Clone, Default)]
pub struct PrivilegeStatus {
    /// Whether a raw socket can be created (needed for ICMP / SYN / UDP-MTR).
    pub raw_socket: bool,
    /// Copyable command shown when privileges are missing.
    pub hint: Option<String>,
}

/// Probe whether the current process can create a raw socket (best effort;
/// failure does not necessarily mean the feature is unusable).
pub fn probe() -> PrivilegeStatus {
    let raw_socket = can_raw_socket();
    PrivilegeStatus {
        raw_socket,
        hint: if raw_socket { None } else { Some(guidance()) },
    }
}

fn can_raw_socket() -> bool {
    #[cfg(unix)]
    {
        use socket2::{Domain, Protocol, Socket, Type};
        // ICMPv4 raw socket: requires privileges on Linux and macOS.
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
    }
    #[cfg(not(unix))]
    {
        // Windows: ICMP probing uses the system API (no privileges needed);
        // only SYN / UDP-MTR need administrator rights. Try a raw socket here.
        use socket2::{Domain, Protocol, Socket, Type};
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
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
