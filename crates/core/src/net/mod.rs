//! Network probing modules.

use std::sync::Once;

/// Install the rustls ring provider once for reqwest and manual TLS clients.
///
/// reqwest is built with `rustls-no-provider`, so it needs an explicitly
/// installed provider before the first client is created.
pub fn ensure_crypto_provider() {
    static PROVIDER: Once = Once::new();
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub mod connections;
pub mod dns;
pub mod dns_tool;
pub mod http;
pub mod icmp;
pub mod ip_insight;
pub mod iperf3;
pub mod lan_discovery;
pub mod librespeed;
#[cfg(target_os = "linux")]
pub(crate) mod linux_icmp;
pub mod mac_vendor;
pub mod mtr;
pub mod ntp;
pub mod overview;
pub mod pmtu;
pub mod ports;
pub mod portscan;
pub mod privilege;
pub mod raw_icmp;
pub mod rdap;
pub mod stun;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod wifi;
#[cfg(windows)]
pub(crate) mod windows_icmp;
pub mod wol;
