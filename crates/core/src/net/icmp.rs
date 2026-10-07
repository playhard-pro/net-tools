//! ICMP probing (ping).
//!
//! Linux uses the dedicated unprivileged datagram-socket engine
//! ([`crate::net::linux_icmp`]), which is the only path that can report the
//! reply TTL there. Everywhere else, and as a fallback, surge-ping is used.

use std::io;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::Duration;

use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};

use crate::clock;
use crate::config::PingSettings;
use crate::control::ProbeHandle;
use crate::model::{IpVersion, ProbeEvent, ProbeSample};
use crate::net::{dns, privilege};

/// A failed probing attempt, together with the question whether missing
/// privileges are the likely cause.
struct ProbeFailure {
    message: String,
    privileged: bool,
}

/// How a probing run against a single address ended.
enum PingOutcome {
    /// The user stopped the probe.
    Cancelled,
    /// The socket refused to go on; another resolved address may still work.
    Failed(ProbeFailure),
}

/// Build an ICMP client whose socket family matches `ip`.
///
/// surge-ping defaults to an IPv4 socket, so probing an IPv6 target through it
/// fails with an address-family error instead of reaching the network; the
/// family therefore has to be selected explicitly.
pub(crate) fn client_for(ip: IpAddr, ttl: Option<u32>) -> io::Result<Client> {
    let kind = if ip.is_ipv6() { ICMP::V6 } else { ICMP::V4 };
    let mut builder = Config::builder().kind(kind);
    // On Unix, prefer a raw socket for IPv4. The Linux ping datagram socket
    // hides the outer IP header, so surge-ping cannot report the reply TTL from
    // it; a raw socket exposes that header. surge-ping falls back to the
    // datagram socket when raw is not permitted, which keeps unprivileged ping
    // working (only without a TTL). IPv6 is left on the default socket because
    // its raw messages carry no header here either.
    #[cfg(unix)]
    if ip.is_ipv4() {
        builder = builder.sock_type_hint(socket2::Type::RAW);
    }
    if let Some(ttl) = ttl {
        builder = builder.ttl(ttl);
    }
    Client::new(&builder.build())
}

/// Build an ICMP client for traceroute (MTR) that explicitly requests a raw
/// socket.
///
/// Traceroute works by reading the ICMP time-exceeded messages sent by
/// intermediate routers. On Unix the unprivileged ping datagram socket does not
/// deliver those errors as normal received data, so a client built through
/// [`client_for`] would only ever see the final echo reply and no hops in
/// between. surge-ping falls back to a datagram socket when raw is unavailable,
/// so callers must confirm the socket type they actually got.
pub(crate) fn trace_client_for(ip: IpAddr, ttl: Option<u32>) -> io::Result<Client> {
    let kind = if ip.is_ipv6() { ICMP::V6 } else { ICMP::V4 };
    let mut builder = Config::builder()
        .kind(kind)
        .sock_type_hint(socket2::Type::RAW);
    if let Some(ttl) = ttl {
        builder = builder.ttl(ttl);
    }
    Client::new(&builder.build())
}

/// Elevation hint for a surge-ping failure, or `None` when the failure is not a
/// permission problem (wrong address family, unreachable network, ...).
pub(crate) fn hint_for_surge_error(e: &surge_ping::SurgeError) -> Option<String> {
    match e {
        surge_ping::SurgeError::IOError(io_err) => {
            privilege::hint_for(io_err.kind() == io::ErrorKind::PermissionDenied)
        }
        _ => None,
    }
}

/// Continuous ICMP ping until cancelled. Results are streamed via `handle`.
pub async fn run_ping_icmp(handle: &ProbeHandle<ProbeEvent>, settings: &PingSettings) {
    let target = settings.common.target.trim().to_string();
    if target.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "empty target".into(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    // Resolve the target. Addresses come back IPv4 first, see `dns::resolve`.
    let addrs = match dns::resolve(&target, settings.common.ip_version).await {
        Ok(a) => a,
        Err(e) => {
            handle.send(ProbeEvent::Error {
                message: format!("resolve failed: {e}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    if addrs.is_empty() {
        handle.send(ProbeEvent::Error {
            message: format!("no addresses found for {target}"),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }
    handle.send(ProbeEvent::Info(format!(
        "resolved {target} -> {}",
        describe(&addrs)
    )));

    // PTR lookup, when enabled, for the address that is tried first.
    if settings.common.reverse_dns {
        if let Some(name) = dns::reverse(addrs[0]).await {
            handle.send(ProbeEvent::Info(format!("reverse: {} -> {name}", addrs[0])));
        }
    }

    // Walk the resolved addresses in order, so that a family which cannot be
    // probed in this environment does not hide one that can.
    let mut last_failure: Option<ProbeFailure> = None;
    for ip in addrs {
        match ping_address_any(handle, settings, ip).await {
            PingOutcome::Cancelled => {
                handle.send(ProbeEvent::Finished);
                return;
            }
            PingOutcome::Failed(failure) => last_failure = Some(failure),
        }
    }

    if let Some(failure) = last_failure {
        handle.send(ProbeEvent::Error {
            message: failure.message,
            hint: privilege::hint_for(failure.privileged),
        });
    }
    handle.send(ProbeEvent::Finished);
}

/// Probe a single address, preferring the unprivileged Linux engine.
async fn ping_address_any(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &PingSettings,
    ip: IpAddr,
) -> PingOutcome {
    #[cfg(target_os = "linux")]
    {
        // The datagram ICMP socket is what lets Linux report the reply TTL
        // without elevation. Fall back to the surge-ping client only when the
        // socket cannot be opened at all (e.g. a restricted ping_group_range).
        if let Ok(socket) = crate::net::linux_icmp::open(ip, None, false) {
            return ping_address_linux(handle, settings, ip, socket).await;
        }
    }

    let client = match client_for(ip, None) {
        Ok(c) => c,
        Err(e) => {
            return PingOutcome::Failed(ProbeFailure {
                message: format!("failed to open ICMP socket for {ip}: {e}"),
                privileged: e.kind() == io::ErrorKind::PermissionDenied,
            });
        }
    };
    ping_address_surge(handle, settings, &client, ip).await
}

/// Probe a single address through the unprivileged Linux engine.
#[cfg(target_os = "linux")]
async fn ping_address_linux(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &PingSettings,
    ip: IpAddr,
    socket: socket2::Socket,
) -> PingOutcome {
    let socket = Arc::new(socket);
    let payload = Arc::new(vec![0x61u8; settings.common.packet_size]);
    let timeout = Duration::from_millis(settings.common.timeout_ms);
    let mut seq: u64 = 0;

    loop {
        if handle.is_cancelled() {
            return PingOutcome::Cancelled;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            return PingOutcome::Cancelled;
        }

        // The blocking probe is kept short (bounded by the timeout) so the
        // cancellation and pause checks above stay responsive.
        let socket = socket.clone();
        let payload = payload.clone();
        let probe_seq = seq as u16;
        let result = tokio::task::spawn_blocking(move || {
            crate::net::linux_icmp::probe(&socket, ip, probe_seq, &payload, timeout, false)
        })
        .await;

        let reply = match result {
            Ok(Ok(reply)) => reply,
            Ok(Err(e)) => {
                return PingOutcome::Failed(ProbeFailure {
                    message: format!("ICMP send/receive error: {e}"),
                    privileged: e.kind() == io::ErrorKind::PermissionDenied,
                });
            }
            Err(_) => {
                return PingOutcome::Failed(ProbeFailure {
                    message: "ICMP probe task panicked".into(),
                    privileged: false,
                });
            }
        };

        match reply {
            Some(reply) => handle.send(ProbeEvent::Latency(ProbeSample {
                seq,
                time: clock::now_string(),
                rtt_ms: reply.rtt.as_secs_f64() * 1000.0,
                ttl: reply.ttl,
                from: reply.from.to_string(),
                size: settings.common.packet_size + 8,
            })),
            None => handle.send(ProbeEvent::Timeout { seq }),
        }

        seq = seq.wrapping_add(1);
        if handle
            .sleep(Duration::from_millis(settings.common.interval_ms))
            .await
        {
            return PingOutcome::Cancelled;
        }
    }
}

/// Probe a single address through surge-ping until cancelled or the socket
/// fails. Used outside Linux and as a fallback when the datagram socket is not
/// available.
async fn ping_address_surge(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &PingSettings,
    client: &Client,
    ip: IpAddr,
) -> PingOutcome {
    let mut pinger = client.pinger(ip, PingIdentifier(ident())).await;
    pinger.timeout(Duration::from_millis(settings.common.timeout_ms));

    let payload = vec![0x61u8; settings.common.packet_size];
    let mut seq: u64 = 0;

    loop {
        if handle.is_cancelled() {
            return PingOutcome::Cancelled;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            return PingOutcome::Cancelled;
        }

        match pinger.ping(PingSequence(seq as u16), &payload).await {
            Ok((packet, dur)) => {
                let (ttl, from) = packet_meta(&packet);
                handle.send(ProbeEvent::Latency(ProbeSample {
                    seq,
                    time: clock::now_string(),
                    rtt_ms: dur.as_secs_f64() * 1000.0,
                    ttl,
                    from: from.to_string(),
                    size: settings.common.packet_size + 8,
                }));
            }
            Err(surge_ping::SurgeError::Timeout { .. }) => {
                handle.send(ProbeEvent::Timeout { seq });
            }
            Err(e) => {
                let privileged = matches!(
                    &e,
                    surge_ping::SurgeError::IOError(io_err)
                        if io_err.kind() == io::ErrorKind::PermissionDenied
                );
                return PingOutcome::Failed(ProbeFailure {
                    message: format!("ICMP send/receive error: {e}"),
                    privileged,
                });
            }
        }

        seq = seq.wrapping_add(1);
        if handle
            .sleep(Duration::from_millis(settings.common.interval_ms))
            .await
        {
            return PingOutcome::Cancelled;
        }
    }
}

/// Comma separated address list for the informational log line.
fn describe(addrs: &[IpAddr]) -> String {
    addrs
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn ident() -> u16 {
    (std::process::id() & 0xffff) as u16
}

fn packet_meta(packet: &IcmpPacket) -> (Option<u8>, IpAddr) {
    match packet {
        IcmpPacket::V4(p) => (p.get_ttl(), IpAddr::V4(p.get_source())),
        // surge-ping never populates the IPv6 hop limit, so report it as
        // unavailable instead of a misleading zero. The Linux engine reads the
        // real value from the socket control data.
        IcmpPacket::V6(p) => (None, IpAddr::V6(p.get_source())),
    }
}

// Reused by mtr: resolve the target according to the settings.
pub(crate) async fn resolve_target(target: &str, version: IpVersion) -> Result<IpAddr, String> {
    let addrs = dns::resolve(target, version)
        .await
        .map_err(|e| e.to_string())?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("no addresses found for {target}"))
}
