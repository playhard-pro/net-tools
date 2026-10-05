//! ICMP probing (ping). Based on surge-ping: cross-platform and, on Linux,
//! unprivileged via the ICMP ping socket.

use std::time::Duration;

use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence};

use crate::config::PingSettings;
use crate::control::ProbeHandle;
use crate::model::{IpVersion, ProbeEvent, ProbeSample};
use crate::net::{dns, privilege};

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

    // Resolve the target.
    let addrs = match dns::resolve(&target, settings.common.ip_version).await {
        Ok(a) if !a.is_empty() => a,
        Ok(_) => {
            handle.send(ProbeEvent::Error {
                message: format!("no addresses found for {target}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
        Err(e) => {
            handle.send(ProbeEvent::Error {
                message: format!("resolve failed: {e}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    let ip = addrs[0];
    handle.send(ProbeEvent::Info(format!(
        "resolved {target} -> {ip} ({})",
        if ip.is_ipv4() { "IPv4" } else { "IPv6" }
    )));

    // PTR lookup, when enabled.
    if settings.common.reverse_dns {
        if let Some(name) = dns::reverse(ip).await {
            handle.send(ProbeEvent::Info(format!("reverse: {ip} -> {name}")));
        }
    }

    // Create the ICMP client (on Linux this uses a ping socket, usually
    // unprivileged).
    let client = match Client::new(&Config::default()) {
        Ok(c) => c,
        Err(e) => {
            handle.send(ProbeEvent::Error {
                message: format!("failed to open ICMP socket: {e}"),
                hint: Some(privilege::guidance()),
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    let mut pinger = client.pinger(ip, PingIdentifier(ident())).await;
    pinger.timeout(Duration::from_millis(settings.common.timeout_ms));

    let payload = vec![0x61u8; settings.common.packet_size];
    let mut seq: u64 = 0;

    loop {
        if handle.is_cancelled() {
            break;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            break;
        }

        match pinger.ping(PingSequence(seq as u16), &payload).await {
            Ok((packet, dur)) => {
                let (ttl, from) = packet_meta(&packet);
                handle.send(ProbeEvent::Latency(ProbeSample {
                    seq,
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
                handle.send(ProbeEvent::Error {
                    message: format!("ICMP send/receive error: {e}"),
                    hint: Some(privilege::guidance()),
                });
                break;
            }
        }

        seq = seq.wrapping_add(1);
        if handle
            .sleep(Duration::from_millis(settings.common.interval_ms))
            .await
        {
            break;
        }
    }

    handle.send(ProbeEvent::Finished);
}

fn ident() -> u16 {
    (std::process::id() & 0xffff) as u16
}

fn packet_meta(packet: &IcmpPacket) -> (Option<u8>, std::net::IpAddr) {
    match packet {
        IcmpPacket::V4(p) => (p.get_ttl(), std::net::IpAddr::V4(p.get_source())),
        IcmpPacket::V6(p) => (
            Some(p.get_max_hop_limit()),
            std::net::IpAddr::V6(p.get_source()),
        ),
    }
}

// Reused by mtr: resolve the target according to the settings.
pub(crate) async fn resolve_target(
    target: &str,
    version: IpVersion,
) -> Result<std::net::IpAddr, String> {
    let addrs = dns::resolve(target, version)
        .await
        .map_err(|e| e.to_string())?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("no addresses found for {target}"))
}
