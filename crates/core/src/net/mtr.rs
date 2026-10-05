//! MTR hop-by-hop routing (ICMP / UDP).

use std::net::IpAddr;
#[cfg(unix)]
use std::net::Ipv4Addr;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use surge_ping::{IcmpPacket, PingIdentifier, PingSequence};

use crate::config::MtrSettings;
use crate::control::ProbeHandle;
use crate::model::{HopStats, ProbeEvent};
use crate::net::{icmp, privilege};

/// Probe the route hop by hop until cancelled.
pub async fn run_mtr(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings) {
    let target = settings.common.target.trim().to_string();
    let ip = match icmp::resolve_target(&target, settings.common.ip_version).await {
        Ok(ip) => ip,
        Err(e) => {
            handle.send(ProbeEvent::Error {
                message: e,
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    handle.send(ProbeEvent::Info(format!("traceroute to {target} ({ip})")));

    match settings.mode {
        crate::model::ProbeMode::Icmp => mtr_icmp(handle, settings, ip).await,
        crate::model::ProbeMode::Udp => mtr_udp(handle, settings, ip).await,
    }

    handle.send(ProbeEvent::Finished);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopKind {
    Intermediate,
    Reached,
    Unreachable,
}

async fn mtr_icmp(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings, ip: IpAddr) {
    let payload = vec![0x6du8; settings.common.packet_size];
    let ident = PingIdentifier((std::process::id() & 0xffff) as u16);
    let mut seq: u16 = 0;

    for hop in 1..=settings.max_hops {
        if handle.is_cancelled() {
            return;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            return;
        }

        // One socket with the given TTL per hop, built for the address family of
        // the target so that IPv6 routes are probed with an IPv6 socket.
        let client = match icmp::client_for(ip, Some(hop as u32)) {
            Ok(c) => c,
            Err(e) => {
                handle.send(ProbeEvent::Error {
                    message: format!("failed to open ICMP socket: {e}"),
                    hint: privilege::hint_for(e.kind() == std::io::ErrorKind::PermissionDenied),
                });
                return;
            }
        };
        let mut pinger = client.pinger(ip, ident).await;
        pinger.timeout(Duration::from_millis(settings.common.timeout_ms));

        let mut sent = 0u32;
        let mut lost = 0u32;
        let mut rtts: Vec<f64> = Vec::new();
        let mut addr: Option<IpAddr> = None;
        let mut reached = false;

        for _ in 0..settings.probes_per_hop {
            if handle.is_cancelled() {
                break;
            }
            handle.wait_if_paused().await;
            seq = seq.wrapping_add(1);
            match pinger.ping(PingSequence(seq), &payload).await {
                Ok((packet, dur)) => {
                    sent += 1;
                    let (kind, src) = classify(&packet);
                    if addr.is_none() {
                        addr = Some(src);
                    }
                    rtts.push(dur.as_secs_f64() * 1000.0);
                    if kind != HopKind::Intermediate {
                        reached = true;
                    }
                }
                Err(surge_ping::SurgeError::Timeout { .. }) => {
                    sent += 1;
                    lost += 1;
                }
                Err(e) => {
                    handle.send(ProbeEvent::Error {
                        message: format!("ICMP error: {e}"),
                        hint: icmp::hint_for_surge_error(&e),
                    });
                    return;
                }
            }
        }

        if sent > 0 {
            let mut stats = build_hop(hop, addr, sent, lost, &rtts, reached);
            if settings.common.reverse_dns {
                if let Some(a) = addr {
                    stats.reverse = crate::net::dns::reverse(a).await;
                }
            }
            handle.send(ProbeEvent::Hop(stats));
        }

        if reached {
            break;
        }
    }
}

fn classify(packet: &IcmpPacket) -> (HopKind, IpAddr) {
    match packet {
        IcmpPacket::V4(p) => {
            let t = p.get_icmp_type();
            let src = IpAddr::V4(p.get_source());
            let kind = if t == IcmpTypes::EchoReply {
                HopKind::Reached
            } else if t == IcmpTypes::TimeExceeded {
                HopKind::Intermediate
            } else {
                HopKind::Unreachable
            };
            (kind, src)
        }
        IcmpPacket::V6(p) => {
            let t = p.get_icmpv6_type();
            let src = IpAddr::V6(p.get_source());
            let kind = if t == Icmpv6Types::EchoReply {
                HopKind::Reached
            } else if t == Icmpv6Types::TimeExceeded {
                HopKind::Intermediate
            } else {
                HopKind::Unreachable
            };
            (kind, src)
        }
    }
}

async fn mtr_udp(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings, ip: IpAddr) {
    #[cfg(not(unix))]
    {
        // Not built on this platform; mark the arguments as used.
        let _ = (settings, ip);
        // A missing platform backend is not a privilege problem, so no hint.
        handle.send(ProbeEvent::Error {
            message: "UDP MTR requires Unix raw sockets (Windows support pending)".into(),
            hint: None,
        });
    }

    #[cfg(unix)]
    {
        let target_v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                handle.send(ProbeEvent::Error {
                    message: "IPv6 UDP MTR is not supported yet; use ICMP mode".into(),
                    hint: None,
                });
                return;
            }
        };

        // Pre-check: the raw ICMP socket the probe loop needs. Report the real
        // error and only mention elevation when that is what is missing.
        if let Err(e) = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        ) {
            handle.send(ProbeEvent::Error {
                message: format!("UDP MTR needs a raw ICMP socket: {e}"),
                hint: privilege::hint_for(e.kind() == std::io::ErrorKind::PermissionDenied),
            });
            return;
        }

        let payload = vec![0x75u8; settings.common.packet_size];
        for hop in 1..=settings.max_hops {
            if handle.is_cancelled() {
                return;
            }
            handle.wait_if_paused().await;
            if handle.is_cancelled() {
                return;
            }

            let mut sent = 0u32;
            let mut lost = 0u32;
            let mut rtts: Vec<f64> = Vec::new();
            let mut addr: Option<IpAddr> = None;
            let mut reached = false;

            for _ in 0..settings.probes_per_hop {
                if handle.is_cancelled() {
                    break;
                }
                handle.wait_if_paused().await;

                let timeout = Duration::from_millis(settings.common.timeout_ms);
                let target = target_v4;
                let port = settings.udp_port;
                let ttl = hop as u32;
                let plen = payload.len();
                let pbuf = payload.clone();
                let result = tokio::task::spawn_blocking(move || {
                    udp_probe_v4(target, port, ttl, &pbuf[..plen], timeout)
                })
                .await;

                match result {
                    Ok(Some((icmp_type, src, rtt))) => {
                        sent += 1;
                        if addr.is_none() {
                            addr = Some(IpAddr::V4(src));
                        }
                        rtts.push(rtt.as_secs_f64() * 1000.0);
                        if icmp_type == 3 {
                            // Destination unreachable -> reached the target.
                            reached = true;
                        } else if icmp_type == 11 {
                            // Time exceeded -> an intermediate router.
                            reached = false;
                        }
                    }
                    Ok(None) => {
                        sent += 1;
                        lost += 1;
                    }
                    Err(_) => {
                        handle.send(ProbeEvent::Error {
                            message: "UDP MTR probe task panicked".into(),
                            hint: None,
                        });
                        return;
                    }
                }
            }

            if sent > 0 {
                let mut stats = build_hop(hop, addr, sent, lost, &rtts, reached);
                if settings.common.reverse_dns {
                    if let Some(a) = addr {
                        stats.reverse = crate::net::dns::reverse(a).await;
                    }
                }
                handle.send(ProbeEvent::Hop(stats));
            }

            if reached {
                break;
            }
        }
    }
}

/// Blocking single UDP probe (Unix): send a UDP datagram and read the raw ICMP
/// error. Returns (icmp_type, responder, RTT); `None` on timeout.
#[cfg(unix)]
fn udp_probe_v4(
    target: Ipv4Addr,
    port: u16,
    ttl: u32,
    payload: &[u8],
    timeout: Duration,
) -> Option<(u8, Ipv4Addr, Duration)> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    let udp = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    udp.set_ttl(ttl).ok()?;
    let dst: std::net::SocketAddr = (target, port).into();
    udp.connect(&SockAddr::from(dst)).ok()?;
    let local_port = udp.local_addr().ok()?.as_socket_ipv4().map(|s| s.port())?;

    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).ok()?;
    raw.set_read_timeout(Some(timeout)).ok()?;

    let start = Instant::now();
    udp.send(payload).ok()?;

    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
    loop {
        let n = raw.recv(&mut buf).ok()?;
        let buf = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if n < 36 {
            continue;
        }
        let icmp_type = buf[0];
        let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        // The quoted IP header follows the ICMP header, then the UDP header.
        let q = 8;
        let q_dst = Ipv4Addr::new(buf[q + 16], buf[q + 17], buf[q + 18], buf[q + 19]);
        let q_src_port = u16::from_be_bytes([buf[q + 20], buf[q + 21]]);
        if q_dst == target && q_src_port == local_port {
            return Some((icmp_type, src, start.elapsed()));
        }
        // Not our probe: keep waiting.
    }
}

fn build_hop(
    hop: u8,
    addr: Option<IpAddr>,
    sent: u32,
    lost: u32,
    rtts: &[f64],
    reached: bool,
) -> HopStats {
    let (avg, best, worst, stdev) = stats(rtts);
    HopStats {
        hop,
        addr: addr.map(|a| a.to_string()),
        reverse: None,
        sent,
        lost,
        last_ms: rtts.last().copied(),
        avg_ms: avg,
        best_ms: best,
        worst_ms: worst,
        stdev_ms: stdev,
        reached,
    }
}

fn stats(rtts: &[f64]) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    if rtts.is_empty() {
        return (None, None, None, None);
    }
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let best = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
    let worst = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let var = rtts.iter().map(|v| (v - avg) * (v - avg)).sum::<f64>() / rtts.len() as f64;
    (Some(avg), Some(best), Some(worst), Some(var.sqrt()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_empty() {
        assert_eq!(stats(&[]), (None, None, None, None));
    }

    #[test]
    fn stats_basic() {
        let (avg, best, worst, _stdev) = stats(&[1.0, 2.0, 3.0]);
        assert_eq!(avg, Some(2.0));
        assert_eq!(best, Some(1.0));
        assert_eq!(worst, Some(3.0));
    }

    #[test]
    fn hop_loss_ratio() {
        let h = build_hop(
            1,
            Some("10.0.0.1".parse().unwrap()),
            4,
            1,
            &[1.0, 2.0, 3.0],
            false,
        );
        assert_eq!(h.loss_ratio(), 0.25);
    }
}
