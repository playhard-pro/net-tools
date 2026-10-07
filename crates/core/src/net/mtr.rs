//! MTR hop-by-hop routing (ICMP / UDP).
//!
//! Probing is continuous and runs every hop concurrently: one round probes all
//! active hops in parallel, then the next round starts after the configured
//! interval, so each individual hop is probed at that interval.

use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(unix)]
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use surge_ping::{Client, IcmpPacket, PingIdentifier, PingSequence, SurgeError};
use tokio::task::JoinSet;

use crate::config::MtrSettings;
use crate::control::ProbeHandle;
use crate::model::{HopNode, HopStats, ProbeEvent};
use crate::net::{dns, icmp, privilege};

/// Upper bound on the distinct responders remembered for one hop, so a heavily
/// load-balanced hop cannot grow without limit.
const MAX_ADDRS_PER_HOP: usize = 8;

/// Outcome of a single probe against one hop.
struct HopProbe {
    /// Whether this reply proves the destination was reached.
    reached: bool,
    /// Responder address, absent on timeout.
    from: Option<IpAddr>,
    /// Round trip time, absent on timeout.
    rtt: Option<Duration>,
}

impl HopProbe {
    fn reply(reached: bool, from: IpAddr, rtt: Duration) -> Self {
        Self {
            reached,
            from: Some(from),
            rtt: Some(rtt),
        }
    }

    fn timeout() -> Self {
        Self {
            reached: false,
            from: None,
            rtt: None,
        }
    }
}

/// Running statistics for one hop over the whole session. It survives across
/// rounds so that the continuous probe accumulates a stable picture.
struct HopAccum {
    hop: u8,
    /// Distinct responder addresses seen for this hop, in first-seen order.
    addrs: Vec<IpAddr>,
    sent: u32,
    lost: u32,
    last_ms: Option<f64>,
    /// Number of successful probes and the running aggregates of their RTTs.
    count: u32,
    sum: f64,
    sum_sq: f64,
    best: Option<f64>,
    worst: Option<f64>,
    reached: bool,
}

impl HopAccum {
    fn new(hop: u8) -> Self {
        Self {
            hop,
            addrs: Vec::new(),
            sent: 0,
            lost: 0,
            last_ms: None,
            count: 0,
            sum: 0.0,
            sum_sq: 0.0,
            best: None,
            worst: None,
            reached: false,
        }
    }

    fn record(&mut self, probe: HopProbe) {
        self.sent += 1;
        if probe.reached {
            self.reached = true;
        }
        if let Some(from) = probe.from {
            if !self.addrs.contains(&from) && self.addrs.len() < MAX_ADDRS_PER_HOP {
                self.addrs.push(from);
            }
        }
        match probe.rtt {
            Some(rtt) => {
                let ms = rtt.as_secs_f64() * 1000.0;
                self.last_ms = Some(ms);
                self.count += 1;
                self.sum += ms;
                self.sum_sq += ms * ms;
                self.best = Some(self.best.map_or(ms, |v| v.min(ms)));
                self.worst = Some(self.worst.map_or(ms, |v| v.max(ms)));
            }
            None => self.lost += 1,
        }
    }

    fn stats(&self, reverse: &HashMap<IpAddr, Option<String>>) -> HopStats {
        let (avg, stdev) = if self.count == 0 {
            (None, None)
        } else {
            let mean = self.sum / self.count as f64;
            // Clamp tiny negative values that floating point rounding can
            // produce before taking the square root.
            let variance = (self.sum_sq / self.count as f64 - mean * mean).max(0.0);
            (Some(mean), Some(variance.sqrt()))
        };
        let nodes = self
            .addrs
            .iter()
            .map(|ip| HopNode {
                addr: ip.to_string(),
                reverse: reverse.get(ip).cloned().flatten(),
            })
            .collect();
        HopStats {
            hop: self.hop,
            nodes,
            sent: self.sent,
            lost: self.lost,
            last_ms: self.last_ms,
            avg_ms: avg,
            best_ms: self.best,
            worst_ms: self.worst,
            stdev_ms: stdev,
            reached: self.reached,
        }
    }
}

/// Resolve PTR names for every address seen in `accums`, caching the result so
/// each address is looked up only once over a long running session.
async fn resolve_reverse(accums: &[HopAccum], cache: &mut HashMap<IpAddr, Option<String>>) {
    // Collect the addresses that still need a lookup first, so the map is only
    // borrowed between awaits, not across them.
    let mut missing: Vec<IpAddr> = Vec::new();
    for acc in accums {
        for &ip in &acc.addrs {
            if !cache.contains_key(&ip) && !missing.contains(&ip) {
                missing.push(ip);
            }
        }
    }
    for ip in missing {
        let name = dns::reverse(ip).await;
        cache.insert(ip, name);
    }
}

/// Probe the route hop by hop until cancelled. The probe never stops on its
/// own: it keeps refreshing every hop at the configured interval.
pub async fn run_mtr(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings) {
    let target = settings.common.target.trim().to_string();
    if target.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "empty target".into(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }
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

/// Classify an ICMP reply: everything but a time-exceeded message is treated as
/// the end of the path (echo reply or destination unreachable).
fn classify(packet: &IcmpPacket) -> (bool, IpAddr) {
    match packet {
        IcmpPacket::V4(p) => {
            let reached = p.get_icmp_type() != IcmpTypes::TimeExceeded;
            (reached, IpAddr::V4(p.get_source()))
        }
        IcmpPacket::V6(p) => {
            let reached = p.get_icmpv6_type() != Icmpv6Types::TimeExceeded;
            (reached, IpAddr::V6(p.get_source()))
        }
    }
}

/// ICMP MTR dispatch: use the unprivileged Linux engine when its datagram
/// socket is available, otherwise fall back to the raw surge-ping path.
async fn mtr_icmp(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings, ip: IpAddr) {
    #[cfg(target_os = "linux")]
    {
        if crate::net::linux_icmp::can_open(ip) {
            mtr_icmp_linux(handle, settings, ip).await;
            return;
        }
    }
    mtr_icmp_surge(handle, settings, ip).await;
}

/// ICMP MTR through the unprivileged Linux datagram socket.
#[cfg(target_os = "linux")]
async fn mtr_icmp_linux(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings, ip: IpAddr) {
    use crate::net::linux_icmp;

    let max_hops = settings.max_hops.max(1);

    // One socket per hop: the TTL is a per-socket setting and the kernel routes
    // each hop's errors by the socket identifier it assigned.
    let mut sockets = Vec::with_capacity(max_hops as usize);
    for hop in 1..=max_hops {
        match linux_icmp::open(ip, Some(hop as u32), true) {
            Ok(socket) => sockets.push(Arc::new(socket)),
            Err(e) => {
                handle.send(ProbeEvent::Error {
                    message: format!("failed to open ICMP socket: {e}"),
                    hint: privilege::hint_for(e.kind() == std::io::ErrorKind::PermissionDenied),
                });
                return;
            }
        }
    }

    let payload = Arc::new(vec![0x6du8; settings.common.packet_size]);
    let timeout = Duration::from_millis(settings.common.timeout_ms);
    let interval = Duration::from_millis(settings.common.interval_ms);

    let mut accums: Vec<HopAccum> = (1..=max_hops).map(HopAccum::new).collect();
    let mut reverse: HashMap<IpAddr, Option<String>> = HashMap::new();
    let mut target_hop: Option<u8> = None;
    let mut seq: u16 = 0;

    loop {
        if handle.is_cancelled() {
            return;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            return;
        }

        let active = target_hop.unwrap_or(max_hops);
        let started = Instant::now();
        let mut set = JoinSet::new();

        for hop in 1..=active {
            seq = seq.wrapping_add(1);
            let socket = sockets[hop as usize - 1].clone();
            let payload = payload.clone();
            let probe_seq = seq;
            set.spawn_blocking(move || {
                let result = linux_icmp::probe(&socket, ip, probe_seq, &payload, timeout, true);
                (hop, result)
            });
        }

        let mut reached_hop: Option<u8> = None;
        while let Some(joined) = set.join_next().await {
            if handle.is_cancelled() {
                return;
            }
            match joined {
                Ok((hop, Ok(Some(reply)))) => {
                    if reply.reached {
                        reached_hop = Some(reached_hop.map_or(hop, |h| h.min(hop)));
                    }
                    accums[hop as usize - 1].record(HopProbe::reply(
                        reply.reached,
                        reply.from,
                        reply.rtt,
                    ));
                }
                Ok((hop, Ok(None))) => accums[hop as usize - 1].record(HopProbe::timeout()),
                Ok((_hop, Err(e))) => {
                    handle.send(ProbeEvent::Error {
                        message: format!("ICMP error: {e}"),
                        hint: privilege::hint_for(e.kind() == std::io::ErrorKind::PermissionDenied),
                    });
                    return;
                }
                Err(_) => {
                    handle.send(ProbeEvent::Error {
                        message: "ICMP probe task panicked".into(),
                        hint: None,
                    });
                    return;
                }
            }
        }

        // Once the destination is reached, stop growing the path and only keep
        // refreshing the hops up to it.
        if let Some(hop) = reached_hop {
            target_hop = Some(target_hop.map_or(hop, |t| t.min(hop)));
        }
        let active = target_hop.unwrap_or(max_hops) as usize;

        if settings.common.reverse_dns {
            resolve_reverse(&accums[..active], &mut reverse).await;
        }
        for acc in &accums[..active] {
            handle.send(ProbeEvent::Hop(acc.stats(&reverse)));
        }

        let elapsed = started.elapsed();
        if elapsed < interval && handle.sleep(interval - elapsed).await {
            return;
        }
    }
}

/// ICMP MTR through a raw socket with surge-ping. Used outside Linux and as a
/// fallback when the Linux datagram socket is unavailable.
async fn mtr_icmp_surge(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings, ip: IpAddr) {
    let max_hops = settings.max_hops.max(1);

    // One client per hop: surge-ping sets the TTL on the socket, so each hop
    // needs its own socket.
    let mut clients: Vec<Client> = Vec::with_capacity(max_hops as usize);
    for hop in 1..=max_hops {
        match icmp::trace_client_for(ip, Some(hop as u32)) {
            Ok(c) => clients.push(c),
            Err(e) => {
                handle.send(ProbeEvent::Error {
                    message: format!("failed to open ICMP socket: {e}"),
                    hint: privilege::hint_for(e.kind() == std::io::ErrorKind::PermissionDenied),
                });
                return;
            }
        }
    }

    // Reading the routers' ICMP time-exceeded messages requires a raw socket.
    // surge-ping silently falls back to the ping datagram socket when raw is
    // not permitted, and that socket hides the intermediate replies, so an
    // unprivileged run would show a route with no hops. Fail loudly instead of
    // producing an empty trace.
    if clients[0].get_socket().get_type() != socket2::Type::RAW {
        handle.send(ProbeEvent::Error {
            message: "ICMP MTR requires a raw socket to see intermediate routers".into(),
            hint: Some(privilege::guidance()),
        });
        return;
    }

    let payload = Arc::new(vec![0x6du8; settings.common.packet_size]);
    let ident = PingIdentifier((std::process::id() & 0xffff) as u16);
    let timeout = Duration::from_millis(settings.common.timeout_ms);
    let interval = Duration::from_millis(settings.common.interval_ms);

    let mut accums: Vec<HopAccum> = (1..=max_hops).map(HopAccum::new).collect();
    let mut reverse: HashMap<IpAddr, Option<String>> = HashMap::new();
    let mut target_hop: Option<u8> = None;
    let mut seq: u16 = 0;

    loop {
        if handle.is_cancelled() {
            return;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            return;
        }

        let active = target_hop.unwrap_or(max_hops);
        let started = Instant::now();
        let mut set = JoinSet::new();

        for hop in 1..=active {
            seq = seq.wrapping_add(1);
            let client = clients[hop as usize - 1].clone();
            let payload = payload.clone();
            let probe_seq = PingSequence(seq);
            set.spawn(async move {
                let mut pinger = client.pinger(ip, ident).await;
                pinger.timeout(timeout);
                let result = match pinger.ping(probe_seq, &payload).await {
                    Ok((packet, rtt)) => {
                        let (reached, from) = classify(&packet);
                        Ok(HopProbe::reply(reached, from, rtt))
                    }
                    Err(SurgeError::Timeout { .. }) => Ok(HopProbe::timeout()),
                    Err(e) => Err(e),
                };
                (hop, result)
            });
        }

        let mut reached_hop: Option<u8> = None;
        while let Some(joined) = set.join_next().await {
            if handle.is_cancelled() {
                return;
            }
            match joined {
                Ok((hop, Ok(probe))) => {
                    if probe.reached {
                        reached_hop = Some(reached_hop.map_or(hop, |h| h.min(hop)));
                    }
                    accums[hop as usize - 1].record(probe);
                }
                Ok((_hop, Err(e))) => {
                    handle.send(ProbeEvent::Error {
                        message: format!("ICMP error: {e}"),
                        hint: icmp::hint_for_surge_error(&e),
                    });
                    return;
                }
                Err(_) => {
                    handle.send(ProbeEvent::Error {
                        message: "ICMP probe task panicked".into(),
                        hint: None,
                    });
                    return;
                }
            }
        }

        // Once the destination is reached, stop growing the path and only keep
        // refreshing the hops up to it.
        if let Some(hop) = reached_hop {
            target_hop = Some(target_hop.map_or(hop, |t| t.min(hop)));
        }
        let active = target_hop.unwrap_or(max_hops) as usize;

        if settings.common.reverse_dns {
            resolve_reverse(&accums[..active], &mut reverse).await;
        }
        for acc in &accums[..active] {
            handle.send(ProbeEvent::Hop(acc.stats(&reverse)));
        }

        // Keep the per-hop probe interval, measured from the start of the round.
        let elapsed = started.elapsed();
        if elapsed < interval && handle.sleep(interval - elapsed).await {
            return;
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

        let max_hops = settings.max_hops.max(1);
        let payload = Arc::new(vec![0x75u8; settings.common.packet_size]);
        let timeout = Duration::from_millis(settings.common.timeout_ms);
        let interval = Duration::from_millis(settings.common.interval_ms);

        let mut accums: Vec<HopAccum> = (1..=max_hops).map(HopAccum::new).collect();
        let mut reverse: HashMap<IpAddr, Option<String>> = HashMap::new();
        let mut target_hop: Option<u8> = None;

        loop {
            if handle.is_cancelled() {
                return;
            }
            handle.wait_if_paused().await;
            if handle.is_cancelled() {
                return;
            }

            let active = target_hop.unwrap_or(max_hops);
            let started = Instant::now();
            let mut set = JoinSet::new();

            for hop in 1..=active {
                let payload = payload.clone();
                let port = settings.udp_port;
                set.spawn_blocking(move || {
                    let result = udp_probe_v4(target_v4, port, hop as u32, &payload, timeout);
                    (hop, result)
                });
            }

            let mut reached_hop: Option<u8> = None;
            while let Some(joined) = set.join_next().await {
                if handle.is_cancelled() {
                    return;
                }
                match joined {
                    Ok((hop, Some((icmp_type, src, rtt)))) => {
                        // A destination-unreachable from the target proves the
                        // path ended; a time-exceeded message is a router.
                        let reached = icmp_type == 3;
                        if reached {
                            reached_hop = Some(reached_hop.map_or(hop, |h| h.min(hop)));
                        }
                        accums[hop as usize - 1].record(HopProbe::reply(
                            reached,
                            IpAddr::V4(src),
                            rtt,
                        ));
                    }
                    Ok((hop, None)) => accums[hop as usize - 1].record(HopProbe::timeout()),
                    Err(_) => {
                        handle.send(ProbeEvent::Error {
                            message: "UDP MTR probe task panicked".into(),
                            hint: None,
                        });
                        return;
                    }
                }
            }

            if let Some(hop) = reached_hop {
                target_hop = Some(target_hop.map_or(hop, |t| t.min(hop)));
            }
            let active = target_hop.unwrap_or(max_hops) as usize;

            if settings.common.reverse_dns {
                resolve_reverse(&accums[..active], &mut reverse).await;
            }
            for acc in &accums[..active] {
                handle.send(ProbeEvent::Hop(acc.stats(&reverse)));
            }

            let elapsed = started.elapsed();
            if elapsed < interval && handle.sleep(interval - elapsed).await {
                return;
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
    udp.set_ttl_v4(ttl).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accum_loss_ratio() {
        let mut acc = HopAccum::new(1);
        acc.record(HopProbe::reply(
            false,
            "10.0.0.1".parse().unwrap(),
            Duration::from_millis(5),
        ));
        acc.record(HopProbe::timeout());
        let stats = acc.stats(&HashMap::new());
        assert_eq!(stats.loss_ratio(), 0.5);
        assert_eq!(stats.sent, 2);
        assert_eq!(stats.lost, 1);
        assert_eq!(stats.success_count(), 1);
        assert_eq!(stats.addr_text(), "10.0.0.1");
    }

    #[test]
    fn accum_multiple_addresses() {
        let mut acc = HopAccum::new(2);
        acc.record(HopProbe::reply(
            false,
            "10.0.0.1".parse().unwrap(),
            Duration::from_millis(1),
        ));
        acc.record(HopProbe::reply(
            false,
            "10.0.0.2".parse().unwrap(),
            Duration::from_millis(2),
        ));
        // A repeated address must not be listed twice.
        acc.record(HopProbe::reply(
            false,
            "10.0.0.1".parse().unwrap(),
            Duration::from_millis(3),
        ));
        let stats = acc.stats(&HashMap::new());
        assert_eq!(stats.addr_text(), "10.0.0.1, 10.0.0.2");
        assert_eq!(stats.reverse_text(), "-");
    }

    #[test]
    fn accum_empty_is_wildcard() {
        let acc = HopAccum::new(1);
        let stats = acc.stats(&HashMap::new());
        assert_eq!(stats.addr_text(), "*");
        assert_eq!(stats.avg_ms, None);
    }
}
