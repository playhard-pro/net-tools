//! MTR hop-by-hop routing (ICMP / UDP).
//!
//! Probing is continuous and runs every hop concurrently: one round probes all
//! active hops in parallel, then the next round starts after the configured
//! interval, so each individual hop is probed at that interval.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use surge_ping::{Client, IcmpPacket, PingIdentifier, PingSequence, SurgeError};
use tokio::task::JoinSet;

use crate::config::MtrSettings;
use crate::control::ProbeHandle;
use crate::model::{HopNode, HopStats, ProbeEvent};
use crate::net::{dns, icmp, privilege, raw_icmp};

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

/// Reverse-DNS results shared between the probe loop and the background
/// resolver.
type ReverseNames = Arc<Mutex<HashMap<IpAddr, Option<String>>>>;

/// Lock the reverse cache, recovering the map if a resolver task panicked.
fn lock_reverse(
    cache: &ReverseNames,
) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Option<String>>> {
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Start resolving PTR names in the background and return the shared cache and
/// the channel used to submit newly seen addresses.
///
/// Probing must not wait for DNS. The probe loop publishes hop statistics on
/// every round, and the resolver fills the cache as names arrive, so a later
/// round shows the names without delaying route or latency updates.
fn start_reverse_resolver(
    handle: &ProbeHandle<ProbeEvent>,
) -> (
    ReverseNames,
    tokio::sync::mpsc::UnboundedSender<Vec<IpAddr>>,
    Arc<tokio::sync::Notify>,
) {
    let cache: ReverseNames = Arc::new(Mutex::new(HashMap::new()));
    let (requests, receiver) = tokio::sync::mpsc::unbounded_channel();
    let names_updated = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(run_reverse_resolver(
        handle.clone(),
        Arc::clone(&cache),
        receiver,
        Arc::clone(&names_updated),
    ));
    (cache, requests, names_updated)
}

/// Submit addresses that have no cached name yet to the resolver.
fn request_reverse_names(
    accums: &[HopAccum],
    cache: &ReverseNames,
    requests: &tokio::sync::mpsc::UnboundedSender<Vec<IpAddr>>,
) {
    let mut missing: Vec<IpAddr> = Vec::new();
    {
        let known = lock_reverse(cache);
        for acc in accums {
            for &ip in &acc.addrs {
                if !known.contains_key(&ip) && !missing.contains(&ip) {
                    missing.push(ip);
                }
            }
        }
    }
    if !missing.is_empty() {
        // The resolver exits when the probe ends, so a closed channel is fine.
        let _ = requests.send(missing);
    }
}

/// Background PTR resolver. Each request is a batch of addresses seen by the
/// probe loop; lookups in a batch run concurrently and results are cached.
async fn run_reverse_resolver(
    handle: ProbeHandle<ProbeEvent>,
    cache: ReverseNames,
    mut requests: tokio::sync::mpsc::UnboundedReceiver<Vec<IpAddr>>,
    names_updated: Arc<tokio::sync::Notify>,
) {
    let mut inflight: HashSet<IpAddr> = HashSet::new();
    loop {
        let addresses = tokio::select! {
            _ = handle.cancelled() => return,
            batch = requests.recv() => match batch {
                Some(addresses) => addresses,
                None => return,
            },
        };

        let mut missing = Vec::new();
        {
            let known = lock_reverse(&cache);
            for ip in addresses {
                if !known.contains_key(&ip) && inflight.insert(ip) {
                    missing.push(ip);
                }
            }
        }
        if missing.is_empty() {
            continue;
        }

        let mut lookups = JoinSet::new();
        for ip in &missing {
            let ip = *ip;
            lookups.spawn(async move {
                let name = dns::reverse(ip).await;
                (ip, name)
            });
        }
        let mut resolved_any = false;
        while !lookups.is_empty() {
            tokio::select! {
                _ = handle.cancelled() => return,
                joined = lookups.join_next() => {
                    if let Some(Ok((ip, name))) = joined {
                        resolved_any |= name.is_some();
                        lock_reverse(&cache).insert(ip, name);
                    }
                }
            }
        }
        if resolved_any {
            // Let the probe loop republish the hop rows right away instead of
            // waiting for the next round.
            names_updated.notify_waiters();
        }
        // Drop the in-flight markers. Addresses that never reached the cache
        // (for example because a lookup task failed) are retried later; names
        // that did resolve stay cached.
        for ip in missing {
            inflight.remove(&ip);
        }
    }
}

/// Publish the current statistics for the active hops.
fn publish_hops(
    handle: &ProbeHandle<ProbeEvent>,
    accums: &[HopAccum],
    active: usize,
    reverse: &ReverseNames,
) {
    let names = lock_reverse(reverse);
    for acc in &accums[..active] {
        handle.send(ProbeEvent::Hop(acc.stats(&names)));
    }
}

/// Publish hop statistics, then keep the per-hop interval. While waiting, a
/// resolved batch of reverse names refreshes the rows immediately instead of
/// waiting for the next probe round.
///
/// Returns `true` when the probe was cancelled while waiting.
async fn publish_and_wait(
    handle: &ProbeHandle<ProbeEvent>,
    accums: &[HopAccum],
    active: usize,
    reverse: &ReverseNames,
    names_updated: &tokio::sync::Notify,
    started: Instant,
    interval: Duration,
) -> bool {
    publish_hops(handle, accums, active, reverse);
    let deadline = started + interval;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::select! {
            cancelled = handle.sleep(remaining) => return cancelled,
            _ = names_updated.notified() => publish_hops(handle, accums, active, reverse),
        }
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
        crate::model::ProbeMode::Tcp => mtr_tcp(handle, settings, ip).await,
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
    let (reverse, reverse_tx, names_updated) = start_reverse_resolver(handle);
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
            request_reverse_names(&accums[..active], &reverse, &reverse_tx);
        }
        if publish_and_wait(
            handle,
            &accums,
            active,
            &reverse,
            &names_updated,
            started,
            interval,
        )
        .await
        {
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
    let (reverse, reverse_tx, names_updated) = start_reverse_resolver(handle);
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
            request_reverse_names(&accums[..active], &reverse, &reverse_tx);
        }
        if publish_and_wait(
            handle,
            &accums,
            active,
            &reverse,
            &names_updated,
            started,
            interval,
        )
        .await
        {
            return;
        }
    }
}

/// TCP traceroute: send a TCP SYN with an increasing TTL and capture the
/// routers' ICMP errors. The TCP handshake also marks the target as reached.
async fn mtr_tcp(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings, ip: IpAddr) {
    // On Windows the intermediate router errors are only visible through a raw
    // ICMP socket, which requires administrator rights. Probe the capability
    // once up front, then request UAC instead of failing after the first hop.
    #[cfg(windows)]
    {
        if !crate::elevation::is_elevated() {
            crate::elevation::run_elevated(
                handle,
                &crate::elevation::HelperRequest::Mtr(settings.clone()),
            )
            .await;
            return;
        }
        if let Err(e) = raw_icmp::Capture::open_capture(ip) {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                crate::elevation::run_elevated(
                    handle,
                    &crate::elevation::HelperRequest::Mtr(settings.clone()),
                )
                .await;
                return;
            }
            handle.send(ProbeEvent::Error {
                message: format!("TCP MTR needs a raw ICMP socket: {e}"),
                hint: None,
            });
            return;
        }
    }

    let max_hops = settings.max_hops.max(1);
    let timeout = Duration::from_millis(settings.common.timeout_ms);
    let interval = Duration::from_millis(settings.common.interval_ms);

    let mut accums: Vec<HopAccum> = (1..=max_hops).map(HopAccum::new).collect();
    let (reverse, reverse_tx, names_updated) = start_reverse_resolver(handle);
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
            let target = ip;
            let port = settings.tcp_port;
            set.spawn_blocking(move || {
                let result = tcp_probe(target, port, hop as u32, timeout);
                (hop, result)
            });
        }

        let mut reached_hop: Option<u8> = None;
        while let Some(joined) = set.join_next().await {
            if handle.is_cancelled() {
                return;
            }
            match joined {
                Ok((hop, Ok(Some(probe)))) => {
                    if probe.reached {
                        reached_hop = Some(reached_hop.map_or(hop, |h| h.min(hop)));
                    }
                    accums[hop as usize - 1].record(probe);
                }
                Ok((hop, Ok(None))) => accums[hop as usize - 1].record(HopProbe::timeout()),
                Ok((_hop, Err(e))) => {
                    // Raw ICMP capture is required for the intermediate hops.
                    // Report the real error and only mention elevation when
                    // that is what is missing.
                    handle.send(ProbeEvent::Error {
                        message: format!("TCP MTR needs a raw ICMP socket: {e}"),
                        hint: privilege::hint_for(e.kind() == std::io::ErrorKind::PermissionDenied),
                    });
                    return;
                }
                Err(_) => {
                    handle.send(ProbeEvent::Error {
                        message: "TCP MTR probe task panicked".into(),
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
            request_reverse_names(&accums[..active], &reverse, &reverse_tx);
        }
        if publish_and_wait(
            handle,
            &accums,
            active,
            &reverse,
            &names_updated,
            started,
            interval,
        )
        .await
        {
            return;
        }
    }
}

/// Blocking single TCP traceroute probe. Returns `None` on timeout.
fn tcp_probe(
    target: IpAddr,
    port: u16,
    ttl: u32,
    timeout: Duration,
) -> std::io::Result<Option<HopProbe>> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    let v6 = target.is_ipv6();
    let (domain, protocol) = if v6 {
        (Domain::IPV6, Protocol::TCP)
    } else {
        (Domain::IPV4, Protocol::TCP)
    };
    let bind: SocketAddr = if v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };

    // Open the capture socket first, so a router cannot answer before the
    // capture is ready.
    let capture = raw_icmp::Capture::open_capture(target)?;

    let tcp = Socket::new(domain, Type::STREAM, Some(protocol))?;
    tcp.bind(&SockAddr::from(bind))?;
    if v6 {
        tcp.set_unicast_hops_v6(ttl)?;
    } else {
        tcp.set_ttl_v4(ttl)?;
    }
    let local = tcp
        .local_addr()?
        .as_socket()
        .ok_or_else(|| std::io::Error::other("TCP socket has no local address"))?;
    let local_port = local.port();
    tcp.set_nonblocking(true)?;

    let destination = SocketAddr::new(target, port);
    let started = Instant::now();
    let deadline = started + timeout;
    match tcp.connect(&SockAddr::from(destination)) {
        Ok(()) => {
            return Ok(Some(HopProbe::reply(true, target, started.elapsed())));
        }
        Err(e) if tcp_connect_pending(&e) => {}
        Err(e) if tcp_error_reaches(&e) => {
            return Ok(Some(HopProbe::reply(true, target, started.elapsed())));
        }
        Err(_) => return Ok(None),
    }

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining = deadline - now;
        let (raw_ready, tcp_ready) = raw_icmp::poll_pair(capture.socket(), &tcp, remaining)?;

        if raw_ready {
            // Drain every ready message; unrelated ICMP traffic is common on a
            // raw socket, so a single read is not enough to find our reply.
            while let Some(message) = capture.recv()? {
                let Some(quoted) = message.quoted else {
                    continue;
                };
                if quoted.protocol != 6
                    || quoted.dst != target
                    || quoted.src_port != local_port
                    || quoted.dst_port != port
                {
                    continue;
                }
                let rtt = started.elapsed();
                return match message.kind {
                    raw_icmp::MessageKind::TimeExceeded | raw_icmp::MessageKind::PacketTooBig => {
                        Ok(Some(HopProbe::reply(false, message.from, rtt)))
                    }
                    raw_icmp::MessageKind::Unreachable => {
                        Ok(Some(HopProbe::reply(true, message.from, rtt)))
                    }
                    _ => continue,
                };
            }
        }

        if tcp_ready {
            match tcp.take_error()? {
                None => return Ok(Some(HopProbe::reply(true, target, started.elapsed()))),
                Some(e) if tcp_error_reaches(&e) => {
                    return Ok(Some(HopProbe::reply(true, target, started.elapsed())));
                }
                // A route error without a usable responder is reported as a
                // timeout, so the round can continue without inventing a hop.
                Some(_) => return Ok(None),
            }
        }
    }
}

/// Whether a non-blocking connect is still in progress.
fn tcp_connect_pending(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::EINPROGRESS) {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEWOULDBLOCK) {
        return true;
    }
    false
}

/// Whether a connect error still proves that the target host answered.
fn tcp_error_reaches(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
    )
}

async fn mtr_udp(handle: &ProbeHandle<ProbeEvent>, settings: &MtrSettings, ip: IpAddr) {
    let target_v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            handle.send(ProbeEvent::Error {
                message: "IPv6 UDP MTR is not supported yet; use ICMP or TCP mode".into(),
                hint: None,
            });
            return;
        }
    };

    // Windows needs administrator rights for the raw ICMP socket. Request UAC
    // once, then run the whole trace in the elevated helper.
    #[cfg(windows)]
    {
        if !crate::elevation::is_elevated() {
            crate::elevation::run_elevated(
                handle,
                &crate::elevation::HelperRequest::Mtr(settings.clone()),
            )
            .await;
            return;
        }
        if let Err(e) = raw_icmp::Capture::open_capture(ip) {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                crate::elevation::run_elevated(
                    handle,
                    &crate::elevation::HelperRequest::Mtr(settings.clone()),
                )
                .await;
                return;
            }
            handle.send(ProbeEvent::Error {
                message: format!("UDP MTR needs a raw ICMP socket: {e}"),
                hint: None,
            });
            return;
        }
    }

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
    let (reverse, reverse_tx, names_updated) = start_reverse_resolver(handle);
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
                    accums[hop as usize - 1].record(HopProbe::reply(reached, IpAddr::V4(src), rtt));
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
            request_reverse_names(&accums[..active], &reverse, &reverse_tx);
        }
        if publish_and_wait(
            handle,
            &accums,
            active,
            &reverse,
            &names_updated,
            started,
            interval,
        )
        .await
        {
            return;
        }
    }
}

/// Blocking single UDP probe: send a UDP datagram and read the raw ICMP error.
/// Returns (icmp_type, responder, RTT); `None` on timeout.
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
    let local = udp.local_addr().ok()?.as_socket_ipv4()?;
    let local_port = local.port();

    let capture = raw_icmp::Capture::open_capture(IpAddr::V4(target)).ok()?;
    let start = Instant::now();
    let deadline = start + timeout;
    udp.send(payload).ok()?;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let ready = raw_icmp::poll_read(capture.socket(), deadline - now).ok()?;
        if !ready {
            return None;
        }
        while let Some(message) = capture.recv().ok()? {
            let Some(quoted) = message.quoted else {
                continue;
            };
            if quoted.protocol != 17
                || quoted.dst != IpAddr::V4(target)
                || quoted.src_port != local_port
                || quoted.dst_port != port
            {
                continue;
            }
            let icmp_type = match message.kind {
                raw_icmp::MessageKind::TimeExceeded => 11,
                raw_icmp::MessageKind::Unreachable | raw_icmp::MessageKind::PacketTooBig => 3,
                _ => continue,
            };
            let IpAddr::V4(source) = message.from else {
                continue;
            };
            return Some((icmp_type, source, start.elapsed()));
        }
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
