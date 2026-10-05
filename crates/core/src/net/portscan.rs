//! Port scanning (TCP connect / SYN / UDP + banner grabbing).

use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::PortScanSettings;
use crate::control::ProbeHandle;
use crate::model::{
    PortPreset, PortProtocol, PortResult, PortState, ProbeEvent, ScanMode, ScanProgress,
};
use crate::net::dns;
use crate::net::ports::{TOP100, TOP1000};

type Job = (String, IpAddr, u16);

/// Scan ports until cancelled or completed.
/// Takes owned arguments so it can run as a standalone task (boxed or via a TaskController).
pub async fn run_scan(handle: ProbeHandle<ProbeEvent>, settings: PortScanSettings) {
    let targets: Vec<String> = settings
        .targets
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if targets.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "no targets".into(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    // Resolve targets to IP addresses.
    let mut host_ips: Vec<(String, IpAddr)> = Vec::new();
    for t in &targets {
        match dns::resolve(t, settings.ip_version).await {
            Ok(ips) if !ips.is_empty() => {
                for ip in ips {
                    host_ips.push((t.clone(), ip));
                }
            }
            Ok(_) => handle.send(ProbeEvent::Info(format!("resolve {t}: no addresses"))),
            Err(e) => handle.send(ProbeEvent::Info(format!("resolve {t} failed: {e}"))),
        }
    }
    if host_ips.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "no resolvable targets".into(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    // Port list.
    let ports = match settings.preset {
        PortPreset::Custom => parse_ports(&settings.ports),
        PortPreset::Top100 => TOP100.to_vec(),
        PortPreset::Top1000 => TOP1000.to_vec(),
        PortPreset::All => (1..=65535).collect(),
    };
    if ports.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "empty port list".into(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    let total = (host_ips.len() * ports.len()) as u64;
    handle.send(ProbeEvent::Info(format!(
        "scanning {} host(s) × {} port(s) = {} probes",
        host_ips.len(),
        ports.len(),
        total
    )));

    let mut jobs: Vec<Job> = Vec::new();
    for (h, ip) in &host_ips {
        for &p in &ports {
            jobs.push((h.clone(), *ip, p));
        }
    }

    match settings.mode {
        ScanMode::TcpConnect => {
            scan_pool(
                &handle,
                &settings,
                total,
                jobs.into_iter(),
                scan_tcp_connect,
            )
            .await;
        }
        ScanMode::Udp => {
            scan_pool(&handle, &settings, total, jobs.into_iter(), scan_udp).await;
        }
        ScanMode::Syn => {
            syn_scan_all(&handle, &settings, &host_ips, &ports).await;
        }
    }

    handle.send(ProbeEvent::Finished);
}

/// Generic concurrent worker pool: `concurrency` workers consume jobs and
/// results are streamed back in completion order.
async fn scan_pool<F, Fut>(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &PortScanSettings,
    total: u64,
    jobs: impl Iterator<Item = Job>,
    worker_fn: F,
) where
    F: Fn(Job, PortScanSettings) -> Fut + Send + Sync + Copy + 'static,
    Fut: std::future::Future<Output = PortResult> + Send,
{
    let (job_tx, job_rx) = mpsc::channel::<Job>(1024);
    let (res_tx, mut res_rx) = mpsc::channel::<PortResult>(1024);
    let job_rx = Arc::new(AsyncMutex::new(job_rx));

    let concurrency = settings.concurrency.max(1);
    let mut workers = Vec::new();
    for _ in 0..concurrency {
        let rx = job_rx.clone();
        let tx = res_tx.clone();
        let h = handle.clone();
        let s = settings.clone();
        workers.push(tokio::spawn(async move {
            loop {
                if h.is_cancelled() {
                    break;
                }
                h.wait_if_paused().await;
                let job = {
                    let mut g = rx.lock().await;
                    g.recv().await
                };
                match job {
                    Some(j) => {
                        let r = worker_fn(j, s.clone()).await;
                        if tx.send(r).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }));
    }

    // Producer.
    for job in jobs {
        if handle.is_cancelled() {
            break;
        }
        if job_tx.send(job).await.is_err() {
            break;
        }
    }
    drop(job_tx);

    // Aggregate results.
    let mut scanned = 0u64;
    let mut open = 0u64;
    while let Some(r) = res_rx.recv().await {
        if r.state == PortState::Open {
            open += 1;
        }
        scanned += 1;
        handle.send(ProbeEvent::Port(r));
        if scanned.is_multiple_of(50) || scanned >= total {
            handle.send(ProbeEvent::ScanProgress(ScanProgress {
                scanned,
                total,
                open,
            }));
        }
    }
    for w in workers {
        let _ = w.await;
    }
}

async fn scan_tcp_connect(job: Job, settings: PortScanSettings) -> PortResult {
    let (host, ip, port) = job;
    let addr = SocketAddr::new(ip, port);
    let timeout = Duration::from_millis(settings.timeout_ms);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let banner = if settings.grab_banner {
                grab_banner_tcp(&mut stream, port).await
            } else {
                None
            };
            PortResult {
                host,
                port,
                protocol: PortProtocol::Tcp,
                state: PortState::Open,
                banner,
                service: port_to_service(port),
            }
        }
        Ok(Err(_)) => PortResult {
            host,
            port,
            protocol: PortProtocol::Tcp,
            state: PortState::Closed,
            banner: None,
            service: None,
        },
        Err(_) => PortResult {
            host,
            port,
            protocol: PortProtocol::Tcp,
            state: PortState::Filtered,
            banner: None,
            service: None,
        },
    }
}

async fn scan_udp(job: Job, settings: PortScanSettings) -> PortResult {
    let (host, ip, port) = job;
    let timeout = Duration::from_millis(settings.timeout_ms);
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            return PortResult {
                host,
                port,
                protocol: PortProtocol::Udp,
                state: PortState::Filtered,
                banner: None,
                service: port_to_service(port),
            }
            .with_error(e.to_string());
        }
    };
    if socket.connect((ip, port)).await.is_err() {
        return PortResult {
            host,
            port,
            protocol: PortProtocol::Udp,
            state: PortState::Filtered,
            banner: None,
            service: port_to_service(port),
        };
    }
    let _ = socket.send(&[0u8; 1]).await;
    let mut buf = [0u8; 512];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(_)) => PortResult {
            host,
            port,
            protocol: PortProtocol::Udp,
            state: PortState::Open,
            banner: None,
            service: port_to_service(port),
        },
        Ok(Err(e))
            if e.raw_os_error() == Some(libc::ECONNREFUSED)
                || e.raw_os_error() == Some(libc::ECONNRESET) =>
        {
            PortResult {
                host,
                port,
                protocol: PortProtocol::Udp,
                state: PortState::Closed,
                banner: None,
                service: port_to_service(port),
            }
        }
        Ok(Err(e)) => PortResult {
            host,
            port,
            protocol: PortProtocol::Udp,
            state: PortState::OpenOrFiltered,
            banner: None,
            service: port_to_service(port),
        }
        .with_error(e.to_string()),
        Err(_) => PortResult {
            host,
            port,
            protocol: PortProtocol::Udp,
            state: PortState::OpenOrFiltered,
            banner: None,
            service: port_to_service(port),
        },
    }
}

trait WithError {
    fn with_error(self, e: String) -> Self;
}
impl WithError for PortResult {
    fn with_error(mut self, e: String) -> Self {
        self.banner = Some(format!("error: {e}"));
        self
    }
}

async fn grab_banner_tcp(stream: &mut TcpStream, port: u16) -> Option<String> {
    let mut buf = [0u8; 512];
    // First try to read a banner the service sends on connect (SSH/SMTP/FTP, ...).
    match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => return Some(clean(&buf[..n])),
        _ => {}
    }
    // Send an active probe to HTTP-like ports.
    if matches!(port, 80 | 8080 | 8000 | 8008 | 8081 | 8888 | 3128 | 8082) {
        let _ = stream
            .write_all(b"GET / HTTP/1.0\r\nHost: net-tools\r\n\r\n")
            .await;
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => return Some(clean(&buf[..n])),
            _ => {}
        }
    }
    None
}

fn clean(buf: &[u8]) -> String {
    let s = String::from_utf8_lossy(buf);
    let s = s.replace(['\r', '\n'], " ");
    let s = s.trim();
    if s.len() > 120 {
        s[..120].to_string()
    } else {
        s.to_string()
    }
}

/// SYN half-open scan (Linux IPv4, requires a raw socket; run sequentially so
/// responses match correctly).
#[cfg(target_os = "linux")]
async fn syn_scan_all(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &PortScanSettings,
    host_ips: &[(String, IpAddr)],
    ports: &[u16],
) {
    // The scan needs a raw TCP socket for the whole run, so check it up front:
    // a missing capability is then reported as a permission problem instead of
    // surfacing as a generic scan failure.
    if let Err(e) = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::TCP),
    ) {
        handle.send(ProbeEvent::Error {
            message: format!("SYN scan needs a raw TCP socket: {e}"),
            hint: crate::net::privilege::hint_for(e.kind() == std::io::ErrorKind::PermissionDenied),
        });
        return;
    }

    for (host, ip) in host_ips {
        let IpAddr::V4(target) = ip else {
            handle.send(ProbeEvent::Info(format!(
                "SYN scan: skip {host} (IPv6 not supported for SYN)"
            )));
            continue;
        };
        match syn_scan_host(handle, settings, host, *target, ports).await {
            Ok(()) => {}
            Err(e) => {
                handle.send(ProbeEvent::Error {
                    message: format!("SYN scan failed: {e}"),
                    hint: None,
                });
                return;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn syn_scan_all(
    handle: &ProbeHandle<ProbeEvent>,
    _settings: &PortScanSettings,
    _host_ips: &[(String, IpAddr)],
    _ports: &[u16],
) {
    // A missing platform backend is not a privilege problem, so no hint.
    handle.send(ProbeEvent::Error {
        message: "SYN scan currently supports Linux only".into(),
        hint: None,
    });
}

#[cfg(target_os = "linux")]
async fn syn_scan_host(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &PortScanSettings,
    host: &str,
    target: Ipv4Addr,
    ports: &[u16],
) -> Result<(), String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    // Source IP of the route to the target.
    let local_ip = local_ip_for(target).await?;
    let raw =
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).map_err(|e| e.to_string())?;
    let timeout = Duration::from_millis(settings.timeout_ms);
    raw.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;

    let src_port: u16 = 40000 + ((std::process::id() as u16) % 20000);
    let seq: u32 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u32)
        ^ 0x5a5a5a5a;

    let total = ports.len() as u64;
    let mut scanned = 0u64;
    let mut open = 0u64;

    for &port in ports {
        if handle.is_cancelled() {
            return Ok(());
        }
        handle.wait_if_paused().await;

        let syn = build_syn(
            src_port,
            port,
            seq.wrapping_add(port as u32),
            target,
            local_ip,
        );
        let dst = SockAddr::from(SocketAddr::new(IpAddr::V4(target), port));
        raw.send_to(&syn, &dst).map_err(|e| e.to_string())?;

        let state = recv_syn_ack(&raw, src_port, port);
        let r = PortResult {
            host: host.to_string(),
            port,
            protocol: PortProtocol::Tcp,
            state,
            banner: None,
            service: port_to_service(port),
        };
        if state == PortState::Open {
            open += 1;
        }
        scanned += 1;
        handle.send(ProbeEvent::Port(r));
        if scanned.is_multiple_of(50) || scanned >= total {
            handle.send(ProbeEvent::ScanProgress(ScanProgress {
                scanned,
                total,
                open,
            }));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_syn(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(20);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
    pkt.push(0x50); // data offset = 5 words, reserved 0
    pkt.push(0x02); // SYN
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent

    let csum = tcp_checksum(&pkt, src_ip, dst_ip);
    pkt[16] = (csum >> 8) as u8;
    pkt[17] = (csum & 0xff) as u8;
    pkt
}

#[cfg(target_os = "linux")]
fn tcp_checksum(tcp: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo header.
    let src = src.octets();
    let dst = dst.octets();
    for i in (0..4).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    sum += 6u32; // TCP
    sum += tcp.len() as u32;
    // Add the TCP segment bytes to the checksum.
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(target_os = "linux")]
fn recv_syn_ack(raw: &socket2::Socket, src_port: u16, dst_port: u16) -> PortState {
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 256];
    loop {
        let n = match raw.recv(&mut buf) {
            Ok(n) => n,
            Err(_) => return PortState::Filtered, // Timeout
        };
        let buf = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if n < 20 {
            continue;
        }
        let p_src = u16::from_be_bytes([buf[0], buf[1]]);
        let p_dst = u16::from_be_bytes([buf[2], buf[3]]);
        if p_src != dst_port || p_dst != src_port {
            continue;
        }
        let flags = buf[13];
        if flags & 0x04 != 0 {
            return PortState::Closed; // RST
        }
        if flags & 0x12 == 0x12 {
            return PortState::Open; // SYN|ACK
        }
    }
}

#[cfg(target_os = "linux")]
async fn local_ip_for(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let s = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    s.connect((target, 9)).await.map_err(|e| e.to_string())?;
    match s.local_addr().map_err(|e| e.to_string())? {
        SocketAddr::V4(a) => Ok(*a.ip()),
        SocketAddr::V6(_) => Err("unexpected IPv6 local addr".into()),
    }
}

/// Parse a port expression, e.g. a comma list of single ports and ranges.
pub fn parse_ports(input: &str) -> Vec<u16> {
    let mut set = BTreeSet::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                for p in lo..=hi {
                    set.insert(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            set.insert(p);
        }
    }
    set.into_iter().collect()
}

/// Map well-known ports to service names.
pub fn port_to_service(port: u16) -> Option<String> {
    let name = match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        67 | 68 => "dhcp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137..=139 => "netbios",
        143 => "imap",
        161 | 162 => "snmp",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        514 => "syslog",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2375 | 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 | 8000 | 8081 | 8888 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => return None,
    };
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_ranges() {
        assert_eq!(
            parse_ports("22,80,8000-8002"),
            vec![22, 80, 8000, 8001, 8002]
        );
    }

    #[test]
    fn parse_ports_reverse_range() {
        assert_eq!(parse_ports("8002-8000"), vec![8000, 8001, 8002]);
    }

    #[test]
    fn parse_ports_empty_and_garbage() {
        assert_eq!(parse_ports(""), Vec::<u16>::new());
        assert_eq!(parse_ports("abc,70000"), Vec::<u16>::new());
    }

    #[test]
    fn service_names() {
        assert_eq!(port_to_service(22), Some("ssh".to_string()));
        assert_eq!(port_to_service(80), Some("http".to_string()));
        assert_eq!(port_to_service(9999), None);
    }
}
