//! Integration tests for the probe engines (loopback based, no external network).

use std::time::Duration;

use net_tools_core::config::{HttpSettings, MtrSettings, PingSettings, PortScanSettings};
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{IpVersion, PortState, ProbeEvent, ScanMode};
use net_tools_core::net::{http, icmp, mtr, portscan, udp};

fn settings(target: &str, port: u16) -> PingSettings {
    let mut s = PingSettings::default();
    s.common.target = target.into();
    s.common.ip_version = IpVersion::V4;
    s.common.timeout_ms = 300;
    s.common.interval_ms = 20;
    s.common.packet_size = 16;
    s.udp_port = port;
    s
}

#[tokio::test]
async fn udp_ping_loopback_echo() {
    // Local UDP echo server.
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = server.recv_from(&mut buf).await {
            let _ = server.send_to(&buf[..n], peer).await;
        }
    });

    let s = settings("127.0.0.1", addr.port());
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        udp::run_ping_udp(&h, &s).await
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    let latencies = events
        .iter()
        .filter(|e| matches!(e, ProbeEvent::Latency(_)))
        .count();
    assert!(
        latencies > 0,
        "expected at least one UDP latency event, got {events:?}"
    );
    srv.abort();
}

#[cfg(not(windows))]
#[tokio::test]
async fn tcp_ping_open_and_closed_loopback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let open_port = listener.local_addr().unwrap().port();
    let srv = tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    // Open port: the handshake succeeds.
    let mut open = settings("127.0.0.1", 0);
    open.mode = net_tools_core::model::ProbeMode::Tcp;
    open.tcp_port = open_port;
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        net_tools_core::net::tcp::run_ping_tcp(&h, &open).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ProbeEvent::Latency(sample) if sample.rtt_ms >= 0.0)),
        "expected a TCP latency on an open port, got {events:?}"
    );
    srv.abort();

    // Closed port: the refusal still proves the host answered.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut closed = settings("127.0.0.1", 0);
    closed.mode = net_tools_core::model::ProbeMode::Tcp;
    closed.tcp_port = closed_port;
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        net_tools_core::net::tcp::run_ping_tcp(&h, &closed).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();
    assert!(
        events.iter().any(|e| matches!(e, ProbeEvent::Latency(_))),
        "expected a refused TCP connection to count as reachable, got {events:?}"
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn pmtu_loopback_binary_search() {
    let mut s = PingSettings::default();
    s.common.target = "127.0.0.1".into();
    s.common.ip_version = IpVersion::V4;
    s.common.timeout_ms = 300;
    s.pmtu.min_mtu = 576;
    s.pmtu.max_mtu = 1200;
    s.pmtu.attempts = 1;

    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        net_tools_core::net::pmtu::run_pmtu(&h, &s).await
    });
    let events = wait_and_drain(&mut ctrl).await;
    if events.iter().any(|e| matches!(e, ProbeEvent::Error { .. })) {
        eprintln!("skipping pmtu test (environment lacks capability): {events:?}");
        return;
    }
    let result = events
        .iter()
        .find_map(|e| match e {
            ProbeEvent::Pmtu(result) => Some(result),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected a Path MTU result, got {events:?}"));
    assert!(!result.steps.is_empty());
    if let Some(error) = &result.error {
        eprintln!("skipping pmtu assertion (environment reported {error})");
        return;
    }
    assert_eq!(result.path_mtu, Some(1200));
}

#[tokio::test]
async fn icmp_ping_loopback() {
    let s = settings("127.0.0.1", 0);
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        icmp::run_ping_icmp(&h, &s).await
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    // Skip when privileges are missing (CI or restricted environments).
    if events.iter().any(|e| matches!(e, ProbeEvent::Error { .. })) {
        eprintln!("skipping icmp test (environment lacks capability): {events:?}");
        return;
    }
    let latencies = events
        .iter()
        .filter(|e| matches!(e, ProbeEvent::Latency(_)))
        .count();
    assert!(
        latencies > 0,
        "expected at least one ICMP latency event, got {events:?}"
    );
}

#[tokio::test]
async fn icmp_mtr_loopback() {
    let mut s = MtrSettings::default();
    s.common.target = "127.0.0.1".into();
    s.common.ip_version = IpVersion::V4;
    s.common.timeout_ms = 300;
    s.common.interval_ms = 50;
    s.max_hops = 3;

    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        mtr::run_mtr(&h, &s).await
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    if events.iter().any(|e| matches!(e, ProbeEvent::Error { .. })) {
        eprintln!("skipping icmp mtr test: {events:?}");
        return;
    }
    let hops: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ProbeEvent::Hop(h) => Some(h),
            _ => None,
        })
        .collect();
    assert!(
        !hops.is_empty(),
        "expected at least one hop, got {events:?}"
    );
    assert!(
        hops.iter().any(|h| h.reached),
        "expected to reach loopback target, got {hops:?}"
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn tcp_mtr_loopback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    let mut s = MtrSettings::default();
    s.common.target = "127.0.0.1".into();
    s.common.ip_version = IpVersion::V4;
    s.common.timeout_ms = 300;
    s.common.interval_ms = 50;
    s.mode = net_tools_core::model::ProbeMode::Tcp;
    s.tcp_port = port;
    s.max_hops = 2;

    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        mtr::run_mtr(&h, &s).await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();
    srv.abort();

    if events.iter().any(|e| matches!(e, ProbeEvent::Error { .. })) {
        eprintln!("skipping tcp mtr test (environment lacks raw sockets): {events:?}");
        return;
    }
    let hops: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ProbeEvent::Hop(h) => Some(h),
            _ => None,
        })
        .collect();
    assert!(
        !hops.is_empty(),
        "expected at least one hop, got {events:?}"
    );
    assert!(
        hops.iter().any(|h| h.reached),
        "expected the TCP handshake to reach loopback, got {hops:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn udp_mtr_loopback() {
    // Needs a raw ICMP socket; skip without privileges.
    if socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .is_err()
    {
        eprintln!("skipping udp mtr test (no raw socket)");
        return;
    }

    let mut s = MtrSettings::default();
    s.common.target = "127.0.0.1".into();
    s.common.ip_version = IpVersion::V4;
    s.common.timeout_ms = 300;
    s.common.interval_ms = 50;
    s.mode = net_tools_core::model::ProbeMode::Udp;
    s.udp_port = 39999; // Likely closed.
    s.max_hops = 2;

    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        mtr::run_mtr(&h, &s).await
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    let hops: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ProbeEvent::Hop(h) => Some(h),
            _ => None,
        })
        .collect();
    assert!(
        !hops.is_empty(),
        "expected at least one hop, got {events:?}"
    );
    assert!(
        hops.iter().any(|h| h.reached),
        "expected port-unreachable to mark loopback reached, got {hops:?}"
    );
}

#[tokio::test]
async fn http_ping_local() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Local HTTP server.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let _conn = tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
            });
        }
    });

    let s = HttpSettings {
        target: format!("http://127.0.0.1:{}/", addr.port()),
        ip_version: IpVersion::V4,
        timeout_ms: 2000,
        interval_ms: 20,
        expect_status: Some(200),
        expect_keyword: Some("hello".into()),
        ..HttpSettings::default()
    };

    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        http::run_http(&h, &s).await
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    let results: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ProbeEvent::Http(r) => Some(r),
            _ => None,
        })
        .collect();
    assert!(!results.is_empty(), "expected HTTP results, got {events:?}");
    assert_eq!(results[0].status, Some(200));
    assert!(results[0].ok, "expected ok with matching status+keyword");
    assert!(results[0].dns_ms >= 0.0);
    assert!(results[0].total_ms > 0.0);
    srv.abort();
}

#[tokio::test]
async fn tcp_connect_scan_open() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _srv = tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    let s = PortScanSettings {
        targets: "127.0.0.1".into(),
        ports: port.to_string(),
        mode: ScanMode::TcpConnect,
        grab_banner: false,
        timeout_ms: 1000,
        ..PortScanSettings::default()
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| {
        portscan::run_scan(h, s)
    });

    tokio::time::sleep(Duration::from_millis(400)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    let open = events.iter().any(|e| match e {
        ProbeEvent::Port(r) => r.port == port && r.state == PortState::Open,
        _ => false,
    });
    assert!(open, "expected port {port} open, got {events:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn udp_scan_closed_port() {
    // Bind a port and release it; it is usually closed afterwards.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let s = PortScanSettings {
        targets: "127.0.0.1".into(),
        ports: port.to_string(),
        mode: ScanMode::Udp,
        timeout_ms: 500,
        ..PortScanSettings::default()
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| {
        portscan::run_scan(h, s)
    });

    tokio::time::sleep(Duration::from_millis(700)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    let closed = events.iter().any(|e| match e {
        ProbeEvent::Port(r) => r.port == port && r.state == PortState::Closed,
        _ => false,
    });
    assert!(
        closed,
        "expected port {port} closed (ICMP unreachable), got {events:?}"
    );
}

#[tokio::test]
async fn port_scan_stops_promptly_with_long_timeout() {
    // A bound but silent UDP socket makes each probe wait for the full
    // timeout. Cancellation must drop those waits instead of leaving the task
    // in the stopping state.
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();

    let s = PortScanSettings {
        targets: "127.0.0.1".into(),
        ports: port.to_string(),
        mode: ScanMode::Udp,
        timeout_ms: 10_000,
        concurrency: 4,
        ..PortScanSettings::default()
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| {
        portscan::run_scan(h, s)
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    ctrl.stop();

    let started = std::time::Instant::now();
    loop {
        let _ = ctrl.drain();
        if ctrl.state == TaskState::Finished {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "port scan did not stop promptly, state: {:?}",
            ctrl.state
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn port_scan_reports_initial_and_final_progress() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _srv = tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    let s = PortScanSettings {
        targets: "127.0.0.1".into(),
        ports: port.to_string(),
        mode: ScanMode::TcpConnect,
        timeout_ms: 500,
        ..PortScanSettings::default()
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| {
        portscan::run_scan(h, s)
    });

    let mut progress = Vec::new();
    for _ in 0..100 {
        for event in ctrl.drain() {
            if let ProbeEvent::ScanProgress(p) = event {
                progress.push(p);
            }
        }
        if ctrl.state == TaskState::Finished {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(!progress.is_empty(), "expected progress events");
    assert_eq!(progress.first().unwrap().scanned, 0);
    assert_eq!(progress.last().unwrap().scanned, 1);
    assert_eq!(progress.last().unwrap().total, 1);
}

/// On Linux the datagram ICMP engine reports the reply TTL without elevation.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_icmp_ping_reports_ttl() {
    let s = settings("127.0.0.1", 0);
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        icmp::run_ping_icmp(&h, &s).await
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    ctrl.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = ctrl.drain();

    // Skip when the environment lacks the unprivileged ICMP socket, for example
    // a restricted `ping_group_range` (CI or hardened hosts).
    if events.iter().any(|e| matches!(e, ProbeEvent::Error { .. })) {
        eprintln!("skipping linux icmp ttl test (environment lacks capability): {events:?}");
        return;
    }

    let ttls: Vec<Option<u8>> = events
        .iter()
        .filter_map(|e| match e {
            ProbeEvent::Latency(sample) => Some(sample.ttl),
            _ => None,
        })
        .collect();
    assert!(!ttls.is_empty(), "expected a reply, got {events:?}");
    assert!(
        ttls.iter().all(|ttl| ttl.is_some()),
        "expected a TTL on every Linux reply, got {ttls:?}"
    );
}

// ---------------------------------------------------------------------------
// NTP
// ---------------------------------------------------------------------------

use std::time::{SystemTime, UNIX_EPOCH};

use net_tools_core::config::NtpSettings;
use net_tools_core::net::ntp::{NtpPacket, NtpTimestamp};

/// Build a minimal valid server response for the request contained in `buf`.
fn ntp_response(buf: &[u8]) -> Vec<u8> {
    let request = NtpPacket::parse(buf).expect("client request is too short");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let t3 = NtpTimestamp::from_unix_seconds(now);
    let t2 = t3;
    let mut packet = [0u8; 48];
    // Leap 0, version 4, mode 4 (server).
    packet[0] = 0x24;
    packet[1] = 2;
    packet[3] = 0xEC;
    packet[12..16].copy_from_slice(b"LOCL");
    packet[16..24].copy_from_slice(&t3.to_bytes());
    packet[24..32].copy_from_slice(&request.transmit_timestamp.to_bytes());
    packet[32..40].copy_from_slice(&t2.to_bytes());
    packet[40..48].copy_from_slice(&t3.to_bytes());
    packet.to_vec()
}

/// Wait until the controller has no active task anymore, then return its events.
async fn wait_and_drain(ctrl: &mut TaskController<ProbeEvent>) -> Vec<ProbeEvent> {
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if !ctrl.is_active() {
            break;
        }
    }
    ctrl.drain()
}

#[tokio::test]
async fn ntp_query_loopback() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        if let Ok((n, peer)) = server.recv_from(&mut buf).await {
            let response = ntp_response(&buf[..n]);
            let _ = server.send_to(&response, peer).await;
        }
    });

    let settings = NtpSettings {
        target: format!("127.0.0.1:{}", addr.port()),
        timeout_ms: 300,
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        net_tools_core::net::ntp::run_query(&h, &settings).await
    });

    let events = wait_and_drain(&mut ctrl).await;
    let result = events
        .iter()
        .find_map(|e| match e {
            ProbeEvent::Ntp(r) => Some(r),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected an NTP result, got {events:?}"));
    assert_eq!(result.stratum, 2);
    assert!(result.server_time_unix > 0.0);
    assert!(result.delay_ms >= 0.0);
    srv.abort();
}

#[tokio::test]
async fn ntp_query_retries_once_then_succeeds() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        // Ignore the first request, answer the retry.
        let _ = server.recv_from(&mut buf).await;
        if let Ok((n, peer)) = server.recv_from(&mut buf).await {
            let response = ntp_response(&buf[..n]);
            let _ = server.send_to(&response, peer).await;
        }
    });

    let settings = NtpSettings {
        target: format!("127.0.0.1:{}", addr.port()),
        timeout_ms: 100,
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        net_tools_core::net::ntp::run_query(&h, &settings).await
    });

    let events = wait_and_drain(&mut ctrl).await;
    assert!(
        events.iter().any(|e| matches!(e, ProbeEvent::Ntp(_))),
        "expected the retry to succeed, got {events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(e, ProbeEvent::Error { .. })),
        "no error should be reported after a successful retry, got {events:?}"
    );
    srv.abort();
}

#[tokio::test]
async fn ntp_query_reports_error_after_both_attempts() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        // Consume both requests without answering.
        let mut buf = [0u8; 1024];
        let _ = server.recv_from(&mut buf).await;
        let _ = server.recv_from(&mut buf).await;
    });

    let settings = NtpSettings {
        target: format!("127.0.0.1:{}", addr.port()),
        timeout_ms: 100,
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(&tokio::runtime::Handle::current(), move |h| async move {
        net_tools_core::net::ntp::run_query(&h, &settings).await
    });

    let events = wait_and_drain(&mut ctrl).await;
    assert!(
        events.iter().any(
            |e| matches!(e, ProbeEvent::Error { message, .. } if message.contains("did not answer"))
        ),
        "expected a timeout error after both attempts, got {events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(e, ProbeEvent::Ntp(_))),
        "expected no result, got {events:?}"
    );
    srv.abort();
}
