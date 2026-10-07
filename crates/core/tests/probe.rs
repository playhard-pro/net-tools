//! Integration tests for the probe engines (loopback based, no external network).

use std::time::Duration;

use net_tools_core::config::{HttpSettings, MtrSettings, PingSettings, PortScanSettings};
use net_tools_core::control::TaskController;
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
