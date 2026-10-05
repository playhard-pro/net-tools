//! UDP probing (the UDP mode of ping).

use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::clock;
use crate::config::PingSettings;
use crate::control::ProbeHandle;
use crate::model::ProbeEvent;
use crate::net::icmp;

/// Continuous UDP ping: send a UDP datagram to the target port and treat a
/// received ICMP port-unreachable (surfaced as ECONNREFUSED on the socket) or a
/// reply as proof that the host is alive, using it to compute the RTT.
/// Unprivileged and best effort: a firewall may suppress the unreachable
/// message, which then shows up as a timeout.
pub async fn run_ping_udp(handle: &ProbeHandle<ProbeEvent>, settings: &PingSettings) {
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
    handle.send(ProbeEvent::Info(format!("resolved {target} -> {ip}")));

    let bind: std::net::SocketAddr = match ip {
        std::net::IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        std::net::IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            handle.send(ProbeEvent::Error {
                message: format!("failed to bind UDP socket: {e}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    if let Err(e) = socket.connect((ip, settings.udp_port)).await {
        handle.send(ProbeEvent::Error {
            message: format!("UDP connect failed: {e}"),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    let payload = vec![0x62u8; settings.common.packet_size];
    let mut buf = [0u8; 2048];
    let mut seq: u64 = 0;

    loop {
        if handle.is_cancelled() {
            break;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            break;
        }

        let started = Instant::now();
        if let Err(e) = socket.send(&payload).await {
            handle.send(ProbeEvent::Error {
                message: format!("UDP send failed: {e}"),
                hint: None,
            });
            break;
        }

        let result = tokio::time::timeout(
            Duration::from_millis(settings.common.timeout_ms),
            socket.recv(&mut buf),
        )
        .await;

        match result {
            Ok(Ok(_n)) => {
                // A reply from the peer: the host is alive.
                handle.send(ProbeEvent::Latency(crate::model::ProbeSample {
                    seq,
                    time: clock::now_string(),
                    rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                    ttl: None,
                    from: ip.to_string(),
                    size: settings.common.packet_size,
                }));
            }
            Ok(Err(e)) => {
                // ICMP port unreachable usually surfaces as ECONNREFUSED.
                if e.raw_os_error() == Some(libc::ECONNREFUSED)
                    || e.raw_os_error() == Some(libc::ECONNRESET)
                {
                    handle.send(ProbeEvent::Latency(crate::model::ProbeSample {
                        seq,
                        time: clock::now_string(),
                        rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                        ttl: None,
                        from: ip.to_string(),
                        size: settings.common.packet_size,
                    }));
                } else {
                    handle.send(ProbeEvent::Error {
                        message: format!("UDP recv error: {e}"),
                        hint: None,
                    });
                    break;
                }
            }
            Err(_) => {
                // Timeout: no response.
                handle.send(ProbeEvent::Timeout { seq });
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
