//! TCP probing (the TCP mode of ping).
//!
//! A TCP connect is used as an unprivileged reachability test: the kernel sends
//! a SYN, and either a completed handshake or a refusal proves that the host is
//! reachable. It works on hosts that drop ICMP, at the cost of not reporting a
//! reply TTL.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::clock;
use crate::config::PingSettings;
use crate::control::ProbeHandle;
use crate::model::{ProbeEvent, ProbeSample};
use crate::net::icmp;

/// Whether a connection error still proves that the target TCP stack answered.
fn proves_reachable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
    )
}

/// Continuous TCP ping until cancelled.
pub async fn run_ping_tcp(handle: &ProbeHandle<ProbeEvent>, settings: &PingSettings) {
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
    handle.send(ProbeEvent::Info(format!("resolved {target} -> {ip}")));
    if settings.common.reverse_dns {
        if let Some(name) = crate::net::dns::reverse(ip).await {
            handle.send(ProbeEvent::Info(format!("reverse: {ip} -> {name}")));
        }
    }

    let destination = SocketAddr::new(ip, settings.tcp_port);
    let timeout = Duration::from_millis(settings.common.timeout_ms);
    let interval = Duration::from_millis(settings.common.interval_ms);
    let mut seq: u64 = 0;
    let mut reported_error: Option<String> = None;

    loop {
        if handle.is_cancelled() {
            break;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            break;
        }

        let started = Instant::now();
        let outcome = tokio::time::timeout(timeout, TcpStream::connect(destination)).await;
        let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;

        match outcome {
            Ok(Ok(stream)) => {
                // The handshake completed; close immediately so an open service
                // is not kept busy by a pure reachability probe.
                drop(stream);
                handle.send(ProbeEvent::Latency(ProbeSample {
                    seq,
                    time: clock::now_string(),
                    rtt_ms,
                    ttl: None,
                    from: ip.to_string(),
                    size: 0,
                }));
            }
            Ok(Err(e)) if proves_reachable(&e) => {
                handle.send(ProbeEvent::Latency(ProbeSample {
                    seq,
                    time: clock::now_string(),
                    rtt_ms,
                    ttl: None,
                    from: ip.to_string(),
                    size: 0,
                }));
            }
            Ok(Err(e)) => {
                // Report a local/system error once, but keep sampling so a
                // transient condition does not stop the run. The sample itself
                // still counts as a timeout, matching ping semantics.
                let message = format!("TCP connect error: {e}");
                if reported_error.as_deref() != Some(message.as_str()) {
                    handle.send(ProbeEvent::Info(message.clone()));
                    reported_error = Some(message);
                }
                handle.send(ProbeEvent::Timeout { seq });
            }
            Err(_) => handle.send(ProbeEvent::Timeout { seq }),
        }

        seq = seq.wrapping_add(1);
        if handle.sleep(interval).await {
            break;
        }
    }

    handle.send(ProbeEvent::Finished);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_connection_proves_reachability() {
        assert!(proves_reachable(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        assert!(proves_reachable(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
        assert!(!proves_reachable(&io::Error::from(io::ErrorKind::TimedOut)));
    }
}
