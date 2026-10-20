//! Path MTU discovery with ICMP echo and a binary search.
//!
//! IPv4 probes carry the Don't Fragment bit. IPv6 has no DF bit, so the local
//! stack is told not to fragment and the search relies on the same "packet too
//! big" feedback. Every size is tried more than once by default, so one lost
//! packet does not decide the path MTU.

use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::PingSettings;
use crate::control::ProbeHandle;
use crate::model::{PmtuOutcome, PmtuResult, PmtuStep, ProbeEvent};
use crate::net::{icmp, raw_icmp};

/// IPv4 + ICMP headers added to every IPv4 echo payload.
const IPV4_OVERHEAD: usize = 20 + 8;
/// IPv6 + ICMPv6 headers added to every IPv6 echo payload. Extension headers
/// are not accounted for, so the result is an estimate for those paths.
const IPV6_OVERHEAD: usize = 40 + 8;
/// IPv4 minimum MTU from RFC 791.
const IPV4_MIN_MTU: u16 = 68;
/// IPv6 minimum link MTU from RFC 8200.
const IPV6_MIN_MTU: u16 = 1280;

/// Result of one size probe.
pub(crate) enum MtuProbe {
    Passed {
        responder: Option<IpAddr>,
        rtt: Duration,
    },
    TooLarge {
        responder: Option<IpAddr>,
        rtt: Option<Duration>,
        detail: Option<String>,
    },
    Timeout,
    Error(String),
}

/// Run Path MTU discovery until cancelled or the search finishes.
pub async fn run_pmtu(handle: &ProbeHandle<ProbeEvent>, settings: &PingSettings) {
    let started = Instant::now();
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
    handle.send(ProbeEvent::Info(format!("Path MTU: {target} -> {ip}")));

    // Path MTU uses a raw ICMP socket on Windows. Ask for UAC once, then run
    // the search in the elevated helper.
    #[cfg(windows)]
    {
        if !crate::elevation::is_elevated() {
            crate::elevation::run_elevated(
                handle,
                &crate::elevation::HelperRequest::Pmtu(settings.clone()),
            )
            .await;
            return;
        }
        if let Err(e) = raw_icmp::Capture::open(ip) {
            if e.kind() == io::ErrorKind::PermissionDenied {
                crate::elevation::run_elevated(
                    handle,
                    &crate::elevation::HelperRequest::Pmtu(settings.clone()),
                )
                .await;
                return;
            }
            handle.send(ProbeEvent::Error {
                message: format!("Path MTU needs a raw ICMP socket: {e}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    }

    let v6 = ip.is_ipv6();
    let overhead = if v6 { IPV6_OVERHEAD } else { IPV4_OVERHEAD };
    let protocol_min = if v6 { IPV6_MIN_MTU } else { IPV4_MIN_MTU };
    let min_mtu = settings.pmtu.min_mtu.max(protocol_min);
    let max_mtu = settings.pmtu.max_mtu.max(min_mtu);
    let attempts = settings.pmtu.attempts.max(1);
    let timeout = Duration::from_millis(settings.common.timeout_ms);

    let mut steps = Vec::new();
    let mut low = min_mtu as i32;
    let mut high = max_mtu as i32;
    let mut best: Option<u16> = None;
    let mut error: Option<String> = None;
    let mut ident = (std::process::id() & 0xffff) as u16;
    let mut seq: u16 = 0;

    while low <= high {
        if handle.is_cancelled() {
            handle.send(ProbeEvent::Finished);
            return;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            handle.send(ProbeEvent::Finished);
            return;
        }

        let mtu = ((low + high) / 2) as u16;
        let payload_bytes = mtu.saturating_sub(overhead as u16) as usize;
        let (outcome, step) = probe_with_attempts(
            ip,
            mtu,
            payload_bytes,
            attempts,
            timeout,
            &mut ident,
            &mut seq,
        )
        .await;
        handle.send(ProbeEvent::PmtuStep(step.clone()));
        steps.push(step);

        match outcome {
            SizeResult::Passed => {
                best = Some(mtu);
                low = mtu as i32 + 1;
            }
            SizeResult::TooLarge | SizeResult::Timeout => {
                high = mtu as i32 - 1;
            }
            SizeResult::Error(message) => {
                error = Some(message);
                break;
            }
        }
    }

    // Confirm the winning size once more. This catches a transient loss that
    // happened to be classified as a pass.
    if error.is_none() {
        if let Some(mtu) = best {
            if handle.is_cancelled() {
                handle.send(ProbeEvent::Finished);
                return;
            }
            let payload_bytes = mtu.saturating_sub(overhead as u16) as usize;
            let (outcome, mut step) = probe_with_attempts(
                ip,
                mtu,
                payload_bytes,
                attempts,
                timeout,
                &mut ident,
                &mut seq,
            )
            .await;
            step.detail = Some(match step.detail {
                Some(detail) => format!("verification: {detail}"),
                None => "verification".to_string(),
            });
            handle.send(ProbeEvent::PmtuStep(step.clone()));
            steps.push(step);
            if !matches!(outcome, SizeResult::Passed) {
                error = Some("the final MTU confirmation did not pass".to_string());
            }
        } else if error.is_none() {
            error = Some("no MTU in the search range passed".to_string());
        }
    }

    let result = PmtuResult {
        target,
        ip: ip.to_string(),
        min_mtu,
        max_mtu,
        path_mtu: best,
        payload_bytes: best.map(|mtu| mtu.saturating_sub(overhead as u16) as usize),
        overhead,
        steps,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        error,
    };
    handle.send(ProbeEvent::Pmtu(result));
    handle.send(ProbeEvent::Finished);
}

/// Classification of one size after all configured attempts.
enum SizeResult {
    Passed,
    TooLarge,
    Timeout,
    Error(String),
}

/// Try one MTU up to `attempts` times and return the first definitive outcome.
async fn probe_with_attempts(
    ip: IpAddr,
    mtu: u16,
    payload_bytes: usize,
    attempts: u8,
    timeout: Duration,
    ident: &mut u16,
    seq: &mut u16,
) -> (SizeResult, PmtuStep) {
    let responder = None;
    let rtt_ms = None;
    let detail = None;

    for _ in 0..attempts {
        *ident = ident.wrapping_add(1);
        *seq = seq.wrapping_add(1);
        let probe_ident = *ident;
        let probe_seq = *seq;
        let result = tokio::task::spawn_blocking(move || {
            probe_size(ip, payload_bytes, timeout, probe_ident, probe_seq)
        })
        .await;

        match result {
            Ok(MtuProbe::Passed {
                responder: from,
                rtt,
            }) => {
                return (
                    SizeResult::Passed,
                    PmtuStep {
                        mtu,
                        payload_bytes,
                        outcome: PmtuOutcome::Passed,
                        responder: from.map(|value| value.to_string()),
                        rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
                        detail,
                    },
                );
            }
            Ok(MtuProbe::TooLarge {
                responder: from,
                rtt,
                detail: why,
            }) => {
                return (
                    SizeResult::TooLarge,
                    PmtuStep {
                        mtu,
                        payload_bytes,
                        outcome: PmtuOutcome::TooLarge,
                        responder: from.map(|value| value.to_string()),
                        rtt_ms: rtt.map(|value| value.as_secs_f64() * 1000.0),
                        detail: why,
                    },
                );
            }
            Ok(MtuProbe::Timeout) => {}
            Ok(MtuProbe::Error(message)) => {
                return (
                    SizeResult::Error(message.clone()),
                    PmtuStep {
                        mtu,
                        payload_bytes,
                        outcome: PmtuOutcome::Error,
                        responder,
                        rtt_ms,
                        detail: Some(message),
                    },
                );
            }
            Err(_) => {
                let message = "Path MTU probe task panicked".to_string();
                return (
                    SizeResult::Error(message.clone()),
                    PmtuStep {
                        mtu,
                        payload_bytes,
                        outcome: PmtuOutcome::Error,
                        responder,
                        rtt_ms,
                        detail: Some(message),
                    },
                );
            }
        }
    }

    (
        SizeResult::Timeout,
        PmtuStep {
            mtu,
            payload_bytes,
            outcome: PmtuOutcome::Timeout,
            responder,
            rtt_ms,
            detail,
        },
    )
}

/// Probe one size. On Linux the unprivileged ping engine is preferred; other
/// platforms use a raw ICMP socket.
fn probe_size(
    target: IpAddr,
    payload_bytes: usize,
    timeout: Duration,
    ident: u16,
    seq: u16,
) -> MtuProbe {
    #[cfg(target_os = "linux")]
    {
        if let Ok(result) =
            crate::net::linux_icmp::probe_mtu(target, payload_bytes, timeout, ident, seq)
        {
            return result;
        }
    }

    probe_size_raw(target, payload_bytes, timeout, ident, seq)
}

/// Raw-socket fallback used on macOS, Windows and when the Linux datagram
/// engine is unavailable.
fn probe_size_raw(
    target: IpAddr,
    payload_bytes: usize,
    timeout: Duration,
    ident: u16,
    seq: u16,
) -> MtuProbe {
    let capture = match raw_icmp::Capture::open(target) {
        Ok(value) => value,
        Err(e) => return MtuProbe::Error(format!("failed to open ICMP socket: {e}")),
    };
    if let Err(e) = capture.set_no_fragment() {
        return MtuProbe::Error(format!("failed to set don't-fragment: {e}"));
    }
    let source = match raw_icmp::local_addr_for(target, 33434) {
        Ok(addr) => addr.ip(),
        Err(e) => return MtuProbe::Error(format!("failed to choose a source address: {e}")),
    };

    let payload = vec![0x7au8; payload_bytes];
    let packet = raw_icmp::echo_request(source, target, ident, seq, &payload);
    let started = Instant::now();
    if let Err(e) = capture.send_to(&packet, target) {
        if is_message_too_long(&e) {
            return MtuProbe::TooLarge {
                responder: None,
                rtt: None,
                detail: Some("local send reported EMSGSIZE".to_string()),
            };
        }
        return MtuProbe::Error(format!("failed to send ICMP probe: {e}"));
    }

    let deadline = started + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return MtuProbe::Timeout;
        }
        let ready = match raw_icmp::poll_read(capture.socket(), deadline - now) {
            Ok(value) => value,
            Err(e) => return MtuProbe::Error(format!("poll failed: {e}")),
        };
        if !ready {
            return MtuProbe::Timeout;
        }
        loop {
            let message = match capture.recv() {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(e) => return MtuProbe::Error(format!("failed to receive ICMP: {e}")),
            };
            match message.kind {
                raw_icmp::MessageKind::EchoReply
                    if message.echo_id == Some(ident) && message.echo_seq == Some(seq) =>
                {
                    return MtuProbe::Passed {
                        responder: Some(message.from),
                        rtt: started.elapsed(),
                    };
                }
                raw_icmp::MessageKind::PacketTooBig
                | raw_icmp::MessageKind::TimeExceeded
                | raw_icmp::MessageKind::Unreachable => {
                    if let Some(quoted) = message.quoted {
                        if quoted.echo_id == Some(ident) && quoted.echo_seq == Some(seq) {
                            return MtuProbe::TooLarge {
                                responder: Some(message.from),
                                rtt: Some(started.elapsed()),
                                detail: Some(format!(
                                    "ICMP {:?} code {}",
                                    message.kind, message.code
                                )),
                            };
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Whether a local send failed because the packet exceeds the local MTU.
fn is_message_too_long(error: &io::Error) -> bool {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::EMSGSIZE) {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overhead_matches_ip_version() {
        assert_eq!(IPV4_OVERHEAD, 28);
        assert_eq!(IPV6_OVERHEAD, 48);
    }
}
