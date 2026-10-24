//! Iterative DNS resolution from the root servers, in the spirit of `dig +trace`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

use super::query::format_message;
use super::transport::{exchange, Exchange};
use crate::config::DnsSettings;
use crate::control::ProbeHandle;
use crate::model::{IpVersion, ProbeEvent};

/// Addresses of the well-known root servers, used as the start of a trace.
/// Both address families are listed so the trace works on IPv4-only and
/// IPv6-only hosts alike.
const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",
    "2001:503:ba3e::2:30",
    "170.247.170.2",
    "2801:1b8:10::b",
    "192.33.4.12",
    "2001:500:2::c",
    "199.7.91.13",
    "2001:500:2d::d",
    "192.203.230.10",
    "2001:500:a8::e",
    "192.5.5.241",
    "2001:500:2f::f",
    "192.112.36.4",
    "2001:500:12::d0d",
    "198.97.190.53",
    "2001:500:1::53",
    "192.36.148.17",
    "2001:7fe::53",
    "192.58.128.30",
    "2001:503:c27::2:30",
    "193.0.14.129",
    "2001:7fd::1",
    "199.7.83.42",
    "2001:500:9f::42",
    "202.12.27.33",
    "2001:dc3::35",
];

/// Upper bound on referral hops during a trace, so a referral loop cannot run
/// forever.
const MAX_TRACE_DEPTH: usize = 30;

/// Run an iterative trace from the root servers and stream the result per hop.
pub async fn run_trace(handle: &ProbeHandle<ProbeEvent>, settings: &DnsSettings) {
    let result = tokio::select! {
        result = trace(handle, settings) => Some(result),
        _ = handle.cancelled() => None,
    };

    if let Some(Err(message)) = result {
        handle.send(ProbeEvent::Error {
            message,
            hint: None,
        });
    }
    handle.send(ProbeEvent::Finished);
}

/// Iterative trace from the root servers down to the answer.
async fn trace(handle: &ProbeHandle<ProbeEvent>, settings: &DnsSettings) -> Result<(), String> {
    let rtype = super::parse_record_type(&settings.record_type)?;
    let name = super::parse_name(&settings.target, rtype)?;
    let timeout = Duration::from_millis(settings.timeout_ms.max(1));

    handle.send(ProbeEvent::DnsText(format!(
        ";; trace for {name} {rtype}\n"
    )));

    let mut servers = root_servers();
    for depth in 0..=MAX_TRACE_DEPTH {
        let (server, exchange) =
            query_first(&servers, &name, rtype, timeout, settings.force_tcp).await?;

        let mut step = format!("\n;; ---------- hop {} ----------\n", depth + 1);
        step.push_str(&format_message(&exchange, &name, rtype, server, false));

        // An answer or a terminal response code ends the trace.
        let metadata = &exchange.message.metadata;
        if !exchange.message.answers.is_empty() || metadata.response_code != ResponseCode::NoError {
            handle.send(ProbeEvent::DnsText(step));
            return Ok(());
        }

        let ns_names = referral_names(&exchange.message);
        if ns_names.is_empty() {
            handle.send(ProbeEvent::DnsText(step));
            return Ok(());
        }

        let mut next = glue_addresses(&exchange.message, &ns_names);
        if next.is_empty() {
            // No glue records: fall back to the system resolver to find the
            // addresses of the delegated name servers.
            for ns in &ns_names {
                let host = ns.to_utf8();
                let host = host.trim_end_matches('.');
                if let Ok(addrs) = crate::net::dns::resolve(host, IpVersion::Auto).await {
                    next.extend(addrs);
                }
            }
        }
        if next.is_empty() {
            step.push_str(";; no reachable name server for the next hop\n");
            handle.send(ProbeEvent::DnsText(step));
            return Ok(());
        }
        step.push_str(&format!(";; next servers: {}\n", join_ips(&next)));
        handle.send(ProbeEvent::DnsText(step));
        servers = next;
    }

    handle.send(ProbeEvent::DnsText(
        "\n;; trace depth limit reached\n".to_string(),
    ));
    Ok(())
}

/// Try each server in order and return the first successful response.
async fn query_first(
    servers: &[IpAddr],
    name: &Name,
    rtype: RecordType,
    timeout: Duration,
    force_tcp: bool,
) -> Result<(SocketAddr, Exchange), String> {
    let mut last_error = None;
    for ip in servers {
        let server = SocketAddr::new(*ip, 53);
        match exchange(server, name, rtype, false, force_tcp, timeout).await {
            Ok(exchange) => return Ok((server, exchange)),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| "no name server available".to_string()))
}

/// NS names from the authority section of a referral.
fn referral_names(message: &Message) -> Vec<Name> {
    message
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::NS(name) => Some(name.0.clone()),
            _ => None,
        })
        .collect()
}

/// Glue addresses from the additional section that belong to `ns_names`.
fn glue_addresses(message: &Message, ns_names: &[Name]) -> Vec<IpAddr> {
    message
        .additionals
        .iter()
        .filter_map(|record| {
            if ns_names.iter().any(|ns| ns == &record.name) {
                record.data.ip_addr()
            } else {
                None
            }
        })
        .collect()
}

/// All root server addresses, IPv4 first so a host without IPv6 connectivity
/// succeeds quickly.
fn root_servers() -> Vec<IpAddr> {
    let mut servers: Vec<IpAddr> = ROOT_SERVERS.iter().filter_map(|s| s.parse().ok()).collect();
    servers.sort_by_key(|ip| ip.is_ipv6());
    servers
}

/// Join addresses for a one-line summary.
fn join_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_servers_cover_both_families() {
        let servers = root_servers();
        assert!(servers.iter().any(IpAddr::is_ipv4));
        assert!(servers.iter().any(IpAddr::is_ipv6));
        // IPv4 addresses come first so a host without IPv6 succeeds quickly.
        assert!(servers.first().unwrap().is_ipv4());
    }
}
