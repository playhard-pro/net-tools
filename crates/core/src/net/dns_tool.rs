//! Raw DNS query and iterative trace, in the spirit of `dig`.
//!
//! Queries are encoded and decoded with `hickory-proto` and sent over UDP with
//! an automatic TCP retry when the response is truncated. A trace starts at the
//! well-known root servers and follows the NS referrals down to the answer.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Edns, Message, MessageType, Metadata, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::DnsSettings;
use crate::control::ProbeHandle;
use crate::model::{IpVersion, ProbeEvent};

/// Record types offered as quick picks in the UI. The user may still type any
/// other type name supported by the protocol library.
pub const COMMON_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA", "HTTPS", "ANY",
];

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

/// Size of the buffer used to receive one UDP datagram.
const UDP_BUFFER: usize = 65_535;

/// Outcome of a single request: decoded message, round-trip time and transport.
struct Exchange {
    message: Message,
    elapsed: Duration,
    transport: &'static str,
}

/// Run a single recursive query and emit the formatted response.
pub async fn run_query(handle: &ProbeHandle<ProbeEvent>, settings: &DnsSettings) {
    let result = tokio::select! {
        result = query_once(settings) => Some(result),
        _ = handle.cancelled() => None,
    };

    match result {
        Some(Ok((server, name, rtype, exchange))) => {
            handle.send(ProbeEvent::DnsText(format_message(
                &exchange, &name, rtype, server, true,
            )));
        }
        Some(Err(message)) => handle.send(ProbeEvent::Error {
            message,
            hint: None,
        }),
        None => {}
    }
    handle.send(ProbeEvent::Finished);
}

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

/// Parse a record type name, accepting any spelling hickory knows.
pub fn parse_record_type(value: &str) -> Result<RecordType, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("record type is empty".to_string());
    }
    RecordType::from_str(&value.to_uppercase()).map_err(|_| format!("unknown record type: {value}"))
}

/// Parse an optional custom server. An empty value means "use the system
/// resolver", a bare address gets the default port appended.
fn parse_server(value: &str) -> Result<Option<SocketAddr>, String> {
    let value = value.trim().trim_start_matches('@');
    if value.is_empty() {
        return Ok(None);
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(Some(addr));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(Some(SocketAddr::new(ip, 53)));
    }
    Err(format!("invalid DNS server: {value}"))
}

/// First name server configured on the host.
fn system_server() -> Result<SocketAddr, String> {
    let (config, _) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|err| format!("failed to read the system resolver configuration: {err}"))?;
    config
        .name_servers()
        .iter()
        .map(|ns| SocketAddr::new(ns.ip, 53))
        .next()
        .ok_or_else(|| "the system resolver has no name server configured".to_string())
}

/// Build the query name. For a PTR query the target may be given as a plain IP
/// address, which is converted to the corresponding reverse name.
fn parse_name(target: &str, rtype: RecordType) -> Result<Name, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target is empty".to_string());
    }
    if rtype == RecordType::PTR {
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Name::from_ascii(reverse_name(ip))
                .map_err(|err| format!("invalid reverse name: {err}"));
        }
    }
    Name::from_utf8(target).map_err(|err| format!("invalid domain name: {err}"))
}

/// Reverse lookup name for an IP address (`in-addr.arpa` / `ip6.arpa`).
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut name = String::new();
            // Reverse nibble order: least significant byte first, low nibble
            // before high nibble inside each byte.
            for byte in v6.octets().iter().rev() {
                name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            name.push_str("ip6.arpa.");
            name
        }
    }
}

/// Perform one recursive query against the configured (or system) server.
async fn query_once(
    settings: &DnsSettings,
) -> Result<(SocketAddr, Name, RecordType, Exchange), String> {
    let rtype = parse_record_type(&settings.record_type)?;
    let name = parse_name(&settings.target, rtype)?;
    let server = match parse_server(&settings.server)? {
        Some(addr) => addr,
        None => system_server()?,
    };
    let timeout = Duration::from_millis(settings.timeout_ms.max(1));
    let exchange = exchange(server, &name, rtype, true, settings.force_tcp, timeout).await?;
    Ok((server, name, rtype, exchange))
}

/// Iterative trace from the root servers down to the answer.
async fn trace(handle: &ProbeHandle<ProbeEvent>, settings: &DnsSettings) -> Result<(), String> {
    let rtype = parse_record_type(&settings.record_type)?;
    let name = parse_name(&settings.target, rtype)?;
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

/// Send one request over UDP (with a TCP retry on truncation) or straight over
/// TCP when forced.
async fn exchange(
    server: SocketAddr,
    name: &Name,
    rtype: RecordType,
    recursive: bool,
    force_tcp: bool,
    timeout: Duration,
) -> Result<Exchange, String> {
    let request = build_query(name, rtype, recursive);
    let bytes = request
        .to_vec()
        .map_err(|err| format!("failed to encode the query: {err}"))?;

    if !force_tcp {
        let started = Instant::now();
        let response = udp_exchange(server, &bytes, request.metadata.id, timeout).await?;
        let elapsed = started.elapsed();
        if !response.metadata.truncation {
            return Ok(Exchange {
                message: response,
                elapsed,
                transport: "UDP",
            });
        }
        // Truncated: fall through and retry over TCP.
    }

    let started = Instant::now();
    let response = tcp_exchange(server, &bytes, timeout).await?;
    Ok(Exchange {
        message: response,
        elapsed: started.elapsed(),
        transport: "TCP",
    })
}

/// Encoded request with EDNS enabled to keep large answers from truncating.
fn build_query(name: &Name, rtype: RecordType, recursive: bool) -> Message {
    let mut message = Message::query();
    message.metadata.recursion_desired = recursive;
    message.add_query(Query::query(name.clone(), rtype));
    message.set_edns(Edns::new());
    message
}

/// Send the request over UDP and decode the response.
async fn udp_exchange(
    server: SocketAddr,
    request: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Message, String> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|err| format!("failed to open a UDP socket: {err}"))?;
    socket
        .connect(server)
        .await
        .map_err(|err| format!("failed to connect to {server}: {err}"))?;
    socket
        .send(request)
        .await
        .map_err(|err| format!("failed to send to {server}: {err}"))?;

    let mut buffer = vec![0u8; UDP_BUFFER];
    let received = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .map_err(|_| format!("query to {server} timed out"))?
        .map_err(|err| format!("failed to receive from {server}: {err}"))?;
    let message = Message::from_vec(&buffer[..received])
        .map_err(|err| format!("failed to decode the response from {server}: {err}"))?;
    if message.metadata.id != id {
        return Err(format!("response from {server} has a mismatched id"));
    }
    Ok(message)
}

/// Send the request over TCP and decode the length-prefixed response.
async fn tcp_exchange(
    server: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> Result<Message, String> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| format!("connecting to {server} timed out"))?
        .map_err(|err| format!("failed to connect to {server}: {err}"))?;

    let length = u16::try_from(request.len())
        .map_err(|_| "the query is too large for TCP framing".to_string())?;
    let mut framed = Vec::with_capacity(2 + request.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(request);
    tokio::time::timeout(timeout, stream.write_all(&framed))
        .await
        .map_err(|_| format!("sending to {server} timed out"))?
        .map_err(|err| format!("failed to send to {server}: {err}"))?;

    let mut length_buffer = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut length_buffer))
        .await
        .map_err(|_| format!("reading from {server} timed out"))?
        .map_err(|err| format!("failed to read from {server}: {err}"))?;
    let body_length = u16::from_be_bytes(length_buffer) as usize;
    let mut body = vec![0u8; body_length];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| format!("reading from {server} timed out"))?
        .map_err(|err| format!("failed to read from {server}: {err}"))?;
    Message::from_vec(&body)
        .map_err(|err| format!("failed to decode the response from {server}: {err}"))
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

/// Render a decoded message in a compact, dig-like text form.
fn format_message(
    exchange: &Exchange,
    name: &Name,
    rtype: RecordType,
    server: SocketAddr,
    recursive: bool,
) -> String {
    let message = &exchange.message;
    let metadata = &message.metadata;
    let mut out = String::new();
    out.push_str(&format!(
        ";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n",
        metadata.op_code, metadata.response_code, metadata.id
    ));
    out.push_str(&format!(
        ";; flags:{}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n",
        flags(metadata),
        message.queries.len(),
        message.answers.len(),
        message.authorities.len(),
        message.additionals.len()
    ));
    out.push_str(&format!(
        ";; QUERY TIME: {} ms\n",
        exchange.elapsed.as_millis()
    ));
    out.push_str(&format!(";; SERVER: {server} ({})\n", exchange.transport));
    out.push_str(&format!(
        ";; QUESTION: {name} {} {}{}\n",
        DNSClass::IN,
        rtype,
        if recursive { " (recursive)" } else { "" }
    ));
    push_section(&mut out, "ANSWER", &message.answers);
    push_section(&mut out, "AUTHORITY", &message.authorities);
    push_section(&mut out, "ADDITIONAL", &message.additionals);
    out
}

/// Header flags as a space separated list.
fn flags(metadata: &Metadata) -> String {
    let mut list = Vec::new();
    if metadata.message_type == MessageType::Response {
        list.push("qr");
    }
    if metadata.authoritative {
        list.push("aa");
    }
    if metadata.truncation {
        list.push("tc");
    }
    if metadata.recursion_desired {
        list.push("rd");
    }
    if metadata.recursion_available {
        list.push("ra");
    }
    if metadata.authentic_data {
        list.push("ad");
    }
    if metadata.checking_disabled {
        list.push("cd");
    }
    if list.is_empty() {
        String::new()
    } else {
        format!(" {}", list.join(" "))
    }
}

/// Append one resource-record section.
fn push_section(out: &mut String, title: &str, records: &[Record]) {
    out.push_str(&format!("\n;; {title} SECTION:\n"));
    if records.is_empty() {
        out.push_str(";; (empty)\n");
        return;
    }
    for record in records {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            record.name,
            record.ttl,
            record.dns_class,
            record.record_type(),
            record.data
        ));
    }
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
    fn record_type_parsing_is_case_insensitive() {
        assert_eq!(parse_record_type("a").unwrap(), RecordType::A);
        assert_eq!(parse_record_type("Mx").unwrap(), RecordType::MX);
        assert!(parse_record_type("not-a-type").is_err());
        assert!(parse_record_type("  ").is_err());
    }

    #[test]
    fn server_parsing_handles_common_forms() {
        assert!(parse_server("").unwrap().is_none());
        assert_eq!(
            parse_server("8.8.8.8").unwrap().unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
        assert_eq!(
            parse_server("@1.1.1.1:5353").unwrap().unwrap(),
            "1.1.1.1:5353".parse().unwrap()
        );
        assert!(parse_server("not a server").is_err());
    }

    #[test]
    fn ptr_targets_are_reversed() {
        assert_eq!(
            reverse_name("1.2.3.4".parse().unwrap()),
            "4.3.2.1.in-addr.arpa."
        );
        let name = parse_name("1.2.3.4", RecordType::PTR).unwrap();
        assert_eq!(name.to_utf8(), "4.3.2.1.in-addr.arpa.");
    }

    #[test]
    fn root_servers_cover_both_families() {
        let servers = root_servers();
        assert!(servers.iter().any(IpAddr::is_ipv4));
        assert!(servers.iter().any(IpAddr::is_ipv6));
        // IPv4 addresses come first so a host without IPv6 succeeds quickly.
        assert!(servers.first().unwrap().is_ipv4());
    }
}
