//! Single recursive DNS queries and dig-like result formatting.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{MessageType, Metadata};
use hickory_proto::rr::{DNSClass, Name, Record, RecordType};

use super::names::{parse_name, parse_record_type, system_server};
use super::transport::{build_query, exchange_spec, Exchange};
use crate::config::DnsSettings;
use crate::control::ProbeHandle;
use crate::model::{
    DnsDnssecReport, DnsDnssecStatus, DnsProtocol, DnsQueryResult, DnsRecordView, DnsResolverSpec,
    ProbeEvent,
};

/// Run a single recursive query and emit both structured and raw results.
pub async fn run_query(handle: &ProbeHandle<ProbeEvent>, settings: &DnsSettings) {
    let result = tokio::select! {
        result = query_result(settings) => Some(result),
        _ = handle.cancelled() => None,
    };

    match result {
        Some(Ok(result)) => {
            handle.send(ProbeEvent::DnsQuery(Box::new(result)));
        }
        Some(Err(message)) => handle.send(ProbeEvent::Error {
            message,
            hint: None,
        }),
        None => {}
    }
    handle.send(ProbeEvent::Finished);
}

/// Build the resolver endpoint for the single-query tool.
///
/// A scheme in the server field overrides the protocol selector: entering a
/// `tls://` or `https://` endpoint is enough, even when the selector still says
/// UDP or TCP.
pub(crate) fn query_spec(settings: &DnsSettings) -> Result<DnsResolverSpec, String> {
    let server = settings.server.trim();
    let protocol = query_protocol(server, settings.effective_protocol());
    if server.is_empty() {
        return match protocol {
            DnsProtocol::Udp | DnsProtocol::Tcp => {
                let addr = system_server()?;
                Ok(DnsResolverSpec::new(
                    "system resolver",
                    protocol,
                    addr.ip().to_string(),
                ))
            }
            _ => Err("DoT and DoH require an explicit server endpoint".to_string()),
        };
    }
    Ok(DnsResolverSpec::new(server, protocol, server))
}

/// Detect the transport from an endpoint scheme, falling back to the selector.
pub(crate) fn query_protocol(server: &str, selected: DnsProtocol) -> DnsProtocol {
    let lower = server.trim().to_ascii_lowercase();
    if lower.starts_with("quic://") || lower.starts_with("doq://") {
        DnsProtocol::Quic
    } else if lower.starts_with("tls://") || lower.starts_with("dot://") {
        DnsProtocol::Dot
    } else if lower.starts_with("https://") || lower.starts_with("doh://") {
        DnsProtocol::Doh
    } else {
        selected
    }
}

/// Run one recursive query and build the structured result used by the UI.
pub(crate) async fn query_result(settings: &DnsSettings) -> Result<DnsQueryResult, String> {
    let rtype = parse_record_type(&settings.record_type)?;
    let name = parse_name(&settings.target, rtype)?;
    let spec = query_spec(settings)?;
    let timeout = Duration::from_millis(settings.timeout_ms.max(1));

    let mut request = build_query(&name, rtype, true);
    if settings.dnssec {
        if let Some(edns) = request.edns.as_mut() {
            edns.set_dnssec_ok(true);
        }
        request.metadata.checking_disabled = true;
    }
    let exchange = exchange_spec(&spec, &request, timeout).await?;
    let metadata = &exchange.message.metadata;

    let mut result = DnsQueryResult {
        target: name.to_utf8(),
        record_type: rtype.to_string(),
        server: spec.endpoint.clone(),
        protocol: spec.protocol,
        response_code: metadata.response_code.to_string(),
        elapsed_ms: exchange.elapsed.as_millis() as u64,
        transport: exchange.transport.to_string(),
        flags: flags(metadata),
        answers: exchange.message.answers.iter().map(record_view).collect(),
        authorities: exchange
            .message
            .authorities
            .iter()
            .map(record_view)
            .collect(),
        additionals: exchange
            .message
            .additionals
            .iter()
            .map(record_view)
            .collect(),
        raw: format_message_with_server(&exchange, &name, rtype, &spec.endpoint, true),
        dnssec: DnsDnssecReport {
            status: if settings.dnssec {
                DnsDnssecStatus::Indeterminate
            } else {
                DnsDnssecStatus::Disabled
            },
            ad: metadata.authentic_data,
            rrsig_count: exchange
                .message
                .all_sections()
                .filter(|record| record.record_type() == RecordType::RRSIG)
                .count(),
            nsec_count: exchange
                .message
                .all_sections()
                .filter(|record| {
                    matches!(
                        record.record_type(),
                        RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM
                    )
                })
                .count(),
            ..DnsDnssecReport::default()
        },
        error: None,
    };
    if settings.dnssec {
        result.dnssec = super::dnssec::validate(&spec, &name, rtype, timeout).await;
    }
    Ok(result)
}

fn record_view(record: &Record) -> DnsRecordView {
    DnsRecordView {
        name: record.name.to_utf8(),
        ttl: record.ttl,
        record_type: record.record_type().to_string(),
        value: record.data.to_string(),
    }
}

/// Render a decoded message in a compact, dig-like text form.
pub(crate) fn format_message(
    exchange: &Exchange,
    name: &Name,
    rtype: RecordType,
    server: SocketAddr,
    recursive: bool,
) -> String {
    format_message_with_server(exchange, name, rtype, &server.to_string(), recursive)
}

/// Render a decoded message with an arbitrary server label.
pub(crate) fn format_message_with_server(
    exchange: &Exchange,
    name: &Name,
    rtype: RecordType,
    server: &str,
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
pub(crate) fn flags(metadata: &Metadata) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_schemes_override_the_protocol_selector() {
        assert_eq!(
            query_protocol("tls://dns.google", DnsProtocol::Udp),
            DnsProtocol::Dot
        );
        assert_eq!(
            query_protocol("https://dns.google/dns-query", DnsProtocol::Udp),
            DnsProtocol::Doh
        );
        assert_eq!(
            query_protocol("quic://dns.quad9.net", DnsProtocol::Udp),
            DnsProtocol::Quic
        );
        assert_eq!(
            query_protocol("8.8.8.8", DnsProtocol::Tcp),
            DnsProtocol::Tcp
        );
    }
}
