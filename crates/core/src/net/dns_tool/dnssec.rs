//! Local DNSSEC validation and trust-chain inspection.
//!
//! Validation is delegated to hickory's validating resolver, which uses the
//! root KSK trust anchors bundled with hickory-proto. The anchors are public
//! keys, not TLS certificates, so there is no certificate renewal process.
//! Updating hickory is only necessary when the IANA root KSK rolls over.

use std::time::Duration;

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::{DnssecSummary, Proof, PublicKey};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

use super::transport::{
    parse_doh_endpoint, parse_dot_endpoint, parse_plain_server, parse_quic_endpoint, resolve_server,
};
use crate::model::{
    DnsDnssecChainStep, DnsDnssecReport, DnsDnssecStatus, DnsProtocol, DnsResolverSpec,
};

/// Validate one answer and build the report shown in the UI.
pub(crate) async fn validate(
    spec: &DnsResolverSpec,
    name: &Name,
    rtype: RecordType,
    timeout: Duration,
) -> DnsDnssecReport {
    let mut report = DnsDnssecReport::default();
    let resolver = match build_resolver(spec, timeout, true).await {
        Ok(resolver) => resolver,
        Err(error) => {
            report.status = DnsDnssecStatus::Unsupported;
            report.error = Some(error);
            return report;
        }
    };

    match timed_lookup(&resolver, name, rtype, timeout).await {
        Ok(lookup) => {
            let message = lookup.message();
            report.ad = message.metadata.authentic_data;
            let records: Vec<_> = message.all_sections().collect();
            report.rrsig_count = records
                .iter()
                .filter(|record| record.record_type() == RecordType::RRSIG)
                .count();
            report.nsec_count = records
                .iter()
                .filter(|record| {
                    matches!(
                        record.record_type(),
                        RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM
                    )
                })
                .count();
            report.status = status_from_records(records.iter().copied());
            report.chain = chain_steps(&resolver, name, timeout).await;
            for step in &report.chain {
                report.ds_present |= step.ds_present;
                report.dnskey_present |= step.dnskey_present;
            }
        }
        Err(error) => {
            report.status = classify_error(&error);
            report.error = Some(error);
            // A non-validating lookup lets the UI show what the resolver sent
            // even when validation failed.
            if let Ok(resolver) = build_resolver(spec, timeout, false).await {
                if let Ok(lookup) = timed_lookup(&resolver, name, rtype, timeout).await {
                    let message = lookup.message();
                    report.ad = message.metadata.authentic_data;
                    report.rrsig_count = message
                        .all_sections()
                        .filter(|record| record.record_type() == RecordType::RRSIG)
                        .count();
                }
            }
        }
    }
    report
}

/// Build a resolver pointing at the same server and transport as the query.
pub(crate) async fn build_resolver(
    spec: &DnsResolverSpec,
    timeout: Duration,
    validate: bool,
) -> Result<TokioResolver, String> {
    let name_server = name_server_config(spec, timeout).await?;
    let config = ResolverConfig::from_name_servers(vec![name_server]);
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    let options: &mut ResolverOpts = builder.options_mut();
    options.validate = validate;
    options.timeout = timeout;
    options.attempts = 1;
    options.cache_size = 0;
    options.use_hosts_file = ResolveHosts::Never;
    options.edns0 = true;
    builder
        .build()
        .map_err(|error| format!("failed to build the DNSSEC resolver: {error}"))
}

async fn name_server_config(
    spec: &DnsResolverSpec,
    timeout: Duration,
) -> Result<NameServerConfig, String> {
    match spec.protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => {
            let addr = parse_plain_server(&spec.endpoint)?;
            Ok(if spec.protocol == DnsProtocol::Udp {
                NameServerConfig::udp(addr.ip())
            } else {
                NameServerConfig::tcp(addr.ip())
            })
            .map(|mut config| {
                if let Some(connection) = config.connections.first_mut() {
                    connection.port = addr.port();
                }
                config
            })
        }
        DnsProtocol::Dot => {
            let (host, port) = parse_dot_endpoint(&spec.endpoint)?;
            let addr = resolve_server(&host, port, timeout).await?;
            let mut config = NameServerConfig::tls(addr.ip(), host.clone().into());
            if let Some(connection) = config.connections.first_mut() {
                connection.port = port;
            }
            Ok(config)
        }
        DnsProtocol::Quic => {
            let (host, port) = parse_quic_endpoint(&spec.endpoint)?;
            let addr = resolve_server(&host, port, timeout).await?;
            let mut config = NameServerConfig::quic(addr.ip(), host.clone().into());
            if let Some(connection) = config.connections.first_mut() {
                connection.port = port;
            }
            Ok(config)
        }
        DnsProtocol::Doh => {
            let url = parse_doh_endpoint(&spec.endpoint)?;
            let host = url
                .host_str()
                .ok_or_else(|| "the DoH URL has no host".to_string())?
                .to_string();
            let port = url.port_or_known_default().unwrap_or(443);
            let path = if url.path().is_empty() {
                "/dns-query".to_string()
            } else {
                url.path().to_string()
            };
            let addr = resolve_server(&host, port, timeout).await?;
            let mut config = NameServerConfig::https(addr.ip(), host.into(), Some(path.into()));
            if let Some(connection) = config.connections.first_mut() {
                connection.port = port;
            }
            Ok(config)
        }
    }
}

async fn timed_lookup(
    resolver: &TokioResolver,
    name: &Name,
    rtype: RecordType,
    timeout: Duration,
) -> Result<hickory_resolver::lookup::Lookup, String> {
    tokio::time::timeout(timeout, resolver.lookup(name.clone(), rtype))
        .await
        .map_err(|_| format!("DNSSEC lookup for {name} timed out"))?
        .map_err(|error| format!("DNSSEC lookup for {name} failed: {error}"))
}

/// Map record proof flags to the report status.
fn status_from_records<'a>(
    records: impl Iterator<Item = &'a hickory_proto::rr::Record>,
) -> DnsDnssecStatus {
    let records: Vec<_> = records.collect();
    if records.is_empty() {
        return DnsDnssecStatus::Indeterminate;
    }
    match DnssecSummary::from_records(records.into_iter()) {
        DnssecSummary::Secure => DnsDnssecStatus::Secure,
        DnssecSummary::Bogus => DnsDnssecStatus::Bogus,
        DnssecSummary::Insecure => DnsDnssecStatus::Insecure,
    }
}

fn classify_error(error: &str) -> DnsDnssecStatus {
    let lower = error.to_ascii_lowercase();
    if lower.contains("bogus") || lower.contains("dnssec") || lower.contains("validation") {
        DnsDnssecStatus::Bogus
    } else {
        DnsDnssecStatus::Indeterminate
    }
}

/// Collect DS/DNSKEY information for up to a few labels above the answer.
async fn chain_steps(
    resolver: &TokioResolver,
    name: &Name,
    timeout: Duration,
) -> Vec<DnsDnssecChainStep> {
    let text = name.to_utf8();
    let labels: Vec<&str> = text.trim_end_matches('.').split('.').collect();
    let mut steps = Vec::new();
    let depth = labels.len().min(4);
    for skipped in 0..depth {
        let zone = labels[skipped..].join(".");
        if zone.is_empty() {
            continue;
        }
        let Ok(zone_name) = Name::from_utf8(&zone) else {
            continue;
        };
        let mut step = DnsDnssecChainStep {
            zone,
            ..DnsDnssecChainStep::default()
        };
        if let Ok(lookup) = timed_lookup(resolver, &zone_name, RecordType::DS, timeout).await {
            for record in lookup.answers() {
                if let RData::DNSSEC(DNSSECRData::DS(ds)) = &record.data {
                    step.ds_present = true;
                    step.key_tag = Some(ds.key_tag());
                    step.algorithm = Some(format!("{:?}", ds.algorithm()));
                    step.secure |= record.proof == Proof::Secure;
                    break;
                }
            }
        }
        if let Ok(lookup) = timed_lookup(resolver, &zone_name, RecordType::DNSKEY, timeout).await {
            for record in lookup.answers() {
                if let RData::DNSSEC(DNSSECRData::DNSKEY(key)) = &record.data {
                    step.dnskey_present = true;
                    if step.key_tag.is_none() {
                        step.key_tag = key.calculate_key_tag().ok();
                    }
                    if step.algorithm.is_none() {
                        step.algorithm = Some(format!("{:?}", key.public_key().algorithm()));
                    }
                    step.secure |= record.proof == Proof::Secure;
                    break;
                }
            }
        }
        if step.ds_present || step.dnskey_present {
            steps.push(step);
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_proofs_map_to_report_status() {
        use hickory_proto::rr::{Name, RData, Record};
        let name = Name::from_ascii("example.com.").unwrap();
        let mut secure =
            Record::from_rdata(name.clone(), 300, RData::A("192.0.2.1".parse().unwrap()));
        secure.proof = Proof::Secure;
        let mut insecure =
            Record::from_rdata(name.clone(), 300, RData::A("192.0.2.2".parse().unwrap()));
        insecure.proof = Proof::Insecure;
        let mut bogus =
            Record::from_rdata(name.clone(), 300, RData::A("192.0.2.3".parse().unwrap()));
        bogus.proof = Proof::Bogus;
        assert_eq!(
            status_from_records([&secure].into_iter()),
            DnsDnssecStatus::Secure
        );
        assert_eq!(
            status_from_records([&insecure].into_iter()),
            DnsDnssecStatus::Insecure
        );
        assert_eq!(
            status_from_records([&bogus].into_iter()),
            DnsDnssecStatus::Bogus
        );
        assert_eq!(
            status_from_records([].into_iter()),
            DnsDnssecStatus::Indeterminate
        );
    }

    #[test]
    fn error_classification_separates_bogus_from_unknown() {
        assert_eq!(
            classify_error("dnssec validation failed: bogus"),
            DnsDnssecStatus::Bogus
        );
        assert_eq!(
            classify_error("connection refused"),
            DnsDnssecStatus::Indeterminate
        );
    }
}
