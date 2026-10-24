//! Multi-resolver propagation comparison.

use std::time::Duration;

use hickory_proto::rr::{Name, RecordType};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::names::{parse_name, parse_record_type};
use super::resolvers::resolve_specs;
use super::transport::exchange_spec;
use crate::config::DnsPropagationSettings;
use crate::control::ProbeHandle;
use crate::model::{
    DnsAnswerGroup, DnsDnssecStatus, DnsPropagationReport, DnsResolverResult, DnsResolverSpec,
    DnsRunProgress, ProbeEvent,
};

/// Hard limits that also protect against hand-edited configuration files.
pub const MAX_RESOLVERS: usize = 20;
pub const MAX_CONCURRENCY: usize = 8;

/// Run a propagation comparison and stream progress plus the final report.
pub async fn run_propagation(handle: &ProbeHandle<ProbeEvent>, settings: &DnsPropagationSettings) {
    let result = tokio::select! {
        result = propagation_inner(handle, settings) => Some(result),
        _ = handle.cancelled() => None,
    };
    match result {
        Some(Ok(report)) => handle.send(ProbeEvent::DnsPropagation(Box::new(report))),
        Some(Err(message)) => handle.send(ProbeEvent::Error {
            message,
            hint: None,
        }),
        None => {}
    }
    handle.send(ProbeEvent::Finished);
}

async fn propagation_inner(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &DnsPropagationSettings,
) -> Result<DnsPropagationReport, String> {
    let rtype = parse_record_type(&settings.record_type)?;
    let name = parse_name(&settings.target, rtype)?;
    let mut specs = resolve_specs(settings.protocol, &settings.resolvers, &settings.custom)?;
    if specs.len() > MAX_RESOLVERS {
        specs.truncate(MAX_RESOLVERS);
    }
    let concurrency = settings.concurrency.clamp(1, MAX_CONCURRENCY);
    let timeout = Duration::from_millis(settings.timeout_ms.clamp(100, 120_000));
    let total = specs.len();
    let semaphore = std::sync::Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();

    for spec in specs.clone() {
        let name = name.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            query_resolver(spec, name, rtype, timeout).await
        });
    }

    let mut results = Vec::with_capacity(total);
    let mut done = 0usize;
    while let Some(joined) = tasks.join_next().await {
        let result = match joined {
            Ok(result) => result,
            Err(error) => DnsResolverResult {
                error: Some(format!("resolver task failed: {error}")),
                ..DnsResolverResult::default()
            },
        };
        done += 1;
        let current = result.resolver.label.clone();
        results.push(result);
        handle.send(ProbeEvent::DnsProgress(DnsRunProgress {
            done,
            total,
            current,
        }));
    }

    results.sort_by(|a, b| a.resolver.label.cmp(&b.resolver.label));
    let groups = answer_groups(&results);
    let failed = results
        .iter()
        .filter(|result| result.error.is_some())
        .count();
    let consistent = groups
        .first()
        .map(|group| group.resolvers.len())
        .unwrap_or(0);
    Ok(DnsPropagationReport {
        target: name.to_utf8(),
        record_type: rtype.to_string(),
        protocol: settings.protocol,
        results,
        groups,
        consistent,
        total,
        failed,
    })
}

pub(crate) async fn query_resolver(
    spec: DnsResolverSpec,
    name: Name,
    rtype: RecordType,
    timeout: Duration,
) -> DnsResolverResult {
    let mut request = super::transport::build_query(&name, rtype, true);
    let mut result = DnsResolverResult {
        resolver: spec.clone(),
        ..DnsResolverResult::default()
    };
    if let Some(edns) = request.edns.as_mut() {
        edns.set_dnssec_ok(true);
    }
    request.metadata.checking_disabled = true;
    match exchange_spec(&spec, &request, timeout).await {
        Ok(exchange) => {
            let message = &exchange.message;
            result.response_code = Some(message.metadata.response_code.to_string());
            result.elapsed_ms = exchange.elapsed.as_millis() as u64;
            result.ad = message.metadata.authentic_data;
            let mut ttl_sum = 0u64;
            let mut ttl_count = 0u64;
            for record in &message.answers {
                if record.record_type() == RecordType::RRSIG {
                    continue;
                }
                result
                    .answers
                    .push(format!("{} {}", record.record_type(), record.data));
                ttl_sum += record.ttl as u64;
                ttl_count += 1;
            }
            if let Some(avg) = ttl_sum.checked_div(ttl_count) {
                result.avg_ttl = Some(avg as u32);
            }
            result.dnssec = if result.ad {
                DnsDnssecStatus::Secure
            } else if message
                .answers
                .iter()
                .any(|record| record.record_type() == RecordType::RRSIG)
            {
                DnsDnssecStatus::Insecure
            } else {
                DnsDnssecStatus::Indeterminate
            };
        }
        Err(error) => result.error = Some(error),
    }
    result
}

/// Group successful resolvers by identical answer sets.
fn answer_groups(results: &[DnsResolverResult]) -> Vec<DnsAnswerGroup> {
    let mut groups: Vec<DnsAnswerGroup> = Vec::new();
    for result in results {
        if result.error.is_some() {
            continue;
        }
        let key = result.answer_key();
        if let Some(group) = groups.iter_mut().find(|group| group.key == key) {
            group.resolvers.push(result.resolver.label.clone());
        } else {
            groups.push(DnsAnswerGroup {
                key,
                resolvers: vec![result.resolver.label.clone()],
            });
        }
    }
    groups.sort_by_key(|group| std::cmp::Reverse(group.resolvers.len()));
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(label: &str, answers: &[&str], error: Option<&str>) -> DnsResolverResult {
        DnsResolverResult {
            resolver: DnsResolverSpec::new(label, crate::model::DnsProtocol::Udp, "127.0.0.1"),
            answers: answers.iter().map(|value| value.to_string()).collect(),
            error: error.map(str::to_string),
            ..DnsResolverResult::default()
        }
    }

    #[test]
    fn answer_groups_ignore_failed_resolvers() {
        let results = vec![
            result("a", &["A 192.0.2.1"], None),
            result("b", &["A 192.0.2.1"], None),
            result("c", &["A 192.0.2.2"], None),
            result("d", &[], Some("timeout")),
        ];
        let groups = answer_groups(&results);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].resolvers.len(), 2);
        assert_eq!(groups[1].resolvers.len(), 1);
    }
}
