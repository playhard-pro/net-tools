//! Domain health checks: MX, SPF, DKIM, DMARC, PTR, CAA, NS/SOA and DNSSEC.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::{Name, RData, RecordType};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::TokioResolver;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::dkim::{self, COMMON_SELECTORS};
use super::dmarc;
use super::names::system_server;
use super::spf;
use super::{build_resolver, check_caa_with_resolver, validate_dnssec};
use crate::config::DomainHealthSettings;
use crate::control::ProbeHandle;
use crate::model::{
    DnsDnssecReport, DnsDnssecStatus, DnsProtocol, DnsResolverSpec, DomainHealthReport,
    HealthCategoryResult, HealthIssue, HealthSeverity, ProbeEvent,
};

pub const MAX_CONCURRENCY: usize = 4;
pub const MAX_DKIM_SELECTORS: usize = 10;

#[derive(Clone)]
struct HealthContext {
    resolver: Arc<TokioResolver>,
    domain: Name,
    domain_str: String,
    timeout: Duration,
    handle: ProbeHandle<ProbeEvent>,
    spec: DnsResolverSpec,
    semaphore: Arc<Semaphore>,
}

/// Run all enabled health checks and emit the report.
pub async fn run_health(handle: &ProbeHandle<ProbeEvent>, settings: &DomainHealthSettings) {
    let result = tokio::select! {
        result = health_inner(handle, settings) => Some(result),
        _ = handle.cancelled() => None,
    };
    match result {
        Some(Ok(report)) => handle.send(ProbeEvent::DnsHealth(Box::new(report))),
        Some(Err(message)) => handle.send(ProbeEvent::Error {
            message,
            hint: None,
        }),
        None => {}
    }
    handle.send(ProbeEvent::Finished);
}

async fn health_inner(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &DomainHealthSettings,
) -> Result<DomainHealthReport, String> {
    let started = Instant::now();
    let domain_str = settings.domain.trim().trim_end_matches('.').to_string();
    if domain_str.is_empty() {
        return Err("the domain is empty".to_string());
    }
    let domain = Name::from_utf8(format!("{domain_str}."))
        .map_err(|error| format!("invalid domain name: {error}"))?;
    let timeout = Duration::from_millis(settings.timeout_ms.clamp(100, 120_000));
    let server = settings.server.trim();
    let protocol = super::query::query_protocol(server, settings.protocol);
    let spec = if server.is_empty() {
        match protocol {
            DnsProtocol::Udp | DnsProtocol::Tcp => {
                let addr = system_server()?;
                DnsResolverSpec::new("system resolver", protocol, addr.ip().to_string())
            }
            _ => return Err("DoT, DoH and DoQ require an explicit health-check server".to_string()),
        }
    } else {
        DnsResolverSpec::new(server, protocol, server)
    };
    let resolver = build_resolver(&spec, timeout, false).await?;
    let concurrency = settings.concurrency.clamp(1, MAX_CONCURRENCY);
    let ctx = HealthContext {
        resolver: Arc::new(resolver),
        domain: domain.clone(),
        domain_str: domain_str.clone(),
        timeout,
        handle: handle.clone(),
        spec,
        semaphore: Arc::new(Semaphore::new(concurrency)),
    };

    let mut tasks = JoinSet::new();
    if settings.check_mx {
        let ctx = ctx.clone();
        tasks.spawn(async move { check_mx(ctx).await });
    }
    if settings.check_spf {
        let ctx = ctx.clone();
        tasks.spawn(async move { check_spf(ctx).await });
    }
    if settings.check_dkim {
        let ctx = ctx.clone();
        let selectors = settings.dkim_selectors.clone();
        tasks.spawn(async move { check_dkim(ctx, &selectors).await });
    }
    if settings.check_dmarc {
        let ctx = ctx.clone();
        tasks.spawn(async move { check_dmarc(ctx).await });
    }
    if settings.check_ptr {
        let ctx = ctx.clone();
        tasks.spawn(async move { check_ptr(ctx).await });
    }
    if settings.check_caa {
        let ctx = ctx.clone();
        tasks.spawn(async move { check_caa_category(ctx).await });
    }
    if settings.check_ns_soa {
        let ctx = ctx.clone();
        tasks.spawn(async move { check_ns_soa(ctx).await });
    }

    let mut categories = Vec::new();
    let mut issues = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok((category, mut category_issues)) = joined {
            categories.push(category);
            issues.append(&mut category_issues);
        }
    }

    let mut dnssec_report = None;
    if settings.check_dnssec {
        let report = validate_dnssec(&ctx.spec, &domain, RecordType::SOA, timeout).await;
        let category = dnssec_category(&report);
        issues.extend(dnssec_issues(&report));
        categories.push(category);
        dnssec_report = Some(report);
    }

    categories.sort_by_key(|category| category_order(&category.category));
    issues.sort_by_key(|issue| std::cmp::Reverse(issue.severity));
    let severity = categories
        .iter()
        .map(|category| category.severity)
        .max()
        .unwrap_or(HealthSeverity::Info);

    Ok(DomainHealthReport {
        domain: domain_str,
        severity,
        categories,
        issues,
        dnssec: dnssec_report,
        generated_at: chrono::Utc::now().to_rfc3339(),
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

fn category_order(category: &str) -> usize {
    [
        "mx", "spf", "dkim", "dmarc", "ptr", "caa", "ns_soa", "dnssec",
    ]
    .iter()
    .position(|value| *value == category)
    .unwrap_or(usize::MAX)
}

fn issue(
    category: &str,
    severity: HealthSeverity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> HealthIssue {
    HealthIssue {
        category: category.to_string(),
        severity,
        title: title.into(),
        detail: detail.into(),
        evidence: Vec::new(),
        advice: None,
    }
}

fn finish(category: &str, issues: Vec<HealthIssue>) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let severity = issues
        .iter()
        .map(|item| item.severity)
        .max()
        .unwrap_or(HealthSeverity::Ok);
    let errors = issues
        .iter()
        .filter(|item| item.severity == HealthSeverity::Error)
        .count();
    let warnings = issues
        .iter()
        .filter(|item| item.severity == HealthSeverity::Warning)
        .count();
    let summary = if issues.is_empty() {
        "ok".to_string()
    } else {
        format!(
            "{errors} error(s), {warnings} warning(s), {} finding(s)",
            issues.len()
        )
    };
    (
        HealthCategoryResult {
            category: category.to_string(),
            severity,
            summary,
        },
        issues,
    )
}

async fn lookup_opt(
    ctx: &HealthContext,
    name: &Name,
    rtype: RecordType,
) -> Result<Option<Lookup>, String> {
    match tokio::time::timeout(ctx.timeout, ctx.resolver.lookup(name.clone(), rtype)).await {
        Ok(Ok(lookup)) => Ok(Some(lookup)),
        Ok(Err(error)) if error.is_no_records_found() => Ok(None),
        Ok(Err(error)) => Err(format!("{rtype} lookup for {name} failed: {error}")),
        Err(_) => Err(format!("{rtype} lookup for {name} timed out")),
    }
}

fn txt_values(lookup: &Lookup) -> Vec<String> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect()
}

async fn lookup_addresses(ctx: &HealthContext, name: &Name) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for rtype in [RecordType::A, RecordType::AAAA] {
        if let Ok(Some(lookup)) = lookup_opt(ctx, name, rtype).await {
            for record in lookup.answers() {
                if let Some(ip) = record.data.ip_addr() {
                    addresses.push(ip);
                }
            }
        }
    }
    addresses
}

async fn check_ptr_for(ctx: &HealthContext, ip: IpAddr, expected: &Name) -> Vec<HealthIssue> {
    let mut issues = Vec::new();
    let lookup = match tokio::time::timeout(ctx.timeout, ctx.resolver.reverse_lookup(ip)).await {
        Ok(Ok(lookup)) => Some(lookup),
        Ok(Err(error)) if error.is_no_records_found() => None,
        Ok(Err(error)) => {
            issues.push(issue(
                "ptr",
                HealthSeverity::Warning,
                format!("PTR lookup failed for {ip}"),
                error.to_string(),
            ));
            None
        }
        Err(_) => {
            issues.push(issue(
                "ptr",
                HealthSeverity::Warning,
                format!("PTR lookup timed out for {ip}"),
                expected.to_string(),
            ));
            None
        }
    };
    let names: Vec<Name> = lookup
        .iter()
        .flat_map(|lookup| lookup.answers())
        .filter_map(|record| match &record.data {
            RData::PTR(name) => Some(name.0.clone()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        issues.push(issue(
            "ptr",
            HealthSeverity::Warning,
            format!("no PTR record for {ip}"),
            format!("{expected} has no reverse record"),
        ));
        return issues;
    }
    let mut finding = issue(
        "ptr",
        HealthSeverity::Info,
        format!("PTR records for {ip}"),
        format!("{expected} resolves from these reverse names"),
    );
    finding.evidence = names.iter().map(Name::to_utf8).collect();
    if names.len() > 1 {
        finding.title = format!("multiple PTR records for {ip}");
    }
    issues.push(finding);
    for name in &names {
        let addresses = lookup_addresses(ctx, name).await;
        if !addresses.contains(&ip) {
            issues.push(issue(
                "ptr",
                HealthSeverity::Warning,
                format!("forward-confirmed reverse DNS mismatch for {ip}"),
                format!("{} resolves to {:?}", name.to_utf8(), addresses),
            ));
        }
    }
    issues
}

async fn check_mx(ctx: HealthContext) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let _permit = ctx.semaphore.acquire().await.ok();
    let mut issues = Vec::new();
    let lookup = match lookup_opt(&ctx, &ctx.domain, RecordType::MX).await {
        Ok(Some(lookup)) => lookup,
        Ok(None) => {
            issues.push(issue(
                "mx",
                HealthSeverity::Warning,
                "no MX records",
                "the domain does not publish MX records",
            ));
            return finish("mx", issues);
        }
        Err(error) => {
            issues.push(issue(
                "mx",
                HealthSeverity::Error,
                "MX lookup failed",
                error,
            ));
            return finish("mx", issues);
        }
    };
    let mut preferences: Vec<u16> = Vec::new();
    let mut mx_records = Vec::new();
    let mut seen = HashSet::new();
    for record in lookup.answers() {
        if let RData::MX(mx) = &record.data {
            let host = mx.exchange.to_utf8();
            let label = format!("{} {}", mx.preference, host);
            if !seen.insert(label.clone()) {
                continue;
            }
            preferences.push(mx.preference);
            mx_records.push(format!("{} {}", mx.preference, host));
            if mx.exchange.is_root() {
                issues.push(issue(
                    "mx",
                    HealthSeverity::Error,
                    "null MX record",
                    "the domain explicitly declares that it does not accept mail",
                ));
                continue;
            }
            let addresses = lookup_addresses(&ctx, &mx.exchange).await;
            if addresses.is_empty() {
                issues.push(issue(
                    "mx",
                    HealthSeverity::Error,
                    format!("MX host has no address: {host}"),
                    "A and AAAA lookups returned no usable address",
                ));
            }
            if let Ok(Some(_)) = lookup_opt(&ctx, &mx.exchange, RecordType::CNAME).await {
                issues.push(issue(
                    "mx",
                    HealthSeverity::Warning,
                    format!("MX host is a CNAME: {host}"),
                    "MX targets should be address records, not aliases",
                ));
            }
            for ip in addresses {
                issues.extend(check_ptr_for(&ctx, ip, &mx.exchange).await);
            }
        }
    }
    preferences.sort_unstable();
    for pair in preferences.windows(2) {
        if pair[0] == pair[1] {
            issues.push(issue(
                "mx",
                HealthSeverity::Info,
                format!("duplicate MX preference {}", pair[0]),
                "multiple MX hosts share the same preference",
            ));
        }
    }
    if !mx_records.is_empty() {
        let mut finding = issue(
            "mx",
            HealthSeverity::Info,
            "MX records",
            format!("{} record(s) published", mx_records.len()),
        );
        finding.evidence = mx_records;
        issues.push(finding);
    }
    finish("mx", issues)
}

async fn check_spf(ctx: HealthContext) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let _permit = ctx.semaphore.acquire().await.ok();
    let mut issues = Vec::new();
    let lookup = match lookup_opt(&ctx, &ctx.domain, RecordType::TXT).await {
        Ok(Some(lookup)) => lookup,
        Ok(None) => {
            issues.push(issue(
                "spf",
                HealthSeverity::Warning,
                "no SPF record",
                "the domain publishes no TXT record at its root",
            ));
            return finish("spf", issues);
        }
        Err(error) => {
            issues.push(issue(
                "spf",
                HealthSeverity::Error,
                "SPF lookup failed",
                error,
            ));
            return finish("spf", issues);
        }
    };
    let records: Vec<String> = txt_values(&lookup)
        .into_iter()
        .filter(|value| value.trim().to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    if records.is_empty() {
        issues.push(issue(
            "spf",
            HealthSeverity::Warning,
            "no SPF record",
            "no v=spf1 TXT record was found",
        ));
        return finish("spf", issues);
    }
    if records.len() > 1 {
        issues.push(issue(
            "spf",
            HealthSeverity::Error,
            "multiple SPF records",
            "RFC 7208 allows exactly one SPF record per domain",
        ));
    }
    let mut record_finding = issue(
        "spf",
        HealthSeverity::Info,
        "SPF record",
        format!("{} SPF record(s) found", records.len()),
    );
    record_finding.evidence = records.clone();
    issues.push(record_finding);

    let mut queue: Vec<(String, String, usize)> = records
        .iter()
        .map(|record| (ctx.domain_str.clone(), record.clone(), 0))
        .collect();
    let mut visited = HashSet::new();
    let mut lookups = 0usize;
    let mut void_lookups = 0usize;
    let mut mechanisms = Vec::new();
    while let Some((zone, record, depth)) = queue.pop() {
        if depth > 10 {
            issues.push(issue(
                "spf",
                HealthSeverity::Error,
                "SPF include depth exceeded",
                format!("include/redirect chain from {zone} is too deep"),
            ));
            continue;
        }
        let parsed = match spf::parse_record(&record) {
            Ok(parsed) => parsed,
            Err(error) => {
                issues.push(issue(
                    "spf",
                    HealthSeverity::Error,
                    format!("invalid SPF record for {zone}"),
                    error,
                ));
                continue;
            }
        };
        for mechanism in parsed {
            mechanisms.push(format!(
                "{} {}{}{}",
                zone,
                mechanism.qualifier,
                mechanism.name,
                mechanism
                    .value
                    .as_ref()
                    .map(|value| format!(":{value}"))
                    .unwrap_or_default()
            ));
            if let Some(term) = mechanism.lookup_term() {
                lookups += 1;
                let target = match &term {
                    spf::LookupTerm::Include(value) | spf::LookupTerm::Redirect(value) => {
                        Some(value.clone())
                    }
                    spf::LookupTerm::Exists(value) => Some(value.clone()),
                    spf::LookupTerm::A | spf::LookupTerm::Mx | spf::LookupTerm::Ptr => None,
                };
                if let Some(target) = target {
                    if visited.insert(target.clone()) {
                        let name = Name::from_utf8(format!("{target}."));
                        if let Ok(name) = name {
                            let child = match lookup_opt(&ctx, &name, RecordType::TXT).await {
                                Ok(Some(lookup)) => txt_values(&lookup).into_iter().find(|value| {
                                    value.trim().to_ascii_lowercase().starts_with("v=spf1")
                                }),
                                _ => None,
                            };
                            if let Some(child) = child {
                                queue.push((target, child, depth + 1));
                            } else {
                                void_lookups += 1;
                                issues.push(issue(
                                    "spf",
                                    HealthSeverity::Warning,
                                    format!("empty SPF include: {target}"),
                                    "the include/redirect target has no SPF record",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    if lookups > 10 {
        issues.push(issue(
            "spf",
            HealthSeverity::Error,
            "SPF DNS lookup limit exceeded",
            format!("{lookups} DNS lookups; RFC 7208 allows at most 10"),
        ));
    }
    if void_lookups > 2 {
        issues.push(issue(
            "spf",
            HealthSeverity::Warning,
            "SPF void lookup limit exceeded",
            format!("{void_lookups} empty lookups; RFC 7208 allows at most 2"),
        ));
    }
    if let Some(qualifier) = spf::all_qualifier(&spf::parse_record(&records[0]).unwrap_or_default())
    {
        match qualifier {
            '+' => issues.push(issue(
                "spf",
                HealthSeverity::Error,
                "+all allows every sender",
                "use -all or ~all instead",
            )),
            '?' => issues.push(issue(
                "spf",
                HealthSeverity::Warning,
                "?all does not reject unauthorized senders",
                "use -all or ~all instead",
            )),
            '~' => issues.push(issue(
                "spf",
                HealthSeverity::Info,
                "~all is softfail",
                "most receivers accept this policy",
            )),
            _ => {}
        }
    } else {
        issues.push(issue(
            "spf",
            HealthSeverity::Warning,
            "SPF has no all mechanism",
            "add -all or ~all at the end of the record",
        ));
    }
    if !mechanisms.is_empty() {
        let mut finding = issue(
            "spf",
            HealthSeverity::Info,
            "SPF expansion",
            format!("{} mechanisms were expanded", mechanisms.len()),
        );
        finding.evidence = mechanisms;
        issues.push(finding);
    }
    finish("spf", issues)
}

async fn check_dkim(ctx: HealthContext, custom: &str) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let _permit = ctx.semaphore.acquire().await.ok();
    let mut issues = Vec::new();
    // Custom selectors take priority over the common defaults so a user can
    // probe a non-standard selector even when the list is capped.
    let mut selectors = spf::parse_selectors(custom);
    for selector in COMMON_SELECTORS {
        let selector = selector.to_string();
        if !selectors.contains(&selector) {
            selectors.push(selector);
        }
    }
    selectors.truncate(MAX_DKIM_SELECTORS);
    let mut found = 0usize;
    for selector in &selectors {
        let name_str = dkim::selector_name(selector, &ctx.domain_str);
        let Ok(name) = Name::from_utf8(format!("{name_str}.")) else {
            continue;
        };
        let Ok(Some(lookup)) = lookup_opt(&ctx, &name, RecordType::TXT).await else {
            continue;
        };
        let record = txt_values(&lookup)
            .into_iter()
            .find(|value| dkim::DkimRecord::is_dkim(value));
        let Some(record) = record else {
            continue;
        };
        found += 1;
        match dkim::parse_record(&record) {
            Ok(parsed) => {
                let mut finding = issue(
                    "dkim",
                    HealthSeverity::Info,
                    format!("DKIM selector found: {selector}"),
                    format!("key type {}", parsed.key_type()),
                );
                finding.evidence.push(record.clone());
                if parsed.revoked() {
                    finding.severity = HealthSeverity::Error;
                    finding.title = format!("DKIM key revoked: {selector}");
                    finding.detail = "the p= tag is empty".to_string();
                } else if !parsed.has_public_key() {
                    finding.severity = HealthSeverity::Error;
                } else if parsed.testing() {
                    finding.severity = HealthSeverity::Warning;
                    finding.title = format!("DKIM selector in testing mode: {selector}");
                }
                if !matches!(parsed.key_type(), "rsa" | "ed25519") {
                    finding.severity = HealthSeverity::Warning;
                    finding.detail = format!("unsupported key type {}", parsed.key_type());
                }
                issues.push(finding);
            }
            Err(error) => {
                issues.push(issue(
                    "dkim",
                    HealthSeverity::Warning,
                    format!("invalid DKIM record: {selector}"),
                    error,
                ));
            }
        }
    }
    if found == 0 {
        issues.push(issue(
            "dkim",
            HealthSeverity::Warning,
            "no DKIM selector found",
            format!(
                "none of the {} common selectors returned a key",
                selectors.len()
            ),
        ));
    }
    finish("dkim", issues)
}

async fn check_dmarc(ctx: HealthContext) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let _permit = ctx.semaphore.acquire().await.ok();
    let mut issues = Vec::new();
    let name = format!("_dmarc.{}", ctx.domain_str);
    let Ok(name) = Name::from_utf8(format!("{name}.")) else {
        issues.push(issue(
            "dmarc",
            HealthSeverity::Error,
            "invalid DMARC name",
            "",
        ));
        return finish("dmarc", issues);
    };
    let lookup = match lookup_opt(&ctx, &name, RecordType::TXT).await {
        Ok(Some(lookup)) => lookup,
        Ok(None) => {
            issues.push(issue(
                "dmarc",
                HealthSeverity::Warning,
                "no DMARC record",
                "_dmarc TXT record is missing",
            ));
            return finish("dmarc", issues);
        }
        Err(error) => {
            issues.push(issue(
                "dmarc",
                HealthSeverity::Error,
                "DMARC lookup failed",
                error,
            ));
            return finish("dmarc", issues);
        }
    };
    let Some(record) = txt_values(&lookup)
        .into_iter()
        .find(|value| dmarc::is_dmarc_record(value))
    else {
        issues.push(issue(
            "dmarc",
            HealthSeverity::Warning,
            "no DMARC record",
            "TXT records exist but none start with v=DMARC1",
        ));
        return finish("dmarc", issues);
    };
    match dmarc::parse_record(&record) {
        Ok(parsed) => {
            let mut finding = issue(
                "dmarc",
                HealthSeverity::Info,
                format!("DMARC policy: {}", parsed.policy().unwrap_or("missing")),
                "DMARC policy record",
            );
            finding.evidence.push(record.clone());
            match parsed.policy() {
                Some("none") => {
                    finding.severity = HealthSeverity::Warning;
                    finding.title = "DMARC policy is none".to_string();
                    finding.detail = "p=none only monitors; use quarantine or reject".to_string();
                }
                Some("quarantine") | Some("reject") => {}
                Some(other) => {
                    finding.severity = HealthSeverity::Warning;
                    finding.detail = format!("unknown policy {other}");
                }
                None => {
                    finding.severity = HealthSeverity::Error;
                    finding.title = "DMARC policy is missing".to_string();
                }
            }
            issues.push(finding);
            if let Some(pct) = parsed.percent() {
                if pct < 100 {
                    issues.push(issue(
                        "dmarc",
                        HealthSeverity::Warning,
                        format!("DMARC applies to {pct}% of mail"),
                        "pct is below 100",
                    ));
                }
            }
            if !parsed.has_report_uri() {
                issues.push(issue(
                    "dmarc",
                    HealthSeverity::Warning,
                    "DMARC has no aggregate report address",
                    "add rua=mailto:... to receive reports",
                ));
            }
            if parsed.subdomain_policy().is_none() {
                issues.push(issue(
                    "dmarc",
                    HealthSeverity::Info,
                    "DMARC has no subdomain policy",
                    "sp defaults to the main policy",
                ));
            }
        }
        Err(error) => issues.push(issue(
            "dmarc",
            HealthSeverity::Error,
            "invalid DMARC record",
            error,
        )),
    }
    finish("dmarc", issues)
}

async fn check_ptr(ctx: HealthContext) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let _permit = ctx.semaphore.acquire().await.ok();
    let mut issues = Vec::new();
    let addresses = lookup_addresses(&ctx, &ctx.domain).await;
    if addresses.is_empty() {
        issues.push(issue(
            "ptr",
            HealthSeverity::Info,
            "no address records for PTR check",
            "the domain has no A or AAAA records",
        ));
        return finish("ptr", issues);
    }
    for ip in addresses {
        issues.extend(check_ptr_for(&ctx, ip, &ctx.domain).await);
    }
    finish("ptr", issues)
}

async fn check_caa_category(ctx: HealthContext) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let _permit = ctx.semaphore.acquire().await.ok();
    let mut issues = Vec::new();
    let check =
        check_caa_with_resolver(&ctx.handle, &ctx.domain_str, ctx.timeout, &ctx.resolver).await;
    if let Some(error) = &check.error {
        issues.push(issue(
            "caa",
            HealthSeverity::Warning,
            "CAA lookup failed",
            error,
        ));
        return finish("caa", issues);
    }
    if check.records.is_empty() {
        issues.push(issue(
            "caa",
            HealthSeverity::Info,
            "no CAA records",
            "CAA is optional, but it limits which CAs may issue certificates",
        ));
        return finish("caa", issues);
    }
    let has_issue = check.records.iter().any(|record| record.tag == "issue");
    let has_wild = check.records.iter().any(|record| record.tag == "issuewild");
    let has_iodef = check.records.iter().any(|record| record.tag == "iodef");
    if has_issue && has_wild {
        issues.push(issue(
            "caa",
            HealthSeverity::Info,
            "CAA defines issue and issuewild",
            "both certificate types have explicit policies",
        ));
    }
    if !has_iodef {
        issues.push(issue(
            "caa",
            HealthSeverity::Info,
            "CAA has no iodef",
            "add iodef=mailto:... to receive violation reports",
        ));
    }
    for record in &check.records {
        let mut finding = issue(
            "caa",
            HealthSeverity::Info,
            format!("CAA {} record", record.tag),
            record.value.clone(),
        );
        finding.evidence.push(format!(
            "flags={} critical={}",
            record.flags, record.critical
        ));
        issues.push(finding);
    }
    finish("caa", issues)
}

async fn check_ns_soa(ctx: HealthContext) -> (HealthCategoryResult, Vec<HealthIssue>) {
    let _permit = ctx.semaphore.acquire().await.ok();
    let mut issues = Vec::new();
    match lookup_opt(&ctx, &ctx.domain, RecordType::NS).await {
        Ok(Some(lookup)) => {
            let names: Vec<Name> = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::NS(name) => Some(name.0.clone()),
                    _ => None,
                })
                .collect();
            if names.len() < 2 {
                issues.push(issue(
                    "ns_soa",
                    HealthSeverity::Warning,
                    "fewer than two NS records",
                    "redundancy is recommended for authoritative service",
                ));
            }
            if !names.is_empty() {
                let mut finding = issue(
                    "ns_soa",
                    HealthSeverity::Info,
                    "NS records",
                    format!("{} name server(s) published", names.len()),
                );
                finding.evidence = names.iter().map(Name::to_utf8).collect();
                issues.push(finding);
            }
            for name in names {
                if lookup_addresses(&ctx, &name).await.is_empty() {
                    issues.push(issue(
                        "ns_soa",
                        HealthSeverity::Error,
                        format!("NS host has no address: {}", name.to_utf8()),
                        "A and AAAA lookups returned no usable address",
                    ));
                }
            }
        }
        Ok(None) => issues.push(issue(
            "ns_soa",
            HealthSeverity::Error,
            "no NS records",
            "the domain has no authoritative name servers",
        )),
        Err(error) => issues.push(issue(
            "ns_soa",
            HealthSeverity::Error,
            "NS lookup failed",
            error,
        )),
    }
    match lookup_opt(&ctx, &ctx.domain, RecordType::SOA).await {
        Ok(Some(lookup)) => {
            if let Some(soa) = lookup
                .answers()
                .iter()
                .find_map(|record| match &record.data {
                    RData::SOA(soa) => Some(soa),
                    _ => None,
                })
            {
                if soa.retry >= soa.refresh {
                    issues.push(issue(
                        "ns_soa",
                        HealthSeverity::Warning,
                        "SOA retry is not shorter than refresh",
                        format!("refresh={} retry={}", soa.refresh, soa.retry),
                    ));
                }
                if soa.expire <= soa.refresh {
                    issues.push(issue(
                        "ns_soa",
                        HealthSeverity::Warning,
                        "SOA expire is not longer than refresh",
                        format!("refresh={} expire={}", soa.refresh, soa.expire),
                    ));
                }
                if soa.refresh <= 0 || soa.retry < 0 {
                    issues.push(issue(
                        "ns_soa",
                        HealthSeverity::Warning,
                        "SOA timers are invalid",
                        format!("refresh={} retry={}", soa.refresh, soa.retry),
                    ));
                }
                let mut finding = issue(
                    "ns_soa",
                    HealthSeverity::Info,
                    "SOA record",
                    format!(
                        "mname={} serial={} refresh={} retry={} expire={} minimum={}",
                        soa.mname.to_utf8(),
                        soa.serial,
                        soa.refresh,
                        soa.retry,
                        soa.expire,
                        soa.minimum
                    ),
                );
                finding.evidence.push(soa.rname.to_utf8());
                issues.push(finding);
            }
        }
        Ok(None) => issues.push(issue(
            "ns_soa",
            HealthSeverity::Warning,
            "no SOA record",
            "the domain has no SOA record",
        )),
        Err(error) => issues.push(issue(
            "ns_soa",
            HealthSeverity::Warning,
            "SOA lookup failed",
            error,
        )),
    }
    finish("ns_soa", issues)
}

fn dnssec_category(report: &DnsDnssecReport) -> HealthCategoryResult {
    let severity = match report.status {
        DnsDnssecStatus::Bogus => HealthSeverity::Error,
        DnsDnssecStatus::Secure => HealthSeverity::Ok,
        _ => HealthSeverity::Info,
    };
    HealthCategoryResult {
        category: "dnssec".to_string(),
        severity,
        summary: report.status.label().to_string(),
    }
}

fn dnssec_issues(report: &DnsDnssecReport) -> Vec<HealthIssue> {
    match report.status {
        DnsDnssecStatus::Secure => vec![issue(
            "dnssec",
            HealthSeverity::Info,
            "DNSSEC validation succeeded",
            "the answer is protected by a trusted chain",
        )],
        DnsDnssecStatus::Insecure => vec![issue(
            "dnssec",
            HealthSeverity::Info,
            "zone is not signed",
            "DNSSEC is not enabled for this zone",
        )],
        DnsDnssecStatus::Bogus => vec![issue(
            "dnssec",
            HealthSeverity::Error,
            "DNSSEC validation failed",
            report
                .error
                .clone()
                .unwrap_or_else(|| "bogus answer".to_string()),
        )],
        DnsDnssecStatus::Indeterminate => vec![issue(
            "dnssec",
            HealthSeverity::Info,
            "DNSSEC state is indeterminate",
            report
                .error
                .clone()
                .unwrap_or_else(|| "missing DNSSEC data".to_string()),
        )],
        DnsDnssecStatus::Unsupported => vec![issue(
            "dnssec",
            HealthSeverity::Info,
            "DNSSEC validation is unavailable",
            report.error.clone().unwrap_or_default(),
        )],
        DnsDnssecStatus::Disabled => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering_puts_errors_first() {
        assert!(HealthSeverity::Error > HealthSeverity::Warning);
        assert!(HealthSeverity::Warning > HealthSeverity::Ok);
    }

    #[test]
    fn category_order_is_stable() {
        assert!(category_order("mx") < category_order("spf"));
        assert!(category_order("dnssec") > category_order("ns_soa"));
        assert_eq!(category_order("unknown"), usize::MAX);
    }
}
