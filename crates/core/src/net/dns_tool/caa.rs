//! Effective CAA policy lookup shared by the TLS and DNS health tools.

use std::time::Duration;

use hickory_resolver::proto::rr::domain::Name;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use crate::control::ProbeHandle;
use crate::model::{CaaCheck, CaaRecordInfo, ProbeEvent};

/// Look up the effective CAA policy for a domain, walking up parent labels.
pub(crate) async fn check_caa(
    handle: &ProbeHandle<ProbeEvent>,
    host: &str,
    timeout: Duration,
) -> CaaCheck {
    let resolver = match TokioResolver::builder_tokio().and_then(|builder| builder.build()) {
        Ok(value) => value,
        Err(error) => {
            return CaaCheck {
                error: Some(format!("resolver build failed: {error}")),
                ..Default::default()
            }
        }
    };
    check_caa_with_resolver(handle, host, timeout, &resolver).await
}

/// Look up CAA through an already configured resolver.
pub(crate) async fn check_caa_with_resolver(
    handle: &ProbeHandle<ProbeEvent>,
    host: &str,
    timeout: Duration,
    resolver: &TokioResolver,
) -> CaaCheck {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return CaaCheck {
            error: Some("CAA applies to domain names only".into()),
            ..Default::default()
        };
    }

    let mut name = match Name::from_utf8(format!("{host}.")) {
        Ok(value) => value,
        Err(error) => {
            return CaaCheck {
                error: Some(format!("invalid DNS name: {error}")),
                ..Default::default()
            }
        }
    };

    loop {
        let source = name.to_string();
        let lookup = tokio::select! {
            _ = handle.cancelled() => {
                return CaaCheck {
                    error: Some("cancelled".into()),
                    ..Default::default()
                }
            }
            result = tokio::time::timeout(
                timeout,
                resolver.lookup(name.clone(), RecordType::CAA),
            ) => match result {
                Ok(Ok(value)) => Some(value),
                // A missing RRset is expected while walking to the parent.
                Ok(Err(error)) if error.is_no_records_found() => None,
                Ok(Err(error)) => {
                    return CaaCheck {
                        error: Some(format!("CAA lookup failed for {source}: {error}")),
                        ..Default::default()
                    }
                }
                Err(_) => {
                    return CaaCheck {
                        error: Some(format!("CAA lookup timed out for {source}")),
                        ..Default::default()
                    }
                }
            }
        };
        if let Some(lookup) = lookup {
            let mut records = Vec::new();
            for record in lookup.answers() {
                if let RData::CAA(caa) = &record.data {
                    records.push(CaaRecordInfo {
                        flags: caa.reserved_flags | if caa.issuer_critical { 0x80 } else { 0 },
                        tag: caa.tag.clone(),
                        value: String::from_utf8_lossy(&caa.value).into_owned(),
                        critical: caa.issuer_critical,
                    });
                }
            }
            if !records.is_empty() {
                return CaaCheck {
                    source: Some(source.trim_end_matches('.').to_string()),
                    records,
                    error: None,
                };
            }
        }
        if name.is_root() {
            break;
        }
        name = name.base_name();
    }
    CaaCheck::default()
}
