//! DNS forward resolution and PTR reverse lookups.

use std::net::IpAddr;

use anyhow::Result;
use hickory_resolver::TokioResolver;

use crate::model::IpVersion;

/// Resolve a host name into addresses filtered by IP version. If the input is
/// already an IP address it is returned as-is.
pub async fn resolve(host: &str, version: IpVersion) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(match version {
            IpVersion::V4 if ip.is_ipv4() => vec![ip],
            IpVersion::V6 if ip.is_ipv6() => vec![ip],
            IpVersion::Auto => vec![ip],
            _ => vec![ip], // Version mismatch: still return it; the caller decides.
        });
    }

    let resolver = TokioResolver::builder_tokio()?.build()?;
    match version {
        IpVersion::V4 => {
            let lookup = resolver.ipv4_lookup(host).await?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| r.data.ip_addr())
                .collect())
        }
        IpVersion::V6 => {
            let lookup = resolver.ipv6_lookup(host).await?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| r.data.ip_addr())
                .collect())
        }
        IpVersion::Auto => Ok(resolver.lookup_ip(host).await?.iter().collect()),
    }
}

/// PTR reverse lookup. Returns `None` on failure.
pub async fn reverse(ip: IpAddr) -> Option<String> {
    let resolver = TokioResolver::builder_tokio().ok()?.build().ok()?;
    let lookup = resolver.reverse_lookup(ip).await.ok()?;
    lookup.answers().iter().find_map(|r| match r.data {
        hickory_resolver::proto::rr::RData::PTR(ref ptr) => Some(ptr.0.to_utf8()),
        _ => None,
    })
}
