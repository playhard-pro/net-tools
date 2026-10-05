//! DNS forward resolution and PTR reverse lookups.

use std::net::IpAddr;

use anyhow::Result;
use hickory_resolver::TokioResolver;

use crate::model::IpVersion;

/// Resolve a host name into addresses filtered by IP version. If the input is
/// already an IP address it is returned as-is, but only when it matches the
/// requested version; otherwise the result is empty and the caller reports that
/// no usable address was found.
pub async fn resolve(host: &str, version: IpVersion) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let matches_version = match version {
            IpVersion::V4 => ip.is_ipv4(),
            IpVersion::V6 => ip.is_ipv6(),
            IpVersion::Auto => true,
        };
        return Ok(if matches_version {
            vec![ip]
        } else {
            Vec::new()
        });
    }

    let resolver = TokioResolver::builder_tokio()?.build()?;
    let mut addrs: Vec<IpAddr> = match version {
        IpVersion::V4 => resolver
            .ipv4_lookup(host)
            .await?
            .answers()
            .iter()
            .filter_map(|r| r.data.ip_addr())
            .collect(),
        IpVersion::V6 => resolver
            .ipv6_lookup(host)
            .await?
            .answers()
            .iter()
            .filter_map(|r| r.data.ip_addr())
            .collect(),
        IpVersion::Auto => resolver.lookup_ip(host).await?.iter().collect(),
    };

    // For a dual-stack name the resolver hands back the IPv6 answers first. Put
    // IPv4 in front instead: it is the family that works without extra
    // privileges and that a host without IPv6 connectivity can actually use.
    // The sort is stable, so the resolver order inside one family is kept.
    addrs.sort_by_key(|addr| addr.is_ipv6());
    addrs.dedup();
    Ok(addrs)
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
