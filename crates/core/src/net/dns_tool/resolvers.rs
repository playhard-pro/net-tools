//! Built-in resolver presets and parsing of user supplied resolver endpoints.

use crate::model::{DnsProtocol, DnsResolverSpec};

/// One built-in resolver entry for a specific transport.
pub struct DnsPreset {
    pub id: &'static str,
    pub label: &'static str,
    pub protocol: DnsProtocol,
    pub endpoint: &'static str,
}

const UDP_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        id: "cloudflare",
        label: "Cloudflare 1.1.1.1",
        protocol: DnsProtocol::Udp,
        endpoint: "1.1.1.1",
    },
    DnsPreset {
        id: "google",
        label: "Google 8.8.8.8",
        protocol: DnsProtocol::Udp,
        endpoint: "8.8.8.8",
    },
    DnsPreset {
        id: "quad9",
        label: "Quad9 9.9.9.9",
        protocol: DnsProtocol::Udp,
        endpoint: "9.9.9.9",
    },
    DnsPreset {
        id: "opendns",
        label: "OpenDNS 208.67.222.222",
        protocol: DnsProtocol::Udp,
        endpoint: "208.67.222.222",
    },
    DnsPreset {
        id: "adguard",
        label: "AdGuard 94.140.14.14",
        protocol: DnsProtocol::Udp,
        endpoint: "94.140.14.14",
    },
];

const TCP_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        id: "cloudflare",
        label: "Cloudflare 1.1.1.1",
        protocol: DnsProtocol::Tcp,
        endpoint: "1.1.1.1",
    },
    DnsPreset {
        id: "google",
        label: "Google 8.8.8.8",
        protocol: DnsProtocol::Tcp,
        endpoint: "8.8.8.8",
    },
    DnsPreset {
        id: "quad9",
        label: "Quad9 9.9.9.9",
        protocol: DnsProtocol::Tcp,
        endpoint: "9.9.9.9",
    },
    DnsPreset {
        id: "opendns",
        label: "OpenDNS 208.67.222.222",
        protocol: DnsProtocol::Tcp,
        endpoint: "208.67.222.222",
    },
    DnsPreset {
        id: "adguard",
        label: "AdGuard 94.140.14.14",
        protocol: DnsProtocol::Tcp,
        endpoint: "94.140.14.14",
    },
];

const DOT_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        id: "cloudflare",
        label: "Cloudflare one.one.one.one",
        protocol: DnsProtocol::Dot,
        endpoint: "tls://one.one.one.one",
    },
    DnsPreset {
        id: "google",
        label: "Google dns.google",
        protocol: DnsProtocol::Dot,
        endpoint: "tls://dns.google",
    },
    DnsPreset {
        id: "quad9",
        label: "Quad9 dns.quad9.net",
        protocol: DnsProtocol::Dot,
        endpoint: "tls://dns.quad9.net",
    },
    DnsPreset {
        id: "adguard",
        label: "AdGuard dns.adguard-dns.com",
        protocol: DnsProtocol::Dot,
        endpoint: "tls://dns.adguard-dns.com",
    },
];

const QUIC_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        id: "quad9",
        label: "Quad9 dns.quad9.net",
        protocol: DnsProtocol::Quic,
        endpoint: "quic://dns.quad9.net",
    },
    DnsPreset {
        id: "adguard",
        label: "AdGuard dns.adguard-dns.com",
        protocol: DnsProtocol::Quic,
        endpoint: "quic://dns.adguard-dns.com",
    },
];

const DOH_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        id: "cloudflare",
        label: "Cloudflare dns-query",
        protocol: DnsProtocol::Doh,
        endpoint: "https://cloudflare-dns.com/dns-query",
    },
    DnsPreset {
        id: "google",
        label: "Google dns-query",
        protocol: DnsProtocol::Doh,
        endpoint: "https://dns.google/dns-query",
    },
    DnsPreset {
        id: "quad9",
        label: "Quad9 dns-query",
        protocol: DnsProtocol::Doh,
        endpoint: "https://dns.quad9.net/dns-query",
    },
    DnsPreset {
        id: "opendns",
        label: "OpenDNS dns-query",
        protocol: DnsProtocol::Doh,
        endpoint: "https://doh.opendns.com/dns-query",
    },
    DnsPreset {
        id: "adguard",
        label: "AdGuard dns-query",
        protocol: DnsProtocol::Doh,
        endpoint: "https://dns.adguard-dns.com/dns-query",
    },
];

/// Built-in presets available for one transport.
pub fn presets_for(protocol: DnsProtocol) -> &'static [DnsPreset] {
    match protocol {
        DnsProtocol::Udp => UDP_PRESETS,
        DnsProtocol::Tcp => TCP_PRESETS,
        DnsProtocol::Dot => DOT_PRESETS,
        DnsProtocol::Doh => DOH_PRESETS,
        DnsProtocol::Quic => QUIC_PRESETS,
    }
}

/// Look up one preset by id for the selected transport.
pub fn preset(protocol: DnsProtocol, id: &str) -> Option<&'static DnsPreset> {
    presets_for(protocol).iter().find(|preset| preset.id == id)
}

/// Build the final resolver list from selected presets and custom lines.
///
/// Custom lines use `label=endpoint`; when no label is given the endpoint is
/// used as the label. The scheme in the endpoint overrides the selected
/// protocol, so a list can mix transports intentionally.
pub fn resolve_specs(
    protocol: DnsProtocol,
    selected: &[String],
    custom: &str,
) -> Result<Vec<DnsResolverSpec>, String> {
    let mut specs = Vec::new();
    for id in selected {
        let Some(preset) = preset(protocol, id) else {
            return Err(format!("unknown resolver preset: {id}"));
        };
        specs.push(DnsResolverSpec::new(
            preset.label,
            preset.protocol,
            preset.endpoint,
        ));
    }
    for line in custom.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        specs.push(parse_resolver_line(line, protocol)?);
    }
    deduplicate(&mut specs);
    if specs.is_empty() {
        return Err("no resolver selected".to_string());
    }
    Ok(specs)
}

/// Parse one custom resolver line.
pub fn parse_resolver_line(
    line: &str,
    default_protocol: DnsProtocol,
) -> Result<DnsResolverSpec, String> {
    let (label, endpoint) = match line.split_once('=') {
        Some((label, endpoint))
            if !label.trim().is_empty()
                && !endpoint.trim().is_empty()
                && !label.contains("://")
                && !label.contains('/') =>
        {
            (label.trim().to_string(), endpoint.trim().to_string())
        }
        _ => (line.trim().to_string(), line.trim().to_string()),
    };
    let (protocol, endpoint) = detect_protocol(&endpoint, default_protocol)?;
    Ok(DnsResolverSpec::new(
        label,
        protocol,
        normalize(protocol, endpoint),
    ))
}

fn detect_protocol(
    endpoint: &str,
    default_protocol: DnsProtocol,
) -> Result<(DnsProtocol, String), String> {
    let lower = endpoint.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok((DnsProtocol::Doh, endpoint.to_string()));
    }
    if lower.starts_with("doh://") {
        return Ok((DnsProtocol::Doh, endpoint.to_string()));
    }
    if lower.starts_with("quic://") || lower.starts_with("doq://") {
        return Ok((DnsProtocol::Quic, endpoint.to_string()));
    }
    if lower.starts_with("tls://") || lower.starts_with("dot://") {
        return Ok((DnsProtocol::Dot, endpoint.to_string()));
    }
    if lower.starts_with("tcp://") {
        return Ok((
            DnsProtocol::Tcp,
            endpoint.trim_start_matches("tcp://").to_string(),
        ));
    }
    if lower.starts_with("udp://") {
        return Ok((
            DnsProtocol::Udp,
            endpoint.trim_start_matches("udp://").to_string(),
        ));
    }
    Ok((default_protocol, endpoint.to_string()))
}

fn normalize(protocol: DnsProtocol, endpoint: String) -> String {
    match protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => endpoint,
        DnsProtocol::Dot => {
            if endpoint.starts_with("tls://") {
                endpoint
            } else {
                format!("tls://{}", endpoint.trim_start_matches("dot://"))
            }
        }
        DnsProtocol::Doh => {
            if endpoint.starts_with("https://") {
                endpoint
            } else if let Some(rest) = endpoint.strip_prefix("doh://") {
                format!("https://{rest}")
            } else {
                format!("https://{endpoint}")
            }
        }
        DnsProtocol::Quic => {
            if endpoint.starts_with("quic://") {
                endpoint
            } else {
                format!("quic://{}", endpoint.trim_start_matches("doq://"))
            }
        }
    }
}

/// Remove duplicate endpoints while keeping the user's order.
fn deduplicate(specs: &mut Vec<DnsResolverSpec>) {
    let mut seen = std::collections::HashSet::new();
    specs.retain(|spec| seen.insert((spec.protocol.id(), spec.endpoint.clone())));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_available_for_each_protocol() {
        for protocol in [
            DnsProtocol::Udp,
            DnsProtocol::Tcp,
            DnsProtocol::Dot,
            DnsProtocol::Doh,
            DnsProtocol::Quic,
        ] {
            assert!(!presets_for(protocol).is_empty());
        }
    }

    #[test]
    fn custom_lines_parse_labels_and_schemes() {
        let spec = parse_resolver_line("local=1.1.1.1", DnsProtocol::Udp).unwrap();
        assert_eq!(spec.label, "local");
        assert_eq!(spec.protocol, DnsProtocol::Udp);
        assert_eq!(spec.endpoint, "1.1.1.1");

        let spec = parse_resolver_line("cf=tls://dns.example:853", DnsProtocol::Udp).unwrap();
        assert_eq!(spec.protocol, DnsProtocol::Dot);
        assert_eq!(spec.endpoint, "tls://dns.example:853");

        let spec = parse_resolver_line("https://dns.example/q", DnsProtocol::Udp).unwrap();
        assert_eq!(spec.protocol, DnsProtocol::Doh);

        let spec = parse_resolver_line("q=quic://dns.example", DnsProtocol::Udp).unwrap();
        assert_eq!(spec.protocol, DnsProtocol::Quic);
    }

    #[test]
    fn selected_presets_and_custom_lines_are_deduplicated() {
        let specs = resolve_specs(
            DnsProtocol::Udp,
            &["cloudflare".into(), "google".into()],
            "custom=1.1.1.1",
        )
        .unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].label, "Cloudflare 1.1.1.1");
        assert_eq!(specs[1].label, "Google 8.8.8.8");
    }

    #[test]
    fn unknown_preset_is_rejected() {
        assert!(resolve_specs(DnsProtocol::Udp, &["missing".into()], "").is_err());
    }
}
