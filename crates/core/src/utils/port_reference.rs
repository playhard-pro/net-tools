//! IANA port and IP protocol reference data.
//!
//! The port table is generated from the official IANA registry by
//! `scripts/update_iana_services.py`. It is embedded in the binary so the tool
//! works offline and never performs a request while the user types.

use std::sync::OnceLock;

use crate::model::PortTransportFilter;

/// One IANA service registry entry.
///
/// A registry row can describe a single port or an inclusive range. The raw
/// text is kept for display, while the numeric bounds make range searches
/// possible.
#[derive(Debug, Clone)]
pub struct IanaService {
    pub port_start: u16,
    pub port_end: u16,
    pub port_text: String,
    pub service: String,
    pub transport: String,
    pub description: String,
}

/// One IP protocol number entry.
#[derive(Debug, Clone, Copy)]
pub struct IpProtocol {
    pub number: u8,
    pub keyword: &'static str,
    pub protocol: &'static str,
    pub description: &'static str,
}

/// Embedded registry generated from the IANA CSV.
const IANA_TSV: &str = include_str!("iana_services.tsv");

static SERVICES: OnceLock<Vec<IanaService>> = OnceLock::new();

/// All embedded IANA rows, parsed once on first use.
pub fn iana_services() -> &'static [IanaService] {
    SERVICES.get_or_init(parse_iana_tsv).as_slice()
}

fn parse_iana_tsv() -> Vec<IanaService> {
    let mut rows = Vec::new();
    for line in IANA_TSV.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The first non-comment line is the column header.
        if line.starts_with("service\t") {
            continue;
        }
        let mut fields = line.splitn(4, '\t');
        let service = fields.next().unwrap_or_default().to_string();
        let port_text = fields.next().unwrap_or_default().to_string();
        let transport = fields.next().unwrap_or_default().to_string();
        let description = fields.next().unwrap_or_default().to_string();
        let Some((port_start, port_end)) = parse_port_range(&port_text) else {
            continue;
        };
        rows.push(IanaService {
            port_start,
            port_end,
            port_text,
            service,
            transport,
            description,
        });
    }
    rows
}

/// Parse a single port or an inclusive `start-end` range.
pub fn parse_port_range(value: &str) -> Option<(u16, u16)> {
    let value = value.trim();
    if let Some((start, end)) = value.split_once('-') {
        let start: u16 = start.trim().parse().ok()?;
        let end: u16 = end.trim().parse().ok()?;
        if start <= end {
            Some((start, end))
        } else {
            None
        }
    } else {
        let port: u16 = value.parse().ok()?;
        Some((port, port))
    }
}

/// Query interpreted as either a numeric port range or free text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortQuery {
    Range { start: u16, end: u16 },
    Text(String),
}

/// Classify a search string. A query such as `230` or `225-241` searches the
/// numeric port ranges; everything else searches the text fields.
pub fn parse_query(query: &str) -> PortQuery {
    let query = query.trim();
    if let Some((start, end)) = parse_port_range(query) {
        PortQuery::Range { start, end }
    } else {
        PortQuery::Text(query.to_ascii_lowercase())
    }
}

/// Indices of the rows matching a query and transport filter.
pub fn search_services(query: &str, filter: PortTransportFilter) -> Vec<usize> {
    let query = parse_query(query);
    let mut matches = Vec::new();
    for (index, row) in iana_services().iter().enumerate() {
        if !filter.accepts(&row.transport) {
            continue;
        }
        let matched = match &query {
            PortQuery::Range { start, end } => row.port_start <= *end && row.port_end >= *start,
            PortQuery::Text(text) => {
                text.is_empty()
                    || row.service.to_ascii_lowercase().contains(text)
                    || row.description.to_ascii_lowercase().contains(text)
                    || row.port_text.contains(text)
            }
        };
        if matched {
            matches.push(index);
        }
    }
    matches
}

/// Common IP protocol numbers from the IANA protocol-number registry.
pub const IP_PROTOCOLS: &[IpProtocol] = &[
    IpProtocol {
        number: 0,
        keyword: "HOPOPT",
        protocol: "IPv6 Hop-by-Hop Option",
        description: "IPv6 hop-by-hop options header",
    },
    IpProtocol {
        number: 1,
        keyword: "ICMP",
        protocol: "Internet Control Message",
        description: "Ping and error reporting for IPv4",
    },
    IpProtocol {
        number: 2,
        keyword: "IGMP",
        protocol: "Internet Group Management",
        description: "IPv4 multicast group membership",
    },
    IpProtocol {
        number: 4,
        keyword: "IP-in-IP",
        protocol: "IP in IP",
        description: "IP encapsulation",
    },
    IpProtocol {
        number: 6,
        keyword: "TCP",
        protocol: "Transmission Control",
        description: "Reliable stream transport",
    },
    IpProtocol {
        number: 17,
        keyword: "UDP",
        protocol: "User Datagram",
        description: "Connectionless datagram transport",
    },
    IpProtocol {
        number: 41,
        keyword: "IPv6",
        protocol: "IPv6 encapsulation",
        description: "IPv6 header carried in IPv4",
    },
    IpProtocol {
        number: 43,
        keyword: "IPv6-Route",
        protocol: "Routing Header for IPv6",
        description: "IPv6 source routing header",
    },
    IpProtocol {
        number: 44,
        keyword: "IPv6-Frag",
        protocol: "Fragment Header for IPv6",
        description: "IPv6 fragmentation header",
    },
    IpProtocol {
        number: 47,
        keyword: "GRE",
        protocol: "Generic Routing Encapsulation",
        description: "Tunneling protocol used by VPNs",
    },
    IpProtocol {
        number: 50,
        keyword: "ESP",
        protocol: "Encap Security Payload",
        description: "IPsec encrypted payload",
    },
    IpProtocol {
        number: 51,
        keyword: "AH",
        protocol: "Authentication Header",
        description: "IPsec authentication header",
    },
    IpProtocol {
        number: 58,
        keyword: "IPv6-ICMP",
        protocol: "ICMP for IPv6",
        description: "Ping and error reporting for IPv6",
    },
    IpProtocol {
        number: 59,
        keyword: "IPv6-NoNxt",
        protocol: "No Next Header for IPv6",
        description: "Marks the end of an IPv6 header chain",
    },
    IpProtocol {
        number: 60,
        keyword: "IPv6-Opts",
        protocol: "Destination Options for IPv6",
        description: "IPv6 destination options header",
    },
    IpProtocol {
        number: 89,
        keyword: "OSPF",
        protocol: "Open Shortest Path First",
        description: "Link-state interior gateway protocol",
    },
    IpProtocol {
        number: 103,
        keyword: "PIM",
        protocol: "Protocol Independent Multicast",
        description: "Multicast routing protocol",
    },
    IpProtocol {
        number: 112,
        keyword: "VRRP",
        protocol: "Virtual Router Redundancy",
        description: "Default gateway redundancy",
    },
    IpProtocol {
        number: 132,
        keyword: "SCTP",
        protocol: "Stream Control Transmission",
        description: "Message-oriented transport protocol",
    },
    IpProtocol {
        number: 136,
        keyword: "UDPLite",
        protocol: "UDP-Lite",
        description: "UDP variant with partial checksums",
    },
];

/// Indices of IP protocols matching a free-text query.
pub fn search_ip_protocols(query: &str) -> Vec<usize> {
    let query = query.trim().to_ascii_lowercase();
    IP_PROTOCOLS
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            query.is_empty()
                || row.number.to_string().contains(&query)
                || row.keyword.to_ascii_lowercase().contains(&query)
                || row.protocol.to_ascii_lowercase().contains(&query)
                || row.description.to_ascii_lowercase().contains(&query)
        })
        .map(|(index, _)| index)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registry_is_complete_enough() {
        assert!(iana_services().len() > 13_000);
        assert!(iana_services()
            .iter()
            .any(|row| row.port_start <= 80 && row.port_end >= 80));
    }

    #[test]
    fn range_query_matches_contained_ports() {
        let matches = search_services("230", PortTransportFilter::All);
        assert!(matches.iter().any(|index| {
            let row = &iana_services()[*index];
            row.port_start <= 230 && row.port_end >= 230
        }));
    }

    #[test]
    fn range_query_matches_overlapping_ranges() {
        let matches = search_services("225-241", PortTransportFilter::All);
        assert!(matches.iter().any(|index| {
            let row = &iana_services()[*index];
            row.port_start <= 241 && row.port_end >= 225
        }));
    }

    #[test]
    fn text_query_matches_service_and_description() {
        let matches = search_services("http", PortTransportFilter::Tcp);
        assert!(matches.iter().any(|index| {
            let row = &iana_services()[*index];
            row.transport.eq_ignore_ascii_case("tcp")
                && (row.service.to_ascii_lowercase().contains("http")
                    || row.description.to_ascii_lowercase().contains("http"))
        }));
    }

    #[test]
    fn range_rows_follow_the_transport_filter() {
        let all = search_services("225-241", PortTransportFilter::All);
        let tcp = search_services("225-241", PortTransportFilter::Tcp);
        assert!(all
            .iter()
            .any(|index| iana_services()[*index].transport.is_empty()));
        assert!(tcp.iter().all(|index| iana_services()[*index]
            .transport
            .eq_ignore_ascii_case("tcp")));
    }

    #[test]
    fn protocol_search_finds_icmp_and_tcp() {
        assert!(search_ip_protocols("icmp")
            .iter()
            .any(|index| IP_PROTOCOLS[*index].number == 1));
        assert!(search_ip_protocols("6")
            .iter()
            .any(|index| IP_PROTOCOLS[*index].keyword == "TCP"));
    }
}
