//! Parsing and normalization of DNS inputs.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hickory_proto::rr::{Name, RecordType};

/// Record types offered as quick picks in the UI. The user may still type any
/// other type name supported by the protocol library.
pub const COMMON_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA", "HTTPS", "ANY",
];

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
pub fn parse_server(value: &str) -> Result<Option<SocketAddr>, String> {
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
pub(crate) fn system_server() -> Result<SocketAddr, String> {
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
pub fn parse_name(target: &str, rtype: RecordType) -> Result<Name, String> {
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
pub fn reverse_name(ip: IpAddr) -> String {
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
}
