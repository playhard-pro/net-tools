//! IPv4 and IPv6 subnet/CIDR calculations.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of one subnet calculation.
///
/// Fields that do not apply to the address family are `None`, so the UI can
/// render one table for both IPv4 and IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetInfo {
    /// Address exactly as entered, trimmed.
    pub input: String,
    pub family: &'static str,
    /// Network address in CIDR notation.
    pub cidr: String,
    pub network: String,
    /// IPv4 broadcast address.
    pub broadcast: Option<String>,
    /// IPv4 dotted netmask.
    pub netmask: Option<String>,
    /// IPv4 wildcard (inverse) mask.
    pub wildcard: Option<String>,
    /// First address in the prefix.
    pub first: String,
    /// Last address in the prefix.
    pub last: String,
    /// Total number of addresses in the prefix.
    pub total: String,
    /// Addresses considered usable for hosts.
    pub usable: String,
    /// Address scope such as private, loopback or documentation.
    pub scope: String,
    /// IPv4 address in binary, grouped by octet.
    pub address_binary: Option<String>,
    /// IPv4 netmask in binary, grouped by octet.
    pub mask_binary: Option<String>,
    /// IPv6 expanded address form.
    pub expanded: Option<String>,
    /// Lower 64 bits of the IPv6 address.
    pub interface_id: Option<String>,
    pub prefix: u8,
}

/// Parse an address with an optional prefix or IPv4 netmask and calculate the
/// network details.
///
/// Accepted forms include `address/prefix`, `address/netmask`,
/// `address wildcard` and a bare address. A bare IPv4 address uses `/32` and a
/// bare IPv6 address uses `/128`.
pub fn parse_subnet(input: &str) -> Result<SubnetInfo, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("enter an IPv4 or IPv6 address".to_string());
    }

    // Both `addr/prefix` and `addr prefix` are accepted. IPv6 addresses never
    // contain spaces, so splitting on whitespace is safe.
    let (address_text, suffix) = if let Some((address, suffix)) = input.split_once('/') {
        (address.trim(), Some(suffix.trim()))
    } else if let Some((address, suffix)) = input.split_once(char::is_whitespace) {
        (address.trim(), Some(suffix.trim()))
    } else {
        (input, None)
    };

    let address: IpAddr = address_text
        .parse()
        .map_err(|_| format!("`{address_text}` is not a valid IP address"))?;

    match address {
        IpAddr::V4(address) => parse_ipv4(input, address, suffix),
        IpAddr::V6(address) => parse_ipv6(input, address, suffix),
    }
}

fn parse_ipv4(input: &str, address: Ipv4Addr, suffix: Option<&str>) -> Result<SubnetInfo, String> {
    let bits = u32::from(address);
    let mask = match suffix {
        None => u32::MAX,
        Some("") => return Err("prefix or netmask is empty".to_string()),
        Some(value) => {
            if value.contains('.') {
                let mask: Ipv4Addr = value
                    .parse()
                    .map_err(|_| format!("`{value}` is not a valid IPv4 netmask"))?;
                let mask = u32::from(mask);
                ensure_contiguous_mask(mask)?;
                mask
            } else {
                let prefix: u8 = value
                    .parse()
                    .map_err(|_| format!("`{value}` is not a valid IPv4 prefix"))?;
                if prefix > 32 {
                    return Err(format!("IPv4 prefix /{prefix} is out of range"));
                }
                prefix_mask(prefix, 32) as u32
            }
        }
    };

    let prefix = mask.leading_ones() as u8;
    let network = bits & mask;
    let broadcast = network | !mask;
    let total = 1u128 << (32 - prefix);
    let usable = if prefix >= 31 {
        total
    } else {
        total.saturating_sub(2)
    };
    let (first, last) = if prefix >= 31 {
        (network, broadcast)
    } else {
        (network.saturating_add(1), broadcast.saturating_sub(1))
    };

    let network_addr = Ipv4Addr::from(network);
    let broadcast_addr = Ipv4Addr::from(broadcast);
    let wildcard = Ipv4Addr::from(!mask);

    Ok(SubnetInfo {
        input: input.to_string(),
        family: "IPv4",
        cidr: format!("{network_addr}/{prefix}"),
        network: network_addr.to_string(),
        broadcast: Some(broadcast_addr.to_string()),
        netmask: Some(Ipv4Addr::from(mask).to_string()),
        wildcard: Some(wildcard.to_string()),
        first: Ipv4Addr::from(first).to_string(),
        last: Ipv4Addr::from(last).to_string(),
        total: total.to_string(),
        usable: usable.to_string(),
        scope: ipv4_scope(address),
        address_binary: Some(binary_ipv4(address)),
        mask_binary: Some(binary_ipv4(Ipv4Addr::from(mask))),
        expanded: None,
        interface_id: None,
        prefix,
    })
}

fn parse_ipv6(input: &str, address: Ipv6Addr, suffix: Option<&str>) -> Result<SubnetInfo, String> {
    let bits = u128::from(address);
    let prefix = match suffix {
        None => 128,
        Some("") => return Err("prefix is empty".to_string()),
        Some(value) => {
            let prefix: u8 = value
                .parse()
                .map_err(|_| format!("`{value}` is not a valid IPv6 prefix"))?;
            if prefix > 128 {
                return Err(format!("IPv6 prefix /{prefix} is out of range"));
            }
            prefix
        }
    };

    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let network = bits & mask;
    let last = network | !mask;

    let network_addr = Ipv6Addr::from(network);
    let last_addr = Ipv6Addr::from(last);
    let total = count_text(128 - prefix, 128);
    // IPv6 has no broadcast address, so every address in the prefix is usable.
    let usable = total.clone();
    let interface_id = format_interface_id(bits);

    Ok(SubnetInfo {
        input: input.to_string(),
        family: "IPv6",
        cidr: format!("{network_addr}/{prefix}"),
        network: network_addr.to_string(),
        broadcast: None,
        netmask: None,
        wildcard: None,
        first: network_addr.to_string(),
        last: last_addr.to_string(),
        total,
        usable,
        scope: ipv6_scope(address),
        address_binary: None,
        mask_binary: None,
        expanded: Some(expand_ipv6(address)),
        interface_id: Some(interface_id),
        prefix,
    })
}

/// Build a prefix mask with `width` total bits.
fn prefix_mask(prefix: u8, width: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (width - prefix)
    }
}

/// Reject netmasks whose one-bits are not contiguous from the most significant
/// bit.
fn ensure_contiguous_mask(mask: u32) -> Result<(), String> {
    let prefix = mask.leading_ones() as u8;
    if prefix > 32 || prefix_mask(prefix, 32) as u32 != mask {
        return Err(format!(
            "`{}` is not a contiguous IPv4 netmask",
            Ipv4Addr::from(mask)
        ));
    }
    Ok(())
}

/// Number of addresses for a host-bit count as text.
///
/// A /0 IPv6 prefix contains 2^128 addresses, which does not fit in `u128`.
fn count_text(host_bits: u8, width: u8) -> String {
    if host_bits == width && width == 128 {
        "340282366920938463463374607431768211456".to_string()
    } else {
        (1u128 << host_bits).to_string()
    }
}

fn binary_ipv4(address: Ipv4Addr) -> String {
    let octets = address.octets();
    format!(
        "{:08b}.{:08b}.{:08b}.{:08b}",
        octets[0], octets[1], octets[2], octets[3]
    )
}

fn expand_ipv6(address: Ipv6Addr) -> String {
    address
        .segments()
        .iter()
        .map(|segment| format!("{segment:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_interface_id(bits: u128) -> String {
    let low = (bits & 0xffff_ffff_ffff_ffff) as u64;
    let segments = [
        (low >> 48) as u16,
        (low >> 32) as u16,
        (low >> 16) as u16,
        low as u16,
    ];
    segments
        .iter()
        .map(|segment| format!("{segment:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn ipv4_scope(address: Ipv4Addr) -> String {
    if address.is_unspecified() {
        "unspecified".into()
    } else if address.is_loopback() {
        "loopback".into()
    } else if address.is_link_local() {
        "link-local".into()
    } else if address.is_broadcast() {
        "broadcast".into()
    } else if address.is_multicast() {
        "multicast".into()
    } else if address.is_documentation() {
        "documentation".into()
    } else if address.is_private() {
        "private".into()
    } else {
        "public".into()
    }
}

fn ipv6_scope(address: Ipv6Addr) -> String {
    let bits = u128::from(address);
    if address.is_unspecified() {
        "unspecified".into()
    } else if address.is_loopback() {
        "loopback".into()
    } else if address.is_multicast() {
        "multicast".into()
    } else if bits & 0xfe00_0000_0000_0000_0000_0000_0000_0000
        == 0xfc00_0000_0000_0000_0000_0000_0000_0000
    {
        "unique-local".into()
    } else if bits & 0xffc0_0000_0000_0000_0000_0000_0000_0000
        == 0xfe80_0000_0000_0000_0000_0000_0000_0000
    {
        "link-local".into()
    } else if bits & 0xffff_ffff_0000_0000_0000_0000_0000_0000
        == 0x2001_0db8_0000_0000_0000_0000_0000_0000
    {
        "documentation".into()
    } else {
        "global".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_is_calculated() {
        let info = parse_subnet("192.168.1.10/24").unwrap();
        assert_eq!(info.cidr, "192.168.1.0/24");
        assert_eq!(info.network, "192.168.1.0");
        assert_eq!(info.broadcast.as_deref(), Some("192.168.1.255"));
        assert_eq!(info.netmask.as_deref(), Some("255.255.255.0"));
        assert_eq!(info.wildcard.as_deref(), Some("0.0.0.255"));
        assert_eq!(info.first, "192.168.1.1");
        assert_eq!(info.last, "192.168.1.254");
        assert_eq!(info.total, "256");
        assert_eq!(info.usable, "254");
        assert_eq!(info.scope, "private");
    }

    #[test]
    fn ipv4_netmask_and_space_forms_are_accepted() {
        let slash = parse_subnet("10.0.0.7/255.255.255.0").unwrap();
        let space = parse_subnet("10.0.0.7 255.255.255.0").unwrap();
        assert_eq!(slash.cidr, "10.0.0.0/24");
        assert_eq!(space.cidr, slash.cidr);
        assert_eq!(slash.netmask, space.netmask);
    }

    #[test]
    fn ipv4_special_prefixes_have_no_broadcast_hosts() {
        let slash31 = parse_subnet("192.0.2.0/31").unwrap();
        assert_eq!(slash31.usable, "2");
        assert_eq!(slash31.first, "192.0.2.0");
        assert_eq!(slash31.last, "192.0.2.1");

        let slash32 = parse_subnet("192.0.2.1/32").unwrap();
        assert_eq!(slash32.usable, "1");
        assert_eq!(slash32.first, "192.0.2.1");
        assert_eq!(slash32.last, "192.0.2.1");
    }

    #[test]
    fn ipv4_bare_address_uses_host_prefix() {
        let info = parse_subnet("8.8.8.8").unwrap();
        assert_eq!(info.cidr, "8.8.8.8/32");
        assert_eq!(info.scope, "public");
    }

    #[test]
    fn non_contiguous_mask_is_rejected() {
        assert!(parse_subnet("192.168.1.1/255.0.255.0").is_err());
    }

    #[test]
    fn ipv6_prefix_is_calculated() {
        let info = parse_subnet("2001:db8::1/64").unwrap();
        assert_eq!(info.cidr, "2001:db8::/64");
        assert_eq!(info.broadcast, None);
        assert_eq!(info.first, "2001:db8::");
        assert_eq!(info.last, "2001:db8::ffff:ffff:ffff:ffff");
        assert_eq!(info.usable, "18446744073709551616");
        assert_eq!(info.scope, "documentation");
        assert_eq!(
            info.expanded.as_deref(),
            Some("2001:0db8:0000:0000:0000:0000:0000:0001")
        );
    }

    #[test]
    fn ipv6_special_prefixes_are_handled() {
        let slash127 = parse_subnet("2001:db8::/127").unwrap();
        assert_eq!(slash127.total, "2");
        assert_eq!(slash127.last, "2001:db8::1");

        let slash128 = parse_subnet("2001:db8::1/128").unwrap();
        assert_eq!(slash128.total, "1");

        let slash0 = parse_subnet("::/0").unwrap();
        assert_eq!(slash0.total, "340282366920938463463374607431768211456");
    }

    #[test]
    fn invalid_input_reports_an_error() {
        assert!(parse_subnet("").is_err());
        assert!(parse_subnet("not an address").is_err());
        assert!(parse_subnet("192.168.1.1/33").is_err());
        assert!(parse_subnet("2001:db8::1/129").is_err());
    }
}
