//! Best-effort mDNS discovery over IPv4 multicast.
//!
//! Queries ask for unicast responses, so the socket does not need to compete
//! with a system mDNS daemon for port 5353.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA, PTR, SRV};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::net::UdpSocket;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const SERVICE_ENUM: &str = "_services._dns-sd._udp.local.";
/// Bound the number of reverse questions in one datagram.
const MAX_REVERSE_QUESTIONS: usize = 64;

/// mDNS information grouped by address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MdnsInfo {
    pub hostname: Option<String>,
    pub services: Vec<String>,
}

/// Query the local multicast domain and group answers by address.
pub(crate) async fn discover(addresses: &[IpAddr], timeout: Duration) -> HashMap<IpAddr, MdnsInfo> {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return HashMap::new();
    };
    let _ = socket.set_multicast_ttl_v4(1);
    let target = SocketAddr::new(IpAddr::V4(MDNS_GROUP), MDNS_PORT);

    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    let mut service_query = Query::query(
        Name::from_ascii(SERVICE_ENUM).unwrap_or_default(),
        RecordType::PTR,
    );
    service_query.set_mdns_unicast_response(true);
    message.add_query(service_query);

    for ip in addresses.iter().take(MAX_REVERSE_QUESTIONS) {
        let reverse = match ip {
            IpAddr::V4(ip) => reverse_name(*ip),
            IpAddr::V6(ip) => reverse_name_v6(*ip),
        };
        if let Ok(name) = Name::from_ascii(reverse) {
            let mut query = Query::query(name, RecordType::PTR);
            query.set_mdns_unicast_response(true);
            message.add_query(query);
        }
    }

    let Ok(bytes) = message.to_vec() else {
        return HashMap::new();
    };
    if socket.send_to(&bytes, target).await.is_err() {
        return HashMap::new();
    }

    let deadline = Instant::now() + timeout;
    let mut records = Records::default();
    let mut buffer = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(received) = tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await
        else {
            break;
        };
        let Ok((size, _)) = received else {
            break;
        };
        let Ok(message) = Message::from_vec(&buffer[..size]) else {
            continue;
        };
        records.absorb(&message.answers);
        records.absorb(&message.authorities);
        records.absorb(&message.additionals);
    }
    records.finish()
}

#[derive(Default)]
struct Records {
    name_to_ip: HashMap<String, IpAddr>,
    reverse: HashMap<IpAddr, String>,
    instance_to_type: HashMap<String, String>,
    srv: HashMap<String, String>,
}

impl Records {
    fn absorb(&mut self, records: &[hickory_proto::rr::Record]) {
        for record in records {
            let owner = normalize(&record.name);
            match &record.data {
                RData::A(A(ip)) => {
                    self.name_to_ip.insert(owner, IpAddr::V4(*ip));
                }
                RData::AAAA(AAAA(ip)) => {
                    self.name_to_ip.insert(owner, IpAddr::V6(*ip));
                }
                RData::PTR(PTR(target)) => {
                    let target = normalize(target);
                    if let Some(ip) = ip_from_reverse_name(&owner) {
                        if crate::net::lan_discovery::neighbors::is_allowed_ip(ip) {
                            self.reverse.insert(ip, target.clone());
                        }
                    }
                    if target != owner {
                        self.instance_to_type.insert(target, owner);
                    }
                }
                RData::SRV(SRV { target, .. }) => {
                    self.srv.insert(owner, normalize(target));
                }
                _ => {}
            }
        }
    }

    fn finish(self) -> HashMap<IpAddr, MdnsInfo> {
        let mut result: HashMap<IpAddr, MdnsInfo> = HashMap::new();
        for (instance, target) in &self.srv {
            let Some(ip) = self.name_to_ip.get(target) else {
                continue;
            };
            if !crate::net::lan_discovery::neighbors::is_allowed_ip(*ip) {
                continue;
            }
            let service = self
                .instance_to_type
                .get(instance)
                .cloned()
                .unwrap_or_else(|| instance.clone());
            let entry = result.entry(*ip).or_default();
            if !entry.services.contains(&service) {
                entry.services.push(service);
            }
        }
        for (ip, name) in &self.reverse {
            result.entry(*ip).or_default().hostname = Some(name.clone());
        }
        for (name, ip) in &self.name_to_ip {
            if !crate::net::lan_discovery::neighbors::is_allowed_ip(*ip) {
                continue;
            }
            let entry = result.entry(*ip).or_default();
            if entry.hostname.is_none() {
                entry.hostname = Some(name.clone());
            }
        }
        for info in result.values_mut() {
            info.services.sort();
            dedup_services(&mut info.services);
        }
        result
    }
}

fn normalize(name: &Name) -> String {
    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
}

fn reverse_name(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!(
        "{}.{}.{}.{}.in-addr.arpa.",
        octets[3], octets[2], octets[1], octets[0]
    )
}

fn reverse_name_v6(ip: Ipv6Addr) -> String {
    let nibbles = format!("{:032x}", u128::from(ip));
    let mut labels = nibbles
        .chars()
        .rev()
        .map(|nibble| nibble.to_string())
        .collect::<Vec<_>>();
    labels.push("ip6".to_string());
    labels.push("arpa".to_string());
    format!("{}.", labels.join("."))
}

fn ip_from_reverse_name(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.');
    if let Some(suffix) = name.strip_suffix(".in-addr.arpa") {
        let mut parts = suffix.split('.');
        let mut octets = [0u8; 4];
        for octet in octets.iter_mut().rev() {
            *octet = parts.next()?.parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    let suffix = name.strip_suffix(".ip6.arpa")?;
    let mut nibbles = suffix.split('.');
    let mut value = 0u128;
    for index in 0..32 {
        let nibble = u8::from_str_radix(nibbles.next()?, 16).ok()?;
        value |= u128::from(nibble) << (index * 4);
    }
    if nibbles.next().is_some() {
        return None;
    }
    Some(IpAddr::V6(Ipv6Addr::from(value)))
}

/// Deduplicate service names while preserving a deterministic order.
pub(crate) fn dedup_services(services: &mut Vec<String>) {
    let mut seen = HashSet::new();
    services.retain(|value| seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_roundtrip() {
        let ip = Ipv4Addr::new(192, 168, 1, 25);
        let name = reverse_name(ip);
        assert_eq!(name, "25.1.168.192.in-addr.arpa.");
        assert_eq!(ip_from_reverse_name(&name), Some(IpAddr::V4(ip)));
    }

    #[test]
    fn ipv6_reverse_names_roundtrip() {
        let ip = "fd00:2004::1234".parse::<Ipv6Addr>().unwrap();
        let name = reverse_name_v6(ip);
        assert!(name.ends_with(".ip6.arpa."));
        assert_eq!(ip_from_reverse_name(&name), Some(IpAddr::V6(ip)));
    }

    #[test]
    fn invalid_reverse_names_are_rejected() {
        assert!(ip_from_reverse_name("example.in-addr.arpa").is_none());
        assert!(ip_from_reverse_name("1.2.3.4.example").is_none());
    }

    #[test]
    fn service_dedup_is_stable() {
        let mut values = vec![
            "_http._tcp.local".to_string(),
            "_http._tcp.local".to_string(),
            "_ssh._tcp.local".to_string(),
        ];
        dedup_services(&mut values);
        assert_eq!(values[0], "_http._tcp.local");
        assert_eq!(values.len(), 2);
    }
}
