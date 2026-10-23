//! Minimal NetBIOS name service (NBSTAT) client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

/// Names returned by a NetBIOS node status response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NetbiosInfo {
    pub name: Option<String>,
    pub workgroup: Option<String>,
}

/// Query one host for its NetBIOS workstation and workgroup names.
pub(crate) async fn query(ip: Ipv4Addr, timeout: Duration) -> Option<NetbiosInfo> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    let packet = build_query(0x4e42);
    socket
        .send_to(&packet, SocketAddr::new(IpAddr::V4(ip), 137))
        .await
        .ok()?;
    let mut buffer = [0u8; 2048];
    let (size, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buffer))
        .await
        .ok()?
        .ok()?;
    parse_response(&buffer[..size])
}

/// Build an NBSTAT wildcard query for a NetBIOS name service.
fn build_query(transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // flags
    packet.extend_from_slice(&1u16.to_be_bytes()); // questions
    packet.extend_from_slice(&0u16.to_be_bytes()); // answers
    packet.extend_from_slice(&0u16.to_be_bytes()); // authority
    packet.extend_from_slice(&0u16.to_be_bytes()); // additional

    // Encode the wildcard name `*` padded with NUL bytes.
    let mut name = [0u8; 16];
    name[0] = b'*';
    packet.push(32);
    for byte in name {
        packet.push(b'A' + (byte >> 4));
        packet.push(b'A' + (byte & 0x0f));
    }
    packet.push(0);
    packet.extend_from_slice(&0x0021u16.to_be_bytes()); // NBSTAT
    packet.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    packet
}

fn parse_response(packet: &[u8]) -> Option<NetbiosInfo> {
    if packet.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        offset = offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    let mut info = NetbiosInfo::default();
    for _ in 0..answers {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let length = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        let end = offset.checked_add(length)?;
        if end > packet.len() {
            return None;
        }
        if record_type == 0x0021 {
            parse_nbstat(&packet[offset..end], &mut info);
        }
        offset = end;
    }
    if info.name.is_some() || info.workgroup.is_some() {
        Some(info)
    } else {
        None
    }
}

fn parse_nbstat(data: &[u8], info: &mut NetbiosInfo) {
    let Some(&count) = data.first() else {
        return;
    };
    for index in 0..count as usize {
        let start = 1 + index * 18;
        let end = start + 18;
        if end > data.len() {
            break;
        }
        let raw_name = &data[start..start + 15];
        let suffix = data[start + 15];
        let name = String::from_utf8_lossy(raw_name)
            .trim_matches(|c: char| c == ' ' || c == '\0')
            .to_string();
        if name.is_empty() {
            continue;
        }
        match suffix {
            0x00 if info.name.is_none() => info.name = Some(name),
            0x1c if info.workgroup.is_none() => info.workgroup = Some(name),
            _ => {}
        }
    }
}

fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            return offset.checked_add(2);
        }
        offset = offset.checked_add(1)?;
        if length == 0 {
            return Some(offset);
        }
        offset = offset.checked_add(length as usize)?;
        if offset > packet.len() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with_names(names: &[(&[u8], u8)]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x4e42u16.to_be_bytes());
        packet.extend_from_slice(&0x8400u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        // Answer name as a compression pointer to the query name area.
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&0x0021u16.to_be_bytes());
        packet.extend_from_slice(&0x0001u16.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        let mut rdata = vec![names.len() as u8];
        for (name, suffix) in names {
            let mut padded = [b' '; 15];
            padded[..name.len()].copy_from_slice(name);
            rdata.extend_from_slice(&padded);
            rdata.push(*suffix);
            rdata.extend_from_slice(&0u16.to_be_bytes());
        }
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
        packet
    }

    #[test]
    fn query_encodes_wildcard_name_and_nbstat_type() {
        let packet = build_query(1);
        assert_eq!(packet.len(), 50);
        assert_eq!(packet[12], 32);
        assert_eq!(&packet[46..50], &[0, 0x21, 0, 1]);
    }

    #[test]
    fn response_extracts_workstation_and_workgroup() {
        let packet = response_with_names(&[(b"OFFICE-PC", 0x00), (b"WORKGROUP", 0x1c)]);
        let info = parse_response(&packet).unwrap();
        assert_eq!(info.name.as_deref(), Some("OFFICE-PC"));
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
    }

    #[test]
    fn malformed_response_is_rejected() {
        assert!(parse_response(&[0, 1, 2]).is_none());
    }
}
