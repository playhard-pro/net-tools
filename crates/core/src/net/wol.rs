//! Wake-on-LAN packet construction and UDP transmission.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::config::WolSettings;
use crate::control::ProbeHandle;
use crate::model::{ProbeEvent, WolResult};

/// A local IPv4 interface broadcast address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBroadcast {
    pub interface: String,
    pub address: Ipv4Addr,
}

/// Parse a MAC address in colon, dash, dot, space or plain hexadecimal form.
pub fn parse_mac(input: &str) -> Result<[u8; 6], String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("MAC address is empty".to_string());
    }
    if !input
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.' | ' '))
    {
        return Err(format!("`{input}` contains invalid MAC address characters"));
    }
    let hex: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() != 12 {
        return Err(format!(
            "`{input}` must contain exactly twelve hexadecimal digits"
        ));
    }
    let mut bytes = [0u8; 6];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("`{input}` is not a valid MAC address"))?;
    }
    Ok(bytes)
}

/// Format a MAC address with colon separators.
pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse an optional SecureOn password.
///
/// SecureOn uses six hexadecimal bytes, just like the MAC address. An empty
/// value disables the password.
pub fn parse_secure_on(input: &str) -> Result<Option<[u8; 6]>, String> {
    if input.trim().is_empty() {
        return Ok(None);
    }
    parse_mac(input)
        .map(Some)
        .map_err(|error| format!("SecureOn password: {error}"))
}

/// Build a magic packet: six `0xFF` bytes followed by the MAC repeated sixteen
/// times, with an optional SecureOn password appended.
pub fn build_magic_packet(mac: [u8; 6], secure_on: Option<[u8; 6]>) -> Vec<u8> {
    let mut packet = Vec::with_capacity(102 + secure_on.map_or(0, |_| 6));
    packet.extend_from_slice(&[0xFF; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    if let Some(password) = secure_on {
        packet.extend_from_slice(&password);
    }
    packet
}

/// Enumerate local IPv4 broadcast addresses for the Wake-on-LAN picker.
pub fn local_broadcasts() -> Vec<LocalBroadcast> {
    let mut list = Vec::new();
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        if let if_addrs::IfAddr::V4(address) = interface.addr {
            if address.ip.is_loopback() {
                continue;
            }
            let broadcast = address.broadcast.unwrap_or_else(|| {
                let ip = u32::from(address.ip);
                let mask = u32::from(address.netmask);
                Ipv4Addr::from(ip | !mask)
            });
            list.push(LocalBroadcast {
                interface: interface.name,
                address: broadcast,
            });
        }
    }
    list.sort_by(|left, right| {
        left.interface
            .cmp(&right.interface)
            .then_with(|| left.address.cmp(&right.address))
    });
    list.dedup();
    list
}

/// Send the configured magic packet and report the result through the event
/// channel.
pub async fn run_wake(handle: &ProbeHandle<ProbeEvent>, settings: &WolSettings) {
    let mac = match parse_mac(&settings.mac) {
        Ok(mac) => mac,
        Err(message) => {
            handle.send(ProbeEvent::Error {
                message,
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    let secure_on = match parse_secure_on(&settings.secure_on) {
        Ok(password) => password,
        Err(message) => {
            handle.send(ProbeEvent::Error {
                message,
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    let broadcast: Ipv4Addr = match settings.broadcast.trim().parse() {
        Ok(address) => address,
        Err(_) => {
            handle.send(ProbeEvent::Error {
                message: format!(
                    "`{}` is not a valid IPv4 broadcast address",
                    settings.broadcast
                ),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    if settings.port == 0 {
        handle.send(ProbeEvent::Error {
            message: "UDP port must be between 1 and 65535".to_string(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(error) => {
            handle.send(ProbeEvent::Error {
                message: format!("failed to bind UDP socket: {error}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    if let Err(error) = socket.set_broadcast(true) {
        handle.send(ProbeEvent::Error {
            message: format!("failed to enable UDP broadcast: {error}"),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    let packet = build_magic_packet(mac, secure_on);
    let target = SocketAddr::V4(SocketAddrV4::new(broadcast, settings.port));
    let repeat = settings.repeat.clamp(1, 10) as usize;
    let interval = Duration::from_millis(settings.interval_ms.clamp(10, 5_000));
    let started = Instant::now();
    let mut packets = 0usize;

    for index in 0..repeat {
        if handle.is_cancelled() {
            break;
        }
        if let Err(error) = socket.send_to(&packet, target).await {
            handle.send(ProbeEvent::Error {
                message: format!("failed to send magic packet to {target}: {error}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
        packets += 1;
        if index + 1 < repeat && handle.sleep(interval).await {
            break;
        }
    }

    if handle.is_cancelled() {
        handle.send(ProbeEvent::Finished);
        return;
    }

    handle.send(ProbeEvent::Wol(WolResult {
        mac: format_mac(mac),
        broadcast: broadcast.to_string(),
        port: settings.port,
        packets,
        bytes: packets * packet.len(),
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        secure_on: secure_on.is_some(),
    }));
    handle.send(ProbeEvent::Finished);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formats_are_normalized() {
        let expected = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        for input in [
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "AABB.CCDD.EEFF",
            "AA BB CC DD EE FF",
            "aabbccddeeff",
        ] {
            assert_eq!(parse_mac(input).unwrap(), expected, "{input}");
        }
        assert_eq!(format_mac(expected), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn invalid_macs_are_rejected() {
        assert!(parse_mac("").is_err());
        assert!(parse_mac("AA:BB:CC:DD:EE").is_err());
        assert!(parse_mac("AA:BB:CC:DD:EE:GG").is_err());
        assert!(parse_mac("not-a-mac").is_err());
    }

    #[test]
    fn magic_packet_has_the_standard_layout() {
        let mac = [1, 2, 3, 4, 5, 6];
        let packet = build_magic_packet(mac, None);
        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        for chunk in packet[6..].chunks(6) {
            assert_eq!(chunk, mac);
        }
    }

    #[test]
    fn secure_on_password_is_appended() {
        let mac = [1, 2, 3, 4, 5, 6];
        let password = [9, 8, 7, 6, 5, 4];
        let packet = build_magic_packet(mac, Some(password));
        assert_eq!(packet.len(), 108);
        assert_eq!(&packet[102..], &password);
        assert_eq!(
            parse_secure_on("09:08:07:06:05:04").unwrap(),
            Some(password)
        );
        assert_eq!(parse_secure_on("").unwrap(), None);
    }

    #[test]
    fn local_broadcast_discovery_does_not_panic() {
        let _ = local_broadcasts();
    }

    #[test]
    fn wake_sends_repeated_packets_over_udp() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let settings = WolSettings {
                mac: "AA:BB:CC:DD:EE:FF".into(),
                broadcast: "127.0.0.1".into(),
                port,
                repeat: 2,
                interval_ms: 10,
                secure_on: "09:08:07:06:05:04".into(),
            };
            let mut controller = crate::control::TaskController::<ProbeEvent>::new();
            let handle = runtime.handle().clone();
            controller.start(&handle, move |probe| async move {
                run_wake(&probe, &settings).await;
            });

            let mut buffer = [0u8; 256];
            for _ in 0..2 {
                let (size, _) =
                    tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut buffer))
                        .await
                        .expect("magic packet was not received")
                        .unwrap();
                assert_eq!(size, 108);
                assert_eq!(&buffer[..6], &[0xFF; 6]);
                assert_eq!(&buffer[102..108], &[9, 8, 7, 6, 5, 4]);
            }

            tokio::time::sleep(Duration::from_millis(20)).await;
            let events = controller.drain();
            assert!(events.iter().any(|event| matches!(
                event,
                ProbeEvent::Wol(result) if result.packets == 2 && result.secure_on
            )));
        });
    }
}
