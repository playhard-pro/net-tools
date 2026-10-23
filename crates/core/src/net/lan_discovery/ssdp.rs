//! SSDP/UPnP discovery and device description parsing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use quick_xml::events::Event;
use quick_xml::Reader;
use tokio::net::UdpSocket;

const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
/// Upper bound for one UPnP description download.
const MAX_DESCRIPTION_BYTES: usize = 256 * 1024;

/// SSDP device information for one address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SsdpInfo {
    pub name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub device_type: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Default)]
struct SearchResponse {
    location: Option<String>,
    device_type: Option<String>,
    usn: Option<String>,
}

/// Send an SSDP search and fetch the unique device descriptions.
pub(crate) async fn discover(timeout: Duration) -> HashMap<IpAddr, SsdpInfo> {
    crate::net::ensure_crypto_provider();
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return HashMap::new();
    };
    let request = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 2\r\n",
        "ST: ssdp:all\r\n\r\n"
    );
    let target = SocketAddr::new(IpAddr::V4(SSDP_GROUP), SSDP_PORT);
    if socket.send_to(request.as_bytes(), target).await.is_err() {
        return HashMap::new();
    }

    let deadline = Instant::now() + timeout;
    let mut responses: HashMap<IpAddr, SearchResponse> = HashMap::new();
    let mut seen_locations = HashMap::new();
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
        let Ok((size, source)) = received else {
            break;
        };
        let ip = source.ip();
        if !crate::net::lan_discovery::neighbors::is_allowed_ip(ip) {
            continue;
        }
        let text = String::from_utf8_lossy(&buffer[..size]);
        let Some(response) = parse_search_response(&text) else {
            continue;
        };
        if let Some(location) = &response.location {
            seen_locations.insert(location.clone(), ip);
        }
        responses.insert(ip, response);
    }

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("net-tools")
        .build()
        .ok();
    let mut result = HashMap::new();
    for (location, ip) in seen_locations {
        let response = responses.entry(ip).or_default();
        if let Some(client) = &client {
            if let Some(description) = fetch_description(client, &location).await {
                response.device_type = description.device_type.or(response.device_type.clone());
                result.insert(
                    ip,
                    SsdpInfo {
                        name: description.name,
                        manufacturer: description.manufacturer,
                        model: description.model,
                        device_type: response.device_type.clone(),
                        location: Some(location),
                    },
                );
                continue;
            }
        }
        result.insert(
            ip,
            SsdpInfo {
                device_type: response.device_type.clone(),
                location: Some(location),
                ..SsdpInfo::default()
            },
        );
    }
    for (ip, response) in responses {
        result.entry(ip).or_insert_with(|| SsdpInfo {
            device_type: response.device_type,
            location: response.location,
            ..SsdpInfo::default()
        });
    }
    result
}

#[derive(Debug, Default)]
struct Description {
    name: Option<String>,
    manufacturer: Option<String>,
    model: Option<String>,
    device_type: Option<String>,
}

async fn fetch_description(client: &reqwest::Client, location: &str) -> Option<Description> {
    let url = url::Url::parse(location).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    if response
        .content_length()
        .is_some_and(|length| length as usize > MAX_DESCRIPTION_BYTES)
    {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    if bytes.len() > MAX_DESCRIPTION_BYTES {
        return None;
    }
    Some(parse_description(&String::from_utf8_lossy(&bytes)))
}

fn parse_search_response(text: &str) -> Option<SearchResponse> {
    let mut response = SearchResponse::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "location" => response.location = Some(value.to_string()),
            "st" => response.device_type = Some(value.to_string()),
            "usn" => response.usn = Some(value.to_string()),
            _ => {}
        }
    }
    if response.location.is_none() && response.device_type.is_none() && response.usn.is_none() {
        None
    } else {
        Some(response)
    }
}

fn parse_description(xml: &str) -> Description {
    let mut description = Description::default();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut current = String::new();
    let mut text_value = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                current = local_name(event.name().as_ref());
                text_value.clear();
            }
            Ok(Event::Text(text)) => {
                if let Ok(decoded) = text.decode() {
                    text_value.push_str(&decoded);
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if let Ok(decoded) = reference.decode() {
                    text_value.push('&');
                    text_value.push_str(&decoded);
                    text_value.push(';');
                }
            }
            Ok(Event::End(_)) => {
                assign_description_field(&mut description, &current, &text_value);
                current.clear();
                text_value.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    description
}

fn assign_description_field(description: &mut Description, field: &str, value: &str) {
    let value = quick_xml::escape::unescape(value)
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| value.trim().to_string());
    if value.is_empty() {
        return;
    }
    match field {
        "friendlyName" if description.name.is_none() => description.name = Some(value),
        "manufacturer" if description.manufacturer.is_none() => {
            description.manufacturer = Some(value);
        }
        "modelName" if description.model.is_none() => description.model = Some(value),
        "deviceType" if description.device_type.is_none() => {
            description.device_type = Some(value);
        }
        _ => {}
    }
}

fn local_name(name: &[u8]) -> String {
    let name = name.rsplit(|byte| *byte == b':').next().unwrap_or(name);
    String::from_utf8_lossy(name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_response_headers_are_parsed_case_insensitively() {
        let text = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/desc.xml\r\n\
St: upnp:rootdevice\r\nUSN: uuid:x::upnp:rootdevice\r\n\r\n";
        let response = parse_search_response(text).unwrap();
        assert_eq!(
            response.location.as_deref(),
            Some("http://192.168.1.1/desc.xml")
        );
        assert_eq!(response.device_type.as_deref(), Some("upnp:rootdevice"));
    }

    #[test]
    fn description_reads_common_fields() {
        let xml = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
<friendlyName>Living Room TV</friendlyName>
<manufacturer>Example &amp; Co</manufacturer>
<modelName>Model X</modelName>
</device></root>"#;
        let description = parse_description(xml);
        assert_eq!(description.name.as_deref(), Some("Living Room TV"));
        assert_eq!(description.manufacturer.as_deref(), Some("Example & Co"));
        assert_eq!(description.model.as_deref(), Some("Model X"));
        assert_eq!(
            description.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
    }
}
