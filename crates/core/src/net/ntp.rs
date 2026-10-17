//! SNTP query engine for the NTP tab.
//!
//! The implementation is intentionally small and dependency free: it builds a
//! client request, validates the server response and derives the clock offset
//! and round-trip delay from the four NTP timestamps.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};
use tokio::net::UdpSocket;

use crate::config::NtpSettings;
use crate::control::ProbeHandle;
use crate::model::{NtpResult, ProbeEvent};

/// NTP packets are always this many bytes long.
const NTP_PACKET_SIZE: usize = 48;

/// Default UDP port for NTP.
const NTP_PORT: u16 = 123;

/// Seconds between the NTP epoch and the Unix epoch.
const NTP_UNIX_EPOCH_DELTA: f64 = 2_208_988_800.0;

/// Number of seconds in one 32-bit NTP era.
const NTP_ERA_SECONDS: f64 = 4_294_967_296.0;

/// Number of fractional units in one second.
const NTP_FRACTION_SCALE: f64 = 4_294_967_296.0;

/// Offset of the transmit timestamp inside an NTP packet.
const TRANSMIT_OFFSET: usize = 40;

/// Maximum number of attempts for one query action: the first try plus one
/// retry after a failure.
const MAX_ATTEMPTS: usize = 2;

/// Delay before the automatic retry.
const RETRY_DELAY: Duration = Duration::from_millis(300);

/// One NTP timestamp, split into seconds and fractional seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NtpTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl NtpTimestamp {
    /// Build a timestamp from a Unix time in seconds.
    ///
    /// `unix_seconds` is rounded to the NTP fraction resolution. The returned
    /// 32-bit seconds wrap at the NTP era boundary, which is expected because
    /// the wire format only carries the low bits.
    pub fn from_unix_seconds(unix_seconds: f64) -> Self {
        let ntp_seconds = unix_seconds + NTP_UNIX_EPOCH_DELTA;
        let total = (ntp_seconds * NTP_FRACTION_SCALE).round().max(0.0) as u128;
        let whole = (total / NTP_FRACTION_SCALE as u128) as u64;
        let fraction = (total % NTP_FRACTION_SCALE as u128) as u32;
        Self {
            seconds: whole as u32,
            fraction,
        }
    }

    /// Convert this timestamp to Unix time, choosing the era closest to
    /// `reference_unix_seconds` so timestamps after the 32-bit rollover still
    /// resolve to the correct date.
    pub fn to_unix_seconds(self, reference_unix_seconds: f64) -> f64 {
        let raw = self.seconds as f64 + self.fraction as f64 / NTP_FRACTION_SCALE;
        let reference_ntp = reference_unix_seconds + NTP_UNIX_EPOCH_DELTA;
        let era = ((reference_ntp - raw) / NTP_ERA_SECONDS).round();
        raw + era * NTP_ERA_SECONDS - NTP_UNIX_EPOCH_DELTA
    }

    /// Wire representation of this timestamp.
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.seconds.to_be_bytes());
        out[4..].copy_from_slice(&self.fraction.to_be_bytes());
        out
    }

    /// Parse a timestamp from its wire representation.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        Some(Self {
            seconds: u32::from_be_bytes(bytes[..4].try_into().ok()?),
            fraction: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
        })
    }
}

/// Decoded fields of an NTP packet that are relevant to the query result.
#[derive(Debug, Clone, Copy)]
pub struct NtpPacket {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    pub reference_timestamp: NtpTimestamp,
    pub originate_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub transmit_timestamp: NtpTimestamp,
}

impl NtpPacket {
    /// Decode a packet from a received datagram.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < NTP_PACKET_SIZE {
            return None;
        }
        let first = bytes[0];
        Some(Self {
            leap: first >> 6,
            version: (first >> 3) & 0x07,
            mode: first & 0x07,
            stratum: bytes[1],
            precision: bytes[3] as i8,
            root_delay: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
            root_dispersion: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
            reference_id: u32::from_be_bytes(bytes[12..16].try_into().ok()?),
            reference_timestamp: NtpTimestamp::from_bytes(&bytes[16..24])?,
            originate_timestamp: NtpTimestamp::from_bytes(&bytes[24..32])?,
            receive_timestamp: NtpTimestamp::from_bytes(&bytes[32..40])?,
            transmit_timestamp: NtpTimestamp::from_bytes(&bytes[40..48])?,
        })
    }
}

/// Build a client request. The transmit timestamp is echoed back in the
/// response's originate field, which is used to reject unrelated datagrams.
pub fn client_request(transmit: NtpTimestamp) -> [u8; NTP_PACKET_SIZE] {
    let mut packet = [0u8; NTP_PACKET_SIZE];
    // Leap indicator 0, version 4, mode 3 (client).
    packet[0] = 0x23;
    packet[TRANSMIT_OFFSET..TRANSMIT_OFFSET + 8].copy_from_slice(&transmit.to_bytes());
    packet
}

/// One query attempt against an already resolved server.
struct Exchange {
    packet: NtpPacket,
    local_sent_unix: f64,
    local_received_unix: f64,
    elapsed: Duration,
    server_addr: SocketAddr,
}

/// Run one SNTP query action, retrying once after a failure.
pub async fn run_query(handle: &ProbeHandle<ProbeEvent>, settings: &NtpSettings) {
    let target = settings.target.trim().to_string();
    if target.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "NTP server address is empty".to_string(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    let mut last_error: Option<String> = None;
    for attempt in 0..MAX_ATTEMPTS {
        if handle.is_cancelled() {
            return;
        }
        match query_once(Some(handle), &target, settings.timeout_ms).await {
            Ok(exchange) => {
                let result = build_result(&target, exchange);
                handle.send(ProbeEvent::Ntp(result));
                handle.send(ProbeEvent::Finished);
                return;
            }
            Err(QueryFailure::Cancelled) => return,
            Err(QueryFailure::Failed(message)) => {
                last_error = Some(message);
                // Only one retry is attempted; after that the error is shown
                // so the user can decide whether to query again.
                if attempt + 1 < MAX_ATTEMPTS && handle.sleep(RETRY_DELAY).await {
                    return;
                }
            }
        }
    }

    handle.send(ProbeEvent::Error {
        message: last_error.unwrap_or_else(|| "NTP query failed".to_string()),
        hint: None,
    });
    handle.send(ProbeEvent::Finished);
}

/// Perform one query action without a task handle and return the result.
///
/// This is used by the elevated helper, which needs the freshest possible time
/// after the user has approved the UAC prompt. It retries once on failure just
/// like the interactive tab, but has no cancellation channel.
pub async fn query(settings: &NtpSettings) -> Result<NtpResult, String> {
    let target = settings.target.trim().to_string();
    if target.is_empty() {
        return Err("NTP server address is empty".to_string());
    }

    let mut last_error = String::new();
    for attempt in 0..MAX_ATTEMPTS {
        match query_once(None, &target, settings.timeout_ms).await {
            Ok(exchange) => return Ok(build_result(&target, exchange)),
            Err(QueryFailure::Failed(message)) => {
                last_error = message;
                if attempt + 1 < MAX_ATTEMPTS {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
            // Without a task handle there is no way to cancel an attempt.
            Err(QueryFailure::Cancelled) => unreachable!(),
        }
    }
    Err(last_error)
}

/// Failure modes of a single attempt.
enum QueryFailure {
    Cancelled,
    Failed(String),
}

/// Resolve the target, send one request and wait for its reply.
async fn query_once(
    handle: Option<&ProbeHandle<ProbeEvent>>,
    target: &str,
    timeout_ms: u64,
) -> Result<Exchange, QueryFailure> {
    let (host, port) = split_target(target).map_err(QueryFailure::Failed)?;
    let server_addr = resolve_server(&host, port)
        .await
        .map_err(QueryFailure::Failed)?;

    let bind: SocketAddr = if server_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| QueryFailure::Failed(format!("failed to bind UDP socket: {e}")))?;
    socket
        .connect(server_addr)
        .await
        .map_err(|e| QueryFailure::Failed(format!("UDP connect failed: {e}")))?;

    let started = Instant::now();
    let local_sent_unix = unix_now_seconds();
    let transmit = NtpTimestamp::from_unix_seconds(local_sent_unix);
    let request = client_request(transmit);
    socket
        .send(&request)
        .await
        .map_err(|e| QueryFailure::Failed(format!("NTP send failed: {e}")))?;

    let mut buf = [0u8; 1024];
    let received = match handle {
        Some(handle) => tokio::select! {
            result = tokio::time::timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)) => result,
            _ = handle.cancelled() => return Err(QueryFailure::Cancelled),
        },
        None => {
            tokio::time::timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await
        }
    };
    let local_received_unix = unix_now_seconds();
    let elapsed = started.elapsed();

    let n = match received {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return Err(QueryFailure::Failed(format!("NTP receive failed: {e}")));
        }
        Err(_) => {
            return Err(QueryFailure::Failed(format!(
                "NTP server {server_addr} did not answer within {timeout_ms} ms"
            )));
        }
    };

    let packet = NtpPacket::parse(&buf[..n])
        .ok_or_else(|| QueryFailure::Failed("received a malformed NTP response".to_string()))?;
    validate_packet(&packet, transmit)?;

    Ok(Exchange {
        packet,
        local_sent_unix,
        local_received_unix,
        elapsed,
        server_addr,
    })
}

/// Check that a response belongs to our request and is usable.
fn validate_packet(packet: &NtpPacket, request: NtpTimestamp) -> Result<(), QueryFailure> {
    if packet.mode != 4 {
        return Err(QueryFailure::Failed(format!(
            "unexpected NTP mode {} (expected a server response)",
            packet.mode
        )));
    }
    if packet.originate_timestamp != request {
        return Err(QueryFailure::Failed(
            "NTP response does not match the request (originate timestamp mismatch)".to_string(),
        ));
    }
    if packet.transmit_timestamp.seconds == 0 && packet.transmit_timestamp.fraction == 0 {
        return Err(QueryFailure::Failed(
            "NTP response contains an empty transmit timestamp".to_string(),
        ));
    }
    if packet.stratum == 0 {
        let code = reference_id_text(0, packet.reference_id);
        let code = if code.is_empty() { "unknown" } else { &code };
        return Err(QueryFailure::Failed(format!(
            "NTP server refused the request (kiss-o'-death: {code})"
        )));
    }
    if packet.stratum >= 16 {
        return Err(QueryFailure::Failed(format!(
            "NTP server is not synchronized (stratum {})",
            packet.stratum
        )));
    }
    Ok(())
}

/// Turn a validated exchange into the result consumed by the UI.
fn build_result(target: &str, exchange: Exchange) -> NtpResult {
    let packet = exchange.packet;
    // Use the local receive time as the era reference. It is the closest time
    // available and keeps the calculation correct even if the local clock has
    // a moderate offset.
    let t2 = packet
        .receive_timestamp
        .to_unix_seconds(exchange.local_received_unix);
    let t3 = packet
        .transmit_timestamp
        .to_unix_seconds(exchange.local_received_unix);
    let t1 = exchange.local_sent_unix;
    let t4 = exchange.local_received_unix;

    let delay_seconds = (t4 - t1) - (t3 - t2);
    let offset_seconds = ((t2 - t1) + (t3 - t4)) / 2.0;
    let server_time_unix = t4 + offset_seconds;

    NtpResult {
        target: target.to_string(),
        server_addr: exchange.server_addr.to_string(),
        stratum: packet.stratum,
        leap: packet.leap,
        version: packet.version,
        mode: packet.mode,
        precision: packet.precision,
        root_delay_ms: short_to_ms(packet.root_delay),
        root_dispersion_ms: short_to_ms(packet.root_dispersion),
        reference_id: reference_id_text(packet.stratum, packet.reference_id),
        reference_time: format_unix_utc(
            packet
                .reference_timestamp
                .to_unix_seconds(exchange.local_received_unix),
        ),
        offset_ms: offset_seconds * 1000.0,
        delay_ms: delay_seconds * 1000.0,
        server_time_unix,
        elapsed_ms: exchange.elapsed.as_secs_f64() * 1000.0,
    }
}

/// Current Unix time from the system clock, down to sub-millisecond precision.
fn unix_now_seconds() -> f64 {
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    nanos as f64 / 1_000_000_000.0
}

/// Convert a 16.16 fixed-point NTP short value to milliseconds.
fn short_to_ms(value: u32) -> f64 {
    value as f64 / 65_536.0 * 1000.0
}

/// Human readable reference identifier: ASCII for reference clocks, otherwise
/// the IPv4 address encoded in the field.
fn reference_id_text(stratum: u8, id: u32) -> String {
    let bytes = id.to_be_bytes();
    if stratum <= 1 {
        let text = String::from_utf8_lossy(&bytes);
        let trimmed = text.trim_matches('\0').trim();
        if !trimmed.is_empty() && trimmed.chars().all(|c| !c.is_control()) {
            return trimmed.to_string();
        }
    }
    Ipv4Addr::from(bytes).to_string()
}

/// Format a Unix timestamp as a UTC date-time with milliseconds.
fn format_unix_utc(unix_seconds: f64) -> String {
    let nanos = (unix_seconds * 1_000_000_000.0).round() as i128;
    let Ok(datetime) = OffsetDateTime::from_unix_timestamp_nanos(nanos) else {
        return "-".to_string();
    };
    let format =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
    datetime
        .to_offset(UtcOffset::UTC)
        .format(&format)
        .unwrap_or_else(|_| "-".to_string())
}

/// Split `host`, `host:port`, `[v6]` and `[v6]:port` forms.
fn split_target(target: &str) -> Result<(String, u16), String> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok((ip.to_string(), NTP_PORT));
    }
    if let Some(rest) = target.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("invalid port in NTP server: {target}"))?;
            return Ok((host.to_string(), port));
        }
        let host = rest
            .strip_suffix(']')
            .ok_or_else(|| format!("invalid IPv6 address: {target}"))?;
        return Ok((host.to_string(), NTP_PORT));
    }
    // A single colon separates host and port; multiple colons without brackets
    // are treated as an unbracketed IPv6 address with the default port.
    if target.matches(':').count() == 1 {
        if let Some((host, port)) = target.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
    }
    Ok((target.to_string(), NTP_PORT))
}

/// Resolve the server host, preferring IPv4 because it needs no extra
/// connectivity that an IPv6-only answer might require.
async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("failed to resolve {host}: {e}"))?
        .collect();
    addrs.sort_by_key(|addr| addr.is_ipv6());
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("no addresses found for {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(seconds: u32, fraction: u32) -> NtpTimestamp {
        NtpTimestamp { seconds, fraction }
    }

    fn response_for(request: NtpTimestamp, t2: NtpTimestamp, t3: NtpTimestamp) -> Vec<u8> {
        let mut packet = [0u8; NTP_PACKET_SIZE];
        // Leap 0, version 4, mode 4 (server).
        packet[0] = 0x24;
        packet[1] = 3;
        packet[3] = 0xEC; // precision -20
        packet[4..8].copy_from_slice(&0x0000_1000u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x0000_2000u32.to_be_bytes());
        packet[12..16].copy_from_slice(b"GPS\0");
        packet[16..24].copy_from_slice(&t3.to_bytes());
        packet[24..32].copy_from_slice(&request.to_bytes());
        packet[32..40].copy_from_slice(&t2.to_bytes());
        packet[40..48].copy_from_slice(&t3.to_bytes());
        packet.to_vec()
    }

    #[test]
    fn timestamp_roundtrip_unix() {
        let unix = 1_700_000_000.125;
        let ts = NtpTimestamp::from_unix_seconds(unix);
        let back = ts.to_unix_seconds(unix);
        assert!((back - unix).abs() < 0.000_001, "back={back}");
    }

    #[test]
    fn timestamp_era_rollover() {
        // A time shortly after the 2036 rollover must resolve to the nearest
        // era, not to a 1900-era date.
        let after_2036 = 2_100_000_000.0;
        let ts = NtpTimestamp::from_unix_seconds(after_2036);
        let back = ts.to_unix_seconds(after_2036);
        assert!((back - after_2036).abs() < 1.0, "back={back}");
    }

    #[test]
    fn packet_parse_and_fields() {
        let request = timestamp(3_900_000_000, 0x8000_0000);
        let t2 = timestamp(3_900_000_001, 0);
        let t3 = timestamp(3_900_000_001, 0x4000_0000);
        let bytes = response_for(request, t2, t3);
        let packet = NtpPacket::parse(&bytes).unwrap();
        assert_eq!(packet.mode, 4);
        assert_eq!(packet.version, 4);
        assert_eq!(packet.stratum, 3);
        assert_eq!(packet.originate_timestamp, request);
        assert_eq!(packet.receive_timestamp, t2);
        assert_eq!(packet.transmit_timestamp, t3);
        assert_eq!(packet.reference_id, u32::from_be_bytes(*b"GPS\0"));
    }

    #[test]
    fn client_request_has_expected_header() {
        let request = timestamp(1, 2);
        let bytes = client_request(request);
        assert_eq!(bytes.len(), NTP_PACKET_SIZE);
        assert_eq!(bytes[0], 0x23);
        assert_eq!(&bytes[40..48], &request.to_bytes());
    }

    #[test]
    fn validate_rejects_bad_mode_and_originate() {
        let request = timestamp(1, 0);
        let bytes = response_for(request, timestamp(2, 0), timestamp(3, 0));
        let mut packet = NtpPacket::parse(&bytes).unwrap();
        packet.mode = 3;
        assert!(validate_packet(&packet, request).is_err());

        let mut packet = NtpPacket::parse(&bytes).unwrap();
        packet.originate_timestamp = timestamp(99, 0);
        assert!(validate_packet(&packet, request).is_err());
    }

    #[test]
    fn validate_rejects_kiss_of_death_and_unsynchronized() {
        let request = timestamp(1, 0);
        let bytes = response_for(request, timestamp(2, 0), timestamp(3, 0));
        let mut packet = NtpPacket::parse(&bytes).unwrap();
        packet.stratum = 0;
        packet.reference_id = u32::from_be_bytes(*b"RSTR");
        let err = validate_packet(&packet, request).err().unwrap();
        match err {
            QueryFailure::Failed(message) => assert!(message.contains("RSTR")),
            QueryFailure::Cancelled => panic!("unexpected cancellation"),
        }

        let mut packet = NtpPacket::parse(&bytes).unwrap();
        packet.stratum = 16;
        assert!(validate_packet(&packet, request).is_err());
    }

    #[test]
    fn empty_transmit_timestamp_is_rejected() {
        let request = timestamp(1, 0);
        let bytes = response_for(request, timestamp(2, 0), timestamp(0, 0));
        let packet = NtpPacket::parse(&bytes).unwrap();
        assert!(validate_packet(&packet, request).is_err());
    }

    #[test]
    fn offset_and_delay_formula() {
        let request = timestamp(100, 0);
        let t1 = request.to_unix_seconds(1_000_000_000.0);
        // Server receives after a transit time, processes the request and
        // replies; the return transit is shorter than the outbound one.
        let t2 = t1 + 0.004;
        let t3 = t2 + 0.002;
        let t4 = t3 + 0.004;
        let delay = (t4 - t1) - (t3 - t2);
        let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
        assert!((delay - 0.008).abs() < 1e-6, "delay={delay}");
        assert!(offset.abs() < 1e-6, "offset={offset}");
    }

    #[test]
    fn target_splitting() {
        assert_eq!(
            split_target("time.example.com").unwrap(),
            ("time.example.com".to_string(), NTP_PORT)
        );
        assert_eq!(
            split_target("time.example.com:1234").unwrap(),
            ("time.example.com".to_string(), 1234)
        );
        assert_eq!(
            split_target("127.0.0.1:1234").unwrap(),
            ("127.0.0.1".to_string(), 1234)
        );
        assert_eq!(
            split_target("[::1]:1234").unwrap(),
            ("::1".to_string(), 1234)
        );
        assert_eq!(split_target("::1").unwrap(), ("::1".to_string(), NTP_PORT));
    }

    #[test]
    fn short_format_to_ms() {
        assert!((short_to_ms(65_536) - 1000.0).abs() < 1e-9);
        assert_eq!(short_to_ms(0), 0.0);
    }
}
