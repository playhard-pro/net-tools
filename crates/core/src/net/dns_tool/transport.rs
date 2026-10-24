//! DNS wire transports: UDP, TCP, DNS over TLS and DNS over HTTPS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::model::{DnsProtocol, DnsResolverSpec};

/// Size of the buffer used to receive one UDP datagram.
const UDP_BUFFER: usize = 65_535;

/// Outcome of a single request: decoded message, round-trip time and transport.
pub(crate) struct Exchange {
    pub message: Message,
    pub elapsed: Duration,
    pub transport: &'static str,
}

/// Send one request over UDP (with a TCP retry on truncation) or straight over
/// TCP when forced.
pub(crate) async fn exchange(
    server: SocketAddr,
    name: &Name,
    rtype: RecordType,
    recursive: bool,
    force_tcp: bool,
    timeout: Duration,
) -> Result<Exchange, String> {
    let request = build_query(name, rtype, recursive);
    exchange_message(server, &request, force_tcp, timeout).await
}

/// Send a prepared message over UDP with a TCP fallback, or straight over TCP.
pub(crate) async fn exchange_message(
    server: SocketAddr,
    request: &Message,
    force_tcp: bool,
    timeout: Duration,
) -> Result<Exchange, String> {
    let bytes = request
        .to_vec()
        .map_err(|err| format!("failed to encode the query: {err}"))?;

    if !force_tcp {
        let started = Instant::now();
        let response = udp_exchange(server, &bytes, request.metadata.id, timeout).await?;
        let elapsed = started.elapsed();
        if !response.metadata.truncation {
            return Ok(Exchange {
                message: response,
                elapsed,
                transport: "UDP",
            });
        }
        // Truncated: fall through and retry over TCP.
    }

    let started = Instant::now();
    let response = tcp_exchange(server, &bytes, timeout).await?;
    Ok(Exchange {
        message: response,
        elapsed: started.elapsed(),
        transport: "TCP",
    })
}

/// Exchange a prepared message with the transport described by `spec`.
pub(crate) async fn exchange_spec(
    spec: &DnsResolverSpec,
    request: &Message,
    timeout: Duration,
) -> Result<Exchange, String> {
    match spec.protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => {
            let server = parse_plain_server(&spec.endpoint)?;
            exchange_message(server, request, spec.protocol == DnsProtocol::Tcp, timeout).await
        }
        DnsProtocol::Dot => {
            let (host, port) = parse_dot_endpoint(&spec.endpoint)?;
            let server = resolve_server(&host, port, timeout).await?;
            dot_exchange(server, &host, request, timeout).await
        }
        DnsProtocol::Doh => {
            let url = parse_doh_endpoint(&spec.endpoint)?;
            doh_exchange(url, request, timeout).await
        }
        DnsProtocol::Quic => {
            let (host, port) = parse_quic_endpoint(&spec.endpoint)?;
            let server = resolve_server(&host, port, timeout).await?;
            quic_exchange(server, &host, request, timeout).await
        }
    }
}

/// Parse a plain DNS server address (`IP` or `IP:port`).
pub(crate) fn parse_plain_server(value: &str) -> Result<SocketAddr, String> {
    let value = value.trim().trim_start_matches('@');
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!("invalid DNS server: {value}"))
}

/// Split a DoT endpoint into host and port.
pub(crate) fn parse_dot_endpoint(value: &str) -> Result<(String, u16), String> {
    let value = value.trim();
    let rest = value
        .strip_prefix("tls://")
        .or_else(|| value.strip_prefix("dot://"))
        .unwrap_or(value);
    if rest.is_empty() {
        return Err("the DoT endpoint is empty".to_string());
    }
    if let Ok(addr) = rest.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    if let Some((host, port)) = split_host_port(rest) {
        return Ok((host, port));
    }
    Ok((rest.trim_end_matches('.').to_string(), 853))
}

/// Split a DoQ endpoint into host and port.
pub(crate) fn parse_quic_endpoint(value: &str) -> Result<(String, u16), String> {
    let value = value.trim();
    let rest = value
        .strip_prefix("quic://")
        .or_else(|| value.strip_prefix("doq://"))
        .unwrap_or(value);
    if rest.is_empty() {
        return Err("the DoQ endpoint is empty".to_string());
    }
    if let Ok(addr) = rest.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    if let Some((host, port)) = split_host_port(rest) {
        return Ok((host, port));
    }
    Ok((rest.trim_end_matches('.').to_string(), 853))
}

/// Split a DoH endpoint into a validated URL.
pub(crate) fn parse_doh_endpoint(value: &str) -> Result<url::Url, String> {
    let value = value.trim();
    if value.starts_with("http://") {
        return Err("DoH requires an https URL".to_string());
    }
    let value = if value.starts_with("https://") {
        value.to_string()
    } else if let Some(rest) = value.strip_prefix("doh://") {
        format!("https://{rest}")
    } else {
        format!("https://{value}")
    };
    let mut url = url::Url::parse(&value).map_err(|err| format!("invalid DoH URL: {err}"))?;
    if url.scheme() != "https" {
        return Err("DoH requires an https URL".to_string());
    }
    if url.host_str().is_none() {
        return Err("the DoH URL has no host".to_string());
    }
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/dns-query");
    }
    Ok(url)
}

fn split_host_port(value: &str) -> Option<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.contains(':') {
        // A bare IPv6 address without brackets is handled by the caller.
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// Resolve a DoT server host name to a socket address.
pub(crate) async fn resolve_server(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs = tokio::time::timeout(
        timeout,
        crate::net::dns::resolve(host, crate::model::IpVersion::Auto),
    )
    .await
    .map_err(|_| format!("resolving {host} timed out"))?
    .map_err(|err| format!("failed to resolve {host}: {err}"))?;
    addrs
        .into_iter()
        .next()
        .map(|ip| SocketAddr::new(ip, port))
        .ok_or_else(|| format!("{host} has no usable address"))
}

/// Send one request over DNS over TLS.
async fn dot_exchange(
    server: SocketAddr,
    server_name: &str,
    request: &Message,
    timeout: Duration,
) -> Result<Exchange, String> {
    crate::net::ensure_crypto_provider();
    let started = Instant::now();
    let stream = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| format!("connecting to {server} timed out"))?
        .map_err(|err| format!("failed to connect to {server}: {err}"))?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| format!("invalid DoT server name: {server_name}"))?;
    let mut stream = tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| format!("TLS handshake with {server} timed out"))?
        .map_err(|err| format!("TLS handshake with {server} failed: {err}"))?;

    let bytes = request
        .to_vec()
        .map_err(|err| format!("failed to encode the query: {err}"))?;
    write_framed(&mut stream, &bytes, server, timeout).await?;
    let response = read_framed(&mut stream, server, timeout).await?;
    Ok(Exchange {
        message: response,
        elapsed: started.elapsed(),
        transport: "DoT",
    })
}

/// Send one request over DNS over QUIC (RFC 9250).
async fn quic_exchange(
    server: SocketAddr,
    server_name: &str,
    request: &Message,
    timeout: Duration,
) -> Result<Exchange, String> {
    crate::net::ensure_crypto_provider();
    let started = Instant::now();

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // RFC 9250 registers this ALPN identifier for DNS over QUIC.
    crypto.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|err| format!("failed to build the DoQ TLS configuration: {err}"))?;
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));

    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("static IPv4 bind address")
    } else {
        "[::]:0".parse().expect("static IPv6 bind address")
    };
    let mut endpoint = quinn::Endpoint::client(bind)
        .map_err(|err| format!("failed to open the DoQ socket: {err}"))?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(server, server_name)
        .map_err(|err| format!("failed to start the DoQ connection to {server}: {err}"))?;
    let connection = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| format!("the DoQ handshake with {server} timed out"))?
        .map_err(|err| format!("the DoQ handshake with {server} failed: {err}"))?;

    let (mut send, mut recv) = tokio::time::timeout(timeout, connection.open_bi())
        .await
        .map_err(|_| format!("opening a DoQ stream to {server} timed out"))?
        .map_err(|err| format!("failed to open a DoQ stream to {server}: {err}"))?;

    let bytes = request
        .to_vec()
        .map_err(|err| format!("failed to encode the query: {err}"))?;
    let length = u16::try_from(bytes.len())
        .map_err(|_| "the query is too large for DoQ framing".to_string())?;
    let mut framed = Vec::with_capacity(2 + bytes.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&bytes);
    tokio::time::timeout(timeout, send.write_all(&framed))
        .await
        .map_err(|_| format!("sending to {server} timed out"))?
        .map_err(|err| format!("failed to send to {server}: {err}"))?;
    send.finish()
        .map_err(|err| format!("failed to finish the DoQ stream to {server}: {err}"))?;

    let mut length_buffer = [0u8; 2];
    tokio::time::timeout(timeout, recv.read_exact(&mut length_buffer))
        .await
        .map_err(|_| format!("reading from {server} timed out"))?
        .map_err(|err| format!("failed to read from {server}: {err}"))?;
    let body_length = u16::from_be_bytes(length_buffer) as usize;
    let mut body = vec![0u8; body_length];
    tokio::time::timeout(timeout, recv.read_exact(&mut body))
        .await
        .map_err(|_| format!("reading from {server} timed out"))?
        .map_err(|err| format!("failed to read from {server}: {err}"))?;
    let message = Message::from_vec(&body)
        .map_err(|err| format!("failed to decode the response from {server}: {err}"))?;
    connection.close(0u32.into(), b"done");

    Ok(Exchange {
        message,
        elapsed: started.elapsed(),
        transport: "DoQ",
    })
}

/// Send one request over DNS over HTTPS.
async fn doh_exchange(
    url: url::Url,
    request: &Message,
    timeout: Duration,
) -> Result<Exchange, String> {
    crate::net::ensure_crypto_provider();
    let started = Instant::now();
    let bytes = request
        .to_vec()
        .map_err(|err| format!("failed to encode the query: {err}"))?;
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| format!("failed to build the DoH client: {err}"))?;
    let response = client
        .post(url.clone())
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(bytes)
        .send()
        .await
        .map_err(|err| format!("DoH request to {url} failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "DoH request to {url} returned HTTP {}",
            response.status()
        ));
    }
    let body = response
        .bytes()
        .await
        .map_err(|err| format!("failed to read the DoH response: {err}"))?;
    if body.len() > UDP_BUFFER {
        return Err("the DoH response is too large".to_string());
    }
    let message = Message::from_vec(&body)
        .map_err(|err| format!("failed to decode the DoH response: {err}"))?;
    Ok(Exchange {
        message,
        elapsed: started.elapsed(),
        transport: "DoH",
    })
}

/// Encoded request with EDNS enabled to keep large answers from truncating.
pub(crate) fn build_query(name: &Name, rtype: RecordType, recursive: bool) -> Message {
    let mut message = Message::query();
    message.metadata.recursion_desired = recursive;
    message.add_query(Query::query(name.clone(), rtype));
    message.set_edns(Edns::new());
    message
}

/// Send the request over UDP and decode the response.
async fn udp_exchange(
    server: SocketAddr,
    request: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Message, String> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|err| format!("failed to open a UDP socket: {err}"))?;
    socket
        .connect(server)
        .await
        .map_err(|err| format!("failed to connect to {server}: {err}"))?;
    socket
        .send(request)
        .await
        .map_err(|err| format!("failed to send to {server}: {err}"))?;

    let mut buffer = vec![0u8; UDP_BUFFER];
    let received = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .map_err(|_| format!("query to {server} timed out"))?
        .map_err(|err| format!("failed to receive from {server}: {err}"))?;
    let message = Message::from_vec(&buffer[..received])
        .map_err(|err| format!("failed to decode the response from {server}: {err}"))?;
    if message.metadata.id != id {
        return Err(format!("response from {server} has a mismatched id"));
    }
    Ok(message)
}

/// Send the request over TCP and decode the length-prefixed response.
async fn tcp_exchange(
    server: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> Result<Message, String> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| format!("connecting to {server} timed out"))?
        .map_err(|err| format!("failed to connect to {server}: {err}"))?;

    write_framed(&mut stream, request, server, timeout).await?;
    read_framed(&mut stream, server, timeout).await
}

/// Write one length-prefixed DNS message.
pub(crate) async fn write_framed<W: AsyncWrite + Unpin>(
    stream: &mut W,
    request: &[u8],
    server: SocketAddr,
    timeout: Duration,
) -> Result<(), String> {
    let length = u16::try_from(request.len())
        .map_err(|_| "the query is too large for TCP framing".to_string())?;
    let mut framed = Vec::with_capacity(2 + request.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(request);
    tokio::time::timeout(timeout, stream.write_all(&framed))
        .await
        .map_err(|_| format!("sending to {server} timed out"))?
        .map_err(|err| format!("failed to send to {server}: {err}"))?;
    Ok(())
}

/// Read one length-prefixed DNS message.
pub(crate) async fn read_framed<R: AsyncRead + Unpin>(
    stream: &mut R,
    server: SocketAddr,
    timeout: Duration,
) -> Result<Message, String> {
    let mut length_buffer = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut length_buffer))
        .await
        .map_err(|_| format!("reading from {server} timed out"))?
        .map_err(|err| format!("failed to read from {server}: {err}"))?;
    let body_length = u16::from_be_bytes(length_buffer) as usize;
    let mut body = vec![0u8; body_length];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| format!("reading from {server} timed out"))?
        .map_err(|err| format!("failed to read from {server}: {err}"))?;
    Message::from_vec(&body)
        .map_err(|err| format!("failed to decode the response from {server}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;

    #[test]
    fn plain_server_parsing_handles_defaults_and_ports() {
        assert_eq!(
            parse_plain_server("8.8.8.8").unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
        assert_eq!(
            parse_plain_server("1.1.1.1:5353").unwrap(),
            "1.1.1.1:5353".parse().unwrap()
        );
        assert_eq!(
            parse_plain_server("[2001:db8::1]:53").unwrap(),
            "[2001:db8::1]:53".parse().unwrap()
        );
        assert!(parse_plain_server("not an address").is_err());
    }

    #[test]
    fn dot_endpoint_parsing_uses_host_and_port() {
        assert_eq!(
            parse_dot_endpoint("tls://dns.google").unwrap(),
            ("dns.google".to_string(), 853)
        );
        assert_eq!(
            parse_dot_endpoint("tls://dns.google:8853").unwrap(),
            ("dns.google".to_string(), 8853)
        );
        assert_eq!(
            parse_dot_endpoint("[2001:db8::1]:853").unwrap(),
            ("2001:db8::1".to_string(), 853)
        );
    }

    #[test]
    fn quic_endpoint_parsing_uses_host_and_port() {
        assert_eq!(
            parse_quic_endpoint("quic://dns.quad9.net").unwrap(),
            ("dns.quad9.net".to_string(), 853)
        );
        assert_eq!(
            parse_quic_endpoint("doq://dns.quad9.net:8853").unwrap(),
            ("dns.quad9.net".to_string(), 8853)
        );
    }

    #[test]
    fn doh_endpoint_parsing_normalizes_scheme_and_path() {
        let url = parse_doh_endpoint("dns.google").unwrap();
        assert_eq!(url.as_str(), "https://dns.google/dns-query");
        let url = parse_doh_endpoint("https://dns.google/custom").unwrap();
        assert_eq!(url.as_str(), "https://dns.google/custom");
        assert!(parse_doh_endpoint("http://dns.google").is_err());
    }

    #[test]
    fn query_messages_round_trip_through_wire_encoding() {
        let name = Name::from_ascii("example.com.").unwrap();
        let query = build_query(&name, RecordType::A, true);
        let bytes = query.to_vec().unwrap();
        let decoded = Message::from_vec(&bytes).unwrap();
        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].query_type(), RecordType::A);
        assert!(decoded.metadata.recursion_desired);
    }
}
