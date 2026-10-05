//! HTTP probing (multiple methods, per-stage timing). The client is implemented
//! manually to obtain precise DNS / connect / TLS / TTFB / total timings.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::config::HttpSettings;
use crate::control::ProbeHandle;
use crate::model::{HttpResult, ProbeEvent};
use crate::net::dns;

const MAX_BODY: usize = 1024 * 1024; // 1 MiB
const MAX_REDIRECTS: usize = 5;

/// Read/write interface unifying plain TCP and TLS streams.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
type BoxConn = Box<dyn AsyncStream>;

/// Continuous HTTP probing until cancelled.
pub async fn run_http(handle: &ProbeHandle<ProbeEvent>, settings: &HttpSettings) {
    let start_url = match Url::parse(settings.target.trim()) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => u,
        _ => {
            handle.send(ProbeEvent::Error {
                message: format!("invalid URL: {}", settings.target),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };

    let mut seq: u64 = 0;
    loop {
        if handle.is_cancelled() {
            break;
        }
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            break;
        }

        let result = probe_once(&start_url, settings, seq).await;
        handle.send(ProbeEvent::Http(result));

        seq = seq.wrapping_add(1);
        if handle
            .sleep(Duration::from_millis(settings.interval_ms))
            .await
        {
            break;
        }
    }

    handle.send(ProbeEvent::Finished);
}

async fn probe_once(start_url: &Url, settings: &HttpSettings, seq: u64) -> HttpResult {
    let overall = Instant::now();
    let mut url = start_url.clone();

    for _ in 0..=MAX_REDIRECTS {
        match request_once(&url, settings).await {
            Ok(mut r) => {
                r.total_ms = overall.elapsed().as_secs_f64() * 1000.0;
                // Follow redirects.
                if settings.follow_redirects
                    && matches!(r.status, Some(300..=399))
                    && r.location.is_some()
                {
                    if let Some(loc) = r.location.take() {
                        if let Ok(next) = url.join(&loc) {
                            url = next;
                            continue;
                        }
                    }
                }
                return HttpResult {
                    seq,
                    ok: r.ok,
                    method: r.method,
                    url: r.url,
                    status: r.status,
                    dns_ms: r.dns_ms,
                    connect_ms: r.connect_ms,
                    tls_ms: r.tls_ms,
                    ttfb_ms: r.ttfb_ms,
                    total_ms: r.total_ms,
                    body_bytes: r.body_bytes,
                    error: r.error,
                };
            }
            Err(e) => {
                return HttpResult {
                    seq,
                    ok: false,
                    method: settings.method.clone(),
                    url: url.to_string(),
                    status: None,
                    dns_ms: 0.0,
                    connect_ms: 0.0,
                    tls_ms: None,
                    ttfb_ms: 0.0,
                    total_ms: overall.elapsed().as_secs_f64() * 1000.0,
                    body_bytes: 0,
                    error: Some(e),
                };
            }
        }
    }

    HttpResult {
        seq,
        ok: false,
        method: settings.method.clone(),
        url: url.to_string(),
        status: None,
        dns_ms: 0.0,
        connect_ms: 0.0,
        tls_ms: None,
        ttfb_ms: 0.0,
        total_ms: overall.elapsed().as_secs_f64() * 1000.0,
        body_bytes: 0,
        error: Some("too many redirects".into()),
    }
}

struct RequestResult {
    ok: bool,
    method: String,
    url: String,
    status: Option<u16>,
    dns_ms: f64,
    connect_ms: f64,
    tls_ms: Option<f64>,
    ttfb_ms: f64,
    total_ms: f64,
    body_bytes: usize,
    error: Option<String>,
    location: Option<String>,
}

async fn request_once(url: &Url, settings: &HttpSettings) -> Result<RequestResult, String> {
    let host = url.host_str().ok_or("URL has no host")?.to_string();
    let port = url
        .port_or_known_default()
        .ok_or("unknown port for scheme")?;
    let https = url.scheme() == "https";

    // DNS (timed).
    let t0 = Instant::now();
    let addrs = dns::resolve(&host, settings.ip_version)
        .await
        .map_err(|e| format!("DNS failed: {e}"))?;
    let ip = *addrs.first().ok_or("no address resolved")?;
    let dns_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // PTR lookup, when enabled; does not affect the main flow.
    if settings.reverse_dns {
        if let Some(name) = dns::reverse(ip).await {
            tracing::debug!("reverse: {ip} -> {name}");
        }
    }

    // TCP connect (timed).
    let t0 = Instant::now();
    let stream = TcpStream::connect((ip, port))
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    let connect_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // TLS (timed).
    let (tls_ms, mut conn): (Option<f64>, BoxConn) = if https {
        let t0 = Instant::now();
        let config = tls_config(settings.verify_tls);
        let connector = TlsConnector::from(Arc::new(config));
        let server_name =
            ServerName::try_from(host.clone()).map_err(|e| format!("invalid server name: {e}"))?;
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS failed: {e}"))?;
        (Some(t0.elapsed().as_secs_f64() * 1000.0), Box::new(tls))
    } else {
        (None, Box::new(stream))
    };

    // Build the request.
    let path = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    let path = match url.query() {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    let method = settings.method.trim().to_uppercase();
    let host_header = if (https && port == 443) || (!https && port == 80) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: net-tools/0.1\r\nConnection: close\r\nAccept: */*\r\n"
    );
    for line in settings.headers.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains(':') {
            continue;
        }
        req.push_str(line);
        req.push_str("\r\n");
    }
    if !settings.body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", settings.body.len()));
    }
    req.push_str("\r\n");
    req.push_str(&settings.body);

    // Send and time the TTFB.
    conn.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("send failed: {e}"))?;

    let t0 = Instant::now();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = conn
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() >= MAX_BODY {
            break;
        }
    }
    let ttfb_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // Parse the response and check expectations.
    let (status, location) = parse_status_and_location(&buf);
    let mut ok = true;
    if let Some(expect) = settings.expect_status {
        if status != Some(expect) {
            ok = false;
        }
    }
    if let Some(kw) = &settings.expect_keyword {
        if !String::from_utf8_lossy(&buf).contains(kw.as_str()) {
            ok = false;
        }
    }

    Ok(RequestResult {
        ok,
        method,
        url: url.to_string(),
        status,
        dns_ms,
        connect_ms,
        tls_ms,
        ttfb_ms,
        total_ms: 0.0,
        body_bytes: buf.len(),
        error: None,
        location,
    })
}

fn parse_status_and_location(buf: &[u8]) -> (Option<u16>, Option<String>) {
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    let location = lines
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .map(|l| l[9..].trim().to_string());
    (status, location)
}

fn tls_config(verify: bool) -> rustls::ClientConfig {
    if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
