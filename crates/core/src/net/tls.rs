//! TLS certificate, protocol and security checks.
//!
//! The module parses user supplied targets and checks certificate metadata,
//! negotiated TLS parameters, revocation status, HSTS, Certificate Transparency
//! and CAA records.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use der::{Decode, Encode};
use pkix_revocation::{CrlChecker, OcspChecker, RevocationChecker};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use crate::config::TlsSettings;
use crate::control::ProbeHandle;
use crate::model::ProbeEvent;
use crate::net::dns;

/// Verification result and stapled OCSP bytes recorded during a handshake.
#[derive(Debug, Clone, Default)]
pub struct VerificationRecord {
    /// Outcome reported by the real WebPKI verifier.
    pub result: Option<Result<(), String>>,
    /// Raw stapled OCSP response, when the server provided one.
    pub ocsp_response: Vec<u8>,
}

/// Certificate verifier that performs real validation but always lets the
/// handshake continue, so invalid certificates can still be inspected.
#[derive(Clone)]
pub struct RecordingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    record: Arc<Mutex<VerificationRecord>>,
}

impl std::fmt::Debug for RecordingVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingVerifier").finish_non_exhaustive()
    }
}

impl RecordingVerifier {
    /// Build a verifier backed by the bundled WebPKI root store.
    pub fn new() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("bundled roots are valid");
        Self::with_inner(inner)
    }

    fn with_inner(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            inner,
            record: Arc::new(Mutex::new(VerificationRecord::default())),
        }
    }

    /// Shared record filled in during the handshake.
    pub fn record(&self) -> Arc<Mutex<VerificationRecord>> {
        self.record.clone()
    }
}

impl Default for RecordingVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let outcome = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map(|_| ())
            .map_err(|error| format!("{error:?}"));
        if let Ok(mut record) = self.record.lock() {
            record.result = Some(outcome);
            record.ocsp_response = ocsp_response.to_vec();
        }
        // The handshake must continue even for an invalid certificate. The
        // recorded outcome is what the UI reports to the user.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A parsed TLS target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsTarget {
    /// Target as entered by the user, used as the result label.
    pub target: String,
    /// Normalized DNS name or IP address without brackets.
    pub host: String,
    pub port: u16,
}

/// Parse a target list containing newline or comma separated entries.
///
/// Empty lines and lines starting with `#` are ignored. Each entry accepts a
/// host name, `host:port`, `[IPv6]:port`, a bare IPv6 address, or a URL whose
/// scheme and path are ignored.
pub fn parse_targets(input: &str, default_port: u16) -> Vec<TlsTarget> {
    let mut targets = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for item in line.split(',') {
            if let Some(target) = parse_target(item.trim(), default_port) {
                targets.push(target);
            }
        }
    }
    targets
}

fn parse_target(input: &str, default_port: u16) -> Option<TlsTarget> {
    if input.is_empty() {
        return None;
    }

    if input.contains("://") {
        let url = Url::parse(input).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let host = url.host_str()?;
        let port = url.port().unwrap_or(default_port);
        let host = normalize_host(host)?;
        return Some(TlsTarget {
            target: input.to_string(),
            host,
            port,
        });
    }

    let (raw_host, port) = split_host_port(input, default_port)?;
    let host = normalize_host(&raw_host)?;
    Some(TlsTarget {
        target: input.to_string(),
        host,
        port,
    })
}

/// Split `host`, `host:port`, `[IPv6]` or `[IPv6]:port`.
fn split_host_port(input: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = if tail.is_empty() {
            default_port
        } else {
            let value = tail.strip_prefix(':')?;
            value.parse::<u16>().ok()?
        };
        return Some((host.to_string(), port));
    }

    // A bare IPv6 address contains multiple colons and has no port suffix.
    if input.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some((input.to_string(), default_port));
    }

    match input.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => {
            Some((host.to_string(), port.parse::<u16>().ok()?))
        }
        Some(_) => None,
        None => Some((input.to_string(), default_port)),
    }
}

/// Normalize a host name through the URL parser, which also converts IDN
/// labels to their ASCII form.
fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    match Host::parse(host).ok()? {
        Host::Domain(domain) => {
            if domain.is_empty() {
                None
            } else {
                Some(domain)
            }
        }
        Host::Ipv4(ip) => Some(ip.to_string()),
        Host::Ipv6(ip) => Some(ip.to_string()),
    }
}

const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Negotiated parameters and raw certificate data from one handshake.
#[derive(Debug, Clone, Default)]
struct HandshakeInfo {
    protocol: Option<String>,
    cipher_suite: Option<String>,
    key_exchange: Option<String>,
    alpn: Option<String>,
    certs: Vec<Vec<u8>>,
    chain_result: Option<Result<(), String>>,
    ocsp_response: Vec<u8>,
}

/// Build a client config that records certificate validation while allowing
/// the handshake to proceed.
fn client_config(
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
    alpn: &[&[u8]],
) -> (Arc<rustls::ClientConfig>, Arc<Mutex<VerificationRecord>>) {
    crate::net::ensure_crypto_provider();
    let verifier = RecordingVerifier::new();
    let record = verifier.record();
    let builder = match versions {
        Some(versions) => rustls::ClientConfig::builder_with_protocol_versions(versions),
        None => rustls::ClientConfig::builder(),
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    (Arc::new(config), record)
}

/// Run a future with the configured timeout and cancellation check.
async fn with_limits<T>(
    handle: &ProbeHandle<ProbeEvent>,
    timeout: Duration,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::select! {
        _ = handle.cancelled() => Err("cancelled".into()),
        result = tokio::time::timeout(timeout, future) => match result {
            Ok(value) => value,
            Err(_) => Err("timed out".into()),
        },
    }
}

fn protocol_label(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        other => format!("{other:?}"),
    }
}

/// Connect, complete a TLS handshake and extract negotiated parameters.
async fn handshake(
    handle: &ProbeHandle<ProbeEvent>,
    host: &str,
    ip: std::net::IpAddr,
    port: u16,
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
    alpn: &[&[u8]],
    timeout: Duration,
) -> Result<(TlsStream<TcpStream>, HandshakeInfo), String> {
    let tcp = with_limits(handle, timeout, async {
        TcpStream::connect((ip, port))
            .await
            .map_err(|error| format!("connect failed: {error}"))
    })
    .await?;

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|error| format!("invalid server name: {error}"))?;
    let (config, record) = client_config(versions, alpn);
    let connector = TlsConnector::from(config);
    let stream = with_limits(handle, timeout, async {
        connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| format!("TLS failed: {error}"))
    })
    .await?;

    let (chain_result, ocsp_response) = record
        .lock()
        .map(|value| (value.result.clone(), value.ocsp_response.clone()))
        .unwrap_or((None, Vec::new()));
    let (_, connection) = stream.get_ref();
    let info = HandshakeInfo {
        protocol: connection.protocol_version().map(protocol_label),
        cipher_suite: connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        key_exchange: connection
            .negotiated_key_exchange_group()
            .map(|group| format!("{:?}", group.name())),
        alpn: connection
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).into_owned()),
        certs: connection
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect(),
        chain_result,
        ocsp_response,
    };
    Ok((stream, info))
}

/// Check whether a server accepts a handshake restricted to given versions.
async fn supports_versions(
    handle: &ProbeHandle<ProbeEvent>,
    ip: std::net::IpAddr,
    host: &str,
    port: u16,
    versions: &[&'static rustls::SupportedProtocolVersion],
    timeout: Duration,
) -> bool {
    handshake(handle, host, ip, port, Some(versions), &[], timeout)
        .await
        .is_ok()
}

/// Perform a handshake that offers the supplied ALPN protocols.
async fn probe_alpn(
    handle: &ProbeHandle<ProbeEvent>,
    ip: std::net::IpAddr,
    host: &str,
    port: u16,
    alpn: &[&[u8]],
    timeout: Duration,
) -> Result<Option<String>, String> {
    handshake(handle, host, ip, port, None, alpn, timeout)
        .await
        .map(|(_, info)| info.alpn)
}

/// TLS version and ALPN capabilities discovered by dedicated handshakes.
#[derive(Debug, Clone, Default)]
struct Capabilities {
    tls12: Option<bool>,
    tls13: Option<bool>,
    alpn_negotiated: Option<String>,
    alpn_h2: Option<bool>,
    alpn_http1: Option<bool>,
}

async fn probe_capabilities(
    handle: &ProbeHandle<ProbeEvent>,
    host: &str,
    ip: std::net::IpAddr,
    port: u16,
    settings: &TlsSettings,
    timeout: Duration,
) -> Capabilities {
    let mut capabilities = Capabilities::default();
    if settings.probe_versions {
        capabilities.tls12 = Some(
            supports_versions(handle, ip, host, port, &[&rustls::version::TLS12], timeout).await,
        );
        capabilities.tls13 = Some(
            supports_versions(handle, ip, host, port, &[&rustls::version::TLS13], timeout).await,
        );
    }

    if settings.probe_alpn {
        let combined = probe_alpn(handle, ip, host, port, &[ALPN_H2, ALPN_HTTP11], timeout).await;
        if let Ok(Some(selected)) = combined {
            capabilities.alpn_negotiated = Some(selected.clone());
            let (supported, other): (bool, &[&[u8]]) = if selected == "h2" {
                (true, &[ALPN_HTTP11])
            } else if selected == "http/1.1" {
                (true, &[ALPN_H2])
            } else {
                (false, &[])
            };
            if supported {
                let other_supported = probe_alpn(handle, ip, host, port, other, timeout)
                    .await
                    .ok()
                    .flatten()
                    .is_some();
                if selected == "h2" {
                    capabilities.alpn_h2 = Some(true);
                    capabilities.alpn_http1 = Some(other_supported);
                } else {
                    capabilities.alpn_http1 = Some(true);
                    capabilities.alpn_h2 = Some(other_supported);
                }
            }
        }
    }
    capabilities
}

const MAX_AUX_BODY: usize = 4 * 1024 * 1024;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

/// OCSP responder URLs declared in the certificate AIA extension.
fn ocsp_urls(der: &[u8]) -> Vec<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP;
    use x509_parser::prelude::*;

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = extension.parsed_extension() {
            for description in aia.iter() {
                if description.access_method == OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
                    if let GeneralName::URI(uri) = description.access_location {
                        urls.push(uri.to_string());
                    }
                }
            }
        }
    }
    urls
}

/// CRL distribution point URLs declared in the certificate.
fn crl_urls(der: &[u8]) -> Vec<String> {
    use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
    use x509_parser::prelude::*;

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() {
            for point in points.iter() {
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            urls.push(uri.to_string());
                        }
                    }
                }
            }
        }
    }
    urls
}

fn build_ocsp_request(leaf_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, String> {
    let leaf = x509_cert::Certificate::from_der(leaf_der)
        .map_err(|error| format!("leaf certificate parse failed: {error}"))?;
    let issuer = x509_cert::Certificate::from_der(issuer_der)
        .map_err(|error| format!("issuer certificate parse failed: {error}"))?;
    let request = x509_ocsp::Request::from_cert::<sha1::Sha1>(&issuer, &leaf)
        .map_err(|error| format!("OCSP request build failed: {error}"))?;
    x509_ocsp::builder::OcspRequestBuilder::default()
        .with_request(request)
        .build()
        .to_der()
        .map_err(|error| format!("OCSP request encode failed: {error}"))
}

/// Fetch a URL and enforce a response body limit.
async fn fetch_limited(request: reqwest::RequestBuilder) -> Result<Vec<u8>, String> {
    let response = request
        .send()
        .await
        .map_err(|error| format!("HTTP request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("HTTP status {}", response.status()));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("response read failed: {error}"))?
    {
        if body.len() + chunk.len() > MAX_AUX_BODY {
            return Err("response body exceeds size limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn revocation_error(error: &pkix_revocation::Error) -> (crate::model::RevocationStatus, String) {
    use crate::model::RevocationStatus;
    match error {
        pkix_revocation::Error::OcspStatusUnknown => (
            RevocationStatus::Unknown,
            "responder returned unknown status".into(),
        ),
        pkix_revocation::Error::OcspExpired | pkix_revocation::Error::CrlExpired => (
            RevocationStatus::Unknown,
            "response is stale or has no nextUpdate".into(),
        ),
        other => (RevocationStatus::Error, format!("{other}")),
    }
}

fn check_ocsp_response(
    response: &[u8],
    leaf_der: &[u8],
    issuer_der: &[u8],
) -> (
    crate::model::RevocationStatus,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    use crate::model::RevocationStatus;

    let leaf = match x509_cert::Certificate::from_der(leaf_der) {
        Ok(value) => value,
        Err(error) => {
            return (
                RevocationStatus::Error,
                Some(format!("leaf certificate parse failed: {error}")),
                None,
                None,
            )
        }
    };
    let issuer = match x509_cert::Certificate::from_der(issuer_der) {
        Ok(value) => value,
        Err(error) => {
            return (
                RevocationStatus::Error,
                Some(format!("issuer certificate parse failed: {error}")),
                None,
                None,
            )
        }
    };
    let checker = match OcspChecker::new(response, now_unix(), pkix_path::DefaultVerifier) {
        Ok(value) => value,
        Err(error) => {
            let (status, detail) = revocation_error(&error);
            return (status, Some(detail), None, None);
        }
    };
    match checker.check_revocation(&leaf, &issuer) {
        Ok(()) => (RevocationStatus::Good, None, None, None),
        Err(pkix_revocation::Error::Revoked { reason_code, .. }) => (
            RevocationStatus::Revoked,
            Some(format!("reason: {reason_code:?}")),
            None,
            None,
        ),
        Err(error) => {
            let (status, detail) = revocation_error(&error);
            (status, Some(detail), None, None)
        }
    }
}

fn check_crl_response(
    response: &[u8],
    leaf_der: &[u8],
    issuer_der: &[u8],
) -> (
    crate::model::RevocationStatus,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    use crate::model::RevocationStatus;

    let (this_update, next_update) = {
        use x509_parser::prelude::FromDer;
        use x509_parser::revocation_list::CertificateRevocationList;
        match CertificateRevocationList::from_der(response) {
            Ok((_, crl)) => (
                Some(format_utc(crl.last_update().timestamp())),
                crl.next_update().map(|value| format_utc(value.timestamp())),
            ),
            Err(_) => (None, None),
        }
    };

    let leaf = match x509_cert::Certificate::from_der(leaf_der) {
        Ok(value) => value,
        Err(error) => {
            return (
                RevocationStatus::Error,
                Some(format!("leaf certificate parse failed: {error}")),
                this_update,
                next_update,
            )
        }
    };
    let issuer = match x509_cert::Certificate::from_der(issuer_der) {
        Ok(value) => value,
        Err(error) => {
            return (
                RevocationStatus::Error,
                Some(format!("issuer certificate parse failed: {error}")),
                this_update,
                next_update,
            )
        }
    };
    let checker = match CrlChecker::new(response, now_unix(), pkix_path::DefaultVerifier) {
        Ok(value) => value,
        Err(error) => {
            let (status, detail) = revocation_error(&error);
            return (status, Some(detail), this_update, next_update);
        }
    };
    match checker.check_revocation(&leaf, &issuer) {
        Ok(()) => (RevocationStatus::Good, None, this_update, next_update),
        Err(pkix_revocation::Error::Revoked { reason_code, .. }) => (
            RevocationStatus::Revoked,
            Some(format!("reason: {reason_code:?}")),
            this_update,
            next_update,
        ),
        Err(error) => {
            let (status, detail) = revocation_error(&error);
            (status, Some(detail), this_update, next_update)
        }
    }
}

/// Check revocation using stapled OCSP, active OCSP and CRL in that order.
async fn check_revocation(
    leaf_der: Option<&[u8]>,
    issuer_der: Option<&[u8]>,
    stapled: &[u8],
    timeout: Duration,
) -> crate::model::RevocationCheck {
    use crate::model::{RevocationCheck, RevocationStatus};

    let mut result = RevocationCheck::default();
    let (Some(leaf), Some(issuer)) = (leaf_der, issuer_der) else {
        result.detail = Some("issuer certificate was not sent by the server".into());
        return result;
    };

    if !stapled.is_empty() {
        let (status, detail, _, _) = check_ocsp_response(stapled, leaf, issuer);
        result.status = status;
        result.source = Some("stapled OCSP".into());
        result.detail = detail;
        if matches!(status, RevocationStatus::Good | RevocationStatus::Revoked) {
            return result;
        }
    }

    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(value) => value,
        Err(error) => {
            result.status = RevocationStatus::Error;
            result.detail = Some(format!("HTTP client build failed: {error}"));
            return result;
        }
    };

    let ocsp_request = build_ocsp_request(leaf, issuer).ok();
    if let Some(request_der) = ocsp_request {
        for url in ocsp_urls(leaf) {
            let fetched = if request_der.len() <= 255 {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&request_der);
                let encoded = percent_encoding::percent_encode(
                    encoded.as_bytes(),
                    percent_encoding::NON_ALPHANUMERIC,
                )
                .to_string();
                let request_url = format!("{}/{}", url.trim_end_matches('/'), encoded);
                fetch_limited(client.get(request_url)).await
            } else {
                fetch_limited(
                    client
                        .post(url)
                        .header("Content-Type", "application/ocsp-request")
                        .body(request_der.clone()),
                )
                .await
            };
            match fetched {
                Ok(response) => {
                    let (status, detail, _, _) = check_ocsp_response(&response, leaf, issuer);
                    result.status = status;
                    result.source = Some("OCSP".into());
                    result.detail = detail;
                    if matches!(status, RevocationStatus::Good | RevocationStatus::Revoked) {
                        return result;
                    }
                }
                Err(error) => {
                    result.status = RevocationStatus::Unavailable;
                    result.source = Some("OCSP".into());
                    result.detail = Some(error);
                }
            }
        }
    }

    for url in crl_urls(leaf) {
        match fetch_limited(client.get(url)).await {
            Ok(response) => {
                let (status, detail, this_update, next_update) =
                    check_crl_response(&response, leaf, issuer);
                result.status = status;
                result.source = Some("CRL".into());
                result.detail = detail;
                result.this_update = this_update;
                result.next_update = next_update;
                if matches!(status, RevocationStatus::Good | RevocationStatus::Revoked) {
                    return result;
                }
            }
            Err(error) => {
                result.status = RevocationStatus::Unavailable;
                result.source = Some("CRL".into());
                result.detail = Some(error);
            }
        }
    }

    if result.source.is_none() {
        result.status = RevocationStatus::Unavailable;
        result.source = Some("none".into());
        result.detail = Some("no OCSP or CRL endpoint declared".into());
    }
    result
}

/// Parse a `Strict-Transport-Security` header value.
fn parse_hsts_header(value: &str) -> crate::model::HstsCheck {
    let mut check = crate::model::HstsCheck {
        present: true,
        header: Some(value.trim().to_string()),
        ..Default::default()
    };
    for directive in value.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }
        let (name, argument) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| {
                (name, Some(value.trim()))
            });
        match name.trim().to_ascii_lowercase().as_str() {
            "max-age" => match argument.and_then(|value| value.parse::<u64>().ok()) {
                Some(value) => check.max_age = Some(value),
                None => check.error = Some("invalid max-age directive".into()),
            },
            "includesubdomains" => check.include_subdomains = true,
            "preload" => check.preload = true,
            _ => {}
        }
    }
    check.enabled = check.max_age.unwrap_or(0) > 0;
    check
}

/// Send a HEAD request on the established TLS stream and parse HSTS.
async fn check_hsts(
    handle: &ProbeHandle<ProbeEvent>,
    stream: &mut TlsStream<TcpStream>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> crate::model::HstsCheck {
    let host_header = match (host.parse::<std::net::Ipv6Addr>(), port == 443) {
        (Ok(_), true) => format!("[{host}]"),
        (Ok(_), false) => format!("[{host}]:{port}"),
        (Err(_), true) => host.to_string(),
        (Err(_), false) => format!("{host}:{port}"),
    };
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: net-tools\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if let Err(error) = with_limits(handle, timeout, async {
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("HEAD send failed: {error}"))
    })
    .await
    {
        return crate::model::HstsCheck {
            error: Some(error),
            ..Default::default()
        };
    }

    let response = with_limits(handle, timeout, async {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|error| format!("HEAD read failed: {error}"))?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() > 64 * 1024 {
                break;
            }
        }
        Ok::<_, String>(buffer)
    })
    .await;

    let response = match response {
        Ok(value) => value,
        Err(error) => {
            return crate::model::HstsCheck {
                error: Some(error),
                ..Default::default()
            }
        }
    };
    let text = String::from_utf8_lossy(&response);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok());
    let header = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("strict-transport-security")
            .then(|| value.trim().to_string())
    });
    match header {
        Some(value) => {
            let mut check = parse_hsts_header(&value);
            check.status = status;
            check
        }
        None => crate::model::HstsCheck {
            status,
            ..Default::default()
        },
    }
}

/// Re-encode a parsed SCT without the TLS list length prefix, as expected by
/// the `sct` verifier.
fn encode_sct(sct: &x509_parser::extensions::SignedCertificateTimestamp<'_>) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(sct.version.0);
    encoded.extend_from_slice(sct.id.key_id);
    encoded.extend_from_slice(&sct.timestamp.to_be_bytes());
    encoded.extend_from_slice(&(sct.extensions.0.len() as u16).to_be_bytes());
    encoded.extend_from_slice(sct.extensions.0);
    encoded.push(sct.signature.hash_alg_id);
    encoded.push(sct.signature.sign_alg_id);
    encoded.extend_from_slice(&(sct.signature.data.len() as u16).to_be_bytes());
    encoded.extend_from_slice(sct.signature.data);
    encoded
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Inspect embedded SCTs and verify their signatures against bundled logs.
fn check_ct(leaf_der: &[u8]) -> crate::model::CtCheck {
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::*;

    let (_, cert) = match X509Certificate::from_der(leaf_der) {
        Ok(value) => value,
        Err(error) => {
            return crate::model::CtCheck {
                error: Some(format!("certificate parse failed: {error}")),
                ..Default::default()
            }
        }
    };

    let mut check = crate::model::CtCheck::default();
    for extension in cert.extensions() {
        let ParsedExtension::SCT(scts) = extension.parsed_extension() else {
            continue;
        };
        check.sct_count = scts.len();
        for sct in scts {
            check.log_ids.push(hex_bytes(sct.id.key_id));
            let encoded = encode_sct(sct);
            match sct::verify_sct(leaf_der, &encoded, now_unix(), ct_logs::LOGS) {
                Ok(_) => check.verified += 1,
                Err(sct::Error::UnknownLog) | Err(sct::Error::UnsupportedSctVersion) => {
                    check.unknown_logs += 1;
                }
                Err(_) => check.invalid += 1,
            }
        }
        break;
    }
    check
}

/// Look up the effective CAA policy for a domain, walking up parent labels.
async fn check_caa(
    handle: &ProbeHandle<ProbeEvent>,
    host: &str,
    timeout: Duration,
) -> crate::model::CaaCheck {
    use hickory_resolver::proto::rr::domain::Name;
    use hickory_resolver::proto::rr::{RData, RecordType};
    use hickory_resolver::TokioResolver;

    if host.parse::<std::net::IpAddr>().is_ok() {
        return crate::model::CaaCheck {
            error: Some("CAA applies to domain names only".into()),
            ..Default::default()
        };
    }

    let resolver = match TokioResolver::builder_tokio().and_then(|builder| builder.build()) {
        Ok(value) => value,
        Err(error) => {
            return crate::model::CaaCheck {
                error: Some(format!("resolver build failed: {error}")),
                ..Default::default()
            }
        }
    };
    let mut name = match Name::from_utf8(format!("{host}.")) {
        Ok(value) => value,
        Err(error) => {
            return crate::model::CaaCheck {
                error: Some(format!("invalid DNS name: {error}")),
                ..Default::default()
            }
        }
    };

    loop {
        let source = name.to_string();
        let lookup = tokio::select! {
            _ = handle.cancelled() => {
                return crate::model::CaaCheck {
                    error: Some("cancelled".into()),
                    ..Default::default()
                }
            }
            result = tokio::time::timeout(
                timeout,
                resolver.lookup(name.clone(), RecordType::CAA),
            ) => match result {
                Ok(Ok(value)) => Some(value),
                // A missing RRset is expected while walking to the parent.
                Ok(Err(error)) if error.is_no_records_found() => None,
                Ok(Err(error)) => {
                    return crate::model::CaaCheck {
                        error: Some(format!("CAA lookup failed for {source}: {error}")),
                        ..Default::default()
                    }
                }
                Err(_) => {
                    return crate::model::CaaCheck {
                        error: Some(format!("CAA lookup timed out for {source}")),
                        ..Default::default()
                    }
                }
            }
        };
        if let Some(lookup) = lookup {
            let mut records = Vec::new();
            for record in lookup.answers() {
                if let RData::CAA(caa) = &record.data {
                    records.push(crate::model::CaaRecordInfo {
                        flags: caa.reserved_flags | if caa.issuer_critical { 0x80 } else { 0 },
                        tag: caa.tag.clone(),
                        value: String::from_utf8_lossy(&caa.value).into_owned(),
                        critical: caa.issuer_critical,
                    });
                }
            }
            if !records.is_empty() {
                return crate::model::CaaCheck {
                    source: Some(source.trim_end_matches('.').to_string()),
                    records,
                    error: None,
                };
            }
        }
        if name.is_root() {
            break;
        }
        name = name.base_name();
    }
    crate::model::CaaCheck::default()
}

/// Hard upper bound for concurrent target checks.
pub const MAX_CONCURRENCY: usize = 10;

/// Clamp a configured concurrency value to the safe range.
fn effective_concurrency(value: usize) -> usize {
    value.clamp(1, MAX_CONCURRENCY)
}

fn failed_result(
    index: usize,
    target: &TlsTarget,
    error: String,
    elapsed_ms: f64,
) -> crate::model::TlsResult {
    crate::model::TlsResult {
        index,
        target: target.target.clone(),
        host: target.host.clone(),
        port: target.port,
        resolved_ip: None,
        elapsed_ms,
        protocol: None,
        cipher_suite: None,
        key_exchange: None,
        alpn_negotiated: None,
        alpn_h2_supported: None,
        alpn_http1_supported: None,
        tls12_supported: None,
        tls13_supported: None,
        chain_valid: false,
        chain_error: None,
        health: crate::model::TlsHealth::Error,
        certs: Vec::new(),
        security: Default::default(),
        error: Some(error),
    }
}

fn classify_health(
    chain_valid: bool,
    chain_error: &Option<String>,
    leaf_days: Option<i64>,
    warn_days: u32,
    revoked: bool,
) -> crate::model::TlsHealth {
    use crate::model::TlsHealth;

    if revoked {
        return TlsHealth::Revoked;
    }
    if let Some(days) = leaf_days {
        if days < 0 {
            return TlsHealth::Expired;
        }
    }
    if let Some(error) = chain_error {
        if error.contains("NotValidForName") {
            return TlsHealth::HostnameMismatch;
        }
    }
    if !chain_valid {
        return TlsHealth::Untrusted;
    }
    if leaf_days.is_some_and(|days| days <= warn_days as i64) {
        return TlsHealth::ExpiringSoon;
    }
    TlsHealth::Ok
}

/// Check one target and return a result even when the connection fails.
async fn check_target(
    handle: &ProbeHandle<ProbeEvent>,
    index: usize,
    target: TlsTarget,
    settings: &TlsSettings,
) -> crate::model::TlsResult {
    use crate::model::{TlsHealth, TlsResult, TlsSecurity};

    let started = Instant::now();
    let timeout = Duration::from_millis(settings.timeout_ms.clamp(100, 120_000));

    let addresses = match with_limits(handle, timeout, async {
        dns::resolve(&target.host, settings.ip_version)
            .await
            .map_err(|error| format!("DNS failed: {error}"))
    })
    .await
    {
        Ok(value) => value,
        Err(error) => {
            return failed_result(
                index,
                &target,
                error,
                started.elapsed().as_secs_f64() * 1000.0,
            )
        }
    };
    let Some(ip) = addresses.first().copied() else {
        return failed_result(
            index,
            &target,
            "no address resolved".into(),
            started.elapsed().as_secs_f64() * 1000.0,
        );
    };

    let (mut stream, info) =
        match handshake(handle, &target.host, ip, target.port, None, &[], timeout).await {
            Ok(value) => value,
            Err(error) => {
                let mut result = failed_result(
                    index,
                    &target,
                    error,
                    started.elapsed().as_secs_f64() * 1000.0,
                );
                result.resolved_ip = Some(ip.to_string());
                return result;
            }
        };

    let certs = match parse_cert_chain(&info.certs) {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => {
            return failed_result(
                index,
                &target,
                "server did not send a certificate".into(),
                started.elapsed().as_secs_f64() * 1000.0,
            )
        }
        Err(error) => {
            return failed_result(
                index,
                &target,
                error,
                started.elapsed().as_secs_f64() * 1000.0,
            )
        }
    };

    let chain_valid = matches!(info.chain_result, Some(Ok(())));
    let chain_error = match &info.chain_result {
        Some(Ok(())) => None,
        Some(Err(error)) => Some(error.clone()),
        None => Some("certificate verification did not complete".into()),
    };

    let mut security = TlsSecurity::default();
    if settings.check_hsts {
        security.hsts = check_hsts(handle, &mut stream, &target.host, target.port, timeout).await;
        if !chain_valid && security.hsts.error.is_none() {
            security.hsts.error =
                Some("the HSTS header was read, but the certificate chain is not trusted".into());
        }
    }
    drop(stream);

    let capabilities =
        probe_capabilities(handle, &target.host, ip, target.port, settings, timeout).await;

    let leaf_der = info.certs.first().map(Vec::as_slice);
    let issuer_der = info.certs.get(1).map(Vec::as_slice);
    if settings.check_revocation {
        security.revocation =
            check_revocation(leaf_der, issuer_der, &info.ocsp_response, timeout).await;
        if !chain_valid && security.revocation.detail.is_none() {
            security.revocation.detail =
                Some("chain is not trusted; revocation result is informational only".into());
        }
    }
    if settings.check_ct {
        if let Some(leaf) = leaf_der {
            security.ct = check_ct(leaf);
        }
    }
    if settings.check_caa {
        security.caa = check_caa(handle, &target.host, timeout).await;
    }

    let revoked = security.revocation.status == crate::model::RevocationStatus::Revoked;
    let leaf_days = certs
        .first()
        .map(|cert| cert.days_remaining(now_unix() as i64));
    let health = classify_health(
        chain_valid,
        &chain_error,
        leaf_days,
        settings.warn_days,
        revoked,
    );

    TlsResult {
        index,
        target: target.target,
        host: target.host,
        port: target.port,
        resolved_ip: Some(ip.to_string()),
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        protocol: info.protocol,
        cipher_suite: info.cipher_suite,
        key_exchange: info.key_exchange,
        alpn_negotiated: capabilities.alpn_negotiated,
        alpn_h2_supported: capabilities.alpn_h2,
        alpn_http1_supported: capabilities.alpn_http1,
        tls12_supported: capabilities.tls12,
        tls13_supported: capabilities.tls13,
        chain_valid,
        chain_error,
        health: if certs.is_empty() {
            TlsHealth::Error
        } else {
            health
        },
        certs,
        security,
        error: None,
    }
}

/// Run a batch of TLS checks with bounded concurrency.
pub async fn run_check(handle: &ProbeHandle<ProbeEvent>, settings: &TlsSettings) {
    crate::net::ensure_crypto_provider();
    use crate::model::TlsProgress;

    let targets = parse_targets(&settings.targets, settings.port);
    if targets.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "no valid TLS targets".into(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    let total = targets.len();
    let concurrency = effective_concurrency(settings.concurrency);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();
    let mut completed = 0usize;

    for (index, target) in targets.into_iter().enumerate() {
        handle.wait_if_paused().await;
        if handle.is_cancelled() {
            tasks.abort_all();
            break;
        }
        let permit = tokio::select! {
            _ = handle.cancelled() => {
                tasks.abort_all();
                break;
            }
            permit = semaphore.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let task_handle = handle.clone();
        let task_settings = settings.clone();
        tasks.spawn(async move {
            let result = check_target(&task_handle, index, target, &task_settings).await;
            drop(permit);
            result
        });
    }

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(result) => {
                handle.send(ProbeEvent::Tls(Box::new(result)));
                completed += 1;
                handle.send(ProbeEvent::TlsProgress(TlsProgress {
                    done: completed,
                    total,
                }));
            }
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                handle.send(ProbeEvent::Error {
                    message: format!("TLS check task failed: {error}"),
                    hint: None,
                });
            }
        }
    }
    handle.send(ProbeEvent::Finished);
}

/// Format a Unix timestamp as a UTC date-time string.
fn format_utc(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|value| {
            value
                .format(time::macros::format_description!(
                    "[year]-[month]-[day] [hour]:[minute]:[second] UTC"
                ))
                .unwrap_or_else(|_| unix.to_string())
        })
        .unwrap_or_else(|_| unix.to_string())
}

fn signature_algorithm_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        other => other.to_string(),
    }
}

fn curve_name(oid: &str) -> Option<String> {
    match oid {
        "1.2.840.10045.3.1.7" => Some("P-256".into()),
        "1.3.132.0.34" => Some("P-384".into()),
        "1.3.132.0.35" => Some("P-521".into()),
        "1.3.132.0.10" => Some("secp256k1".into()),
        other => Some(other.to_string()),
    }
}

fn ip_from_san(bytes: &[u8]) -> Option<std::net::IpAddr> {
    match bytes.len() {
        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Parse one DER certificate into display fields.
fn parse_cert_info(der: &[u8], index: usize) -> Result<crate::model::TlsCertInfo, String> {
    use sha2::Digest;
    use x509_parser::prelude::*;
    use x509_parser::public_key::PublicKey;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|error| format!("certificate parse failed: {error}"))?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|value| value.as_str().ok())
        .map(str::to_string);

    let mut san_dns = Vec::new();
    let mut san_ips = Vec::new();
    let mut san_emails = Vec::new();
    let mut san_uris = Vec::new();
    if let Ok(Some(extension)) = cert.subject_alternative_name() {
        for name in &extension.value.general_names {
            match name {
                GeneralName::DNSName(value) => san_dns.push((*value).to_string()),
                GeneralName::IPAddress(value) => {
                    if let Some(ip) = ip_from_san(value) {
                        san_ips.push(ip.to_string());
                    }
                }
                GeneralName::RFC822Name(value) => san_emails.push((*value).to_string()),
                GeneralName::URI(value) => san_uris.push((*value).to_string()),
                _ => {}
            }
        }
    }

    let public_key = cert.public_key();
    let algorithm_oid = public_key.algorithm.algorithm.to_id_string();
    let (key_algorithm, key_bits, curve) = match public_key.parsed() {
        Ok(PublicKey::RSA(rsa)) => ("RSA".to_string(), Some(rsa.key_size() as u32), None),
        Ok(PublicKey::EC(point)) => {
            let curve = public_key
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .and_then(|oid| curve_name(&oid.to_id_string()));
            ("ECDSA".to_string(), Some(point.key_size() as u32), curve)
        }
        Ok(PublicKey::DSA(_)) => ("DSA".to_string(), None, None),
        Ok(PublicKey::GostR3410(_)) | Ok(PublicKey::GostR3410_2012(_)) => {
            ("GOST".to_string(), None, None)
        }
        Ok(PublicKey::Unknown(_)) => match algorithm_oid.as_str() {
            "1.3.101.112" => ("Ed25519".to_string(), Some(256), None),
            "1.3.101.113" => ("Ed448".to_string(), Some(448), None),
            _ => ("unknown".to_string(), None, None),
        },
        Err(_) => ("unknown".to_string(), None, None),
    };

    let fingerprint = sha2::Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let not_after_unix = cert.validity().not_after.timestamp();
    let role = if index == 0 {
        if cert.is_ca() && subject == issuer {
            "self-signed"
        } else {
            "leaf"
        }
    } else if cert.is_ca() {
        "intermediate"
    } else {
        "chain"
    };

    Ok(crate::model::TlsCertInfo {
        role: role.to_string(),
        subject,
        issuer,
        common_name,
        serial: cert.raw_serial_as_string(),
        not_before: format_utc(cert.validity().not_before.timestamp()),
        not_after: format_utc(not_after_unix),
        not_after_unix,
        signature_algorithm: signature_algorithm_name(
            &cert.signature_algorithm.algorithm.to_id_string(),
        ),
        key_algorithm,
        key_bits,
        curve,
        san_dns,
        san_ips,
        san_emails,
        san_uris,
        fingerprint_sha256: fingerprint,
    })
}

/// Parse every certificate returned by the server.
fn parse_cert_chain(certs: &[Vec<u8>]) -> Result<Vec<crate::model::TlsCertInfo>, String> {
    certs
        .iter()
        .enumerate()
        .map(|(index, der)| parse_cert_info(der, index))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_ports_and_ipv6() {
        let targets = parse_targets(
            "example.com\nwww.example.com:8443\n[::1]:9443\n2001:db8::1\n",
            443,
        );
        assert_eq!(targets.len(), 4);
        assert_eq!(targets[0].host, "example.com");
        assert_eq!(targets[0].port, 443);
        assert_eq!(targets[1].port, 8443);
        assert_eq!(targets[2].host, "::1");
        assert_eq!(targets[2].port, 9443);
        assert_eq!(targets[3].host, "2001:db8::1");
        assert_eq!(targets[3].port, 443);
    }

    #[test]
    fn parses_commas_comments_and_urls() {
        let targets = parse_targets(
            "# comment\nhttps://example.com/path, https://example.com:8443/x\n",
            443,
        );
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].host, "example.com");
        assert_eq!(targets[0].port, 443);
        assert_eq!(targets[1].port, 8443);
    }

    #[test]
    fn normalizes_idn_and_invalid_entries() {
        let targets = parse_targets("bücher.example\n:443\nhttps://[::1]:8443/\n", 443);
        assert_eq!(targets.len(), 2);
        assert!(targets[0].host.starts_with("xn--"));
        assert_eq!(targets[1].host, "::1");
        assert_eq!(targets[1].port, 8443);
    }

    #[test]
    fn parses_hsts_directives() {
        let check = parse_hsts_header("max-age=31536000; includeSubDomains; preload");
        assert!(check.present);
        assert!(check.enabled);
        assert_eq!(check.max_age, Some(31_536_000));
        assert!(check.include_subdomains);
        assert!(check.preload);

        let disabled = parse_hsts_header("max-age=0");
        assert!(disabled.present);
        assert!(!disabled.enabled);

        let invalid = parse_hsts_header("max-age=abc");
        assert!(!invalid.enabled);
        assert!(invalid.error.is_some());
    }

    #[test]
    fn concurrency_is_capped() {
        assert_eq!(effective_concurrency(0), 1);
        assert_eq!(effective_concurrency(4), 4);
        assert_eq!(effective_concurrency(100), MAX_CONCURRENCY);
    }

    #[test]
    fn health_priority_prefers_revocation_and_expiry() {
        assert_eq!(
            classify_health(false, &None, Some(10), 30, true),
            crate::model::TlsHealth::Revoked
        );
        assert_eq!(
            classify_health(false, &None, Some(-1), 30, false),
            crate::model::TlsHealth::Expired
        );
        assert_eq!(
            classify_health(
                false,
                &Some("InvalidCertificate(NotValidForName)".into()),
                Some(10),
                30,
                false
            ),
            crate::model::TlsHealth::HostnameMismatch
        );
        assert_eq!(
            classify_health(true, &None, Some(10), 30, false),
            crate::model::TlsHealth::ExpiringSoon
        );
        assert_eq!(
            classify_health(true, &None, Some(100), 30, false),
            crate::model::TlsHealth::Ok
        );
    }
}
