//! Loopback integration tests for the TLS checker.

use std::sync::Arc;
use std::time::{Duration, Instant};

use net_tools_core::config::TlsSettings;
use net_tools_core::control::TaskController;
use net_tools_core::model::{ProbeEvent, TlsHealth, TlsResult};
use net_tools_core::net::tls;
use rcgen::{generate_simple_self_signed, CertificateParams, CertifiedKey, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Start a loopback TLS server and return its port.
async fn start_server(der: Vec<u8>, key_der: Vec<u8>, hsts: bool) -> u16 {
    let cert = rustls::pki_types::CertificateDer::from(der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                if hsts {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    let response = b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=123; includeSubDomains\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response).await;
                    let _ = stream.shutdown().await;
                } else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            });
        }
    });
    port
}

async fn start_alpn_server(der: Vec<u8>, key_der: Vec<u8>, alpn: &[&[u8]]) -> u16 {
    let cert = rustls::pki_types::CertificateDer::from(der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(tcp).await {
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    port
}

fn settings(port: u16) -> TlsSettings {
    let mut settings = TlsSettings {
        targets: format!("localhost:{port}"),
        timeout_ms: 2_000,
        concurrency: 1,
        probe_versions: false,
        probe_alpn: false,
        check_revocation: false,
        check_hsts: false,
        check_ct: false,
        check_caa: false,
        ..TlsSettings::default()
    };
    settings.port = port;
    settings
}

async fn run(settings: TlsSettings) -> TlsResult {
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(
        &tokio::runtime::Handle::current(),
        move |handle| async move {
            tls::run_check(&handle, &settings).await;
        },
    );

    let started = Instant::now();
    let mut result = None;
    loop {
        for event in ctrl.drain() {
            if let ProbeEvent::Tls(value) = event {
                result = Some(*value);
            }
        }
        if result.is_some() && !ctrl.is_active() {
            break;
        }
        if started.elapsed() > Duration::from_secs(8) {
            panic!("TLS check did not finish in time");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    result.expect("TLS result")
}

#[tokio::test]
async fn parses_self_signed_certificate() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let port = start_server(cert.der().to_vec(), signing_key.serialize_der(), false).await;
    let result = run(settings(port)).await;

    assert!(
        result.error.is_none(),
        "unexpected error: {:?}",
        result.error
    );
    assert!(result.protocol.is_some());
    assert!(!result.certs.is_empty());
    let leaf = &result.certs[0];
    assert_eq!(leaf.role, "leaf");
    assert!(leaf.san_dns.iter().any(|name| name == "localhost"));
    assert!(leaf.key_bits.unwrap_or(0) > 0);
    assert!(!leaf.fingerprint_sha256.is_empty());
    assert!(!result.chain_valid);
    assert_eq!(result.health, TlsHealth::Untrusted);
}

#[tokio::test]
async fn reads_hsts_header() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let port = start_server(cert.der().to_vec(), signing_key.serialize_der(), true).await;
    let mut settings = settings(port);
    settings.check_hsts = true;
    let result = run(settings).await;

    assert!(result.security.hsts.present);
    assert!(result.security.hsts.enabled);
    assert_eq!(result.security.hsts.max_age, Some(123));
    assert!(result.security.hsts.include_subdomains);
}

#[tokio::test]
async fn detects_expired_certificate() {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(10);
    params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let cert = params.self_signed(&key).unwrap();
    let port = start_server(cert.der().to_vec(), key.serialize_der(), false).await;
    let result = run(settings(port)).await;

    assert!(
        result.error.is_none(),
        "unexpected error: {:?}",
        result.error
    );
    assert_eq!(result.health, TlsHealth::Expired);
    assert!(result.certs[0].days_remaining(time::OffsetDateTime::now_utc().unix_timestamp()) < 0);
}

#[tokio::test]
async fn rejects_empty_target_list() {
    let settings = TlsSettings {
        targets: "  # only a comment\n".into(),
        ..TlsSettings::default()
    };
    let mut ctrl: TaskController<ProbeEvent> = TaskController::new();
    ctrl.start(
        &tokio::runtime::Handle::current(),
        move |handle| async move {
            tls::run_check(&handle, &settings).await;
        },
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = ctrl.drain();
    assert!(events
        .iter()
        .any(|event| matches!(event, ProbeEvent::Error { .. })));
    assert!(events
        .iter()
        .any(|event| matches!(event, ProbeEvent::Finished)));
}

#[tokio::test]
async fn probes_alpn_and_tls_versions() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let port = start_alpn_server(
        cert.der().to_vec(),
        signing_key.serialize_der(),
        &[b"h2", b"http/1.1"],
    )
    .await;
    let mut settings = settings(port);
    settings.probe_versions = true;
    settings.probe_alpn = true;
    let result = run(settings).await;

    assert_eq!(result.alpn_negotiated.as_deref(), Some("h2"));
    assert_eq!(result.alpn_h2_supported, Some(true));
    assert_eq!(result.alpn_http1_supported, Some(true));
    assert_eq!(result.tls12_supported, Some(true));
    assert_eq!(result.tls13_supported, Some(true));
}
