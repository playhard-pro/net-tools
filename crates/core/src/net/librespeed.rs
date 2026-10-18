//! LibreSpeed-compatible HTTP speed test.
//!
//! The implementation speaks the protocol used by the official LibreSpeed
//! backend: a small HTTP latency probe, parallel downloads from `garbage.php`
//! and parallel uploads to `empty.php`. It deliberately does not depend on the
//! LGPL-licensed LibreSpeed CLI crate.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::clock;
use crate::config::LibreSpeedSettings;
use crate::control::ProbeHandle;
use crate::model::{
    LibreSpeedServer, ProbeEvent, SpeedPhase, SpeedProgress, SpeedResult, SpeedSample,
    SpeedtestTool,
};
use crate::net::dns;

/// Public LibreSpeed server list maintained by the project.
const SERVER_LIST_URL: &str = "https://librespeed.org/backend-servers/servers.php";

/// Number of latency requests. The first one is discarded as connection warm-up.
const LATENCY_PROBES: usize = 6;

/// Query size requested from `garbage.php`, in MiB per request.
const DOWNLOAD_CHUNK_MIB: u32 = 25;

/// Upload payload size in bytes. Small enough to keep progress responsive.
const UPLOAD_PAYLOAD: usize = 2 * 1024 * 1024;

/// Progress sampling cadence.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Time excluded from the throughput average at the start of a phase.
const WARMUP: Duration = Duration::from_secs(1);

/// Refresh the public server list.
pub async fn run_server_list(
    handle: &ProbeHandle<ProbeEvent>,
    timeout_ms: u64,
    ip_version: crate::model::IpVersion,
) {
    match fetch_servers(timeout_ms, ip_version).await {
        Ok(servers) => handle.send(ProbeEvent::LibreSpeedServers(servers)),
        Err(message) => handle.send(ProbeEvent::Error {
            message,
            hint: None,
        }),
    }
}

/// Fetch and parse the public server list.
pub async fn fetch_servers(
    timeout_ms: u64,
    ip_version: crate::model::IpVersion,
) -> Result<Vec<LibreSpeedServer>, String> {
    let client = build_client(&[SERVER_LIST_URL], timeout_ms, ip_version, None).await?;
    let response = client
        .get(SERVER_LIST_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("server list request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "server list request returned HTTP {}",
            response.status()
        ));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("server list could not be read: {e}"))?;
    let servers: Vec<LibreSpeedServer> =
        serde_json::from_str(&body).map_err(|e| format!("invalid server list: {e}"))?;
    if servers.is_empty() {
        return Err("the server list is empty".into());
    }
    Ok(servers)
}

/// Run one complete LibreSpeed test.
pub async fn run_test(handle: &ProbeHandle<ProbeEvent>, settings: &LibreSpeedSettings) {
    if let Err(message) = run_test_inner(handle, settings).await {
        handle.send(ProbeEvent::Error {
            message,
            hint: None,
        });
    }
    handle.send(ProbeEvent::Finished);
}

async fn run_test_inner(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &LibreSpeedSettings,
) -> Result<(), String> {
    let started_at = clock::now_string();
    let started = Instant::now();
    let duration = Duration::from_secs(settings.duration_s.max(1));
    let connections = settings.connections.clamp(1, 32);

    send_phase(
        handle,
        SpeedPhase::Latency,
        0.0,
        duration.as_secs_f64(),
        0.0,
    );

    let server = select_server(handle, settings).await?;
    handle.send(ProbeEvent::Info(format!(
        "LibreSpeed server: {} ({})",
        server.name, server.server
    )));

    let client = build_client(
        &[server.server.as_str()],
        settings.timeout_ms,
        settings.ip_version,
        Some(duration),
    )
    .await?;

    let (ping_ms, jitter_ms) = measure_latency(&client, &server, handle).await?;

    let mut samples = Vec::new();
    let mut download_mbps = None;
    let mut upload_mbps = None;

    if !settings.skip_download {
        download_mbps = Some(
            run_download(
                handle,
                &client,
                &server,
                duration,
                connections,
                &mut samples,
            )
            .await?,
        );
    }
    if !settings.skip_upload {
        upload_mbps = Some(
            run_upload(
                handle,
                &client,
                &server,
                duration,
                connections,
                &mut samples,
            )
            .await?,
        );
    }

    if handle.is_cancelled() {
        return Ok(());
    }

    let mut direction = Vec::new();
    if download_mbps.is_some() {
        direction.push("download");
    }
    if upload_mbps.is_some() {
        direction.push("upload");
    }

    handle.send(ProbeEvent::SpeedResult(SpeedResult {
        tool: SpeedtestTool::LibreSpeed,
        server: format!("{} ({})", server.name, server.server),
        protocol: "HTTP".into(),
        direction: direction.join(" + "),
        ping_ms: Some(ping_ms),
        jitter_ms: Some(jitter_ms),
        download_mbps,
        upload_mbps,
        retransmits: None,
        lost_percent: None,
        started_at,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        samples,
        error: None,
    }));
    Ok(())
}

/// Pick the configured server, or probe the list and choose the lowest latency.
async fn select_server(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &LibreSpeedSettings,
) -> Result<LibreSpeedServer, String> {
    if !settings.custom_url.trim().is_empty() {
        return custom_server(&settings.custom_url);
    }

    let servers = fetch_servers(settings.timeout_ms, settings.ip_version).await?;
    let wanted = settings.server.trim();
    if !wanted.is_empty() && wanted != "auto" {
        return servers
            .into_iter()
            .find(|s| s.id.to_string() == wanted)
            .ok_or_else(|| format!("LibreSpeed server id {wanted} is no longer listed"));
    }

    // Auto mode: probe every server in parallel and keep the fastest response.
    let hosts: Vec<&str> = servers.iter().map(|s| s.server.as_str()).collect();
    let client = build_client(
        &hosts,
        settings.timeout_ms.min(5_000),
        settings.ip_version,
        None,
    )
    .await?;
    let mut tasks = JoinSet::new();
    for server in servers {
        let client = client.clone();
        tasks.spawn(async move {
            let latency = ping_once(&client, &server).await.ok();
            (server, latency)
        });
    }
    let mut best: Option<(LibreSpeedServer, f64)> = None;
    while let Some(joined) = tasks.join_next().await {
        if handle.is_cancelled() {
            tasks.abort_all();
            return Err("cancelled".into());
        }
        if let Ok((server, Some(latency))) = joined {
            if best.as_ref().is_none_or(|(_, current)| latency < *current) {
                best = Some((server, latency));
            }
        }
    }
    best.map(|(server, _)| server)
        .ok_or_else(|| "no LibreSpeed server answered the latency probe".into())
}

/// Build a custom server description from a backend base URL.
fn custom_server(base: &str) -> Result<LibreSpeedServer, String> {
    let base = base.trim().trim_end_matches('/');
    let parsed = Url::parse(base).map_err(|e| format!("invalid custom server URL: {e}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("custom server URL must use http or https".into());
    }
    Ok(LibreSpeedServer {
        id: -1,
        name: "Custom server".into(),
        server: base.to_string(),
        download_url: "garbage.php".into(),
        upload_url: "empty.php".into(),
        ping_url: "empty.php".into(),
        get_ip_url: "getIP.php".into(),
        sponsor_name: String::new(),
        sponsor_url: String::new(),
    })
}

/// Measure average HTTP latency and jitter. The first sample is discarded.
async fn measure_latency(
    client: &Client,
    server: &LibreSpeedServer,
    handle: &ProbeHandle<ProbeEvent>,
) -> Result<(f64, f64), String> {
    let mut samples = Vec::new();
    for index in 0..LATENCY_PROBES {
        if handle.is_cancelled() {
            return Err("cancelled".into());
        }
        if let Ok(ms) = ping_once(client, server).await {
            if index > 0 {
                samples.push(ms);
            }
        }
        let _ = handle.sleep(Duration::from_millis(60)).await;
    }
    if samples.is_empty() {
        return Err("the LibreSpeed server did not answer the latency probe".into());
    }
    let average = samples.iter().sum::<f64>() / samples.len() as f64;
    let jitter = weighted_jitter(&samples);
    Ok((average, jitter))
}

/// One HTTP request to the latency endpoint.
async fn ping_once(client: &Client, server: &LibreSpeedServer) -> Result<f64, String> {
    let url = endpoint(&server.server, &server.ping_url)?;
    let started = Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("latency probe failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("latency probe returned HTTP {}", response.status()));
    }
    // Drain the body so the connection can be reused.
    let _ = response.bytes().await;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

/// Weighted jitter used by the LibreSpeed CLI.
fn weighted_jitter(samples: &[f64]) -> f64 {
    let mut last = 0.0;
    let mut jitter = 0.0;
    for (index, sample) in samples.iter().enumerate() {
        if index > 0 {
            let instant = (last - sample).abs();
            if index > 1 {
                jitter = if jitter > instant {
                    jitter * 0.7 + instant * 0.3
                } else {
                    instant * 0.2 + jitter * 0.8
                };
            }
        }
        last = *sample;
    }
    jitter
}

/// Download phase with parallel streaming requests.
async fn run_download(
    handle: &ProbeHandle<ProbeEvent>,
    client: &Client,
    server: &LibreSpeedServer,
    duration: Duration,
    connections: usize,
    samples: &mut Vec<SpeedSample>,
) -> Result<f64, String> {
    let url = endpoint(&server.server, &server.download_url)?;
    let cancel = CancellationToken::new();
    let bytes = Arc::new(AtomicU64::new(0));
    let mut tasks = JoinSet::new();
    for _ in 0..connections {
        let client = client.clone();
        let url = url.clone();
        let cancel = cancel.clone();
        let bytes = bytes.clone();
        tasks.spawn(async move {
            download_worker(client, url, cancel, bytes).await;
        });
    }
    let average = drive_phase(
        handle,
        SpeedPhase::Download,
        duration,
        bytes.clone(),
        samples,
        &cancel,
    )
    .await?;
    cancel.cancel();
    while tasks.join_next().await.is_some() {}
    Ok(average)
}

async fn download_worker(
    client: Client,
    url: Url,
    cancel: CancellationToken,
    bytes: Arc<AtomicU64>,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let mut request_url = url.clone();
        request_url
            .query_pairs_mut()
            .append_pair("ckSize", &DOWNLOAD_CHUNK_MIB.to_string());
        let response = tokio::select! {
            _ = cancel.cancelled() => return,
            result = client.get(request_url).send() => result,
        };
        let Ok(mut response) = response else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        if !response.status().is_success() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        loop {
            let chunk = tokio::select! {
                _ = cancel.cancelled() => return,
                chunk = response.chunk() => chunk,
            };
            match chunk {
                Ok(Some(data)) => {
                    bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }
}

/// Upload phase with parallel POST requests.
async fn run_upload(
    handle: &ProbeHandle<ProbeEvent>,
    client: &Client,
    server: &LibreSpeedServer,
    duration: Duration,
    connections: usize,
    samples: &mut Vec<SpeedSample>,
) -> Result<f64, String> {
    let url = endpoint(&server.server, &server.upload_url)?;
    let cancel = CancellationToken::new();
    let bytes = Arc::new(AtomicU64::new(0));
    let payload = Arc::new(vec![0u8; UPLOAD_PAYLOAD]);
    let mut tasks = JoinSet::new();
    for _ in 0..connections {
        let client = client.clone();
        let url = url.clone();
        let cancel = cancel.clone();
        let bytes = bytes.clone();
        let payload = payload.clone();
        tasks.spawn(async move {
            upload_worker(client, url, cancel, bytes, payload).await;
        });
    }
    let average = drive_phase(
        handle,
        SpeedPhase::Upload,
        duration,
        bytes.clone(),
        samples,
        &cancel,
    )
    .await?;
    cancel.cancel();
    while tasks.join_next().await.is_some() {}
    Ok(average)
}

async fn upload_worker(
    client: Client,
    url: Url,
    cancel: CancellationToken,
    bytes: Arc<AtomicU64>,
    payload: Arc<Vec<u8>>,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let body = payload.as_ref().clone();
        let size = body.len() as u64;
        let response = tokio::select! {
            _ = cancel.cancelled() => return,
            result = client.post(url.clone()).body(body).send() => result,
        };
        match response {
            Ok(response) if response.status().is_success() => {
                let _ = response.bytes().await;
                bytes.fetch_add(size, Ordering::Relaxed);
            }
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

/// Drive one timed phase, emit progress samples and return the average rate
/// over the post-warm-up window.
async fn drive_phase(
    handle: &ProbeHandle<ProbeEvent>,
    phase: SpeedPhase,
    duration: Duration,
    bytes: Arc<AtomicU64>,
    samples: &mut Vec<SpeedSample>,
    cancel: &CancellationToken,
) -> Result<f64, String> {
    let started = Instant::now();
    let total_s = duration.as_secs_f64();
    // Short tests still need a measurable post-warm-up window.
    let warmup = WARMUP.min(duration / 4);
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut warm_at: Option<Duration> = None;
    let mut warm_bytes = 0u64;
    let mut last_bytes = 0u64;
    let mut last_at = Duration::ZERO;

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = handle.cancelled() => {
                cancel.cancel();
                return Err("cancelled".into());
            }
        }
        if handle.is_cancelled() {
            cancel.cancel();
            return Err("cancelled".into());
        }
        let elapsed = started.elapsed();
        let current_bytes = bytes.load(Ordering::Relaxed);

        if warm_at.is_none() && elapsed >= warmup {
            warm_at = Some(elapsed);
            warm_bytes = current_bytes;
            last_bytes = current_bytes;
            last_at = elapsed;
        }
        if warm_at.is_some() {
            let seconds = (elapsed - last_at).as_secs_f64().max(0.001);
            let mbps =
                (current_bytes.saturating_sub(last_bytes)) as f64 * 8.0 / seconds / 1_000_000.0;
            last_bytes = current_bytes;
            last_at = elapsed;
            let sample = SpeedSample {
                elapsed_s: elapsed.as_secs_f64(),
                mbps,
                phase,
            };
            samples.push(sample);
            let progress = (elapsed.as_secs_f64() / total_s).clamp(0.0, 1.0) as f32;
            handle.send(ProbeEvent::SpeedProgress(SpeedProgress {
                tool: SpeedtestTool::LibreSpeed,
                phase,
                current_mbps: mbps,
                elapsed_s: elapsed.as_secs_f64(),
                total_s,
                progress,
            }));
        }

        if elapsed >= duration {
            break;
        }
    }

    let end = started.elapsed();
    let end_bytes = bytes.load(Ordering::Relaxed);
    let average = match warm_at {
        Some(warm) => {
            let seconds = (end - warm).as_secs_f64().max(0.001);
            end_bytes.saturating_sub(warm_bytes) as f64 * 8.0 / seconds / 1_000_000.0
        }
        None => 0.0,
    };
    handle.send(ProbeEvent::SpeedProgress(SpeedProgress {
        tool: SpeedtestTool::LibreSpeed,
        phase,
        current_mbps: average,
        elapsed_s: end.as_secs_f64(),
        total_s,
        progress: 1.0,
    }));
    Ok(average)
}

fn send_phase(
    handle: &ProbeHandle<ProbeEvent>,
    phase: SpeedPhase,
    elapsed_s: f64,
    total_s: f64,
    progress: f32,
) {
    handle.send(ProbeEvent::SpeedProgress(SpeedProgress {
        tool: SpeedtestTool::LibreSpeed,
        phase,
        current_mbps: 0.0,
        elapsed_s,
        total_s,
        progress,
    }));
}

/// Join a backend base URL with one of its endpoint names.
fn endpoint(base: &str, path: &str) -> Result<Url, String> {
    let base = format!("{}/", base.trim().trim_end_matches('/'));
    let base = Url::parse(&base).map_err(|e| format!("invalid server URL: {e}"))?;
    base.join(path)
        .map_err(|e| format!("invalid endpoint URL: {e}"))
}

/// Build a reqwest client that resolves each host to the requested IP family.
async fn build_client(
    urls: &[&str],
    timeout_ms: u64,
    ip_version: crate::model::IpVersion,
    extra: Option<Duration>,
) -> Result<Client, String> {
    let mut hosts = Vec::new();
    for value in urls {
        if let Ok(url) = Url::parse(value) {
            if let Some(host) = url.host_str() {
                if !hosts.iter().any(|h: &String| h == host) {
                    hosts.push(host.to_string());
                }
            }
        }
    }

    let mut resolved = Vec::new();
    let mut tasks = JoinSet::new();
    for host in hosts {
        let task_host = host.clone();
        tasks.spawn(async move {
            let addrs = dns::resolve(&task_host, ip_version).await.ok();
            (host, addrs)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok((host, Some(addrs))) = joined {
            if !addrs.is_empty() {
                resolved.push((host, addrs));
            }
        }
    }

    let mut builder = Client::builder()
        .user_agent(format!("net-tools/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_millis(timeout_ms.max(500)));
    if let Some(extra) = extra {
        builder = builder.timeout(Duration::from_millis(timeout_ms) + extra);
    } else {
        builder = builder.timeout(Duration::from_millis(timeout_ms));
    }
    for (host, addrs) in resolved {
        let sockets: Vec<SocketAddr> = addrs
            .into_iter()
            .map(|addr| SocketAddr::new(addr, 0))
            .collect();
        builder = builder.resolve_to_addrs(&host, &sockets);
    }
    builder
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_public_server_list() {
        let json = r#"[{
            "name": "Example",
            "server": "https://speed.example/backend",
            "id": 7,
            "dlURL": "garbage.php",
            "ulURL": "empty.php",
            "pingURL": "empty.php",
            "getIpURL": "getIP.php",
            "sponsorName": "Example Sponsor",
            "sponsorURL": "https://example.com"
        }]"#;
        let servers: Vec<LibreSpeedServer> = serde_json::from_str(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, 7);
        assert_eq!(servers[0].download_url, "garbage.php");
        assert_eq!(servers[0].sponsor_name, "Example Sponsor");
    }

    #[test]
    fn joins_endpoints_with_and_without_trailing_slash() {
        assert_eq!(
            endpoint("https://speed.example/backend", "garbage.php")
                .unwrap()
                .as_str(),
            "https://speed.example/backend/garbage.php"
        );
        assert_eq!(
            endpoint("https://speed.example/", "empty.php")
                .unwrap()
                .as_str(),
            "https://speed.example/empty.php"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_test_produces_download_and_upload() {
        use crate::control::TaskController;
        use crate::model::IpVersion;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 4096];
                    loop {
                        let read = stream.read(&mut buffer).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..read]);
                        if let Some(position) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers = request[..position + 4].to_vec();
                            let content_length = String::from_utf8_lossy(&headers)
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .and_then(|value| value.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            let mut remaining =
                                content_length.saturating_sub(request.len() - position - 4);
                            while remaining > 0 {
                                let read = stream.read(&mut buffer).await.unwrap_or(0);
                                if read == 0 {
                                    break;
                                }
                                remaining = remaining.saturating_sub(read);
                            }
                            let first_line = String::from_utf8_lossy(&headers)
                                .lines()
                                .next()
                                .unwrap_or_default()
                                .to_string();
                            let mut body = Vec::new();
                            if first_line.starts_with("GET /garbage.php") {
                                body = vec![7u8; 256 * 1024];
                            }
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.write_all(&body).await;
                            let _ = stream.shutdown().await;
                            return;
                        }
                    }
                });
            }
        });

        let settings = LibreSpeedSettings {
            server: "auto".into(),
            custom_url: format!("http://{addr}"),
            duration_s: 1,
            connections: 2,
            skip_download: false,
            skip_upload: false,
            timeout_ms: 5000,
            ip_version: IpVersion::Auto,
        };
        let runtime = tokio::runtime::Handle::current();
        let mut ctrl = TaskController::new();
        ctrl.start(&runtime, move |handle| async move {
            run_test(&handle, &settings).await;
        });

        let mut result = None;
        let mut saw_download_progress = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        while tokio::time::Instant::now() < deadline {
            for event in ctrl.drain() {
                match event {
                    ProbeEvent::SpeedResult(value) => result = Some(value),
                    ProbeEvent::SpeedProgress(progress)
                        if progress.phase == SpeedPhase::Download =>
                    {
                        saw_download_progress = true;
                    }
                    _ => {}
                }
            }
            if ctrl.state == crate::control::TaskState::Finished {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        server.abort();

        let result = result.expect("the loopback test should produce a result");
        assert!(saw_download_progress);
        assert!(result.ping_ms.is_some());
        assert!(result.download_mbps.unwrap_or(0.0) > 0.0);
        assert!(result.upload_mbps.unwrap_or(0.0) > 0.0);
        assert!(!result.samples.is_empty());
    }

    #[test]
    fn jitter_follows_the_weighted_formula() {
        // A constant series has no jitter.
        assert_eq!(weighted_jitter(&[10.0, 10.0, 10.0, 10.0]), 0.0);
        // A changing series produces a positive value.
        assert!(weighted_jitter(&[10.0, 20.0, 10.0, 20.0]) > 0.0);
    }
}
