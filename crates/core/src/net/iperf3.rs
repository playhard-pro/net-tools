//! iperf3 client and server integration based on the `riperf3` crate.
//!
//! The GUI runs the actual client or server in a hidden worker process because
//! `riperf3` exposes live interval data through its line-delimited
//! `json_stream` output. This module owns the worker-side setup and the parsing
//! of those events into the shared speed test models.

use std::time::Duration;

use serde_json::Value;

use crate::config::{Iperf3ServerSettings, Iperf3Settings};
use crate::control::ProbeHandle;
use crate::model::{
    Iperf3Protocol, Iperf3Server, Iperf3ServerProgress, Iperf3ServerResult, ProbeEvent, SpeedPhase,
    SpeedResult, SpeedSample, SpeedtestTool,
};

/// Public iperf3 server directory maintained by iperf3serverlist.net.
const SERVER_LIST_URL: &str = "https://export.iperf3serverlist.net/listed_iperf3_servers.json";

/// Local interface addresses that can be used as a server bind address.
///
/// The unspecified addresses are omitted because an empty bind field already
/// means "all interfaces"; loopback and every assigned address are included.
pub fn local_ip_addresses() -> Vec<String> {
    let mut addresses = Vec::new();
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        let ip = match interface.addr {
            if_addrs::IfAddr::V4(address) => std::net::IpAddr::V4(address.ip),
            if_addrs::IfAddr::V6(address) => std::net::IpAddr::V6(address.ip),
        };
        if !ip.is_unspecified() {
            addresses.push(ip.to_string());
        }
    }
    addresses.sort();
    addresses.dedup();
    addresses
}

/// Fetch the public server list and send it to the UI.
pub async fn run_server_list(handle: &ProbeHandle<ProbeEvent>, timeout_ms: u64) {
    match fetch_servers(timeout_ms).await {
        Ok(servers) => handle.send(ProbeEvent::Iperf3Servers(servers)),
        Err(message) => handle.send(ProbeEvent::Error {
            message,
            hint: None,
        }),
    }
}

/// Fetch and parse the public iperf3 server directory.
pub async fn fetch_servers(timeout_ms: u64) -> Result<Vec<Iperf3Server>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.max(1_000)))
        .user_agent(format!("net-tools/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))?;
    let response = client
        .get(SERVER_LIST_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("iperf3 server list request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "iperf3 server list returned HTTP {}",
            response.status()
        ));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("iperf3 server list could not be read: {e}"))?;
    let mut servers: Vec<Iperf3Server> =
        serde_json::from_str(&body).map_err(|e| format!("invalid iperf3 server list: {e}"))?;
    servers.retain(|server| !server.host.trim().is_empty());
    if servers.is_empty() {
        return Err("the iperf3 server list is empty".into());
    }
    servers.sort_by(|a, b| {
        a.continent
            .cmp(&b.continent)
            .then_with(|| a.country.cmp(&b.country))
            .then_with(|| a.site.cmp(&b.site))
            .then_with(|| a.host.cmp(&b.host))
    });
    Ok(servers)
}

/// One throughput reading extracted from a streamed interval event.
#[derive(Debug, Clone)]
pub struct IntervalReading {
    pub phase: SpeedPhase,
    /// End of this interval, in seconds since the test started.
    pub end_s: f64,
    pub mbps: f64,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_percent: Option<f64>,
}

/// Connection and test parameters reported by a json-stream `start` event.
#[derive(Debug, Clone, Default)]
pub struct StreamStart {
    pub peer: Option<String>,
    pub protocol: String,
    pub reverse: bool,
    pub bidir: bool,
    pub duration_s: f64,
}

/// A parsed line from `riperf3`'s json-stream mode.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    Start(StreamStart),
    Interval(Vec<IntervalReading>),
    End(Value),
    Error(String),
}

/// Run the iperf3 client in json-stream mode. Used by the hidden worker mode.
///
/// This function writes JSON event lines to stdout through `riperf3`; callers
/// must keep stdout dedicated to the event stream.
pub async fn run_worker(settings: &Iperf3Settings) -> Result<(), String> {
    let mut builder = riperf3::ClientBuilder::new(settings.host.trim())
        .port(Some(settings.port))
        .protocol(match settings.protocol {
            Iperf3Protocol::Tcp => riperf3::TransportProtocol::Tcp,
            Iperf3Protocol::Udp => riperf3::TransportProtocol::Udp,
        })
        .duration(settings.duration_s as u32)
        .num_streams(settings.streams.max(1))
        .reverse(settings.reverse)
        .bidir(settings.bidir)
        .omit(settings.omit_s as u32)
        .connect_timeout(Duration::from_secs(10))
        .json_stream(true)
        .interval(1.0)
        .forceflush(true);

    // riperf3 only accepts an explicit family; leaving the option unset means
    // automatic selection by the operating system.
    match settings.ip_version {
        crate::model::IpVersion::Auto => {}
        crate::model::IpVersion::V4 => builder = builder.ip_version(4),
        crate::model::IpVersion::V6 => builder = builder.ip_version(6),
    }

    if settings.block_size > 0 {
        builder = builder.blksize(settings.block_size);
    }
    if settings.bandwidth_bps > 0 {
        builder = builder.bandwidth(settings.bandwidth_bps);
    }

    let client = builder
        .build()
        .map_err(|e| format!("invalid iperf3 settings: {e}"))?;
    client
        .run()
        .await
        .map(|_| ())
        .map_err(|e| format!("iperf3 test failed: {e}"))
}

/// Run the iperf3 server in json-stream mode. Used by the hidden server worker.
///
/// The worker writes one JSON event line per interval/test to stdout and keeps
/// listening until it is terminated or, with `one_off`, until one test ends.
pub async fn run_server_worker(settings: &Iperf3ServerSettings) -> Result<(), String> {
    let mut builder = riperf3::ServerBuilder::new()
        .port(Some(settings.port))
        .one_off(settings.one_off)
        .json_stream(true)
        .forceflush(true);
    if !settings.bind_address.trim().is_empty() {
        builder = builder.bind_address(settings.bind_address.trim());
    }
    if settings.max_duration_s > 0 {
        builder = builder.server_max_duration(settings.max_duration_s as u32);
    }
    if settings.bitrate_limit_bps > 0 {
        builder = builder.server_bitrate_limit(settings.bitrate_limit_bps);
    }
    let server = builder
        .build()
        .map_err(|e| format!("invalid iperf3 server settings: {e}"))?;
    server
        .run()
        .await
        .map_err(|e| format!("iperf3 server failed: {e}"))
}

/// Build a server-side result from a streamed `end` event.
pub fn server_result_from_end(
    data: &Value,
    start: &StreamStart,
    time: String,
) -> Iperf3ServerResult {
    let sum = data.get("sum");
    let sum_sent = data.get("sum_sent");
    let sum_received = data.get("sum_received");
    let mbps = |value: Option<&Value>| {
        value
            .and_then(|v| v.get("bits_per_second"))
            .and_then(Value::as_f64)
            .map(|bps| bps / 1_000_000.0)
    };
    let direction = if start.bidir {
        "bidirectional"
    } else if start.reverse {
        "server -> client"
    } else {
        "client -> server"
    };
    Iperf3ServerResult {
        time,
        peer: start.peer.clone().unwrap_or_else(|| "-".into()),
        protocol: start.protocol.clone(),
        direction: direction.to_string(),
        duration_s: start.duration_s,
        sent_mbps: mbps(sum_sent),
        received_mbps: mbps(sum_received),
        retransmits: sum_sent
            .and_then(|v| v.get("retransmits"))
            .and_then(Value::as_u64),
        jitter_ms: sum.and_then(|v| v.get("jitter_ms")).and_then(Value::as_f64),
        lost_percent: sum
            .and_then(|v| v.get("lost_percent"))
            .and_then(Value::as_f64),
        error: data
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

/// Build live progress from a streamed server interval event.
pub fn server_progress_from_interval(
    data: &Value,
    start: &StreamStart,
) -> Option<Iperf3ServerProgress> {
    let sum = data.get("sum")?;
    let direction = if start.bidir {
        "bidirectional"
    } else if start.reverse {
        "server -> client"
    } else {
        "client -> server"
    };
    Some(Iperf3ServerProgress {
        peer: start.peer.clone().unwrap_or_else(|| "-".into()),
        protocol: start.protocol.clone(),
        direction: direction.to_string(),
        elapsed_s: sum.get("end").and_then(Value::as_f64).unwrap_or(0.0),
        total_s: start.duration_s,
        current_mbps: sum
            .get("bits_per_second")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            / 1_000_000.0,
        retransmits: sum.get("retransmits").and_then(Value::as_u64),
        jitter_ms: sum.get("jitter_ms").and_then(Value::as_f64),
        lost_percent: sum.get("lost_percent").and_then(Value::as_f64),
    })
}

/// Parse one line of `riperf3` json-stream output.
pub fn parse_stream_line(line: &str, settings: &Iperf3Settings) -> Option<StreamEvent> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    let event = value.get("event")?.as_str()?;
    let data = value.get("data")?;
    match event {
        "start" => Some(StreamEvent::Start(start_info(data))),
        "interval" => Some(StreamEvent::Interval(interval_readings(data, settings))),
        "end" => Some(StreamEvent::End(data.clone())),
        "error" => Some(StreamEvent::Error(
            data.as_str()
                .unwrap_or("iperf3 reported an error")
                .to_string(),
        )),
        _ => None,
    }
}

/// Extract the connection peer and test parameters from a start event.
fn start_info(data: &Value) -> StreamStart {
    let peer = data
        .get("connected")
        .and_then(Value::as_array)
        .and_then(|connections| connections.first())
        .and_then(|connection| {
            let host = connection.get("remote_host")?.as_str()?;
            let port = connection.get("remote_port").and_then(Value::as_u64);
            Some(match port {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        });
    let test = data.get("test_start");
    StreamStart {
        peer,
        protocol: test
            .and_then(|value| value.get("protocol"))
            .and_then(Value::as_str)
            .unwrap_or("TCP")
            .to_string(),
        reverse: test
            .and_then(|value| value.get("reverse"))
            .and_then(Value::as_i64)
            .is_some_and(|value| value != 0),
        bidir: test
            .and_then(|value| value.get("bidir"))
            .and_then(Value::as_i64)
            .is_some_and(|value| value != 0),
        duration_s: test
            .and_then(|value| value.get("duration"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
    }
}

/// Extract the local and, for bidirectional tests, reverse interval readings.
fn interval_readings(data: &Value, settings: &Iperf3Settings) -> Vec<IntervalReading> {
    let mut readings = Vec::new();
    if let Some(reading) = reading_from_sum(data.get("sum"), false, settings) {
        readings.push(reading);
    }
    if let Some(reading) = reading_from_sum(data.get("sum_bidir_reverse"), true, settings) {
        readings.push(reading);
    }
    readings
}

fn reading_from_sum(
    sum: Option<&Value>,
    reverse_stream: bool,
    settings: &Iperf3Settings,
) -> Option<IntervalReading> {
    let sum = sum?;
    let mbps = sum.get("bits_per_second").and_then(Value::as_f64)? / 1_000_000.0;
    let end_s = sum.get("end").and_then(Value::as_f64).unwrap_or(0.0);
    Some(IntervalReading {
        phase: interval_phase(settings, reverse_stream),
        end_s,
        mbps,
        retransmits: sum.get("retransmits").and_then(Value::as_u64),
        jitter_ms: sum.get("jitter_ms").and_then(Value::as_f64),
        lost_percent: sum.get("lost_percent").and_then(Value::as_f64),
    })
}

/// Phase used for a streamed interval sample.
fn interval_phase(settings: &Iperf3Settings, reverse_stream: bool) -> SpeedPhase {
    if settings.bidir {
        if reverse_stream {
            SpeedPhase::Download
        } else {
            SpeedPhase::Upload
        }
    } else if settings.reverse {
        SpeedPhase::Download
    } else {
        SpeedPhase::Upload
    }
}

/// Build a result from the final `end` event.
pub fn result_from_end(
    data: &Value,
    settings: &Iperf3Settings,
    started_at: String,
    elapsed_ms: f64,
    samples: Vec<SpeedSample>,
) -> SpeedResult {
    let sum = data.get("sum");
    let sum_sent = data.get("sum_sent").or(sum);
    let sum_received = data.get("sum_received").or(sum);
    let reverse_sum = data.get("sum_bidir_reverse");

    let sum_mbps = |value: Option<&Value>| {
        value
            .and_then(|v| v.get("bits_per_second"))
            .and_then(Value::as_f64)
            .map(|bps| bps / 1_000_000.0)
    };

    let (download_mbps, upload_mbps) = if settings.bidir {
        (
            sum_mbps(reverse_sum).or_else(|| sum_mbps(sum_received)),
            sum_mbps(sum_sent).or_else(|| sum_mbps(sum)),
        )
    } else if settings.reverse {
        (sum_mbps(sum_received), None)
    } else {
        (None, sum_mbps(sum_sent))
    };

    // iperf3 does not implement a ping phase. For TCP it exposes RTT values
    // measured from TCP_INFO on the data streams; use their mean as the
    // closest equivalent to a latency figure. UDP has no such value.
    let ping_ms = tcp_mean_rtt_ms(data);

    let retransmits = sum_sent
        .and_then(|v| v.get("retransmits"))
        .and_then(Value::as_u64);
    let jitter_ms = sum.and_then(|v| v.get("jitter_ms")).and_then(Value::as_f64);
    let lost_percent = sum
        .and_then(|v| v.get("lost_percent"))
        .and_then(Value::as_f64);
    let error = data
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_string);

    let direction = if settings.bidir {
        "bidirectional"
    } else if settings.reverse {
        "download"
    } else {
        "upload"
    };

    SpeedResult {
        tool: SpeedtestTool::Iperf3,
        server: format!("{}:{}", settings.host.trim(), settings.port),
        protocol: settings.protocol.label().to_string(),
        direction: direction.to_string(),
        ping_ms,
        jitter_ms,
        download_mbps,
        upload_mbps,
        retransmits,
        lost_percent,
        started_at,
        elapsed_ms,
        samples,
        error,
    }
}

/// Average TCP RTT across the end-of-test streams, in milliseconds.
fn tcp_mean_rtt_ms(data: &Value) -> Option<f64> {
    let streams = data.get("streams")?.as_array()?;
    let samples: Vec<f64> = streams
        .iter()
        .filter_map(|stream| stream.get("sender"))
        .filter_map(|sender| sender.get("mean_rtt"))
        .filter_map(Value::as_f64)
        .collect();
    if samples.is_empty() {
        None
    } else {
        Some(samples.iter().sum::<f64>() / samples.len() as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::IpVersion;

    fn settings() -> Iperf3Settings {
        Iperf3Settings {
            host: "speed.example".into(),
            port: 5201,
            protocol: Iperf3Protocol::Tcp,
            reverse: false,
            bidir: false,
            duration_s: 5,
            omit_s: 0,
            streams: 1,
            block_size: 0,
            bandwidth_bps: 0,
            ip_version: IpVersion::Auto,
        }
    }

    /// Manual check against the live directory. Ignored by default so CI does
    /// not depend on a third-party service.
    #[tokio::test]
    #[ignore]
    async fn live_server_list_is_reachable() {
        let servers = fetch_servers(10_000).await.expect("live list should load");
        assert!(servers.len() > 1);
        assert!(servers.iter().all(|server| !server.host.is_empty()));
    }

    #[test]
    fn parses_public_server_entries() {
        let json = r#"[{
            "IP/HOST": "speed.example.net",
            "PORT": "5201-5209",
            "OPTIONS": "-R,-u",
            "GB/S": "10",
            "CONTINENT": "Europe",
            "COUNTRY": "DE",
            "SITE": "Frankfurt",
            "PROVIDER": "Example"
        }]"#;
        let servers: Vec<Iperf3Server> = serde_json::from_str(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].host, "speed.example.net");
        assert_eq!(servers[0].first_port(), 5201);
        assert!(servers[0].label().contains("Frankfurt"));
        assert!(servers[0].label().contains("Example"));
    }

    #[test]
    fn parses_start_event_metadata() {
        let line = r#"{"event":"start","data":{"connected":[{"remote_host":"203.0.113.9","remote_port":5201}],"test_start":{"protocol":"UDP","reverse":1,"bidir":0,"duration":5}}}"#;
        match parse_stream_line(line, &settings()) {
            Some(StreamEvent::Start(start)) => {
                assert_eq!(start.peer.as_deref(), Some("203.0.113.9:5201"));
                assert_eq!(start.protocol, "UDP");
                assert!(start.reverse);
                assert!(!start.bidir);
                assert_eq!(start.duration_s, 5.0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn builds_server_progress_from_interval_event() {
        let data: Value = serde_json::from_str(
            r#"{"sum":{"start":0,"end":1,"bits_per_second":250000000.0,"retransmits":1,"jitter_ms":0.4,"lost_percent":0.1}}"#,
        )
        .unwrap();
        let start = StreamStart {
            peer: Some("198.51.100.7:43210".into()),
            protocol: "UDP".into(),
            reverse: false,
            bidir: false,
            duration_s: 10.0,
        };
        let progress = server_progress_from_interval(&data, &start).unwrap();
        assert_eq!(progress.peer, "198.51.100.7:43210");
        assert!((progress.current_mbps - 250.0).abs() < 0.001);
        assert_eq!(progress.elapsed_s, 1.0);
        assert_eq!(progress.total_s, 10.0);
        assert_eq!(progress.retransmits, Some(1));
    }

    #[test]
    fn builds_server_result_from_end_event() {
        let end: Value = serde_json::from_str(
            r#"{
                "sum_sent": {"bits_per_second": 950000000.0, "retransmits": 2},
                "sum_received": {"bits_per_second": 120000000.0},
                "sum": {"jitter_ms": 1.5, "lost_percent": 0.25}
            }"#,
        )
        .unwrap();
        let start = StreamStart {
            peer: Some("198.51.100.7:43210".into()),
            protocol: "TCP".into(),
            reverse: false,
            bidir: false,
            duration_s: 10.0,
        };
        let result = server_result_from_end(&end, &start, "now".into());
        assert_eq!(result.peer, "198.51.100.7:43210");
        assert!((result.sent_mbps.unwrap() - 950.0).abs() < 0.001);
        assert!((result.received_mbps.unwrap() - 120.0).abs() < 0.001);
        assert_eq!(result.retransmits, Some(2));
        assert_eq!(result.direction, "client -> server");
    }

    #[test]
    fn parses_interval_events() {
        let line = r#"{"event":"interval","data":{"streams":[],"sum":{"bits_per_second":125000000.0,"retransmits":3,"jitter_ms":0.5,"lost_percent":0.0}}}"#;
        match parse_stream_line(line, &settings()) {
            Some(StreamEvent::Interval(readings)) => {
                assert_eq!(readings.len(), 1);
                assert!((readings[0].mbps - 125.0).abs() < 0.001);
                assert_eq!(readings[0].retransmits, Some(3));
                assert_eq!(readings[0].phase, SpeedPhase::Upload);
                assert_eq!(readings[0].end_s, 0.0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parses_bidirectional_intervals() {
        let mut settings = settings();
        settings.bidir = true;
        let line = r#"{"event":"interval","data":{"sum":{"end":1.0,"bits_per_second":100000000.0},"sum_bidir_reverse":{"end":1.0,"bits_per_second":200000000.0}}}"#;
        match parse_stream_line(line, &settings) {
            Some(StreamEvent::Interval(readings)) => {
                assert_eq!(readings.len(), 2);
                assert_eq!(readings[0].phase, SpeedPhase::Upload);
                assert_eq!(readings[1].phase, SpeedPhase::Download);
                assert!((readings[1].mbps - 200.0).abs() < 0.001);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parses_error_and_end_events() {
        assert!(matches!(
            parse_stream_line(r#"{"event":"error","data":"server busy"}"#, &settings()),
            Some(StreamEvent::Error(message)) if message == "server busy"
        ));
        assert!(matches!(
            parse_stream_line(r#"{"event":"end","data":{}}"#, &settings()),
            Some(StreamEvent::End(_))
        ));
    }

    #[test]
    fn converts_end_event_for_upload() {
        let data: Value = serde_json::from_str(
            r#"{
                "streams": [{"sender": {"mean_rtt": 12000}}],
                "sum_sent": {"bits_per_second": 800000000.0, "retransmits": 4},
                "sum": {"jitter_ms": 0.0, "lost_percent": 0.0}
            }"#,
        )
        .unwrap();
        let result = result_from_end(&data, &settings(), "now".into(), 5000.0, vec![]);
        assert_eq!(result.tool, SpeedtestTool::Iperf3);
        assert!((result.upload_mbps.unwrap() - 800.0).abs() < 0.001);
        assert!(result.download_mbps.is_none());
        assert_eq!(result.retransmits, Some(4));
        assert!((result.ping_ms.unwrap() - 12.0).abs() < 0.001);
        assert_eq!(result.direction, "upload");
    }

    #[test]
    fn converts_end_event_for_reverse() {
        let mut settings = settings();
        settings.reverse = true;
        let data: Value = serde_json::from_str(
            r#"{"sum_received": {"bits_per_second": 450000000.0}, "sum": {}}"#,
        )
        .unwrap();
        let result = result_from_end(&data, &settings, "now".into(), 5000.0, vec![]);
        assert!((result.download_mbps.unwrap() - 450.0).abs() < 0.001);
        assert!(result.upload_mbps.is_none());
        assert_eq!(result.direction, "download");
    }
}
