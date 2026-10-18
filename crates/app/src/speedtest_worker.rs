//! Hidden iperf3 worker process.
//!
//! `riperf3` streams live interval data through stdout, so the GUI starts a
//! second copy of this executable in worker mode and reads that event stream.
//! Keeping the worker in the same binary means packages still ship a single
//! executable.

use std::io::{Read, Write};
use std::process::Stdio;
use std::time::Instant;

use net_tools_core::config::{Iperf3ServerSettings, Iperf3Settings};
use net_tools_core::control::ProbeHandle;
use net_tools_core::model::{ProbeEvent, SpeedPhase, SpeedProgress, SpeedSample, SpeedtestTool};
use net_tools_core::net::iperf3::{self, StreamEvent};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Command line flag that switches the application into client worker mode.
pub const WORKER_ARG: &str = "--speedtest-iperf3-worker";

/// Command line flag that switches the application into server worker mode.
pub const SERVER_WORKER_ARG: &str = "--speedtest-iperf3-server-worker";

/// Whether the current process was started as a hidden worker.
pub fn is_worker_invocation() -> bool {
    matches!(
        std::env::args().nth(1).as_deref(),
        Some(WORKER_ARG) | Some(SERVER_WORKER_ARG)
    )
}

/// Run the hidden worker. Returns the process exit code.
pub fn run_worker() -> i32 {
    match std::env::args().nth(1).as_deref() {
        Some(SERVER_WORKER_ARG) => run_server_worker_mode(),
        _ => run_client_worker_mode(),
    }
}

fn read_worker_input() -> Option<String> {
    let mut input = String::new();
    match std::io::stdin().read_to_string(&mut input) {
        Ok(_) => Some(input),
        Err(error) => {
            eprintln!("iperf3 worker could not read its settings: {error}");
            None
        }
    }
}

fn worker_runtime() -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Some(runtime),
        Err(error) => {
            eprintln!("iperf3 worker could not start a runtime: {error}");
            None
        }
    }
}

fn run_client_worker_mode() -> i32 {
    let Some(input) = read_worker_input() else {
        return 1;
    };
    let settings: Iperf3Settings = match serde_json::from_str(&input) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("iperf3 worker received invalid settings: {error}");
            return 1;
        }
    };
    let Some(runtime) = worker_runtime() else {
        return 1;
    };
    match runtime.block_on(iperf3::run_worker(&settings)) {
        Ok(()) => 0,
        Err(error) => emit_worker_error(error),
    }
}

fn run_server_worker_mode() -> i32 {
    let Some(input) = read_worker_input() else {
        return 1;
    };
    let settings: Iperf3ServerSettings = match serde_json::from_str(&input) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("iperf3 server worker received invalid settings: {error}");
            return 1;
        }
    };
    let Some(runtime) = worker_runtime() else {
        return 1;
    };
    match runtime.block_on(iperf3::run_server_worker(&settings)) {
        Ok(()) => 0,
        Err(error) => emit_worker_error(error),
    }
}

fn emit_worker_error(error: String) -> i32 {
    // Emit a machine readable error line so the parent can display the failure
    // even when riperf3 did not produce one itself.
    let event = serde_json::json!({ "event": "error", "data": error });
    println!("{event}");
    let _ = std::io::stdout().flush();
    1
}

/// Parent-side task: start the worker, stream its interval events and emit
/// unified probe events.
pub async fn run_iperf3(handle: &ProbeHandle<ProbeEvent>, settings: &Iperf3Settings) {
    if let Err(message) = run_iperf3_inner(handle, settings).await {
        handle.send(ProbeEvent::Error {
            message,
            hint: None,
        });
    }
    handle.send(ProbeEvent::Finished);
}

async fn run_iperf3_inner(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &Iperf3Settings,
) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("could not locate the application executable: {e}"))?;
    let mut child = Command::new(exe)
        .arg(WORKER_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("could not start the iperf3 worker: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("the iperf3 worker has no input pipe")?;
    let payload =
        serde_json::to_vec(settings).map_err(|e| format!("could not encode settings: {e}"))?;
    stdin
        .write_all(&payload)
        .await
        .map_err(|e| format!("could not send settings to the iperf3 worker: {e}"))?;
    drop(stdin);

    let stdout = child
        .stdout
        .take()
        .ok_or("the iperf3 worker has no output pipe")?;
    let stderr = child.stderr.take();
    let stderr_task = tokio::spawn(async move {
        let mut text = String::new();
        if let Some(mut stderr) = stderr {
            let _ = stderr.read_to_string(&mut text).await;
        }
        text
    });

    let mut lines = BufReader::new(stdout).lines();
    let started_at = net_tools_core::clock::now_string();
    let started = Instant::now();
    let total_s = settings.duration_s.max(1) as f64;
    let mut samples: Vec<SpeedSample> = Vec::new();
    let mut end_data = None;
    let mut error: Option<String> = None;
    let mut cancelled = false;

    handle.send(ProbeEvent::SpeedProgress(SpeedProgress {
        tool: SpeedtestTool::Iperf3,
        phase: SpeedPhase::Connecting,
        current_mbps: 0.0,
        elapsed_s: 0.0,
        total_s,
        progress: 0.0,
    }));

    loop {
        let line = tokio::select! {
            _ = handle.cancelled() => {
                cancelled = true;
                let _ = child.kill().await;
                break;
            }
            line = lines.next_line() => line,
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(io_error) => {
                error = Some(format!("could not read iperf3 output: {io_error}"));
                break;
            }
        };
        let Some(event) = iperf3::parse_stream_line(&line, settings) else {
            continue;
        };
        match event {
            StreamEvent::Start(_) => {
                handle.send(ProbeEvent::SpeedProgress(SpeedProgress {
                    tool: SpeedtestTool::Iperf3,
                    phase: SpeedPhase::Testing,
                    current_mbps: 0.0,
                    elapsed_s: 0.0,
                    total_s,
                    progress: 0.0,
                }));
            }
            StreamEvent::Interval(readings) => {
                let Some(primary) = readings.first() else {
                    continue;
                };
                for reading in &readings {
                    samples.push(SpeedSample {
                        elapsed_s: reading.end_s,
                        mbps: reading.mbps,
                        phase: reading.phase,
                    });
                }
                let elapsed_s = primary.end_s.max(started.elapsed().as_secs_f64());
                let progress = (elapsed_s / total_s).clamp(0.0, 1.0) as f32;
                handle.send(ProbeEvent::SpeedProgress(SpeedProgress {
                    tool: SpeedtestTool::Iperf3,
                    phase: SpeedPhase::Testing,
                    current_mbps: primary.mbps,
                    elapsed_s,
                    total_s,
                    progress,
                }));
            }
            StreamEvent::End(data) => {
                end_data = Some(data);
            }
            StreamEvent::Error(message) => {
                if end_data.is_none() {
                    error = Some(message);
                }
            }
        }
    }

    let status = if cancelled {
        None
    } else {
        Some(child.wait().await)
    };
    if cancelled {
        let _ = child.wait().await;
    }
    let stderr_text = stderr_task.await.unwrap_or_default();
    if cancelled {
        return Ok(());
    }

    if let Some(data) = end_data {
        let result = iperf3::result_from_end(
            &data,
            settings,
            started_at,
            started.elapsed().as_secs_f64() * 1000.0,
            samples,
        );
        if let Some(message) = &result.error {
            if error.is_none() {
                error = Some(message.clone());
            }
        }
        handle.send(ProbeEvent::SpeedResult(result));
        if let Some(message) = error {
            handle.send(ProbeEvent::Error {
                message,
                hint: None,
            });
        }
        return Ok(());
    }

    if let Some(status) = status {
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                if error.is_none() {
                    error = Some(format!(
                        "iperf3 worker exited with status {}",
                        status.code().unwrap_or(-1)
                    ));
                }
            }
            Err(io_error) => {
                if error.is_none() {
                    error = Some(format!("could not wait for the iperf3 worker: {io_error}"));
                }
            }
        }
    }
    let stderr_text = stderr_text.trim();
    if error.is_none() && !stderr_text.is_empty() {
        error = Some(stderr_text.to_string());
    }
    Err(error.unwrap_or_else(|| "iperf3 worker produced no result".into()))
}

/// Parent-side task for the built-in iperf3 server.
pub async fn run_iperf3_server(handle: &ProbeHandle<ProbeEvent>, settings: &Iperf3ServerSettings) {
    if let Err(message) = run_iperf3_server_inner(handle, settings).await {
        handle.send(ProbeEvent::Error {
            message,
            hint: None,
        });
    }
    handle.send(ProbeEvent::Finished);
}

async fn run_iperf3_server_inner(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &Iperf3ServerSettings,
) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("could not locate the application executable: {e}"))?;
    let mut child = Command::new(exe)
        .arg(SERVER_WORKER_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("could not start the iperf3 server worker: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("the iperf3 server worker has no input pipe")?;
    let payload =
        serde_json::to_vec(settings).map_err(|e| format!("could not encode settings: {e}"))?;
    stdin
        .write_all(&payload)
        .await
        .map_err(|e| format!("could not send settings to the iperf3 server worker: {e}"))?;
    drop(stdin);

    let stdout = child
        .stdout
        .take()
        .ok_or("the iperf3 server worker has no output pipe")?;
    let stderr = child.stderr.take();
    let stderr_task = tokio::spawn(async move {
        let mut text = String::new();
        if let Some(mut stderr) = stderr {
            let _ = stderr.read_to_string(&mut text).await;
        }
        text
    });

    let mut lines = BufReader::new(stdout).lines();
    // Client settings are only needed to satisfy the shared interval parser;
    // the server does not use them.
    let parser_settings = Iperf3Settings::default();
    let mut start = None;
    let mut cancelled = false;
    let mut error: Option<String> = None;

    handle.send(ProbeEvent::Info(format!(
        "iperf3 server listening on {}:{}",
        if settings.bind_address.trim().is_empty() {
            "0.0.0.0"
        } else {
            settings.bind_address.trim()
        },
        settings.port
    )));

    loop {
        let line = tokio::select! {
            _ = handle.cancelled() => {
                cancelled = true;
                let _ = child.kill().await;
                break;
            }
            line = lines.next_line() => line,
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(io_error) => {
                error = Some(format!("could not read iperf3 server output: {io_error}"));
                break;
            }
        };
        let raw: Option<serde_json::Value> = serde_json::from_str(&line).ok();
        let Some(event) = iperf3::parse_stream_line(&line, &parser_settings) else {
            continue;
        };
        match event {
            StreamEvent::Start(info) => {
                let peer = info.peer.clone().unwrap_or_else(|| "-".into());
                handle.send(ProbeEvent::Info(format!(
                    "client connected: {} ({})",
                    peer, info.protocol
                )));
                handle.send(ProbeEvent::Iperf3ServerProgress(
                    net_tools_core::model::Iperf3ServerProgress {
                        peer,
                        protocol: info.protocol.clone(),
                        direction: if info.bidir {
                            "bidirectional".into()
                        } else if info.reverse {
                            "server -> client".into()
                        } else {
                            "client -> server".into()
                        },
                        elapsed_s: 0.0,
                        total_s: info.duration_s,
                        current_mbps: 0.0,
                        retransmits: None,
                        jitter_ms: None,
                        lost_percent: None,
                    },
                ));
                start = Some(info);
            }
            StreamEvent::End(data) => {
                let info = start.take().unwrap_or_default();
                let result = iperf3::server_result_from_end(
                    &data,
                    &info,
                    net_tools_core::clock::now_string(),
                );
                handle.send(ProbeEvent::Iperf3ServerResult(result));
            }
            StreamEvent::Error(message) => {
                handle.send(ProbeEvent::Error {
                    message,
                    hint: None,
                });
            }
            StreamEvent::Interval(_) => {
                if let (Some(info), Some(data)) = (
                    start.as_ref(),
                    raw.as_ref().and_then(|value| value.get("data")),
                ) {
                    if let Some(progress) = iperf3::server_progress_from_interval(data, info) {
                        handle.send(ProbeEvent::Iperf3ServerProgress(progress));
                    }
                }
            }
        }
    }

    let status = if cancelled {
        None
    } else {
        Some(child.wait().await)
    };
    if cancelled {
        let _ = child.wait().await;
    }
    let stderr_text = stderr_task.await.unwrap_or_default();
    if cancelled {
        return Ok(());
    }
    if let Some(status) = status {
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                if error.is_none() {
                    error = Some(format!(
                        "iperf3 server worker exited with status {}",
                        status.code().unwrap_or(-1)
                    ));
                }
            }
            Err(io_error) => {
                if error.is_none() {
                    error = Some(format!(
                        "could not wait for the iperf3 server worker: {io_error}"
                    ));
                }
            }
        }
    }
    let stderr_text = stderr_text.trim();
    if error.is_none() && !stderr_text.is_empty() {
        error = Some(stderr_text.to_string());
    }
    if let Some(error) = error {
        Err(error)
    } else {
        Ok(())
    }
}
