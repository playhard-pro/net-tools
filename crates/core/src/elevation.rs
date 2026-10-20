//! Privileged probe helper used on Windows.
//!
//! Raw ICMP sockets need administrator rights on Windows. Instead of restarting
//! the whole UI, the parent process starts this same executable through UAC and
//! asks it to run one probe. Events are exchanged through a small temporary
//! directory: a JSON request, a JSON-lines event stream and a cancellation
//! marker.

#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::time::Duration;
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{MtrSettings, PingSettings};
use crate::control::ProbeHandle;
use crate::model::ProbeEvent;

/// Environment marker set inside the elevated helper process.
const HELPER_ENV: &str = "NET_TOOLS_PROBE_HELPER";

/// Whether this process is the elevated helper.
pub fn in_helper_process() -> bool {
    std::env::var_os(HELPER_ENV).is_some()
}

/// Probe requested from the elevated helper process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperRequest {
    Mtr(MtrSettings),
    Pmtu(PingSettings),
}

impl HelperRequest {
    /// Short name used in diagnostics.
    pub fn label(&self) -> &'static str {
        match self {
            HelperRequest::Mtr(_) => "tcp mtr",
            HelperRequest::Pmtu(_) => "path mtu",
        }
    }
}

/// Files used to communicate with the elevated helper.
#[cfg(windows)]
struct HelperPaths {
    dir: PathBuf,
    request: PathBuf,
    events: PathBuf,
    cancel: PathBuf,
}

#[cfg(windows)]
impl HelperPaths {
    fn new() -> std::io::Result<Self> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("net-tools-probe-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            request: dir.join("request.json"),
            events: dir.join("events.jsonl"),
            cancel: dir.join("cancel"),
            dir,
        })
    }

    /// Remove exactly the files this helper created, then the directory.
    fn cleanup(&self) {
        for path in [&self.request, &self.events, &self.cancel] {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Handle the helper command line, if this process was started as the elevated
/// helper. Returns the process exit code for the caller in `main`.
pub fn handle_helper_request() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("--probe-helper") {
        return None;
    }
    // Mark the helper process so a failed privileged probe does not try to
    // elevate itself recursively.
    std::env::set_var(HELPER_ENV, "1");
    if args.len() != 4 {
        return Some(1);
    }
    Some(run_helper(
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    ))
}

/// Run one helper request and stream its events to the parent.
fn run_helper(request_path: &Path, events_path: &Path, cancel_path: &Path) -> i32 {
    let request: HelperRequest = match std::fs::read_to_string(request_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
    {
        Some(value) => value,
        None => return 1,
    };

    let mut events = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_path)
    {
        Ok(value) => value,
        Err(_) => return 1,
    };

    // The helper loop below is synchronous, so the runtime needs worker
    // threads that keep the spawned probe running between drains.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(value) => value,
        Err(_) => return 1,
    };
    let handle = runtime.handle().clone();
    let mut controller: crate::control::TaskController<ProbeEvent> =
        crate::control::TaskController::new();
    match request {
        HelperRequest::Mtr(settings) => {
            controller.start(&handle, move |inner| async move {
                crate::net::mtr::run_mtr(&inner, &settings).await
            });
        }
        HelperRequest::Pmtu(settings) => {
            controller.start(&handle, move |inner| async move {
                crate::net::pmtu::run_pmtu(&inner, &settings).await
            });
        }
    }

    let mut saw_finished = false;
    loop {
        for event in controller.drain() {
            if matches!(event, ProbeEvent::Finished) {
                saw_finished = true;
            }
            write_event(&mut events, &event);
        }
        if saw_finished {
            break;
        }
        if cancel_path.exists() {
            controller.stop();
        }
        if !controller.is_active() {
            // Drain once more so the final events are not lost.
            for event in controller.drain() {
                if matches!(event, ProbeEvent::Finished) {
                    saw_finished = true;
                }
                write_event(&mut events, &event);
            }
            if saw_finished {
                break;
            }
            // The task ended without Finished (for example after a panic).
            write_event(
                &mut events,
                &ProbeEvent::Error {
                    message: "the elevated probe stopped unexpectedly".to_string(),
                    hint: None,
                },
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !saw_finished {
        write_event(&mut events, &ProbeEvent::Finished);
    }
    0
}

/// Append one event as a JSON line and flush it so the parent can observe it.
fn write_event(file: &mut std::fs::File, event: &ProbeEvent) {
    use std::io::Write;
    if let Ok(line) = serde_json::to_string(event) {
        let _ = writeln!(file, "{line}");
        let _ = file.flush();
    }
}

/// Run a probe through an elevated helper process on Windows.
///
/// The caller's `ProbeEvent` stream is fed from the helper's event file. On
/// other platforms automatic elevation is unavailable.
pub async fn run_elevated(handle: &ProbeHandle<ProbeEvent>, request: &HelperRequest) {
    if in_helper_process() {
        handle.send(ProbeEvent::Error {
            message: format!("{} still needs privileges after elevation", request.label()),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }
    #[cfg(windows)]
    {
        run_elevated_windows(handle, request).await;
    }
    #[cfg(not(windows))]
    {
        handle.send(ProbeEvent::Error {
            message: format!(
                "automatic elevation is only available on Windows ({} needs privileges)",
                request.label()
            ),
            hint: Some(privilege_hint()),
        });
        handle.send(ProbeEvent::Finished);
    }
}

/// Whether this platform can request elevation automatically.
pub fn supports_elevation_prompt() -> bool {
    cfg!(windows)
}

/// Whether the current process already has the privileges needed for raw
/// sockets.
///
/// Windows allows some raw socket objects to be created without elevation but
/// does not deliver transport ICMP errors or allow promiscuous capture, which
/// makes a probe silently lose every packet. Checking the token up front avoids
/// that misleading all-loss result.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = std::ptr::null_mut();
        // Safety: the token handle is written by OpenProcessToken and closed
        // before returning. The buffer size matches TOKEN_ELEVATION exactly.
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut length = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut length,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Platform guidance used when automatic elevation is not available.
#[cfg(not(windows))]
fn privilege_hint() -> String {
    crate::net::privilege::guidance()
}

#[cfg(windows)]
async fn run_elevated_windows(handle: &ProbeHandle<ProbeEvent>, request: &HelperRequest) {
    let paths = match HelperPaths::new() {
        Ok(value) => value,
        Err(e) => {
            handle.send(ProbeEvent::Error {
                message: format!("failed to prepare the elevated probe: {e}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    let request_text = match serde_json::to_string(request) {
        Ok(value) => value,
        Err(e) => {
            paths.cleanup();
            handle.send(ProbeEvent::Error {
                message: format!("failed to serialize the elevated probe: {e}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    if let Err(e) = std::fs::write(&paths.request, request_text) {
        paths.cleanup();
        handle.send(ProbeEvent::Error {
            message: format!("failed to write the elevated probe request: {e}"),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }
    if let Err(e) = std::fs::File::create(&paths.events) {
        paths.cleanup();
        handle.send(ProbeEvent::Error {
            message: format!("failed to create the elevated probe event file: {e}"),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

    let parameters = format!(
        "--probe-helper {} {} {}",
        quote_arg(&paths.request),
        quote_arg(&paths.events),
        quote_arg(&paths.cancel)
    );
    let (tx, rx) = std::sync::mpsc::channel::<Result<i32, String>>();
    std::thread::spawn(move || {
        let _ = tx.send(launch_and_wait(&parameters));
    });

    let mut offset = 0u64;
    let mut partial = String::new();
    let mut saw_finished = false;
    let mut exit: Option<Result<i32, String>> = None;
    let mut cancel_started: Option<std::time::Instant> = None;

    loop {
        read_events(
            &paths.events,
            &mut offset,
            &mut partial,
            handle,
            &mut saw_finished,
        );
        if exit.is_none() {
            match rx.try_recv() {
                Ok(value) => exit = Some(value),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    exit = Some(Err(
                        "the elevated helper thread stopped unexpectedly".to_string()
                    ));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(status) = &exit {
            read_events(
                &paths.events,
                &mut offset,
                &mut partial,
                handle,
                &mut saw_finished,
            );
            match status {
                Ok(0) => {}
                Ok(code) => handle.send(ProbeEvent::Error {
                    message: format!("the elevated probe failed with exit code {code}"),
                    hint: None,
                }),
                Err(message) => handle.send(ProbeEvent::Error {
                    message: message.clone(),
                    hint: None,
                }),
            }
            break;
        }
        if handle.is_cancelled() && cancel_started.is_none() {
            let _ = std::fs::write(&paths.cancel, b"cancel");
            cancel_started = Some(std::time::Instant::now());
        }
        // Do not keep the UI task alive forever if the helper ignores the
        // cancellation marker.
        if cancel_started.is_some_and(|start| start.elapsed() > Duration::from_secs(3)) {
            handle.send(ProbeEvent::Error {
                message: "the elevated probe did not stop in time".to_string(),
                hint: None,
            });
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Parse a final line that may not have been terminated by a newline.
    if !partial.trim().is_empty() {
        if let Ok(event) = serde_json::from_str::<ProbeEvent>(partial.trim()) {
            if matches!(event, ProbeEvent::Finished) {
                saw_finished = true;
            }
            handle.send(event);
        }
    }
    if !saw_finished {
        handle.send(ProbeEvent::Finished);
    }
    paths.cleanup();
}

/// Read events appended since the last offset.
#[cfg(windows)]
fn read_events(
    path: &Path,
    offset: &mut u64,
    partial: &mut String,
    handle: &ProbeHandle<ProbeEvent>,
    saw_finished: &mut bool,
) {
    let mut file = match std::fs::File::open(path) {
        Ok(value) => value,
        Err(_) => return,
    };
    if file.seek(SeekFrom::Start(*offset)).is_err() {
        return;
    }
    let mut data = Vec::new();
    if file.read_to_end(&mut data).is_err() {
        return;
    }
    *offset += data.len() as u64;
    partial.push_str(&String::from_utf8_lossy(&data));
    while let Some(position) = partial.find('\n') {
        let line = partial[..position].trim().to_string();
        partial.drain(..=position);
        if line.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<ProbeEvent>(&line) {
            if matches!(event, ProbeEvent::Finished) {
                *saw_finished = true;
            }
            handle.send(event);
        }
    }
}

/// Start this executable through UAC and wait for it to finish.
///
/// Returns the helper's exit code, or a readable launch error. The caller maps
/// exit codes to probe-specific diagnostics.
#[cfg(windows)]
pub fn launch_and_wait(parameters: &str) -> Result<i32, String> {
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe = std::env::current_exe()
        .map_err(|error| format!("failed to locate the application executable: {error}"))?;
    let verb = wide(std::ffi::OsStr::new("runas"));
    let file = wide(exe.as_os_str());
    let parameters = wide(std::ffi::OsStr::new(parameters));

    let com_result = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_SHOWNORMAL;

        let launched = ShellExecuteExW(&mut info);
        let launch_error = std::io::Error::last_os_error();
        if com_result >= 0 {
            CoUninitialize();
        }
        if launched == 0 {
            const ERROR_CANCELLED: i32 = 1223;
            if launch_error.raw_os_error() == Some(ERROR_CANCELLED) {
                return Err("administrator approval was cancelled".to_string());
            }
            return Err(format!(
                "failed to request administrator approval: {launch_error}"
            ));
        }
        if info.hProcess.is_null() {
            return Err("the elevated helper did not start".to_string());
        }

        let waited = WaitForSingleObject(info.hProcess, INFINITE);
        let mut exit_code = 0u32;
        let got_exit_code = GetExitCodeProcess(info.hProcess, &mut exit_code);
        CloseHandle(info.hProcess);
        if waited != 0 {
            return Err(format!(
                "failed while waiting for the elevated helper: {}",
                std::io::Error::last_os_error()
            ));
        }
        if got_exit_code == 0 {
            return Err(format!(
                "failed to read the elevated helper result: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(exit_code as i32)
    }
}

/// Quote one command-line argument for the ShellExecuteEx parameter string.
#[cfg(windows)]
fn quote_arg(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('"', "\\\""))
}

/// Convert an OS string to the NUL-terminated UTF-16 form used by Win32 APIs.
#[cfg(windows)]
fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_request_roundtrip() {
        let request = HelperRequest::Pmtu(PingSettings::default());
        let text = serde_json::to_string(&request).unwrap();
        let back: HelperRequest = serde_json::from_str(&text).unwrap();
        assert_eq!(back.label(), "path mtu");
    }

    #[test]
    fn helper_flag_is_not_confused_with_normal_start() {
        // The test process has no helper arguments.
        assert!(handle_helper_request().is_none());
    }
}
