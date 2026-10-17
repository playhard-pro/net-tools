//! Cross-platform system clock adjustment.
//!
//! Setting the wall clock is a privileged operation on every supported
//! platform. The caller decides when to request elevation; this module only
//! performs the write and reports whether the failure looks like a permission
//! problem, so the UI can show the matching guidance.

use std::fmt;

use time::OffsetDateTime;

/// Error returned when the system clock cannot be changed.
#[derive(Debug, Clone)]
pub struct SetTimeError {
    /// Human readable description of the failure.
    pub message: String,
    /// Whether the failure is consistent with missing elevation.
    pub permission_denied: bool,
}

impl fmt::Display for SetTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SetTimeError {}

impl SetTimeError {
    /// Used by the fallback for platforms without an implementation.
    #[allow(dead_code)]
    fn other(message: String) -> Self {
        Self {
            message,
            permission_denied: false,
        }
    }

    fn from_io(context: &str, error: std::io::Error, permission_codes: &[i32]) -> Self {
        let permission_denied = error
            .raw_os_error()
            .is_some_and(|code| permission_codes.contains(&code));
        Self {
            message: format!("{context}: {error}"),
            permission_denied,
        }
    }
}

/// Write `utc` to the operating system wall clock.
///
/// The timestamp is always passed as UTC; local timezone configuration is left
/// untouched by the platform APIs used here.
pub fn set_system_time_utc(utc: OffsetDateTime) -> Result<(), SetTimeError> {
    let utc = utc.to_offset(time::UtcOffset::UTC);
    #[cfg(unix)]
    {
        set_unix(utc)
    }
    #[cfg(windows)]
    {
        set_windows(utc)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = utc;
        Err(SetTimeError::other(
            "setting the system time is not supported on this platform".to_string(),
        ))
    }
}

/// Whether this build can show the operating system's elevation prompt.
///
/// Only Windows is handled automatically; the other platforms require the user
/// to start the application with the appropriate privileges.
pub fn supports_elevation_prompt() -> bool {
    cfg!(windows)
}

/// Ask the operating system for elevation and let an elevated copy of this
/// executable query the NTP server again and apply the fresh result.
///
/// On Windows this shows the UAC prompt. The function blocks until the helper
/// process has finished, so callers should run it off the UI thread. Other
/// platforms report that automatic elevation is unavailable.
pub fn set_system_time_elevated(server: &str, timeout_ms: u64) -> Result<(), SetTimeError> {
    #[cfg(windows)]
    {
        set_system_time_elevated_windows(server, timeout_ms)
    }
    #[cfg(not(windows))]
    {
        let _ = (server, timeout_ms);
        Err(SetTimeError::other(
            "automatic elevation is only available on Windows".to_string(),
        ))
    }
}

/// Handle the command line used by the elevated helper process.
///
/// Returns `Some(exit_code)` when the process was started as the elevation
/// helper, so `main` can exit without opening the UI. Returns `None` for a
/// normal launch and on platforms without automatic elevation.
#[cfg(windows)]
pub fn handle_elevation_request() -> Option<i32> {
    const FLAG: &str = "--set-system-time-from-ntp";

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg.to_string_lossy() != FLAG {
            continue;
        }
        let Some(server) = args.next() else {
            return Some(1);
        };
        let Some(timeout) = args.next() else {
            return Some(1);
        };
        let Ok(timeout_ms) = timeout.to_string_lossy().parse::<u64>() else {
            return Some(1);
        };
        let server = server.to_string_lossy().to_string();
        return Some(match set_system_time_from_ntp(&server, timeout_ms) {
            Ok(()) => 0,
            Err(code) => code,
        });
    }
    None
}

/// Query the server again after elevation and write the fresh result.
///
/// Exit codes are used to tell the parent process whether the network query or
/// the clock write failed.
#[cfg(windows)]
fn set_system_time_from_ntp(server: &str, timeout_ms: u64) -> Result<(), i32> {
    const QUERY_FAILED: i32 = 2;
    const SET_FAILED: i32 = 3;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SET_FAILED)?;
    let settings = crate::config::NtpSettings {
        target: server.to_string(),
        timeout_ms,
    };
    let result = runtime
        .block_on(crate::net::ntp::query(&settings))
        .map_err(|_| QUERY_FAILED)?;
    let nanos = (result.server_time_unix * 1_000_000_000.0).round() as i128;
    let datetime = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| SET_FAILED)?;
    set_system_time_utc(datetime).map_err(|_| SET_FAILED)
}

/// Non-Windows builds never expose the helper entry point.
#[cfg(not(windows))]
pub fn handle_elevation_request() -> Option<i32> {
    None
}

/// Elevation hint matching the current platform, with both the network and the
/// clock capabilities on Linux.
pub fn elevation_hint() -> String {
    #[cfg(target_os = "linux")]
    {
        "sudo setcap cap_net_raw,cap_sys_time+ep \"$(readlink -f \"$(which net-tools)\")\""
            .to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "sudo ./net-tools".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Run net-tools as administrator".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "run with elevated privileges".to_string()
    }
}

#[cfg(unix)]
fn set_unix(utc: OffsetDateTime) -> Result<(), SetTimeError> {
    let timespec = libc::timespec {
        tv_sec: utc.unix_timestamp() as libc::time_t,
        tv_nsec: utc.nanosecond() as libc::c_long,
    };
    // Safety: the pointer refers to a fully initialized timespec for the
    // duration of the call.
    let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &timespec) };
    if rc == 0 {
        return Ok(());
    }
    Err(SetTimeError::from_io(
        "failed to set the system time",
        std::io::Error::last_os_error(),
        &[libc::EPERM, libc::EACCES],
    ))
}

#[cfg(windows)]
fn set_windows(utc: OffsetDateTime) -> Result<(), SetTimeError> {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::SetSystemTime;

    let system_time = SYSTEMTIME {
        wYear: utc.year() as u16,
        wMonth: utc.month() as u16,
        wDayOfWeek: 0,
        wDay: utc.day() as u16,
        wHour: utc.hour() as u16,
        wMinute: utc.minute() as u16,
        wSecond: utc.second() as u16,
        wMilliseconds: (utc.nanosecond() / 1_000_000) as u16,
    };
    // Safety: the pointer refers to a fully initialized SYSTEMTIME.
    let ok = unsafe { SetSystemTime(&system_time) };
    if ok != 0 {
        return Ok(());
    }
    // ERROR_PRIVILEGE_NOT_HELD is returned when the process is not elevated.
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    Err(SetTimeError::from_io(
        "failed to set the system time",
        std::io::Error::last_os_error(),
        &[ERROR_PRIVILEGE_NOT_HELD],
    ))
}

/// Launch the current executable with the `runas` verb and wait for the helper.
///
/// The helper receives the selected server and timeout, queries it again after
/// the user approves the UAC prompt, performs the write and exits. Re-querying
/// keeps the applied time fresh even if the prompt stayed open for a while.
#[cfg(windows)]
fn set_system_time_elevated_windows(server: &str, timeout_ms: u64) -> Result<(), SetTimeError> {
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

    // The server is appended to the helper command line, so reject characters
    // that would change how the arguments are split.
    if server.trim().is_empty()
        || server
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return Err(SetTimeError {
            message: "invalid NTP server address for the elevated helper".to_string(),
            permission_denied: false,
        });
    }

    let exe = std::env::current_exe().map_err(|error| SetTimeError {
        message: format!("failed to locate the application executable: {error}"),
        permission_denied: false,
    })?;
    let parameters = format!("--set-system-time-from-ntp {server} {timeout_ms}");

    let verb = wide(std::ffi::OsStr::new("runas"));
    let file = wide(exe.as_os_str());
    let parameters = wide(std::ffi::OsStr::new(&parameters));

    // ShellExecuteEx may use COM internally; initialize it for the calling
    // thread and ignore the mode-already-initialized result.
    let com_result = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };

    // Safety: every pointer in the structure points to a NUL-terminated buffer
    // that lives until ShellExecuteExW returns.
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
            return Err(elevation_launch_error(launch_error));
        }
        if info.hProcess.is_null() {
            return Err(SetTimeError {
                message: "the elevated helper did not start".to_string(),
                permission_denied: false,
            });
        }

        let waited = WaitForSingleObject(info.hProcess, INFINITE);
        let mut exit_code = 0u32;
        let got_exit_code = GetExitCodeProcess(info.hProcess, &mut exit_code);
        CloseHandle(info.hProcess);

        if waited != 0 {
            return Err(SetTimeError {
                message: format!(
                    "failed while waiting for the elevated helper: {}",
                    std::io::Error::last_os_error()
                ),
                permission_denied: false,
            });
        }
        if got_exit_code == 0 {
            return Err(SetTimeError {
                message: format!(
                    "failed to read the elevated helper result: {}",
                    std::io::Error::last_os_error()
                ),
                permission_denied: false,
            });
        }
        if exit_code != 0 {
            return Err(match exit_code {
                2 => SetTimeError {
                    message: "the elevated helper could not query the NTP server".to_string(),
                    permission_denied: false,
                },
                3 => SetTimeError {
                    message: "the elevated helper could not set the system time".to_string(),
                    permission_denied: false,
                },
                other => SetTimeError {
                    message: format!("the elevated helper failed with exit code {other}"),
                    permission_denied: false,
                },
            });
        }
        Ok(())
    }
}

/// Turn a ShellExecuteEx failure into a readable error, including the common
/// case where the user dismisses the UAC prompt.
#[cfg(windows)]
fn elevation_launch_error(error: std::io::Error) -> SetTimeError {
    const ERROR_CANCELLED: i32 = 1223;
    if error.raw_os_error() == Some(ERROR_CANCELLED) {
        return SetTimeError {
            message: "administrator approval was cancelled".to_string(),
            permission_denied: false,
        };
    }
    SetTimeError {
        message: format!("failed to request administrator approval: {error}"),
        permission_denied: false,
    }
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
    fn permission_error_is_flagged() {
        let err = SetTimeError::from_io("test", std::io::Error::from_raw_os_error(1), &[1]);
        assert!(err.permission_denied);
        assert!(err.message.contains("test"));
    }

    #[test]
    fn ordinary_error_is_not_flagged() {
        let err = SetTimeError::from_io("test", std::io::Error::from_raw_os_error(2), &[1]);
        assert!(!err.permission_denied);
    }

    #[test]
    fn hint_is_not_empty() {
        assert!(!elevation_hint().is_empty());
    }

    #[test]
    fn elevation_prompt_matches_platform() {
        assert_eq!(supports_elevation_prompt(), cfg!(windows));
    }

    #[test]
    fn helper_is_inert_without_the_flag() {
        assert!(handle_elevation_request().is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn automatic_elevation_is_unavailable_off_windows() {
        assert!(set_system_time_elevated("time.example.com", 1000).is_err());
    }
}
