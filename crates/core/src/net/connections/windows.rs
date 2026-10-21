//! Windows socket collection through the IP Helper API.
//!
//! The owner-PID tables provide the complete TCP and UDP inventory without
//! elevation. Process names and destructive actions use the Win32 process API.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, SetTcpEntry, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD,
    MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

use super::{
    sort_entries, ConnectionEntry, ConnectionProtocol, ConnectionSnapshot, ConnectionState,
};

/// Cache of process names and whether any owner was hidden by access rights.
struct ProcessNames {
    cache: HashMap<u32, Option<String>>,
    hidden: bool,
}

impl ProcessNames {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            hidden: false,
        }
    }

    /// Return the executable base name for `pid`.
    fn name(&mut self, pid: u32) -> Option<String> {
        if let Some(name) = self.cache.get(&pid) {
            return name.clone();
        }
        let name = process_name(pid);
        if name.is_none() && pid != 0 {
            self.hidden = true;
        }
        self.cache.insert(pid, name.clone());
        name
    }
}

/// Read the executable path and keep only its base name.
fn process_name(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    std::path::Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .or_else(|| (!path.is_empty()).then_some(path))
}

/// Collect the IPv4 and IPv6 TCP/UDP tables.
pub(super) fn collect() -> Result<ConnectionSnapshot, String> {
    let mut entries = Vec::new();
    let mut names = ProcessNames::new();
    let mut errors = Vec::new();

    for family in [AF_INET as u32, AF_INET6 as u32] {
        if let Err(error) = read_tcp_table(family, &mut entries, &mut names) {
            errors.push(error);
        }
        if let Err(error) = read_udp_table(family, &mut entries, &mut names) {
            errors.push(error);
        }
    }

    if entries.is_empty() && !errors.is_empty() {
        return Err(errors.join("; "));
    }

    sort_entries(&mut entries);
    let mut warnings = errors;
    if names.hidden {
        warnings.push(
            "some socket owners are protected; run as administrator to see every process"
                .to_string(),
        );
    }

    Ok(ConnectionSnapshot {
        captured_at: super::super::overview::captured_at_now(),
        entries,
        warnings,
    })
}

/// Read one address family of the TCP owner-PID table.
fn read_tcp_table(
    family: u32,
    entries: &mut Vec<ConnectionEntry>,
    names: &mut ProcessNames,
) -> Result<(), String> {
    let buffer = query_table(|pointer, size| unsafe {
        GetExtendedTcpTable(pointer, size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    if buffer.is_empty() {
        return Ok(());
    }

    if family == AF_INET as u32 {
        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
        for row in rows {
            entries.push(tcp_entry(row, names));
        }
    } else {
        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
        for row in rows {
            entries.push(tcp6_entry(row, names));
        }
    }
    Ok(())
}

/// Read one address family of the UDP owner-PID table.
fn read_udp_table(
    family: u32,
    entries: &mut Vec<ConnectionEntry>,
    names: &mut ProcessNames,
) -> Result<(), String> {
    let buffer = query_table(|pointer, size| unsafe {
        GetExtendedUdpTable(pointer, size, 0, family, UDP_TABLE_OWNER_PID, 0)
    })?;
    if buffer.is_empty() {
        return Ok(());
    }

    if family == AF_INET as u32 {
        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
        for row in rows {
            entries.push(udp_entry(row, names));
        }
    } else {
        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let rows =
            unsafe { slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
        for row in rows {
            entries.push(udp6_entry(row, names));
        }
    }
    Ok(())
}

/// Allocate and fill an IP Helper table buffer.
///
/// The first call asks for the required size, then the table is queried again
/// into an aligned buffer. The caller casts the result to the matching table
/// type.
fn query_table(query: impl Fn(*mut c_void, *mut u32) -> u32) -> Result<Vec<usize>, String> {
    let mut size = 0u32;
    let status = query(std::ptr::null_mut(), &mut size);
    if status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS {
        return Err(format!(
            "IP Helper table size query failed with error {status}"
        ));
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let words = (size as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let status = query(buffer.as_mut_ptr() as *mut c_void, &mut size);
    if status != ERROR_SUCCESS {
        return Err(format!("IP Helper table query failed with error {status}"));
    }
    Ok(buffer)
}

/// Convert one IPv4 TCP row.
fn tcp_entry(row: &MIB_TCPROW_OWNER_PID, names: &mut ProcessNames) -> ConnectionEntry {
    let remote_port = network_port(row.dwRemotePort);
    let has_peer = remote_port != 0;
    ConnectionEntry {
        protocol: ConnectionProtocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_le_bytes())),
        local_port: network_port(row.dwLocalPort),
        remote_addr: has_peer.then(|| IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_le_bytes()))),
        remote_port: has_peer.then_some(remote_port),
        state: tcp_state(row.dwState),
        pid: Some(row.dwOwningPid),
        process: names.name(row.dwOwningPid),
        uid: None,
    }
}

/// Convert one IPv6 TCP row.
fn tcp6_entry(row: &MIB_TCP6ROW_OWNER_PID, names: &mut ProcessNames) -> ConnectionEntry {
    let remote_port = network_port(row.dwRemotePort);
    let has_peer = remote_port != 0;
    ConnectionEntry {
        protocol: ConnectionProtocol::Tcp,
        local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
        local_port: network_port(row.dwLocalPort),
        remote_addr: has_peer.then(|| IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr))),
        remote_port: has_peer.then_some(remote_port),
        state: tcp_state(row.dwState),
        pid: Some(row.dwOwningPid),
        process: names.name(row.dwOwningPid),
        uid: None,
    }
}

/// Convert one IPv4 UDP row.
fn udp_entry(row: &MIB_UDPROW_OWNER_PID, names: &mut ProcessNames) -> ConnectionEntry {
    ConnectionEntry {
        protocol: ConnectionProtocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_le_bytes())),
        local_port: network_port(row.dwLocalPort),
        remote_addr: None,
        remote_port: None,
        state: ConnectionState::Unconnected,
        pid: Some(row.dwOwningPid),
        process: names.name(row.dwOwningPid),
        uid: None,
    }
}

/// Convert one IPv6 UDP row.
fn udp6_entry(row: &MIB_UDP6ROW_OWNER_PID, names: &mut ProcessNames) -> ConnectionEntry {
    ConnectionEntry {
        protocol: ConnectionProtocol::Udp,
        local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
        local_port: network_port(row.dwLocalPort),
        remote_addr: None,
        remote_port: None,
        state: ConnectionState::Unconnected,
        pid: Some(row.dwOwningPid),
        process: names.name(row.dwOwningPid),
        uid: None,
    }
}

/// Convert a DWORD network-order port field into host order.
fn network_port(value: u32) -> u16 {
    u16::from_be((value & 0xFFFF) as u16)
}

/// Translate an IP Helper TCP state number into the shared state type.
fn tcp_state(value: u32) -> ConnectionState {
    match value as i32 {
        MIB_TCP_STATE_CLOSED => ConnectionState::Closed,
        MIB_TCP_STATE_LISTEN => ConnectionState::Listen,
        MIB_TCP_STATE_SYN_SENT => ConnectionState::SynSent,
        MIB_TCP_STATE_SYN_RCVD => ConnectionState::SynReceived,
        MIB_TCP_STATE_ESTAB => ConnectionState::Established,
        MIB_TCP_STATE_FIN_WAIT1 => ConnectionState::FinWait1,
        MIB_TCP_STATE_FIN_WAIT2 => ConnectionState::FinWait2,
        MIB_TCP_STATE_CLOSE_WAIT => ConnectionState::CloseWait,
        MIB_TCP_STATE_CLOSING => ConnectionState::Closing,
        MIB_TCP_STATE_LAST_ACK => ConnectionState::LastAck,
        MIB_TCP_STATE_TIME_WAIT => ConnectionState::TimeWait,
        MIB_TCP_STATE_DELETE_TCB => ConnectionState::Closed,
        _ => ConnectionState::Unknown,
    }
}

/// Terminate a process. Windows has no graceful signal equivalent, so both
/// normal and forced termination use `TerminateProcess`.
pub(super) fn terminate_process(pid: u32, _force: bool) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        return Err(windows_error("OpenProcess"));
    }
    let ok = unsafe { TerminateProcess(handle, 1) };
    let error = if ok == 0 {
        Some(windows_error("TerminateProcess"))
    } else {
        None
    };
    unsafe { CloseHandle(handle) };
    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Destroy an IPv4 TCP connection by moving its row to `DELETE_TCB`.
pub(super) fn close_connection(entry: &ConnectionEntry) -> Result<(), String> {
    let (IpAddr::V4(local_addr), Some(IpAddr::V4(remote_addr))) =
        (entry.local_addr, entry.remote_addr)
    else {
        return Err("closing an IPv6 connection is not supported on Windows".to_string());
    };
    let Some(remote_port) = entry.remote_port else {
        return Err("the socket has no remote endpoint".to_string());
    };

    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            dwState: MIB_TCP_STATE_DELETE_TCB as u32,
        },
        dwLocalAddr: u32::from_le_bytes(local_addr.octets()),
        dwLocalPort: u16::to_be(entry.local_port) as u32,
        dwRemoteAddr: u32::from_le_bytes(remote_addr.octets()),
        dwRemotePort: u16::to_be(remote_port) as u32,
    };
    let status = unsafe { SetTcpEntry(&row) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("SetTcpEntry failed with error {status}"))
    }
}

/// Format a Win32 error with its numeric code for diagnostics.
fn windows_error(operation: &str) -> String {
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
        format!("{operation} failed: access denied; run as administrator")
    } else {
        format!("{operation} failed: {error}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_network_port() {
        assert_eq!(network_port(u16::to_be(80) as u32), 80);
        assert_eq!(network_port(u16::to_be(443) as u32), 443);
        assert_eq!(network_port(0), 0);
    }

    #[test]
    fn maps_tcp_states() {
        assert_eq!(
            tcp_state(MIB_TCP_STATE_LISTEN as u32),
            ConnectionState::Listen
        );
        assert_eq!(
            tcp_state(MIB_TCP_STATE_ESTAB as u32),
            ConnectionState::Established
        );
        assert_eq!(
            tcp_state(MIB_TCP_STATE_TIME_WAIT as u32),
            ConnectionState::TimeWait
        );
        assert_eq!(tcp_state(999), ConnectionState::Unknown);
    }
}
