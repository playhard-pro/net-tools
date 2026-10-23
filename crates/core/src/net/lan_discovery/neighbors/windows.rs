//! Windows neighbor table reader using the IP Helper API.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::slice;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

use super::NeighborEntry;

pub(super) fn collect() -> Result<Vec<NeighborEntry>, String> {
    let mut table: *mut MIB_IPNET_TABLE2 = ptr::null_mut();
    let status = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) };
    if status != 0 || table.is_null() {
        return Err(format!("GetIpNetTable2 failed: {status}"));
    }

    let rows = unsafe {
        let table = &*table;
        slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize)
    };
    let entries = rows.iter().filter_map(entry_from_row).collect::<Vec<_>>();
    unsafe { FreeMibTable(table as *const _) };
    Ok(entries)
}

fn entry_from_row(row: &MIB_IPNET_ROW2) -> Option<NeighborEntry> {
    let ip = sockaddr_ip(&row.Address)?;
    let mac = mac_text(&row.PhysicalAddress[..(row.PhysicalAddressLength as usize).min(32)])?;
    Some(NeighborEntry {
        ip,
        mac,
        interface: Some(format!("if{}", row.InterfaceIndex)),
    })
}

fn sockaddr_ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
    match unsafe { address.si_family } {
        AF_INET => {
            let bytes = unsafe { address.Ipv4.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(
                bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
            )))
        }
        AF_INET6 => {
            let bytes = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn mac_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_formatted() {
        assert_eq!(
            mac_text(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).as_deref(),
            Some("00:11:22:33:44:55")
        );
        assert!(mac_text(&[0; 6]).is_none());
    }
}
