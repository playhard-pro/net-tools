//! Windows implementation using the IP Helper API.
//!
//! `GetIfTable2` provides the link attributes and counters in one call, while
//! `GetIpForwardTable2` and `GetNetworkParams` provide routes and DNS servers.
//! Addresses are taken from `getifaddrs` so their families and prefix lengths
//! are handled by the same crate on every platform.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::slice;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, GetIpForwardTable2, GetNetworkParams, FIXED_INFO_W2KSP1,
    IP_ADDR_STRING, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_OPER_STATUS_UP;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

use super::{
    captured_at_now, format_mac, with_prefix, DefaultGateway, InterfaceCounters, NetworkInterface,
    NetworkRoute, NetworkSnapshot,
};

/// Interfaces plus the index and LUID lookup maps used by the route table.
type InterfaceTables = (
    BTreeMap<String, NetworkInterface>,
    BTreeMap<u32, String>,
    BTreeMap<u64, String>,
);

/// Collect interfaces, addresses, routes and DNS servers.
pub(super) fn collect() -> Result<NetworkSnapshot, String> {
    let (mut interfaces, index_names, luid_names) = read_interfaces()?;
    merge_if_addrs(&mut interfaces);

    let routes = read_routes(&index_names, &luid_names);
    let default_gateways = default_gateways(&routes);

    Ok(NetworkSnapshot {
        captured_at: captured_at_now(),
        interfaces: interfaces.into_values().collect(),
        default_gateways,
        dns_servers: read_dns_servers(),
        routes,
    })
}

/// Read link attributes and counters through `GetIfTable2`.
///
/// Also returns the index and LUID mappings used by the route table. IPv6
/// routes may carry a different index from IPv4, so the LUID is the primary key.
fn read_interfaces() -> Result<InterfaceTables, String> {
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    let status = unsafe { GetIfTable2(&mut table) };
    if status != 0 || table.is_null() {
        return Err(format!("GetIfTable2 failed: {status}"));
    }

    let mut interfaces = BTreeMap::new();
    let mut index_names = BTreeMap::new();
    let mut luid_names = BTreeMap::new();
    // The table owns a trailing variable-length array, so the valid row count
    // comes from `NumEntries` rather than the declared single-element field.
    let rows = unsafe {
        let table = &*table;
        slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize)
    };
    for row in rows {
        let interface = interface_from_row(row);
        index_names.insert(row.InterfaceIndex, interface.name.clone());
        luid_names.insert(unsafe { row.InterfaceLuid.Value }, interface.name.clone());
        interfaces.insert(interface.name.clone(), interface);
    }
    unsafe { FreeMibTable(table as *const _) };
    Ok((interfaces, index_names, luid_names))
}

/// Convert one MIB row into the shared interface type.
fn interface_from_row(row: &MIB_IF_ROW2) -> NetworkInterface {
    let mut name = wide_string(&row.Alias);
    if name.is_empty() {
        name = wide_string(&row.Description);
    }
    if name.is_empty() {
        name = format!("if{}", row.InterfaceIndex);
    }

    let mac_length = (row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len());
    let link_speed = row.TransmitLinkSpeed.max(row.ReceiveLinkSpeed);

    NetworkInterface {
        name,
        mac: format_mac(&row.PhysicalAddress[..mac_length]),
        ipv4: Vec::new(),
        ipv6: Vec::new(),
        mtu: (row.Mtu > 0).then_some(row.Mtu),
        link_speed_bps: (link_speed > 0).then_some(link_speed),
        up: row.OperStatus == NET_IF_OPER_STATUS_UP,
        counters: InterfaceCounters {
            rx_bytes: row.InOctets,
            tx_bytes: row.OutOctets,
            rx_packets: row.InUcastPkts.saturating_add(row.InNUcastPkts),
            tx_packets: row.OutUcastPkts.saturating_add(row.OutNUcastPkts),
        },
    }
}

/// Add IP addresses from `getifaddrs`, which also covers interfaces that the
/// MIB table does not expose.
fn merge_if_addrs(interfaces: &mut BTreeMap<String, NetworkInterface>) {
    let Ok(addresses) = if_addrs::get_if_addrs() else {
        return;
    };
    for address in addresses {
        let interface =
            interfaces
                .entry(address.name.clone())
                .or_insert_with(|| NetworkInterface {
                    name: address.name.clone(),
                    ..NetworkInterface::default()
                });
        match address.addr {
            if_addrs::IfAddr::V4(v4) => {
                let text = with_prefix(v4.ip, v4.prefixlen);
                if !interface.ipv4.contains(&text) {
                    interface.ipv4.push(text);
                }
            }
            if_addrs::IfAddr::V6(v6) => {
                let text = with_prefix(v6.ip, v6.prefixlen);
                if !interface.ipv6.contains(&text) {
                    interface.ipv6.push(text);
                }
            }
        }
    }
}

/// Read the routing table for both address families.
fn read_routes(
    index_names: &BTreeMap<u32, String>,
    luid_names: &BTreeMap<u64, String>,
) -> Vec<NetworkRoute> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if status != 0 || table.is_null() {
        return Vec::new();
    }

    let mut routes = Vec::new();
    // As with the interface table, the row count is stored separately.
    let rows = unsafe {
        let table = &*table;
        slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize)
    };
    for row in rows {
        let Some(destination) = sockaddr_ip(&row.DestinationPrefix.Prefix) else {
            continue;
        };
        let Some(gateway) = sockaddr_ip(&row.NextHop) else {
            continue;
        };
        let prefix = row.DestinationPrefix.PrefixLength;
        let family = if destination.is_ipv6() {
            "IPv6"
        } else {
            "IPv4"
        };
        let destination = if destination.is_unspecified() && prefix == 0 {
            "default".to_string()
        } else {
            with_prefix(destination, prefix)
        };
        routes.push(NetworkRoute {
            family: family.to_string(),
            destination,
            gateway: gateway_text(gateway),
            interface: luid_names
                .get(&unsafe { row.InterfaceLuid.Value })
                .or_else(|| index_names.get(&row.InterfaceIndex))
                .cloned()
                .unwrap_or_else(|| format!("if{}", row.InterfaceIndex)),
            metric: Some(row.Metric),
        });
    }
    unsafe { FreeMibTable(table as *const _) };
    routes.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.destination.cmp(&b.destination))
            .then_with(|| a.metric.cmp(&b.metric))
    });
    routes
}

fn default_gateways(routes: &[NetworkRoute]) -> Vec<DefaultGateway> {
    let mut gateways: Vec<DefaultGateway> = routes
        .iter()
        .filter(|route| route.destination == "default")
        .map(|route| DefaultGateway {
            family: route.family.clone(),
            gateway: route.gateway.clone(),
            interface: route.interface.clone(),
            metric: route.metric,
        })
        .collect();
    gateways.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.metric.cmp(&b.metric))
    });
    gateways
}

/// Read the system DNS server list through `GetNetworkParams`.
fn read_dns_servers() -> Vec<String> {
    let mut size = 0u32;
    let status = unsafe { GetNetworkParams(ptr::null_mut(), &mut size) };
    if status != ERROR_BUFFER_OVERFLOW || size == 0 {
        return Vec::new();
    }

    let mut buffer = vec![0u8; size as usize];
    let info = buffer.as_mut_ptr() as *mut FIXED_INFO_W2KSP1;
    let status = unsafe { GetNetworkParams(info, &mut size) };
    if status != ERROR_SUCCESS || info.is_null() {
        return Vec::new();
    }

    let mut servers = Vec::new();
    let mut current: *const IP_ADDR_STRING = unsafe { &(*info).DnsServerList };
    while !current.is_null() {
        let server = ip_string(unsafe { (*current).IpAddress.String });
        if !server.is_empty() && !servers.contains(&server) {
            servers.push(server);
        }
        current = unsafe { (*current).Next };
    }
    servers
}

/// Convert a fixed IP string buffer into text.
fn ip_string(buffer: [i8; 16]) -> String {
    let bytes: Vec<u8> = buffer
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Decode a NUL-terminated UTF-16 field.
fn wide_string(buffer: &[u16]) -> String {
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

/// Convert a WinSock address union into a Rust address.
fn sockaddr_ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
    let family = unsafe { address.si_family };
    match family {
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

fn gateway_text(gateway: IpAddr) -> String {
    if gateway.is_unspecified() {
        "-".to_string()
    } else {
        gateway.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_string_reads_until_nul() {
        let mut buffer = [0i8; 16];
        for (index, byte) in b"1.1.1.1".iter().enumerate() {
            buffer[index] = *byte as i8;
        }
        assert_eq!(ip_string(buffer), "1.1.1.1");
    }

    #[test]
    fn wide_string_reads_until_nul() {
        let mut buffer = [0u16; 8];
        for (index, value) in "eth0".encode_utf16().enumerate() {
            buffer[index] = value;
        }
        assert_eq!(wide_string(&buffer), "eth0");
    }
}
