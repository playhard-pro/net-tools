//! LAN device discovery: neighbor tables, ICMP sweeping and name/service lookup.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use surge_ping::{Client, PingIdentifier, PingSequence};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::LanDiscoverySettings;
use crate::control::ProbeHandle;
use crate::model::{
    LanDevice, LanDiscoverySource, LanScanProgress, LocalSubnet, MacVendorSource, ProbeEvent,
};
use crate::net::mac_vendor::{lookup_local, normalize_mac, query_online};
use crate::net::{dns, privilege};
use crate::utils::subnet::parse_subnet;

pub mod mdns;
pub mod neighbors;
pub mod netbios;
pub mod ssdp;

/// Upper bound for one scan. Local networks are usually much smaller; the cap
/// prevents an accidental large prefix from turning into a long-running scan.
const MAX_SCAN_HOSTS: u64 = 4096;

/// Target expansion result used by the scan task.
#[derive(Debug, Default)]
pub(crate) struct TargetPlan {
    pub hosts: Vec<Ipv4Addr>,
    pub subnets: Vec<LocalSubnet>,
    pub warnings: Vec<String>,
    /// Explicit target networks used to filter passive results.
    networks: Vec<(IpAddr, u8)>,
    /// Whether the user entered targets instead of relying on auto detection.
    explicit: bool,
    /// Whether an IPv6 preset or target is part of this scan.
    has_ipv6: bool,
}

impl TargetPlan {
    /// Whether a passive result belongs to this scan.
    fn allows(&self, ip: IpAddr) -> bool {
        if !neighbors::is_allowed_ip(ip) {
            return false;
        }
        if !self.explicit {
            return true;
        }
        self.networks
            .iter()
            .any(|(network, prefix)| ip_in_network(ip, *network, *prefix))
    }
}

/// Local interfaces that may be used as scan presets.
///
/// Public and loopback addresses are omitted. Both the address and the
/// calculated network must fall inside an allowed private/link-local range.
pub fn local_subnets() -> Vec<LocalSubnet> {
    let (all, _) = all_local_subnets();
    all
}

fn all_local_subnets() -> (Vec<LocalSubnet>, Vec<String>) {
    let mut subnets = Vec::new();
    let mut warnings = Vec::new();
    let Ok(addresses) = if_addrs::get_if_addrs() else {
        return (subnets, warnings);
    };
    for address in addresses {
        let (input, ip) = match address.addr {
            if_addrs::IfAddr::V4(v4) => {
                if v4.ip.is_loopback() || v4.ip.is_unspecified() {
                    continue;
                }
                (format!("{}/{}", v4.ip, v4.prefixlen), IpAddr::V4(v4.ip))
            }
            if_addrs::IfAddr::V6(v6) => {
                if v6.ip.is_loopback() || v6.ip.is_unspecified() {
                    continue;
                }
                (format!("{}/{}", v6.ip, v6.prefixlen), IpAddr::V6(v6.ip))
            }
        };
        let Ok(info) = parse_subnet(&input) else {
            warnings.push(format!(
                "{}: could not calculate the local subnet",
                address.name
            ));
            continue;
        };
        let network = info.network.parse::<IpAddr>().ok();
        let last = info.last.parse::<IpAddr>().ok();
        let allowed = network.is_some_and(neighbors::is_allowed_ip)
            && last.is_some_and(neighbors::is_allowed_ip)
            && neighbors::is_allowed_ip(ip);
        if !allowed {
            warnings.push(format!(
                "{} ({input}) is not a private or link-local subnet and was skipped",
                address.name
            ));
            continue;
        }
        subnets.push(LocalSubnet {
            interface: address.name,
            address: input,
            prefix: info.prefix,
            cidr: info.cidr,
        });
    }
    subnets.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then_with(|| a.cidr.cmp(&b.cidr))
    });
    subnets.dedup_by(|a, b| a.cidr == b.cidr);
    (subnets, warnings)
}

/// Expand the configured targets into IPv4 hosts, enforcing the LAN-only rule.
pub(crate) fn resolve_targets(targets: &str) -> Result<TargetPlan, String> {
    let mut plan = TargetPlan::default();
    let mut requested = BTreeSet::new();
    let explicit = targets
        .split([',', '\n', '\r'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();

    let auto = explicit.is_empty();
    plan.explicit = !auto;
    if auto {
        let (subnets, warnings) = all_local_subnets();
        plan.warnings.extend(warnings);
        if subnets.is_empty() {
            return Err(
                "no local private or link-local subnet was found; enter a target manually"
                    .to_string(),
            );
        }
        plan.has_ipv6 = subnets.iter().any(|subnet| subnet.cidr.contains(':'));
        plan.subnets = subnets;
        for subnet in &plan.subnets {
            if subnet.cidr.contains(':') {
                continue;
            }
            requested.insert(subnet.cidr.clone());
        }
    } else {
        for target in explicit {
            requested.insert(target);
        }
    }

    let local_addresses = local_ipv4_addresses();
    let mut hosts = BTreeSet::new();
    for target in requested {
        let info = parse_subnet(&target)?;
        match info.network.parse::<IpAddr>() {
            Ok(IpAddr::V4(network)) => {
                let last = info
                    .last
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("`{target}` does not contain a usable IPv4 range"))?;
                if !is_allowed_ipv4(network) || !is_allowed_ipv4(last) {
                    return Err(format!(
                        "`{target}` is not entirely inside a private or link-local IPv4 range"
                    ));
                }
                let count = host_count(info.prefix);
                if hosts.len() as u64 + count > MAX_SCAN_HOSTS {
                    return Err(format!(
                        "`{target}` is too large for one scan; use a smaller subnet"
                    ));
                }
                expand_ipv4_network(network, info.prefix, &local_addresses, &mut hosts);
                if !auto {
                    plan.networks.push((IpAddr::V4(network), info.prefix));
                    if !plan.subnets.iter().any(|subnet| subnet.cidr == info.cidr) {
                        plan.subnets.push(LocalSubnet {
                            interface: "manual".to_string(),
                            address: info.input.clone(),
                            prefix: info.prefix,
                            cidr: info.cidr.clone(),
                        });
                    }
                }
            }
            Ok(IpAddr::V6(network)) => {
                let first = info.first.parse::<IpAddr>().ok();
                let last = info.last.parse::<IpAddr>().ok();
                if !first.is_some_and(neighbors::is_allowed_ip)
                    || !last.is_some_and(neighbors::is_allowed_ip)
                {
                    return Err(format!(
                        "`{target}` is not entirely inside a private or link-local IPv6 range"
                    ));
                }
                if !auto {
                    plan.has_ipv6 = true;
                    plan.networks.push((IpAddr::V6(network), info.prefix));
                    if !plan.subnets.iter().any(|subnet| subnet.cidr == info.cidr) {
                        plan.subnets.push(LocalSubnet {
                            interface: "manual".to_string(),
                            address: info.input.clone(),
                            prefix: info.prefix,
                            cidr: info.cidr.clone(),
                        });
                    }
                }
            }
            Err(_) => return Err(format!("`{target}` is not a valid IP subnet")),
        }
    }

    plan.hosts = hosts.into_iter().collect();
    if plan.hosts.is_empty() && !plan.has_ipv6 {
        return Err("the selected targets contain no usable host addresses".to_string());
    }
    Ok(plan)
}

/// Run one full LAN discovery scan and stream updates to the UI.
pub async fn run_scan(handle: ProbeHandle<ProbeEvent>, settings: LanDiscoverySettings) {
    if let Err(message) = scan(&handle, &settings).await {
        handle.send(ProbeEvent::Error {
            message,
            hint: None,
        });
    }
    handle.send(ProbeEvent::Finished);
}

async fn scan(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &LanDiscoverySettings,
) -> Result<(), String> {
    let plan = resolve_targets(&settings.targets)?;
    if !plan.subnets.is_empty() {
        let text = plan
            .subnets
            .iter()
            .map(|subnet| format!("{} ({})", subnet.cidr, subnet.interface))
            .collect::<Vec<_>>()
            .join(", ");
        handle.send(ProbeEvent::Info(format!("targets: {text}")));
    }
    for warning in &plan.warnings {
        handle.send(ProbeEvent::Info(warning.clone()));
    }
    if plan.has_ipv6 {
        handle.send(ProbeEvent::Info(
            "IPv6 targets use passive neighbor discovery only".to_string(),
        ));
    }
    if handle.is_cancelled() {
        return Ok(());
    }

    let mut found: BTreeMap<IpAddr, LanDevice> = BTreeMap::new();
    let neighbors = tokio::task::spawn_blocking(neighbors::collect)
        .await
        .map_err(|error| format!("neighbor table task failed: {error}"))??;
    handle.send(ProbeEvent::Info(format!(
        "neighbor table: {} device(s)",
        neighbors.len()
    )));
    // A ULA target often has no cached ULA neighbor entries even when the host
    // has an IPv6 address. IPv6 is passive-only, so fall back to the complete
    // allowed neighbor table instead of showing an empty result.
    let show_all_neighbors = plan.has_ipv6 && !neighbors.iter().any(|entry| plan.allows(entry.ip));
    if show_all_neighbors {
        handle.send(ProbeEvent::Info(
            "no neighbor entries matched the IPv6 target; showing all private neighbor entries"
                .to_string(),
        ));
    }
    for entry in neighbors {
        if !show_all_neighbors && !plan.allows(entry.ip) {
            continue;
        }
        let mut device = LanDevice::new(entry.ip);
        device.mac = Some(entry.mac);
        device.add_source(LanDiscoverySource::Neighbor);
        apply_device_update(handle, &mut found, device);
    }
    if handle.is_cancelled() {
        return Ok(());
    }

    if settings.icmp_scan && !plan.hosts.is_empty() {
        handle.send(ProbeEvent::Info(format!(
            "ICMP scanning {} host(s)",
            plan.hosts.len()
        )));
        if let Err(error) = icmp_sweep(
            handle,
            &plan.hosts,
            settings.timeout_ms,
            settings.concurrency,
            &mut found,
        )
        .await
        {
            let hint = privilege::hint_for(error.contains("Permission denied"));
            handle.send(ProbeEvent::Error {
                message: error,
                hint,
            });
        }

        if handle.is_cancelled() {
            return Ok(());
        }
        match tokio::task::spawn_blocking(neighbors::collect).await {
            Ok(Ok(entries)) => {
                let mut added = 0usize;
                for entry in entries {
                    if !plan.allows(entry.ip) {
                        continue;
                    }
                    let mut device = LanDevice::new(entry.ip);
                    device.mac = Some(entry.mac);
                    device.add_source(LanDiscoverySource::Neighbor);
                    if apply_device_update(handle, &mut found, device) {
                        added += 1;
                    }
                }
                if added > 0 {
                    handle.send(ProbeEvent::Info(format!(
                        "neighbor table added {added} device(s) after the sweep"
                    )));
                }
            }
            Ok(Err(error)) => handle.send(ProbeEvent::Info(format!(
                "could not refresh the neighbor table: {error}"
            ))),
            Err(error) => handle.send(ProbeEvent::Info(format!(
                "neighbor table refresh failed: {error}"
            ))),
        }
    }
    if handle.is_cancelled() {
        return Ok(());
    }

    if settings.reverse_dns {
        enrich_ptr(
            handle,
            settings.timeout_ms,
            settings.concurrency,
            &mut found,
        )
        .await;
    }
    if handle.is_cancelled() {
        return Ok(());
    }
    if settings.netbios {
        enrich_netbios(
            handle,
            settings.timeout_ms,
            settings.concurrency,
            &mut found,
        )
        .await;
    }
    if handle.is_cancelled() {
        return Ok(());
    }

    let addresses = found.keys().copied().collect::<Vec<_>>();
    let service_timeout = Duration::from_millis(settings.timeout_ms.max(500));

    if settings.mdns {
        let results = mdns::discover(&addresses, service_timeout).await;
        handle.send(ProbeEvent::Info(format!(
            "mDNS: {} device(s)",
            results.len()
        )));
        for (ip, info) in results {
            if !accepts_enrichment(&found, &plan, ip) {
                continue;
            }
            let mut device = LanDevice::new(ip);
            device.add_source(LanDiscoverySource::Mdns);
            device.mdns_services = info.services;
            if let Some(hostname) = info.hostname {
                device.hostname = Some(hostname);
                device.hostname_source = Some(crate::model::LanNameSource::Mdns);
            }
            apply_device_update(handle, &mut found, device);
        }
    }
    if handle.is_cancelled() {
        return Ok(());
    }

    if settings.ssdp {
        let results = ssdp::discover(service_timeout).await;
        handle.send(ProbeEvent::Info(format!(
            "SSDP/UPnP: {} device(s)",
            results.len()
        )));
        for (ip, info) in results {
            if !accepts_enrichment(&found, &plan, ip) {
                continue;
            }
            let mut device = LanDevice::new(ip);
            device.add_source(LanDiscoverySource::Ssdp);
            device.upnp_name = info.name;
            device.upnp_manufacturer = info.manufacturer;
            device.upnp_model = info.model;
            device.upnp_device_type = info.device_type;
            if device.hostname.is_none() {
                if let Some(name) = &device.upnp_name {
                    device.hostname = Some(name.clone());
                    device.hostname_source = Some(crate::model::LanNameSource::Upnp);
                }
            }
            apply_device_update(handle, &mut found, device);
        }
    }

    enrich_vendors(
        handle,
        settings.allow_online_mac,
        settings.timeout_ms,
        &mut found,
    )
    .await;

    if !plan.hosts.is_empty() {
        handle.send(ProbeEvent::LanProgress(LanScanProgress {
            scanned: plan.hosts.len() as u64,
            total: plan.hosts.len() as u64,
            found: found.len() as u64,
        }));
    }
    Ok(())
}

/// Whether a name or service result should be merged. Rows already discovered
/// through the neighbor table are enriched even when an IPv6 target caused the
/// passive fallback to show entries outside that target.
fn accepts_enrichment(found: &BTreeMap<IpAddr, LanDevice>, plan: &TargetPlan, ip: IpAddr) -> bool {
    found.contains_key(&ip) || plan.allows(ip)
}

fn apply_device_update(
    handle: &ProbeHandle<ProbeEvent>,
    found: &mut BTreeMap<IpAddr, LanDevice>,
    update: LanDevice,
) -> bool {
    let ip = update.ip;
    let is_new = !found.contains_key(&ip);
    let device = found.entry(ip).or_insert_with(|| LanDevice::new(ip));
    if update.mac.is_some() && device.mac.is_none() {
        device.mac = update.mac;
    }
    if update.vendor.is_some() {
        device.vendor = update.vendor;
        device.vendor_source = update.vendor_source;
    }
    if update.hostname.is_some() && device.hostname.is_none() {
        device.hostname = update.hostname;
        device.hostname_source = update.hostname_source;
    }
    if update.netbios_name.is_some() {
        device.netbios_name = update.netbios_name;
    }
    if update.netbios_workgroup.is_some() {
        device.netbios_workgroup = update.netbios_workgroup;
    }
    for service in update.mdns_services {
        if !device.mdns_services.contains(&service) {
            device.mdns_services.push(service);
        }
    }
    if update.upnp_name.is_some() {
        device.upnp_name = update.upnp_name;
    }
    if update.upnp_manufacturer.is_some() {
        device.upnp_manufacturer = update.upnp_manufacturer;
    }
    if update.upnp_model.is_some() {
        device.upnp_model = update.upnp_model;
    }
    if update.upnp_device_type.is_some() {
        device.upnp_device_type = update.upnp_device_type;
    }
    if update.rtt_ms.is_some() {
        device.rtt_ms = update.rtt_ms;
    }
    for source in update.sources {
        device.add_source(source);
    }
    handle.send(ProbeEvent::LanDevice(device.clone()));
    is_new
}

async fn enrich_ptr(
    handle: &ProbeHandle<ProbeEvent>,
    timeout_ms: u64,
    concurrency: usize,
    found: &mut BTreeMap<IpAddr, LanDevice>,
) {
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let permits = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for ip in found.keys().copied().collect::<Vec<_>>() {
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit,
            _ = handle.cancelled() => return,
        };
        let Ok(permit) = permit else {
            return;
        };
        tasks.spawn(async move {
            let _permit = permit;
            let name = tokio::time::timeout(timeout, dns::reverse(ip))
                .await
                .ok()
                .flatten();
            (ip, name)
        });
    }
    while let Some(result) = tasks.join_next().await {
        if handle.is_cancelled() {
            tasks.abort_all();
            return;
        }
        if let Ok((ip, Some(name))) = result {
            if let Some(device) = found.get_mut(&ip) {
                if device.hostname.is_none() {
                    device.hostname = Some(name);
                    device.hostname_source = Some(crate::model::LanNameSource::Ptr);
                    handle.send(ProbeEvent::LanDevice(device.clone()));
                }
            }
        }
    }
}

async fn enrich_netbios(
    handle: &ProbeHandle<ProbeEvent>,
    timeout_ms: u64,
    concurrency: usize,
    found: &mut BTreeMap<IpAddr, LanDevice>,
) {
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let permits = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for ip in found.keys().copied().collect::<Vec<_>>() {
        let IpAddr::V4(ip) = ip else {
            continue;
        };
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit,
            _ = handle.cancelled() => return,
        };
        let Ok(permit) = permit else {
            return;
        };
        tasks.spawn(async move {
            let _permit = permit;
            (ip, netbios::query(ip, timeout).await)
        });
    }
    while let Some(result) = tasks.join_next().await {
        if handle.is_cancelled() {
            tasks.abort_all();
            return;
        }
        let Ok((ip, Some(info))) = result else {
            continue;
        };
        let key = IpAddr::V4(ip);
        let Some(device) = found.get_mut(&key) else {
            continue;
        };
        device.add_source(LanDiscoverySource::Netbios);
        device.netbios_name = info.name;
        device.netbios_workgroup = info.workgroup;
        if device.hostname.is_none() {
            if let Some(name) = &device.netbios_name {
                device.hostname = Some(name.clone());
                device.hostname_source = Some(crate::model::LanNameSource::Netbios);
            }
        }
        handle.send(ProbeEvent::LanDevice(device.clone()));
    }
}

/// Resolve MAC vendors locally, with an optional cached online fallback.
pub(crate) async fn enrich_vendors(
    handle: &ProbeHandle<ProbeEvent>,
    allow_online: bool,
    timeout_ms: u64,
    found: &mut BTreeMap<IpAddr, LanDevice>,
) {
    let mut cache: HashMap<String, Option<(String, MacVendorSource)>> = HashMap::new();
    for device in found.values_mut() {
        if handle.is_cancelled() {
            return;
        }
        let Some(mac) = device.mac.clone() else {
            continue;
        };
        let Ok(normalized) = normalize_mac(&mac) else {
            continue;
        };
        let oui = normalized.oui().to_string();
        let info = if let Some(cached) = cache.get(&oui) {
            cached.clone()
        } else {
            let mut info = lookup_local(&mac)
                .ok()
                .flatten()
                .map(|result| (result.vendor, result.source));
            if info.is_none() && allow_online {
                let result: Result<Option<crate::model::MacVendorResult>, String> = tokio::select! {
                    result = query_online(&oui, timeout_ms) => result,
                    _ = handle.cancelled() => return,
                };
                info = result
                    .ok()
                    .flatten()
                    .map(|result| (result.vendor, result.source));
            }
            cache.insert(oui, info.clone());
            info
        };
        if let Some((vendor, source)) = info {
            device.vendor = Some(vendor);
            device.vendor_source = Some(source);
            handle.send(ProbeEvent::LanDevice(device.clone()));
        }
    }
}

/// Probe every host once with ICMP and merge responders into the device map.
pub(crate) async fn icmp_sweep(
    handle: &ProbeHandle<ProbeEvent>,
    hosts: &[Ipv4Addr],
    timeout_ms: u64,
    concurrency: usize,
    found: &mut BTreeMap<IpAddr, LanDevice>,
) -> Result<(), String> {
    if hosts.is_empty() {
        return Ok(());
    }
    let client = crate::net::icmp::client_for(IpAddr::V4(Ipv4Addr::UNSPECIFIED), None)
        .map_err(|error| format!("failed to open ICMP socket: {error}"))?;
    let client = Arc::new(client);
    let permits = Arc::new(Semaphore::new(concurrency.max(1)));
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let total = hosts.len() as u64;
    let mut scanned = 0u64;
    let mut tasks = JoinSet::new();

    for (index, ip) in hosts.iter().copied().enumerate() {
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit,
            _ = handle.cancelled() => break,
        };
        let Ok(permit) = permit else {
            break;
        };
        let client = client.clone();
        tasks.spawn(async move {
            let _permit = permit;
            ping_one(&client, ip, timeout, index as u16).await
        });
    }

    while let Some(result) = tasks.join_next().await {
        if handle.is_cancelled() {
            tasks.abort_all();
            break;
        }
        scanned += 1;
        match result {
            Ok(Some((ip, rtt_ms))) => {
                let device = found
                    .entry(IpAddr::V4(ip))
                    .or_insert_with(|| LanDevice::new(IpAddr::V4(ip)));
                device.rtt_ms = Some(rtt_ms);
                device.add_source(LanDiscoverySource::Icmp);
                handle.send(ProbeEvent::LanDevice(device.clone()));
            }
            Ok(None) => {}
            Err(error) => {
                if error.is_panic() {
                    return Err("ICMP probe task panicked".to_string());
                }
            }
        }
        handle.send(ProbeEvent::LanProgress(LanScanProgress {
            scanned,
            total,
            found: found.len() as u64,
        }));
    }
    Ok(())
}

async fn ping_one(
    client: &Client,
    ip: Ipv4Addr,
    timeout: Duration,
    ident: u16,
) -> Option<(Ipv4Addr, f64)> {
    let mut pinger = client.pinger(IpAddr::V4(ip), PingIdentifier(ident)).await;
    pinger.timeout(timeout);
    match pinger.ping(PingSequence(ident), b"net-tools lan").await {
        Ok((_, rtt)) => Some((ip, rtt.as_secs_f64() * 1000.0)),
        Err(surge_ping::SurgeError::Timeout { .. }) => None,
        Err(_) => None,
    }
}

fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix as u32)
            };
            u32::from(ip) & mask == u32::from(network)
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix as u32)
            };
            u128::from(ip) & mask == u128::from(network)
        }
        _ => false,
    }
}

fn host_count(prefix: u8) -> u64 {
    let host_bits = 32u32.saturating_sub(prefix as u32);
    let total = 1u64.checked_shl(host_bits).unwrap_or(u64::MAX);
    if prefix >= 31 {
        total
    } else {
        total.saturating_sub(2)
    }
}

fn expand_ipv4_network(
    network: Ipv4Addr,
    prefix: u8,
    local_addresses: &BTreeSet<Ipv4Addr>,
    out: &mut BTreeSet<Ipv4Addr>,
) {
    let base = u32::from(network);
    let total = host_count(prefix);
    let first = if prefix >= 31 {
        base
    } else {
        base.saturating_add(1)
    };
    for offset in 0..total {
        let Some(value) = first.checked_add(offset as u32) else {
            break;
        };
        let address = Ipv4Addr::from(value);
        if prefix < 31 && address == Ipv4Addr::from(base | !mask_for(prefix)) {
            continue;
        }
        if !address.is_loopback() && !local_addresses.contains(&address) {
            out.insert(address);
        }
    }
}

fn mask_for(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn local_ipv4_addresses() -> BTreeSet<Ipv4Addr> {
    let mut addresses = BTreeSet::new();
    if let Ok(all) = if_addrs::get_if_addrs() {
        for address in all {
            if let if_addrs::IfAddr::V4(v4) = address.addr {
                addresses.insert(v4.ip);
            }
        }
    }
    addresses
}

fn is_allowed_ipv4(ip: Ipv4Addr) -> bool {
    neighbors::is_allowed_ip(IpAddr::V4(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_targets_expand_and_skip_network_and_broadcast() {
        let plan = resolve_targets("192.168.50.0/30").unwrap();
        let hosts = plan.hosts;
        assert_eq!(
            hosts,
            vec![
                "192.168.50.1".parse::<Ipv4Addr>().unwrap(),
                "192.168.50.2".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn public_ipv4_targets_are_rejected() {
        for target in ["8.8.8.0/24", "1.1.1.0/24", "172.32.0.0/16", "100.64.0.0/16"] {
            assert!(resolve_targets(target).is_err(), "{target}");
        }
    }

    #[test]
    fn public_ipv6_targets_are_rejected() {
        for target in ["2001:db8::/32", "2400::/4"] {
            let error = resolve_targets(target).unwrap_err();
            assert!(error.contains("private or link-local"), "{error}");
        }
    }

    #[test]
    fn private_ipv6_target_is_passive_only() {
        let plan = resolve_targets("fd00::/120").unwrap();
        assert!(plan.hosts.is_empty());
        assert!(plan.has_ipv6);
        assert!(plan.allows("fd00::1".parse().unwrap()));
        assert!(!plan.allows("fd00:1::1".parse().unwrap()));
    }

    #[test]
    fn discovered_rows_accept_enrichment_outside_the_target() {
        let plan = resolve_targets("fd00::/120").unwrap();
        let mut found = BTreeMap::new();
        let ip = "192.168.1.10".parse().unwrap();
        found.insert(ip, LanDevice::new(ip));
        assert!(accepts_enrichment(&found, &plan, ip));
        assert!(!accepts_enrichment(
            &BTreeMap::new(),
            &plan,
            "192.168.1.11".parse().unwrap()
        ));
    }

    #[test]
    fn explicit_targets_filter_passive_results() {
        let plan = resolve_targets("192.168.50.0/30").unwrap();
        assert!(plan.allows("192.168.50.1".parse().unwrap()));
        assert!(!plan.allows("192.168.51.1".parse().unwrap()));
    }

    #[test]
    fn oversized_network_is_rejected() {
        let error = resolve_targets("10.0.0.0/8").unwrap_err();
        assert!(error.contains("too large"), "{error}");
    }

    #[test]
    fn host_count_excludes_network_and_broadcast() {
        assert_eq!(host_count(30), 2);
        assert_eq!(host_count(31), 2);
        assert_eq!(host_count(32), 1);
    }
}
