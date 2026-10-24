//! Windows Wi-Fi collection through the native WLAN API.

use std::ptr;
use std::slice;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_SERVICE_DISABLED, ERROR_SERVICE_NOT_ACTIVE, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_any, dot11_phy_type_eht, dot11_phy_type_he, dot11_phy_type_ht,
    dot11_phy_type_vht, dot11_radio_state_off, wlan_interface_state_connected,
    wlan_intf_opcode_channel_number, wlan_intf_opcode_current_connection,
    wlan_intf_opcode_radio_state, wlan_intf_opcode_rssi, WlanCloseHandle, WlanEnumInterfaces,
    WlanFreeMemory, WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface,
    DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_AUTH_ALGO_OWE,
    DOT11_AUTH_ALGO_RSNA, DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA3,
    DOT11_AUTH_ALGO_WPA3_ENT, DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGO_WPA_PSK,
    DOT11_CIPHER_ALGO_WEP, DOT11_CIPHER_ALGO_WEP104, DOT11_CIPHER_ALGO_WEP40, WLAN_API_VERSION_2_0,
    WLAN_BSS_ENTRY, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO,
    WLAN_RADIO_STATE,
};

use crate::model::{
    WifiBand, WifiCapabilities, WifiCurrentConnection, WifiNetwork, WifiSecurity, WifiStandard,
};

use super::analysis;
use super::ie;
use super::WifiError;

pub async fn capabilities() -> WifiCapabilities {
    WifiCapabilities {
        platform: "Windows".to_string(),
        current_supported: true,
        scan_supported: true,
        note: Some(if running_from_network_path() {
            "Windows blocks Wi-Fi scanning when net-tools runs from a network/UNC path such as \\wsl.localhost. Copy the executable to a local drive and run it there."
                .to_string()
        } else {
            "Using the native Windows WLAN API. Nearby scanning requires Location Services."
                .to_string()
        }),
    }
}

pub async fn sample_current() -> Result<(Option<WifiCurrentConnection>, Vec<String>), WifiError> {
    tokio::task::spawn_blocking(sample_current_sync)
        .await
        .map_err(|error| WifiError::new(format!("WLAN task failed: {error}")))?
}

pub async fn scan_networks() -> Result<(Vec<WifiNetwork>, Vec<String>), WifiError> {
    tokio::task::spawn_blocking(scan_networks_sync)
        .await
        .map_err(|error| WifiError::new(format!("WLAN task failed: {error}")))?
}

struct WlanHandle(HANDLE);

impl Drop for WlanHandle {
    fn drop(&mut self) {
        unsafe {
            WlanCloseHandle(self.0, ptr::null());
        }
    }
}

fn open_wlan() -> Result<(WlanHandle, Vec<WLAN_INTERFACE_INFO>), WifiError> {
    let mut negotiated = 0_u32;
    let mut handle: HANDLE = ptr::null_mut();
    let status = unsafe {
        WlanOpenHandle(
            WLAN_API_VERSION_2_0,
            ptr::null(),
            &mut negotiated,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(wlan_error("WlanOpenHandle", status));
    }
    let handle = WlanHandle(handle);

    let mut list: *mut windows_sys::Win32::NetworkManagement::WiFi::WLAN_INTERFACE_INFO_LIST =
        ptr::null_mut();
    let status = unsafe { WlanEnumInterfaces(handle.0, ptr::null(), &mut list) };
    if status != 0 || list.is_null() {
        return Err(wlan_error("WlanEnumInterfaces", status));
    }
    let interfaces = unsafe {
        let count = (*list).dwNumberOfItems as usize;
        let entries = slice::from_raw_parts((*list).InterfaceInfo.as_ptr(), count).to_vec();
        WlanFreeMemory(list as *const _);
        entries
    };
    if interfaces.is_empty() {
        return Err(WifiError::new("No WLAN interface was found"));
    }
    Ok((handle, interfaces))
}

fn preferred_interface(interfaces: &[WLAN_INTERFACE_INFO]) -> &WLAN_INTERFACE_INFO {
    interfaces
        .iter()
        .find(|interface| interface.isState == wlan_interface_state_connected)
        .unwrap_or(&interfaces[0])
}

fn query_u32(handle: &WlanHandle, guid: &windows_sys::core::GUID, opcode: i32) -> Option<u32> {
    let mut size = 0_u32;
    let mut data: *mut std::ffi::c_void = ptr::null_mut();
    let mut value_type = 0_i32;
    let status = unsafe {
        WlanQueryInterface(
            handle.0,
            guid,
            opcode,
            ptr::null(),
            &mut size,
            &mut data,
            &mut value_type,
        )
    };
    if status != 0 || data.is_null() || size < std::mem::size_of::<u32>() as u32 {
        if !data.is_null() {
            unsafe { WlanFreeMemory(data) };
        }
        return None;
    }
    let value = unsafe {
        let value = *(data as *const u32);
        WlanFreeMemory(data);
        value
    };
    Some(value)
}

fn query_i32(handle: &WlanHandle, guid: &windows_sys::core::GUID, opcode: i32) -> Option<i32> {
    let mut size = 0_u32;
    let mut data: *mut std::ffi::c_void = ptr::null_mut();
    let mut value_type = 0_i32;
    let status = unsafe {
        WlanQueryInterface(
            handle.0,
            guid,
            opcode,
            ptr::null(),
            &mut size,
            &mut data,
            &mut value_type,
        )
    };
    if status != 0 || data.is_null() || size < std::mem::size_of::<i32>() as u32 {
        if !data.is_null() {
            unsafe { WlanFreeMemory(data) };
        }
        return None;
    }
    let value = unsafe {
        let value = *(data as *const i32);
        WlanFreeMemory(data);
        value
    };
    Some(value)
}

fn radio_is_off(handle: &WlanHandle, guid: &windows_sys::core::GUID) -> bool {
    let mut size = 0_u32;
    let mut data: *mut std::ffi::c_void = ptr::null_mut();
    let mut value_type = 0_i32;
    let status = unsafe {
        WlanQueryInterface(
            handle.0,
            guid,
            wlan_intf_opcode_radio_state,
            ptr::null(),
            &mut size,
            &mut data,
            &mut value_type,
        )
    };
    if status != 0 || data.is_null() || size < std::mem::size_of::<WLAN_RADIO_STATE>() as u32 {
        if !data.is_null() {
            unsafe { WlanFreeMemory(data) };
        }
        return false;
    }
    let radio = unsafe {
        let radio = &*(data as *const WLAN_RADIO_STATE);
        let count = (radio.dwNumberOfPhys as usize).min(radio.PhyRadioState.len());
        let all_off = count > 0
            && radio.PhyRadioState[..count].iter().all(|phy| {
                phy.dot11SoftwareRadioState == dot11_radio_state_off
                    || phy.dot11HardwareRadioState == dot11_radio_state_off
            });
        WlanFreeMemory(data);
        all_off
    };
    radio
}

fn sample_current_sync() -> Result<(Option<WifiCurrentConnection>, Vec<String>), WifiError> {
    let (handle, interfaces) = open_wlan()?;
    let interface = preferred_interface(&interfaces);
    let guid = &interface.InterfaceGuid;

    let mut size = 0_u32;
    let mut data: *mut std::ffi::c_void = ptr::null_mut();
    let mut value_type = 0_i32;
    let status = unsafe {
        WlanQueryInterface(
            handle.0,
            guid,
            wlan_intf_opcode_current_connection,
            ptr::null(),
            &mut size,
            &mut data,
            &mut value_type,
        )
    };
    if status != 0
        || data.is_null()
        || size < std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>() as u32
    {
        if !data.is_null() {
            unsafe { WlanFreeMemory(data) };
        }
        return Ok((None, Vec::new()));
    }

    let attributes = unsafe { *(data as *const WLAN_CONNECTION_ATTRIBUTES) };
    unsafe { WlanFreeMemory(data) };
    if attributes.isState != wlan_interface_state_connected {
        return Ok((None, Vec::new()));
    }

    let association = attributes.wlanAssociationAttributes;
    let ssid = ssid_string(&association.dot11Ssid);
    let bssid = bssid_string(&association.dot11Bssid);
    let channel = query_u32(&handle, guid, wlan_intf_opcode_channel_number);
    let rssi = query_i32(&handle, guid, wlan_intf_opcode_rssi);
    let quality = (association.wlanSignalQuality.min(100)) as u8;
    let signal_dbm = rssi.or_else(|| {
        analysis::signal_quality(None, Some(quality)).map(|percent| (percent as i32 / 2) - 100)
    });
    let band = channel
        .map(|channel| {
            if channel <= 14 {
                WifiBand::Ghz24
            } else {
                WifiBand::Ghz5
            }
        })
        .unwrap_or_default();
    let frequency = channel.and_then(|channel| analysis::frequency_for_channel(band, channel));

    Ok((
        Some(WifiCurrentConnection {
            interface: wide_string(&interface.strInterfaceDescription),
            ssid,
            bssid,
            vendor: None,
            signal_dbm,
            signal_quality: Some(quality),
            noise_dbm: None,
            snr_db: None,
            channel,
            frequency_mhz: frequency,
            width_mhz: None,
            band,
            security: security_from_auth(
                attributes.wlanSecurityAttributes.dot11AuthAlgorithm,
                attributes.wlanSecurityAttributes.dot11CipherAlgorithm,
            ),
            security_detail: String::new(),
            standard: standard_from_phy(association.dot11PhyType),
            rx_rate_mbps: Some(association.ulRxRate as f64 / 1_000.0),
            tx_rate_mbps: Some(association.ulTxRate as f64 / 1_000.0),
        }),
        Vec::new(),
    ))
}

fn scan_networks_sync() -> Result<(Vec<WifiNetwork>, Vec<String>), WifiError> {
    let (handle, interfaces) = open_wlan()?;
    let interface = preferred_interface(&interfaces);
    let guid = &interface.InterfaceGuid;
    if radio_is_off(&handle, guid) {
        return Err(WifiError {
            message: "The Wi-Fi radio is turned off".to_string(),
            hint: Some(
                "Turn Wi-Fi on in the Windows quick settings or Settings > Network & Internet > Wi-Fi, then retry."
                    .to_string(),
            ),
        });
    }

    let mut list: *mut WLAN_BSS_LIST = ptr::null_mut();
    let status = unsafe {
        WlanGetNetworkBssList(
            handle.0,
            guid,
            ptr::null(),
            dot11_BSS_type_any,
            0,
            ptr::null(),
            &mut list,
        )
    };
    if status != 0 || list.is_null() {
        return Err(wlan_error("WlanGetNetworkBssList", status));
    }

    let networks = unsafe {
        let list_ref = &*list;
        let count = list_ref.dwNumberOfItems as usize;
        let list_start = list as *const u8;
        let list_end = list_start.add(list_ref.dwTotalSize as usize);
        let entries = slice::from_raw_parts(list_ref.wlanBssEntries.as_ptr(), count);
        let mut networks = Vec::with_capacity(count);
        for entry in entries {
            networks.push(network_from_bss_entry(entry, list_start, list_end));
        }
        WlanFreeMemory(list as *const _);
        networks
    };

    Ok((networks, Vec::new()))
}

fn wlan_error(context: &str, status: u32) -> WifiError {
    let hint = match status {
        ERROR_ACCESS_DENIED if running_from_network_path() => Some(
            "Windows denies Wi-Fi scanning when the executable runs from a network/UNC path such as \\wsl.localhost. Copy net-tools.exe to a local drive and run it there."
                .to_string(),
        ),
        ERROR_ACCESS_DENIED => Some(
            "Windows blocks nearby Wi-Fi scans while Location Services is off. Open Settings > Privacy & security > Location and enable Location services and the global desktop-app location access. Windows does not list net-tools as a separate app there. Administrator rights do not bypass this restriction."
                .to_string(),
        ),
        ERROR_SERVICE_NOT_ACTIVE | ERROR_SERVICE_DISABLED => Some(
            "The WLAN AutoConfig service is not running. Start the service, then retry."
                .to_string(),
        ),
        _ => None,
    };
    WifiError {
        message: format!("{context} failed with error {status}"),
        hint,
    }
}

fn running_from_network_path() -> bool {
    std::env::current_exe()
        .map(|path| is_network_path(&path))
        .unwrap_or(false)
}

fn is_network_path(path: &std::path::Path) -> bool {
    let text = path.to_string_lossy();
    text.starts_with(r"\\") && !text.starts_with(r"\\?\")
}

fn network_from_bss_entry(
    entry: &WLAN_BSS_ENTRY,
    list_start: *const u8,
    list_end: *const u8,
) -> WifiNetwork {
    let ssid = ssid_string(&entry.dot11Ssid);
    let mut network = WifiNetwork::new(bssid_string(&entry.dot11Bssid));
    network.ssid = ssid.clone();
    network.is_hidden = ssid.is_empty();
    network.signal_dbm = Some(entry.lRssi);
    network.signal_quality = Some(entry.uLinkQuality.min(100) as u8);
    network.frequency_mhz = Some(entry.ulChCenterFrequency / 1_000);
    network.band = analysis::band_for_frequency(network.frequency_mhz.unwrap_or_default());
    network.channel = network
        .frequency_mhz
        .and_then(analysis::channel_for_frequency);
    network.standard = standard_from_phy(entry.dot11BssPhyType);
    if network.standard == WifiStandard::Wifi6 && network.band == WifiBand::Ghz6 {
        network.standard = WifiStandard::Wifi6E;
    }
    network.max_rate_mbps = max_rate(&entry.wlanRateSet);

    if let Some(ies) = ie_bytes(entry, list_start, list_end) {
        let info = ie::parse_ies(ies);
        if let Some(channel) = info.channel {
            network.channel = Some(channel);
        }
        if let Some(width) = info.width_mhz {
            network.width_mhz = Some(width);
        }
        if let Some(security) = info.security {
            network.security = security;
        }
        if info.standard != WifiStandard::Unknown {
            network.standard = info.standard;
        }
    }
    if network.width_mhz.is_none() {
        network.width_mhz = Some(20);
    }
    if network.security == WifiSecurity::Unknown {
        let privacy = entry.usCapabilityInformation & 0x10 != 0;
        network.security = if privacy {
            WifiSecurity::Unknown
        } else {
            WifiSecurity::Open
        };
    }
    network.security_detail = network.security.label().to_string();
    network.snr_db = analysis::snr_db(network.signal_dbm, network.noise_dbm);
    network
}

fn ie_bytes(entry: &WLAN_BSS_ENTRY, list_start: *const u8, list_end: *const u8) -> Option<&[u8]> {
    let size = entry.ulIeSize as usize;
    if size == 0 {
        return None;
    }
    let entry_ptr = entry as *const WLAN_BSS_ENTRY as *const u8;
    let start = unsafe { entry_ptr.add(entry.ulIeOffset as usize) };
    let end = unsafe { start.add(size) };
    if start < list_start || end > list_end {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(start, size) })
}

fn ssid_string(ssid: &windows_sys::Win32::NetworkManagement::WiFi::DOT11_SSID) -> String {
    let length = (ssid.uSSIDLength as usize).min(ssid.ucSSID.len());
    String::from_utf8_lossy(&ssid.ucSSID[..length]).into_owned()
}

fn bssid_string(bssid: &[u8; 6]) -> String {
    bssid
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn wide_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn max_rate(rate_set: &windows_sys::Win32::NetworkManagement::WiFi::WLAN_RATE_SET) -> Option<f64> {
    let length = (rate_set.uRateSetLength as usize).min(rate_set.usRateSet.len());
    rate_set.usRateSet[..length]
        .iter()
        .map(|rate| *rate as f64 / 2.0)
        .max_by(|left, right| left.total_cmp(right))
}

fn standard_from_phy(phy: i32) -> WifiStandard {
    if phy == dot11_phy_type_eht {
        WifiStandard::Wifi7
    } else if phy == dot11_phy_type_he {
        WifiStandard::Wifi6
    } else if phy == dot11_phy_type_vht {
        WifiStandard::Wifi5
    } else if phy == dot11_phy_type_ht {
        WifiStandard::Wifi4
    } else {
        WifiStandard::Unknown
    }
}

fn security_from_auth(auth: i32, cipher: i32) -> WifiSecurity {
    match auth {
        DOT11_AUTH_ALGO_OWE => WifiSecurity::Owe,
        DOT11_AUTH_ALGO_WPA3_SAE | DOT11_AUTH_ALGO_WPA3 => WifiSecurity::Wpa3,
        DOT11_AUTH_ALGO_WPA3_ENT => WifiSecurity::Enterprise,
        DOT11_AUTH_ALGO_RSNA | DOT11_AUTH_ALGO_RSNA_PSK => WifiSecurity::Wpa2,
        DOT11_AUTH_ALGO_WPA | DOT11_AUTH_ALGO_WPA_PSK => WifiSecurity::Wpa,
        DOT11_AUTH_ALGO_80211_OPEN => WifiSecurity::Open,
        DOT11_AUTH_ALGO_80211_SHARED_KEY => {
            if matches!(
                cipher,
                DOT11_CIPHER_ALGO_WEP | DOT11_CIPHER_ALGO_WEP40 | DOT11_CIPHER_ALGO_WEP104
            ) {
                WifiSecurity::Wep
            } else {
                WifiSecurity::Unknown
            }
        }
        _ => WifiSecurity::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bssid_is_normalized_for_display() {
        assert_eq!(
            bssid_string(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn phy_types_map_to_standards() {
        assert_eq!(standard_from_phy(dot11_phy_type_ht), WifiStandard::Wifi4);
        assert_eq!(standard_from_phy(dot11_phy_type_vht), WifiStandard::Wifi5);
        assert_eq!(standard_from_phy(dot11_phy_type_he), WifiStandard::Wifi6);
        assert_eq!(standard_from_phy(dot11_phy_type_eht), WifiStandard::Wifi7);
    }

    #[test]
    fn auth_algorithms_map_to_security() {
        assert_eq!(
            security_from_auth(DOT11_AUTH_ALGO_RSNA_PSK, 4),
            WifiSecurity::Wpa2
        );
        assert_eq!(
            security_from_auth(DOT11_AUTH_ALGO_WPA3_SAE, 4),
            WifiSecurity::Wpa3
        );
        assert_eq!(
            security_from_auth(DOT11_AUTH_ALGO_80211_OPEN, 0),
            WifiSecurity::Open
        );
        assert_eq!(
            security_from_auth(DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_CIPHER_ALGO_WEP),
            WifiSecurity::Wep
        );
    }
}
