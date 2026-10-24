//! Minimal 802.11 information-element parsing shared by platform backends.

use crate::model::{WifiSecurity, WifiStandard};

const IE_SSID: u8 = 0;
const IE_DS_PARAMETER: u8 = 3;
const IE_HT_CAPABILITIES: u8 = 45;
const IE_RSN: u8 = 48;
const IE_HT_OPERATION: u8 = 61;
const IE_VHT_CAPABILITIES: u8 = 191;
const IE_VHT_OPERATION: u8 = 192;
const IE_VENDOR: u8 = 221;
const IE_EXTENSION: u8 = 255;

const EXT_HE_CAPABILITIES: u8 = 35;
const EXT_HE_OPERATION: u8 = 36;
const EXT_EHT_OPERATION: u8 = 106;
const EXT_EHT_CAPABILITIES: u8 = 108;

const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xf2];
const OUI_IEEE: [u8; 3] = [0x00, 0x0f, 0xac];

const WPA_OUI_TYPE: u8 = 1;
const WPS_OUI_TYPE: u8 = 4;

/// Parsed properties relevant to Wi-Fi analysis.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IeInfo {
    pub channel: Option<u32>,
    pub width_mhz: Option<u32>,
    pub security: Option<WifiSecurity>,
    pub standard: WifiStandard,
    pub wps: bool,
    pub ssid: Option<String>,
}

/// Upgrade the detected standard to the newest generation found.
fn upgrade_standard(current: WifiStandard, candidate: WifiStandard) -> WifiStandard {
    use WifiStandard::*;
    let rank = |standard| match standard {
        Unknown => 0,
        Legacy => 1,
        Wifi4 => 2,
        Wifi5 => 3,
        Wifi6 => 4,
        Wifi6E => 5,
        Wifi7 => 6,
    };
    if rank(candidate) >= rank(current) {
        candidate
    } else {
        current
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Parse a list of information elements.
pub fn parse_ies(data: &[u8]) -> IeInfo {
    let mut info = IeInfo::default();
    let mut offset = 0;
    while offset + 2 <= data.len() {
        let id = data[offset];
        let length = data[offset + 1] as usize;
        let start = offset + 2;
        let end = start.saturating_add(length);
        if end > data.len() {
            break;
        }
        let body = &data[start..end];
        match id {
            IE_SSID => {
                if !body.is_empty() {
                    info.ssid = Some(String::from_utf8_lossy(body).into_owned());
                }
            }
            IE_DS_PARAMETER => {
                if let Some(channel) = body.first() {
                    info.channel = Some(*channel as u32);
                }
            }
            IE_HT_CAPABILITIES => {
                info.standard = upgrade_standard(info.standard, WifiStandard::Wifi4);
            }
            IE_HT_OPERATION => {
                parse_ht_operation(body, &mut info);
            }
            IE_VHT_CAPABILITIES => {
                info.standard = upgrade_standard(info.standard, WifiStandard::Wifi5);
            }
            IE_VHT_OPERATION => {
                parse_vht_operation(body, &mut info);
            }
            IE_RSN => {
                if let Some(security) = parse_rsn(body) {
                    info.security = Some(security);
                }
            }
            IE_VENDOR => {
                parse_vendor(body, &mut info);
            }
            IE_EXTENSION => {
                if let Some((&ext, body)) = body.split_first() {
                    parse_extension(ext, body, &mut info);
                }
            }
            _ => {}
        }
        offset = end;
    }
    info
}

fn parse_ht_operation(body: &[u8], info: &mut IeInfo) {
    info.standard = upgrade_standard(info.standard, WifiStandard::Wifi4);
    if let Some(primary) = body.first() {
        info.channel = Some(*primary as u32);
    }
    if let Some(operation) = body.get(1) {
        let width = if operation & 0x04 != 0 { 40 } else { 20 };
        info.width_mhz = Some(info.width_mhz.unwrap_or(0).max(width));
    }
}

fn parse_vht_operation(body: &[u8], info: &mut IeInfo) {
    info.standard = upgrade_standard(info.standard, WifiStandard::Wifi5);
    if let Some(width) = body.first() {
        let width = match width & 0x03 {
            0 => 20,
            1 => 80,
            2 => 160,
            _ => 80,
        };
        info.width_mhz = Some(info.width_mhz.unwrap_or(0).max(width));
    }
}

fn parse_extension(ext: u8, body: &[u8], info: &mut IeInfo) {
    match ext {
        EXT_HE_CAPABILITIES => {
            info.standard = upgrade_standard(info.standard, WifiStandard::Wifi6);
        }
        EXT_HE_OPERATION => {
            info.standard = upgrade_standard(info.standard, WifiStandard::Wifi6);
            parse_he_operation(body, info);
        }
        EXT_EHT_CAPABILITIES => {
            info.standard = upgrade_standard(info.standard, WifiStandard::Wifi7);
        }
        EXT_EHT_OPERATION => {
            info.standard = upgrade_standard(info.standard, WifiStandard::Wifi7);
            parse_eht_operation(body, info);
        }
        _ => {}
    }
}

fn parse_he_operation(body: &[u8], info: &mut IeInfo) {
    if body.len() < 6 {
        return;
    }
    let params = u32::from(body[0]) | (u32::from(body[1]) << 8) | (u32::from(body[2]) << 16);
    let mut offset = 6;
    if params & (1 << 10) != 0 {
        if let Some(width) = body.get(offset) {
            let width = match width & 0x03 {
                0 => 20,
                1 => 40,
                2 => 80,
                _ => 160,
            };
            info.width_mhz = Some(info.width_mhz.unwrap_or(0).max(width));
        }
        offset += 3;
    }
    if params & (1 << 11) != 0 {
        offset += 1;
    }
    if params & (1 << 13) != 0 {
        if let Some(primary) = body.get(offset) {
            info.channel = Some(*primary as u32);
        }
        if let Some(control) = body.get(offset + 1) {
            let width = match control & 0x03 {
                0 => 20,
                1 => 40,
                2 => 80,
                _ => 160,
            };
            info.width_mhz = Some(info.width_mhz.unwrap_or(0).max(width));
            info.standard = upgrade_standard(info.standard, WifiStandard::Wifi6E);
        }
    }
}

fn parse_eht_operation(body: &[u8], info: &mut IeInfo) {
    // The EHT Operation element starts with parameters and a basic MCS set,
    // followed by optional operation information. Parse defensively because
    // drivers expose slightly different lengths.
    if let Some(control) = body.get(5) {
        let width = match control & 0x07 {
            0 => 20,
            1 => 40,
            2 => 80,
            3 => 160,
            4 => 320,
            _ => 20,
        };
        info.width_mhz = Some(info.width_mhz.unwrap_or(0).max(width));
    }
}

fn parse_vendor(body: &[u8], info: &mut IeInfo) {
    if body.len() < 4 || body[..3] != OUI_MICROSOFT {
        return;
    }
    match body[3] {
        WPA_OUI_TYPE => {
            if info.security.is_none() {
                if let Some(security) = parse_wpa_vendor(&body[4..]) {
                    info.security = Some(security);
                }
            }
        }
        WPS_OUI_TYPE => info.wps = true,
        _ => {}
    }
}

fn parse_rsn(data: &[u8]) -> Option<WifiSecurity> {
    if read_u16(data, 0)? != 1 {
        return None;
    }
    let mut offset = 2;
    offset += 4; // group cipher
    let pairwise_count = read_u16(data, offset)? as usize;
    offset += 2 + pairwise_count * 4;
    let akm_count = read_u16(data, offset)? as usize;
    offset += 2;

    let mut akm_types = Vec::new();
    for index in 0..akm_count {
        let start = offset + index * 4;
        let suite = data.get(start..start + 4)?;
        if suite[..3] == OUI_IEEE {
            akm_types.push(suite[3]);
        }
    }
    security_from_akms(&akm_types, true)
}

fn parse_wpa_vendor(data: &[u8]) -> Option<WifiSecurity> {
    if read_u16(data, 0)? != 1 {
        return None;
    }
    let mut offset = 2;
    offset += 4;
    let pairwise_count = read_u16(data, offset)? as usize;
    offset += 2 + pairwise_count * 4;
    let akm_count = read_u16(data, offset)? as usize;
    offset += 2;

    let mut akm_types = Vec::new();
    for index in 0..akm_count {
        let start = offset + index * 4;
        let suite = data.get(start..start + 4)?;
        if suite[..3] == OUI_IEEE {
            akm_types.push(suite[3]);
        }
    }
    security_from_akms(&akm_types, false)
}

fn security_from_akms(akms: &[u8], rsn: bool) -> Option<WifiSecurity> {
    if akms.is_empty() {
        return Some(if rsn {
            WifiSecurity::Wpa2
        } else {
            WifiSecurity::Wpa
        });
    }

    let has_sae = akms.iter().any(|akm| matches!(akm, 8 | 9 | 24));
    let has_psk = akms.iter().any(|akm| matches!(akm, 2 | 5 | 6));
    let has_owe = akms.contains(&18);
    let has_enterprise = akms
        .iter()
        .any(|akm| matches!(akm, 1 | 3 | 4 | 11 | 12 | 13));

    if has_owe {
        return Some(WifiSecurity::Owe);
    }
    if has_sae && has_psk {
        return Some(WifiSecurity::Wpa2Wpa3);
    }
    if has_sae {
        return Some(WifiSecurity::Wpa3);
    }
    if has_enterprise {
        return Some(WifiSecurity::Enterprise);
    }
    Some(if rsn {
        WifiSecurity::Wpa2
    } else {
        WifiSecurity::Wpa
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ie(id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![id, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    fn ext(ext_id: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![ext_id];
        payload.extend_from_slice(body);
        ie(IE_EXTENSION, &payload)
    }

    fn rsn(akms: &[u8]) -> Vec<u8> {
        let mut body = vec![1, 0];
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
        body.extend_from_slice(&[(akms.len() as u8), 0]);
        for akm in akms {
            body.extend_from_slice(&[0x00, 0x0f, 0xac, *akm]);
        }
        body
    }

    #[test]
    fn parses_ds_and_ht_operation() {
        let mut data = ie(IE_DS_PARAMETER, &[6]);
        data.extend(ie(IE_HT_CAPABILITIES, &[0; 26]));
        data.extend(ie(IE_HT_OPERATION, &[6, 0x04, 0, 0, 0, 0]));
        let info = parse_ies(&data);
        assert_eq!(info.channel, Some(6));
        assert_eq!(info.width_mhz, Some(40));
        assert_eq!(info.standard, WifiStandard::Wifi4);
    }

    #[test]
    fn parses_vht_width_and_standard() {
        let mut data = ie(IE_VHT_CAPABILITIES, &[0; 12]);
        data.extend(ie(IE_VHT_OPERATION, &[1, 0, 0, 0, 0, 0]));
        let info = parse_ies(&data);
        assert_eq!(info.width_mhz, Some(80));
        assert_eq!(info.standard, WifiStandard::Wifi5);
    }

    #[test]
    fn detects_wpa2_wpa3_enterprise_and_owe() {
        assert_eq!(
            parse_ies(&ie(IE_RSN, &rsn(&[2]))).security,
            Some(WifiSecurity::Wpa2)
        );
        assert_eq!(
            parse_ies(&ie(IE_RSN, &rsn(&[8]))).security,
            Some(WifiSecurity::Wpa3)
        );
        assert_eq!(
            parse_ies(&ie(IE_RSN, &rsn(&[2, 8]))).security,
            Some(WifiSecurity::Wpa2Wpa3)
        );
        assert_eq!(
            parse_ies(&ie(IE_RSN, &rsn(&[1]))).security,
            Some(WifiSecurity::Enterprise)
        );
        assert_eq!(
            parse_ies(&ie(IE_RSN, &rsn(&[18]))).security,
            Some(WifiSecurity::Owe)
        );
    }

    #[test]
    fn detects_wpa_vendor_and_wps() {
        let mut body = vec![0x00, 0x50, 0xf2, WPA_OUI_TYPE];
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x02]);
        let mut data = ie(IE_VENDOR, &body);
        data.extend(ie(IE_VENDOR, &[0x00, 0x50, 0xf2, WPS_OUI_TYPE, 0x00]));
        let info = parse_ies(&data);
        assert_eq!(info.security, Some(WifiSecurity::Wpa));
        assert!(info.wps);
    }

    #[test]
    fn detects_he_and_six_ghz_width() {
        let mut data = ext(EXT_HE_CAPABILITIES, &[0; 10]);
        let mut operation = vec![0; 6];
        // Mark the 6 GHz operation information as present.
        operation[1] |= 0x20;
        operation.extend_from_slice(&[37, 0x02, 0, 0, 0]);
        data.extend(ext(EXT_HE_OPERATION, &operation));
        let info = parse_ies(&data);
        assert_eq!(info.standard, WifiStandard::Wifi6E);
        assert_eq!(info.channel, Some(37));
        assert_eq!(info.width_mhz, Some(80));
    }

    #[test]
    fn detects_eht_standard() {
        let data = ext(EXT_EHT_CAPABILITIES, &[0; 8]);
        let info = parse_ies(&data);
        assert_eq!(info.standard, WifiStandard::Wifi7);
    }
}
