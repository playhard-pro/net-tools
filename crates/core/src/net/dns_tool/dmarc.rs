//! DMARC record parsing and policy helpers.

use std::collections::BTreeMap;

/// Parsed DMARC policy record.
#[derive(Debug, Clone, Default)]
pub struct DmarcRecord {
    pub tags: BTreeMap<String, String>,
}

impl DmarcRecord {
    pub fn policy(&self) -> Option<&str> {
        self.tags.get("p").map(String::as_str)
    }

    pub fn subdomain_policy(&self) -> Option<&str> {
        self.tags.get("sp").map(String::as_str)
    }

    pub fn percent(&self) -> Option<u8> {
        self.tags
            .get("pct")
            .and_then(|value| value.trim().parse().ok())
    }

    pub fn has_report_uri(&self) -> bool {
        self.tags
            .get("rua")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Parse a TXT value into DMARC tags.
pub fn parse_record(record: &str) -> Result<DmarcRecord, String> {
    let trimmed = record.trim();
    if !trimmed.to_ascii_lowercase().starts_with("v=dmarc1") {
        return Err("the record does not start with v=DMARC1".to_string());
    }
    let mut tags = BTreeMap::new();
    for part in trimmed.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid DMARC tag: {part}"))?;
        tags.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok(DmarcRecord { tags })
}

/// Whether a TXT value looks like a DMARC record.
pub fn is_dmarc_record(record: &str) -> bool {
    record.trim().to_ascii_lowercase().starts_with("v=dmarc1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_tags() {
        let record =
            parse_record("v=DMARC1; p=quarantine; sp=none; pct=50; rua=mailto:a@example.com")
                .unwrap();
        assert_eq!(record.policy(), Some("quarantine"));
        assert_eq!(record.subdomain_policy(), Some("none"));
        assert_eq!(record.percent(), Some(50));
        assert!(record.has_report_uri());
    }

    #[test]
    fn rejects_non_dmarc_records() {
        assert!(parse_record("v=spf1 -all").is_err());
    }
}
