//! DKIM selector probing and record parsing.

use std::collections::BTreeMap;

/// Selectors probed by default. DKIM selectors cannot be enumerated, so a
/// missing record only means that none of these common selectors are present.
pub const COMMON_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "mail",
    "dkim",
];

/// Parsed DKIM key record tags.
#[derive(Debug, Clone, Default)]
pub struct DkimRecord {
    pub tags: BTreeMap<String, String>,
}

impl DkimRecord {
    /// Whether the record looks like a DKIM key record.
    pub fn is_dkim(record: &str) -> bool {
        let lower = record.to_ascii_lowercase();
        lower.contains("v=dkim1") || lower.contains("p=")
    }

    pub fn key_type(&self) -> &str {
        self.tags.get("k").map(String::as_str).unwrap_or("rsa")
    }

    pub fn revoked(&self) -> bool {
        self.tags
            .get("p")
            .map(|value| value.trim().is_empty())
            .unwrap_or(false)
    }

    pub fn testing(&self) -> bool {
        self.tags
            .get("t")
            .map(|value| value.split(':').any(|flag| flag.trim() == "y"))
            .unwrap_or(false)
    }

    pub fn has_public_key(&self) -> bool {
        self.tags
            .get("p")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Parse a TXT value into DKIM tags.
pub fn parse_record(record: &str) -> Result<DkimRecord, String> {
    let mut tags = BTreeMap::new();
    for part in record.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid DKIM tag: {part}"))?;
        tags.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    if !tags.contains_key("p") {
        return Err("the DKIM record has no p= tag".to_string());
    }
    Ok(DkimRecord { tags })
}

/// Build the DNS name for one selector.
pub fn selector_name(selector: &str, domain: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags_and_detects_revoked_keys() {
        let record = parse_record("v=DKIM1; k=rsa; p=ABC; t=y: s=email").unwrap();
        assert_eq!(record.key_type(), "rsa");
        assert!(record.has_public_key());
        assert!(record.testing());
        assert!(!record.revoked());

        let revoked = parse_record("v=DKIM1; p=").unwrap();
        assert!(revoked.revoked());
    }

    #[test]
    fn rejects_records_without_public_key_tag() {
        assert!(parse_record("v=DKIM1; k=rsa").is_err());
    }

    #[test]
    fn selector_names_are_stable() {
        assert_eq!(
            selector_name("google", "example.com"),
            "google._domainkey.example.com"
        );
    }
}
