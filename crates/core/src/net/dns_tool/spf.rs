//! SPF record parsing and expansion helpers.

/// One SPF mechanism parsed from a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfMechanism {
    /// Qualifier character: `+`, `-`, `~` or `?`.
    pub qualifier: char,
    pub name: String,
    pub value: Option<String>,
}

impl SpfMechanism {
    /// DNS-lookup term represented by this mechanism, if any.
    pub fn lookup_term(&self) -> Option<LookupTerm> {
        match self.name.as_str() {
            "include" => self.value.clone().map(LookupTerm::Include),
            "redirect" => self.value.clone().map(LookupTerm::Redirect),
            "a" => Some(LookupTerm::A),
            "mx" => Some(LookupTerm::Mx),
            "ptr" => Some(LookupTerm::Ptr),
            "exists" => self.value.clone().map(LookupTerm::Exists),
            _ => None,
        }
    }
}

/// DNS lookup terms that count against the SPF lookup limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupTerm {
    Include(String),
    Redirect(String),
    A,
    Mx,
    Ptr,
    Exists(String),
}

/// Parse an SPF record into mechanisms.
pub fn parse_record(record: &str) -> Result<Vec<SpfMechanism>, String> {
    let mut tokens = record.split_whitespace();
    let version = tokens
        .next()
        .ok_or_else(|| "the SPF record is empty".to_string())?;
    if !version.eq_ignore_ascii_case("v=spf1") {
        return Err(format!("not an SPF record: {version}"));
    }
    let mut mechanisms = Vec::new();
    for token in tokens {
        if token.contains('=')
            && !token.starts_with('+')
            && !token.starts_with('-')
            && !token.starts_with('~')
            && !token.starts_with('?')
        {
            // Unknown modifier such as `exp=...`; keep it for display only.
            let (name, value) = token.split_once('=').unwrap();
            mechanisms.push(SpfMechanism {
                qualifier: '+',
                name: name.to_ascii_lowercase(),
                value: Some(value.to_string()),
            });
            continue;
        }
        let mut chars = token.chars();
        let first = chars.next().unwrap_or('+');
        let (qualifier, rest) = match first {
            '+' | '-' | '~' | '?' => (first, chars.as_str()),
            _ => ('+', token),
        };
        if rest.is_empty() {
            return Err("the SPF record contains an empty mechanism".to_string());
        }
        let (name, value) = match rest.split_once(':') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (rest, None),
        };
        let (name, value) = match name.split_once('/') {
            Some((name, cidr)) => {
                let value = match value {
                    Some(value) => Some(format!("{value}/{cidr}")),
                    None => Some(format!("/{cidr}")),
                };
                (name, value)
            }
            None => (name, value),
        };
        let name = name.to_ascii_lowercase();
        if name.is_empty() {
            return Err("the SPF record contains an empty mechanism".to_string());
        }
        mechanisms.push(SpfMechanism {
            qualifier,
            name,
            value,
        });
    }
    Ok(mechanisms)
}

/// Return the `all` mechanism qualifier when present.
pub fn all_qualifier(mechanisms: &[SpfMechanism]) -> Option<char> {
    mechanisms
        .iter()
        .find(|mechanism| mechanism.name == "all")
        .map(|mechanism| mechanism.qualifier)
}

/// Parse a selector list separated by commas or newlines.
pub fn parse_selectors(value: &str) -> Vec<String> {
    value
        .split([',', '\n', '\r'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mechanisms_and_qualifiers() {
        let mechanisms =
            parse_record("v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all").unwrap();
        assert_eq!(mechanisms.len(), 3);
        assert_eq!(mechanisms[1].name, "include");
        assert_eq!(mechanisms[1].value.as_deref(), Some("_spf.example.net"));
        assert_eq!(all_qualifier(&mechanisms), Some('-'));
    }

    #[test]
    fn identifies_lookup_terms() {
        let mechanisms =
            parse_record("v=spf1 a mx ptr exists:%{i}.example.net redirect=_spf.example.net")
                .unwrap();
        let terms: Vec<_> = mechanisms.iter().filter_map(|m| m.lookup_term()).collect();
        assert_eq!(terms.len(), 5);
        assert!(matches!(terms[0], LookupTerm::A));
        assert!(matches!(terms[4], LookupTerm::Redirect(_)));
    }

    #[test]
    fn rejects_invalid_records() {
        assert!(parse_record("v=dmarc1 p=none").is_err());
        assert!(parse_record("v=spf1 +").is_err());
    }

    #[test]
    fn selector_lists_are_normalized() {
        assert_eq!(
            parse_selectors(" default, Google\nS1 "),
            vec!["default", "google", "s1"]
        );
    }
}
