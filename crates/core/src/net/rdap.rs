//! RDAP lookup: query registration data for a domain or IP address.
//!
//! Requests go through the public rdap.org bootstrap service, which redirects
//! to the authoritative RDAP server for the target. `reqwest` follows the
//! redirect automatically, so a single GET yields the final JSON document.
//!
//! Two convenience transformations are applied to the raw document:
//! - jCard `vcardArray` values are parsed into a compact object, because the
//!   raw nested-array form is hard to read in a tree.
//! - When a domain is not registered (HTTP 404), parent domains are tried one
//!   label at a time, stopping at the top-level domain, so a user who typed
//!   `www.example.com` still sees the `example.com` record.

use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::config::LookupSettings;
use crate::control::ProbeHandle;
use crate::model::{LookupResult, ProbeEvent};

/// Base URL of the rdap.org bootstrap redirect service.
const RDAP_BASE: &str = "https://rdap.org";

/// User agent sent with the request; some servers reject empty agents.
const USER_AGENT: &str = "net-tools";

/// Upper bound on how many characters of a non-JSON body are kept for display.
const MAX_RAW_CHARS: usize = 500;

/// The kind of object a lookup target refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKind {
    Domain,
    Ip,
}

impl LookupKind {
    /// Short label used in the result and the request path.
    pub fn label(&self) -> &'static str {
        match self {
            LookupKind::Domain => "domain",
            LookupKind::Ip => "ip",
        }
    }
}

/// Resolve a user supplied target into a lookup kind and the rdap.org URL.
///
/// The classification is intentionally conservative: anything that parses as an
/// IP address is treated as an IP, and only whitespace-free dotted names are
/// treated as domains. This avoids sending obviously invalid input to the
/// remote service and lets the UI show an actionable error instead.
pub fn lookup_url(target: &str) -> Result<(LookupKind, String), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target is empty".to_string());
    }
    if target.parse::<std::net::IpAddr>().is_ok() {
        return Ok((LookupKind::Ip, rdap_url(LookupKind::Ip, target)));
    }
    if target.contains('.') && !target.chars().any(char::is_whitespace) {
        return Ok((LookupKind::Domain, rdap_url(LookupKind::Domain, target)));
    }
    Err(format!(
        "`{target}` is neither an IP address nor a domain name"
    ))
}

/// Build the rdap.org URL for a target without validating it. Used for the
/// fallback candidates, which may be a bare top-level domain label.
fn rdap_url(kind: LookupKind, target: &str) -> String {
    format!("{RDAP_BASE}/{}/{target}", kind.label())
}

/// Candidate domains to try for a target, from the full name up to (and
/// including) the top-level domain. For an IP address the only candidate is the
/// address itself.
///
/// Example: `www.example.com` yields `www.example.com`, `example.com`, `com`.
pub fn lookup_candidates(target: &str, kind: LookupKind) -> Vec<String> {
    if kind == LookupKind::Ip {
        return vec![target.to_string()];
    }
    let labels: Vec<&str> = target.split('.').filter(|s| !s.is_empty()).collect();
    (0..labels.len())
        .map(|start| labels[start..].join("."))
        .collect()
}

/// Run a lookup and stream the result back to the UI.
///
/// For domains, a 404 from one candidate triggers a retry with the parent
/// domain, until a response is found or only the top-level domain is left. Any
/// non-404 outcome (including transport errors) stops the fallback immediately.
/// The request is cancellation aware, so stopping the task aborts the in-flight
/// HTTP request.
pub async fn run_lookup(handle: &ProbeHandle<ProbeEvent>, settings: &LookupSettings) {
    let original = settings.target.trim().to_string();
    let (kind, _) = match lookup_url(&original) {
        Ok(pair) => pair,
        Err(message) => {
            handle.send(ProbeEvent::Error {
                message,
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(settings.timeout_ms))
        .user_agent(USER_AGENT)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            handle.send(ProbeEvent::Error {
                message: format!("failed to create HTTP client: {err}"),
                hint: None,
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };

    // The first 404 is kept so that, if every candidate fails, the user still
    // sees the result for the target they actually entered.
    let mut first_not_found: Option<LookupResult> = None;
    for candidate in lookup_candidates(&original, kind) {
        let url = rdap_url(kind, &candidate);
        let queried = tokio::select! {
            result = query(&client, &candidate, kind, &url) => Some(result),
            _ = handle.cancelled() => None,
        };
        let Some(mut result) = queried else {
            break;
        };
        result.original_target = original.clone();
        if result.status == Some(404) {
            if first_not_found.is_none() {
                first_not_found = Some(result);
            }
            continue;
        }
        handle.send(ProbeEvent::Lookup(result));
        handle.send(ProbeEvent::Finished);
        return;
    }

    if let Some(result) = first_not_found {
        handle.send(ProbeEvent::Lookup(result));
    }
    handle.send(ProbeEvent::Finished);
}

/// Perform one HTTP request and turn the response into a result, never failing.
async fn query(
    client: &reqwest::Client,
    target: &str,
    kind: LookupKind,
    url: &str,
) -> LookupResult {
    let started = Instant::now();
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(err) => {
            return LookupResult::failed(
                target,
                kind.label(),
                url,
                None,
                elapsed_ms(&started),
                format!("request failed: {err}"),
            );
        }
    };
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let body = match response.text().await {
        Ok(body) => body,
        // Some RDAP servers answer an unknown object with an empty body and then
        // close the TLS connection without close_notify, which rustls reports as
        // a body error. A 404 is therefore treated as a clean "not found" so the
        // parent-domain fallback can still continue.
        Err(_) if status == 404 => {
            return LookupResult::not_found(target, kind.label(), url, elapsed_ms(&started));
        }
        Err(err) => {
            return LookupResult::failed(
                target,
                kind.label(),
                url,
                Some(status),
                elapsed_ms(&started),
                format!("failed to read response: {err}"),
            );
        }
    };
    let elapsed = elapsed_ms(&started);

    match serde_json::from_str::<Value>(&body) {
        Ok(mut data) => {
            simplify_rdap(&mut data);
            LookupResult {
                target: target.to_string(),
                original_target: target.to_string(),
                kind: kind.label().to_string(),
                url: final_url,
                status: Some(status),
                elapsed_ms: elapsed,
                data: Some(data),
                raw: None,
                error: None,
            }
        }
        Err(err) => LookupResult {
            target: target.to_string(),
            original_target: target.to_string(),
            kind: kind.label().to_string(),
            url: final_url,
            status: Some(status),
            elapsed_ms: elapsed,
            data: None,
            raw: Some(truncate(&body)),
            error: Some(format!("response is not valid JSON: {err}")),
        },
    }
}

fn elapsed_ms(started: &Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

/// Keep at most [`MAX_RAW_CHARS`] characters, marking a truncation.
fn truncate(text: &str) -> String {
    let mut out: String = text.chars().take(MAX_RAW_CHARS).collect();
    if text.chars().count() > MAX_RAW_CHARS {
        out.push('…');
    }
    out
}

// ---------------------------------------------------------------------------
// RDAP document simplification
// ---------------------------------------------------------------------------

/// Recursively replace every jCard `vcardArray` in an RDAP document with its
/// compact object form.
pub fn simplify_rdap(value: &mut Value) {
    match value {
        Value::Object(map) => {
            // Replace the jCard with its compact form and rename the key so the
            // result no longer looks like raw vCard data.
            if let Some(vcard) = map.remove("vcardArray") {
                let simplified = if is_jcard(&vcard) {
                    simplify_vcard(&vcard)
                } else {
                    vcard
                };
                map.insert("vcard".to_string(), simplified);
            }
            for (_, child) in map.iter_mut() {
                simplify_rdap(child);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                simplify_rdap(item);
            }
        }
        _ => {}
    }
}

/// Whether a value is a jCard array (`["vcard", [...]]`).
fn is_jcard(value: &Value) -> bool {
    value
        .as_array()
        .and_then(|items| items.first())
        .and_then(|first| first.as_str())
        .map(|tag| tag == "vcard")
        .unwrap_or(false)
}

/// Field names of the seven-part vCard `adr` value.
const ADR_FIELDS: [&str; 7] = [
    "post_office_box",
    "extended",
    "street",
    "locality",
    "region",
    "postal_code",
    "country",
];

/// Field names of the five-part vCard `n` value.
const N_FIELDS: [&str; 5] = ["family", "given", "additional", "prefix", "suffix"];

/// Parse a jCard value into a compact object keyed by readable property names.
///
/// Repeated properties (several emails, addresses, ...) are collected into an
/// array. Structured values (`adr`, `n`, `org`, `geo`) are expanded into named
/// fields so they no longer appear as positional arrays.
pub fn simplify_vcard(jcard: &Value) -> Value {
    let mut out = Map::new();
    let Some(entries) = jcard.get(1).and_then(|v| v.as_array()) else {
        return Value::Object(out);
    };

    for entry in entries {
        let Some(parts) = entry.as_array() else {
            continue;
        };
        let name = parts.first().and_then(|v| v.as_str()).unwrap_or("");
        // The version property carries no useful information for a record view.
        if name.is_empty() || name == "version" {
            continue;
        }
        let params = parts.get(1);
        let raw = parts.get(3).unwrap_or(&Value::Null);

        let mut simplified = simplify_vcard_value(name, raw);
        // An address label is more readable than the positional street parts, so
        // fold it in before any type wrapping.
        if name == "adr" {
            if let (Some(label), Value::Object(fields)) = (
                params.and_then(|p| p.get("label")).and_then(|v| v.as_str()),
                &mut simplified,
            ) {
                fields.insert("label".to_string(), Value::String(label.to_string()));
            }
        }
        // Keep the vCard type parameter (home / work / voice / ...) when present.
        if let Some(types) = param_types(params) {
            simplified = json!({ "type": types, "value": simplified });
        }

        insert_aggregate(&mut out, &vcard_key(name), simplified);
    }

    Value::Object(out)
}

/// Map a vCard property name to a readable key, leaving unknown names as-is.
fn vcard_key(name: &str) -> String {
    match name {
        "fn" => "name".to_string(),
        "n" => "name_parts".to_string(),
        "org" => "organization".to_string(),
        "adr" => "address".to_string(),
        "tel" => "telephone".to_string(),
        "tz" => "timezone".to_string(),
        other => other.to_string(),
    }
}

/// Simplify one vCard property value according to its property name.
fn simplify_vcard_value(name: &str, raw: &Value) -> Value {
    match name {
        "adr" => positional_object(raw, &ADR_FIELDS),
        "n" => positional_object(raw, &N_FIELDS),
        "org" => join_strings(raw),
        "geo" => geo_object(raw),
        // Unknown properties are kept as-is so nothing is silently dropped.
        _ => raw.clone(),
    }
}

/// Build an object from a positional vCard array, skipping empty strings.
fn positional_object(value: &Value, fields: &[&str]) -> Value {
    let mut map = Map::new();
    if let Some(items) = value.as_array() {
        for (field, item) in fields.iter().zip(items) {
            if let Some(text) = item.as_str() {
                if !text.is_empty() {
                    map.insert((*field).to_string(), Value::String(text.to_string()));
                }
            }
        }
    }
    Value::Object(map)
}

/// Join the lines of a multi-valued text property into one string.
fn join_strings(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            Value::String(parts.join(" / "))
        }
        other => other.clone(),
    }
}

/// Turn a vCard geo value into a named object.
fn geo_object(value: &Value) -> Value {
    let mut map = Map::new();
    if let Some(items) = value.as_array() {
        for (field, item) in ["latitude", "longitude", "altitude"].iter().zip(items) {
            map.insert((*field).to_string(), item.clone());
        }
    }
    Value::Object(map)
}

/// Extract the `type` parameter of a vCard property, if any.
fn param_types(params: Option<&Value>) -> Option<Value> {
    let value = params?.get("type")?;
    match value {
        Value::String(s) => Some(Value::String(s.clone())),
        m @ Value::Array(_) => Some(m.clone()),
        _ => None,
    }
}

/// Insert a value under a key, promoting an existing entry to an array.
fn insert_aggregate(map: &mut Map<String, Value>, key: &str, value: Value) {
    match map.get_mut(key) {
        None => {
            map.insert(key.to_string(), value);
        }
        Some(existing) => {
            if let Value::Array(items) = existing {
                items.push(value);
            } else {
                let previous = existing.take();
                *existing = Value::Array(vec![previous, value]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_ipv4_and_ipv6() {
        let (kind, url) = lookup_url("1.1.1.1").unwrap();
        assert_eq!(kind, LookupKind::Ip);
        assert!(url.ends_with("/ip/1.1.1.1"));

        let (kind, url) = lookup_url("2001:db8::1").unwrap();
        assert_eq!(kind, LookupKind::Ip);
        assert!(url.ends_with("/ip/2001:db8::1"));
    }

    #[test]
    fn classifies_domain() {
        let (kind, url) = lookup_url("example.com").unwrap();
        assert_eq!(kind, LookupKind::Domain);
        assert!(url.ends_with("/domain/example.com"));
    }

    #[test]
    fn rejects_empty_and_plain_labels() {
        assert!(lookup_url("   ").is_err());
        assert!(lookup_url("localhost").is_err());
        assert!(lookup_url("not a domain").is_err());
    }

    #[test]
    fn domain_candidates_walk_up_to_the_tld() {
        assert_eq!(
            lookup_candidates("www.sub.example.com", LookupKind::Domain),
            vec![
                "www.sub.example.com",
                "sub.example.com",
                "example.com",
                "com"
            ]
        );
        // A trailing dot does not create an empty candidate.
        assert_eq!(
            lookup_candidates("example.com.", LookupKind::Domain),
            vec!["example.com", "com"]
        );
    }

    #[test]
    fn ip_has_a_single_candidate() {
        assert_eq!(
            lookup_candidates("1.1.1.1", LookupKind::Ip),
            vec!["1.1.1.1"]
        );
    }

    #[test]
    fn simplifies_vcard_into_named_fields() {
        let jcard = json!(["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Jane Doe"],
            ["org", {}, "text", ["Example Inc", "NOC"]],
            ["adr", { "label": "Main St" }, "text", ["", "", "1 Main St", "Springfield", "IL", "62701", "US"]],
            ["tel", { "type": ["voice", "work"] }, "uri", "tel:+1-555"],
            ["tel", {}, "uri", "tel:+1-556"],
            ["email", {}, "text", "jane@example.com"]
        ]]);

        let simplified = simplify_vcard(&jcard);
        assert_eq!(simplified["name"], "Jane Doe");
        assert_eq!(simplified["organization"], "Example Inc / NOC");
        assert_eq!(simplified["address"]["street"], "1 Main St");
        assert_eq!(simplified["address"]["locality"], "Springfield");
        assert_eq!(simplified["address"]["label"], "Main St");
        assert_eq!(simplified["telephone"][0]["type"][1], "work");
        assert_eq!(simplified["telephone"][1], "tel:+1-556");
        assert_eq!(simplified["email"], "jane@example.com");
    }

    #[test]
    fn simplify_rdap_replaces_nested_vcard_array() {
        let mut doc = json!({
            "entities": [
                { "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Acme"]]] }
            ]
        });
        simplify_rdap(&mut doc);
        assert_eq!(doc["entities"][0]["vcard"]["name"], "Acme");
        assert!(doc["entities"][0].get("vcardArray").is_none());
        // The surrounding document is untouched.
        assert_eq!(doc["entities"][0]["roles"][0], "registrant");
    }
}
