//! IP insight: query a target IP against several online geolocation APIs and
//! return each provider's JSON response so the UI can render it as a table.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::config::IpInsightSettings;
use crate::control::ProbeHandle;
use crate::model::{IpInsightResult, ProbeEvent};

/// Placeholder inside a provider URL template that is replaced by the target IP.
const IP_PLACEHOLDER: &str = "{ip}";

/// User agent sent with every request; some providers reject empty agents.
const USER_AGENT: &str = "net-tools";

/// Upper bound on how many characters of a non-JSON body are kept for display.
const MAX_RAW_CHARS: usize = 500;

/// How long to wait for a result before re-checking the cancellation flag.
const CANCEL_POLL_MS: u64 = 100;

/// Fallback key used when the top level JSON value is not an object.
const VALUE_LABEL: &str = "value";

/// One online IP geolocation API provider.
#[derive(Debug, Clone, Copy)]
pub struct IpApiProvider {
    /// Display name shown as the table heading.
    pub name: &'static str,
    /// URL template containing the [`IP_PLACEHOLDER`] placeholder.
    pub url_template: &'static str,
}

/// The providers queried by the IP insight tab, in display order.
pub const IP_API_PROVIDERS: &[IpApiProvider] = &[
    IpApiProvider {
        name: "IP.SB",
        url_template: "https://api.ip.sb/geoip/{ip}",
    },
    IpApiProvider {
        name: "IPQuery.io",
        url_template: "https://api.ipquery.io/{ip}",
    },
    IpApiProvider {
        name: "GeoJS.io",
        url_template: "https://get.geojs.io/v1/ip/geo/{ip}.json",
    },
    IpApiProvider {
        name: "IPInfo.ES",
        url_template: "https://api.ipinfo.es/ipinfo?ip={ip}",
    },
];

/// Query all providers concurrently and stream one event per provider back to
/// the UI, followed by a final `Finished` event.
pub async fn run_ip_insight(handle: &ProbeHandle<ProbeEvent>, settings: &IpInsightSettings) {
    let ip = settings.target.trim().to_string();
    if ip.is_empty() {
        handle.send(ProbeEvent::Error {
            message: "target IP is empty".to_string(),
            hint: None,
        });
        handle.send(ProbeEvent::Finished);
        return;
    }

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

    // One task per provider so a slow API never delays the others.
    let mut tasks = tokio::task::JoinSet::new();
    for provider in IP_API_PROVIDERS {
        let name = provider.name.to_string();
        let url = provider.url_template.replace(IP_PLACEHOLDER, &ip);
        let client = client.clone();
        tasks.spawn(async move { query_one(&client, &name, &url).await });
    }

    // Collect results as they arrive, aborting in-flight requests on cancel.
    loop {
        if handle.is_cancelled() {
            tasks.abort_all();
            break;
        }
        match tokio::time::timeout(Duration::from_millis(CANCEL_POLL_MS), tasks.join_next()).await {
            Ok(Some(Ok(result))) => handle.send(ProbeEvent::IpInsight(result)),
            Ok(Some(Err(err))) => handle.send(ProbeEvent::Error {
                message: format!("query task failed: {err}"),
                hint: None,
            }),
            // All tasks have completed.
            Ok(None) => break,
            // Timed out waiting for the next result: re-check cancellation.
            Err(_) => continue,
        }
    }

    handle.send(ProbeEvent::Finished);
}

/// Perform a single API request and turn it into a result, never failing.
async fn query_one(client: &reqwest::Client, provider: &str, url: &str) -> IpInsightResult {
    let started = Instant::now();
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(err) => {
            return error_result(
                provider,
                url,
                elapsed_ms(&started),
                format!("request failed: {err}"),
            );
        }
    };
    let status = response.status().as_u16();
    let body = match response.text().await {
        Ok(body) => body,
        Err(err) => {
            return error_result(
                provider,
                url,
                elapsed_ms(&started),
                format!("failed to read response: {err}"),
            );
        }
    };
    let elapsed = elapsed_ms(&started);

    match serde_json::from_str::<Value>(&body) {
        Ok(data) => IpInsightResult {
            provider: provider.to_string(),
            url: url.to_string(),
            status: Some(status),
            elapsed_ms: elapsed,
            data: Some(data),
            raw: None,
            error: None,
        },
        Err(err) => IpInsightResult {
            provider: provider.to_string(),
            url: url.to_string(),
            status: Some(status),
            elapsed_ms: elapsed,
            data: None,
            raw: Some(truncate(&body)),
            error: Some(format!("response is not valid JSON: {err}")),
        },
    }
}

fn error_result(provider: &str, url: &str, elapsed_ms: f64, message: String) -> IpInsightResult {
    IpInsightResult {
        provider: provider.to_string(),
        url: url.to_string(),
        status: None,
        elapsed_ms,
        data: None,
        raw: None,
        error: Some(message),
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

/// Flatten an arbitrary JSON value into ordered key/value rows for a table.
///
/// Nested objects use dotted paths and array items are suffixed with their
/// index, so a provider's JSON structure does not need to be known in advance.
pub fn flatten_json(value: &Value) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    flatten_into("", value, &mut rows);
    rows
}

fn flatten_into(prefix: &str, value: &Value, rows: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                rows.push((label(prefix), "{}".to_string()));
                return;
            }
            for (key, child) in map {
                let path = join(prefix, key);
                flatten_into(&path, child, rows);
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                rows.push((label(prefix), "[]".to_string()));
                return;
            }
            for (index, child) in items.iter().enumerate() {
                let path = format!("{}[{}]", label(prefix), index);
                flatten_into(&path, child, rows);
            }
        }
        Value::Null => rows.push((label(prefix), "null".to_string())),
        Value::String(s) => rows.push((label(prefix), s.clone())),
        other => rows.push((label(prefix), other.to_string())),
    }
}

/// Join a parent path and a child key with a dot.
fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

/// The path shown for a value, falling back to a generic label at the root.
fn label(prefix: &str) -> String {
    if prefix.is_empty() {
        VALUE_LABEL.to_string()
    } else {
        prefix.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flatten_handles_nesting_and_arrays() {
        let value = json!({
            "ip": "1.1.1.1",
            "nested": { "city": "Sydney" },
            "list": [true, null],
            "empty": {}
        });
        let rows = flatten_json(&value);
        assert!(rows.contains(&("ip".to_string(), "1.1.1.1".to_string())));
        assert!(rows.contains(&("nested.city".to_string(), "Sydney".to_string())));
        assert!(rows.contains(&("list[0]".to_string(), "true".to_string())));
        assert!(rows.contains(&("list[1]".to_string(), "null".to_string())));
        assert!(rows.contains(&("empty".to_string(), "{}".to_string())));
    }

    #[test]
    fn flatten_scalar_root_uses_value_label() {
        let rows = flatten_json(&json!("plain"));
        assert_eq!(rows, vec![(VALUE_LABEL.to_string(), "plain".to_string())]);
    }

    #[test]
    fn every_provider_url_has_the_placeholder() {
        for provider in IP_API_PROVIDERS {
            assert!(provider.url_template.contains(IP_PLACEHOLDER));
        }
    }
}
