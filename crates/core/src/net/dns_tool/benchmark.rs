//! Resolver latency benchmark with warm-up and bounded sampling.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::names::{parse_name, parse_record_type};
use super::propagation::query_resolver;
use super::resolvers::resolve_specs;
use crate::config::DnsBenchmarkSettings;
use crate::control::ProbeHandle;
use crate::model::{
    DnsBenchmarkReport, DnsBenchmarkRow, DnsResolverSpec, DnsRunProgress, ProbeEvent,
};

pub const MAX_RESOLVERS: usize = 20;
pub const MAX_SAMPLES: usize = 20;
pub const MAX_CONCURRENCY: usize = 4;
pub const MIN_INTERVAL_MS: u64 = 100;

/// Run a benchmark and stream progress plus the final report.
pub async fn run_benchmark(handle: &ProbeHandle<ProbeEvent>, settings: &DnsBenchmarkSettings) {
    let result = tokio::select! {
        result = benchmark_inner(handle, settings) => Some(result),
        _ = handle.cancelled() => None,
    };
    match result {
        Some(Ok(report)) => handle.send(ProbeEvent::DnsBenchmark(Box::new(report))),
        Some(Err(message)) => handle.send(ProbeEvent::Error {
            message,
            hint: None,
        }),
        None => {}
    }
    handle.send(ProbeEvent::Finished);
}

async fn benchmark_inner(
    handle: &ProbeHandle<ProbeEvent>,
    settings: &DnsBenchmarkSettings,
) -> Result<DnsBenchmarkReport, String> {
    let rtype = parse_record_type(&settings.record_type)?;
    let name = parse_name(&settings.target, rtype)?;
    let mut specs = resolve_specs(settings.protocol, &settings.resolvers, &settings.custom)?;
    if specs.len() > MAX_RESOLVERS {
        specs.truncate(MAX_RESOLVERS);
    }
    let samples = settings.samples.clamp(1, MAX_SAMPLES);
    let concurrency = settings.concurrency.clamp(1, MAX_CONCURRENCY);
    let interval = Duration::from_millis(settings.interval_ms.max(MIN_INTERVAL_MS));
    let timeout = Duration::from_millis(settings.timeout_ms.clamp(100, 120_000));
    let total_resolvers = specs.len();
    let total_samples = total_resolvers.saturating_mul(samples);
    let completed = Arc::new(AtomicUsize::new(0));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();
    handle.send(ProbeEvent::DnsProgress(DnsRunProgress {
        done: 0,
        total: total_samples,
        current: "warming up".to_string(),
    }));

    for spec in specs {
        let name = name.clone();
        let semaphore = semaphore.clone();
        let handle = handle.clone();
        let completed = completed.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            benchmark_resolver(
                spec,
                name,
                rtype,
                samples,
                interval,
                timeout,
                handle,
                completed,
                total_samples,
            )
            .await
        });
    }

    let mut rows = Vec::with_capacity(total_resolvers);
    while let Some(joined) = tasks.join_next().await {
        let row = match joined {
            Ok(row) => row,
            Err(error) => DnsBenchmarkRow {
                resolver: DnsResolverSpec::new("task", settings.protocol, ""),
                error: Some(format!("benchmark task failed: {error}")),
                ..DnsBenchmarkRow::default()
            },
        };
        rows.push(row);
    }

    rows.sort_by(|a, b| match (a.success == 0, b.success == 0) {
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        _ => a
            .avg_ms
            .partial_cmp(&b.avg_ms)
            .unwrap_or(std::cmp::Ordering::Equal),
    });
    Ok(DnsBenchmarkReport {
        target: name.to_utf8(),
        record_type: rtype.to_string(),
        protocol: settings.protocol,
        samples,
        rows,
    })
}

#[allow(clippy::too_many_arguments)]
async fn benchmark_resolver(
    spec: DnsResolverSpec,
    name: hickory_proto::rr::Name,
    rtype: hickory_proto::rr::RecordType,
    samples: usize,
    interval: Duration,
    timeout: Duration,
    handle: ProbeHandle<ProbeEvent>,
    completed: Arc<AtomicUsize>,
    total_samples: usize,
) -> DnsBenchmarkRow {
    let mut row = DnsBenchmarkRow {
        resolver: spec.clone(),
        ..DnsBenchmarkRow::default()
    };

    // Warm up connection setup and resolver caches before measuring.
    let _ = query_resolver(spec.clone(), name.clone(), rtype, timeout).await;

    let mut elapsed = Vec::with_capacity(samples);
    let mut ttls = Vec::with_capacity(samples);
    for index in 0..samples {
        if index > 0 {
            tokio::time::sleep(interval).await;
        }
        let result = query_resolver(spec.clone(), name.clone(), rtype, timeout).await;
        match result.error {
            Some(error) => {
                row.failure += 1;
                row.error = Some(error);
            }
            None => {
                row.success += 1;
                elapsed.push(result.elapsed_ms as f64);
                if let Some(ttl) = result.avg_ttl {
                    ttls.push(ttl as f64);
                }
            }
        }
        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
        handle.send(ProbeEvent::DnsProgress(DnsRunProgress {
            done: done.min(total_samples),
            total: total_samples,
            current: format!("{} ({}/{})", spec.label, index + 1, samples),
        }));
    }

    if !elapsed.is_empty() {
        let stats = latency_stats(&elapsed);
        row.min_ms = stats.min;
        row.avg_ms = stats.avg;
        row.p50_ms = stats.p50;
        row.p95_ms = stats.p95;
        row.max_ms = stats.max;
        row.stddev_ms = stats.stddev;
    }
    if !ttls.is_empty() {
        row.avg_ttl = Some(ttls.iter().sum::<f64>() / ttls.len() as f64);
    }
    row
}

/// Latency statistics for one resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct LatencyStats {
    pub min: f64,
    pub avg: f64,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
    pub stddev: f64,
}

/// Compute min/avg/percentiles/stddev from successful samples.
pub fn latency_stats(values: &[f64]) -> LatencyStats {
    if values.is_empty() {
        return LatencyStats::default();
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let sum: f64 = sorted.iter().sum();
    let avg = sum / sorted.len() as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - avg).powi(2))
        .sum::<f64>()
        / sorted.len() as f64;
    LatencyStats {
        min: sorted[0],
        avg,
        p50: percentile(&sorted, 0.50),
        p95: percentile(&sorted, 0.95),
        max: *sorted.last().unwrap_or(&0.0),
        stddev: variance.sqrt(),
    }
}

/// Nearest-rank percentile over an already sorted slice.
fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (fraction * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_handles_known_samples() {
        let stats = latency_stats(&[10.0, 20.0, 30.0, 40.0]);
        assert_eq!(stats.min, 10.0);
        assert_eq!(stats.max, 40.0);
        assert_eq!(stats.avg, 25.0);
        assert_eq!(stats.p50, 20.0);
        assert_eq!(stats.p95, 40.0);
        assert_eq!(stats.stddev, 11.180339887498949);
    }

    #[test]
    fn latency_stats_are_empty_for_no_samples() {
        let stats = latency_stats(&[]);
        assert_eq!(stats.min, 0.0);
        assert_eq!(stats.p95, 0.0);
    }

    #[test]
    fn limits_are_fixed() {
        assert_eq!(MAX_SAMPLES, 20);
        assert_eq!(MAX_CONCURRENCY, 4);
        assert_eq!(MIN_INTERVAL_MS, 100);
    }
}
