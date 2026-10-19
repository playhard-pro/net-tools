//! Summary statistics for latency samples.

/// Summary statistics for a set of latency values in milliseconds.
#[derive(Debug, Clone, Default)]
pub struct LatencyStats {
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub stdev_ms: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
}

impl LatencyStats {
    /// Compute summary statistics from an iterator of latency values.
    pub fn from_values(values: impl IntoIterator<Item = f64>) -> Self {
        let mut values: Vec<f64> = values.into_iter().collect();
        if values.is_empty() {
            return Self::default();
        }

        let sample_count = values.len() as f64;
        let mean = values.iter().sum::<f64>() / sample_count;
        let variance = values
            .iter()
            .map(|value| (value - mean) * (value - mean))
            .sum::<f64>()
            / sample_count;

        values.sort_by(|a, b| a.total_cmp(b));
        Self {
            min_ms: values.first().copied(),
            avg_ms: Some(mean),
            max_ms: values.last().copied(),
            stdev_ms: Some(variance.max(0.0).sqrt()),
            p50_ms: percentile(&values, 0.50),
            p95_ms: percentile(&values, 0.95),
            p99_ms: percentile(&values, 0.99),
        }
    }
}

/// Return a percentile using linear interpolation between the two closest
/// ranks. `fraction` is expected to be in the inclusive range `0.0..=1.0`.
fn percentile(sorted: &[f64], fraction: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }

    let rank = fraction * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        return Some(sorted[lower]);
    }

    let weight = rank - lower as f64;
    Some(sorted[lower] + (sorted[upper] - sorted[lower]) * weight)
}

#[cfg(test)]
mod tests {
    use super::{percentile, LatencyStats};

    #[test]
    fn percentile_interpolates_between_ranks() {
        let values = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile(&values, 0.0), Some(1.0));
        assert_eq!(percentile(&values, 0.5), Some(2.5));
        assert!((percentile(&values, 0.95).unwrap() - 3.85).abs() < 1e-12);
        assert_eq!(percentile(&values, 1.0), Some(4.0));
        assert_eq!(percentile(&[], 0.5), None);
    }

    #[test]
    fn stats_cover_aggregates_and_percentiles() {
        let stats = LatencyStats::from_values([1.0, 2.0, 3.0, 4.0]);
        assert_eq!(stats.min_ms, Some(1.0));
        assert_eq!(stats.max_ms, Some(4.0));
        assert_eq!(stats.avg_ms, Some(2.5));
        assert!((stats.stdev_ms.unwrap() - 1.118_033_988_749_895).abs() < 1e-12);
        assert_eq!(stats.p50_ms, Some(2.5));
        assert!((stats.p95_ms.unwrap() - 3.85).abs() < 1e-12);
        assert!((stats.p99_ms.unwrap() - 3.97).abs() < 1e-12);
    }

    #[test]
    fn stats_are_empty_without_values() {
        let stats = LatencyStats::from_values([]);
        assert!(stats.min_ms.is_none());
        assert!(stats.p99_ms.is_none());
    }
}
