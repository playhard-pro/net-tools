//! Raw DNS query, iterative trace and diagnostic helpers.
//!
//! The module is split by responsibility:
//! - `names`: input parsing and name normalization.
//! - `transport`: wire transport and message exchange.
//! - `query`: single recursive queries and dig-like formatting.
//! - `trace`: iterative resolution from the root servers.

mod benchmark;
mod caa;
mod dkim;
mod dmarc;
mod dnssec;
mod health;
mod names;
mod propagation;
mod query;
mod resolvers;
mod spf;
mod trace;
mod transport;

pub use benchmark::{latency_stats, run_benchmark, LatencyStats};
pub use dkim::COMMON_SELECTORS;
pub use health::run_health;
pub use names::{parse_name, parse_record_type, parse_server, reverse_name, COMMON_RECORD_TYPES};
pub use propagation::run_propagation;
pub use query::run_query;
pub use resolvers::{parse_resolver_line, presets_for, resolve_specs, DnsPreset};
pub use spf::{all_qualifier, parse_record as parse_spf, parse_selectors};
pub use trace::run_trace;

// Shared internals used by the diagnostic submodules. They stay crate-private so
// the public surface remains focused on the entry points above.
pub(crate) use caa::{check_caa, check_caa_with_resolver};
pub(crate) use dnssec::{build_resolver, validate as validate_dnssec};
