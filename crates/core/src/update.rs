//! Update manifest fetching and version comparison.
//!
//! The application reads a small JSON manifest published as a release asset.
//! GitHub resolves `/releases/latest/download/update.json` against the latest
//! stable release, so pre-release testing builds are never advertised here.

use std::cmp::Ordering;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Manifest schema understood by this client. A different schema is rejected
/// instead of being interpreted with potentially wrong field semantics.
const MANIFEST_SCHEMA: u32 = 1;

/// Fixed manifest address. It always follows the latest non-prerelease release.
pub const UPDATE_MANIFEST_URL: &str = concat!(
    env!("CARGO_PKG_REPOSITORY"),
    "/releases/latest/download/update.json"
);

/// Release pages must live under this prefix; the manifest may only point at
/// this project's own GitHub releases.
const RELEASE_URL_PREFIX: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/tag/");

/// Request timeout for the manifest fetch.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on the manifest body accepted from the network.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// User agent sent with update checks. Including the version helps diagnose
/// requests without tracking individual installations.
const USER_AGENT: &str = concat!("net-tools/", env!("CARGO_PKG_VERSION"));

/// Machine-readable release metadata.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub schema: u32,
    pub version: String,
    pub release_url: String,
}

/// Result of comparing the installed version with the published manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStatus {
    UpToDate,
    Available(AvailableUpdate),
}

/// A newer release the user can open on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableUpdate {
    pub version: String,
    pub release_url: String,
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("manifest URL must use HTTPS")]
    InsecureManifestUrl,
    #[error("invalid manifest URL: {0}")]
    InvalidManifestUrl(String),
    #[error("update request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("update server returned HTTP {0}")]
    HttpStatus(u16),
    #[error("invalid update manifest: {0}")]
    InvalidManifest(String),
    #[error("unsupported update manifest schema: {0}")]
    UnsupportedSchema(u32),
    #[error("invalid version: {0}")]
    InvalidVersion(String),
    #[error("manifest release URL does not belong to this project")]
    InvalidReleaseUrl,
}

/// Fetch the manifest and decide whether a newer release exists.
pub async fn check_for_update(
    manifest_url: &str,
    current_version: &str,
) -> Result<UpdateStatus, UpdateError> {
    let url = Url::parse(manifest_url)
        .map_err(|_| UpdateError::InvalidManifestUrl(manifest_url.into()))?;
    if url.scheme() != "https" {
        return Err(UpdateError::InsecureManifestUrl);
    }

    crate::net::ensure_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(UpdateError::HttpStatus(response.status().as_u16()));
    }

    let manifest: UpdateManifest = parse_manifest_body(&response.text().await?)?;
    evaluate_manifest(&manifest, current_version)
}

/// Parse a manifest response body while keeping its size bounded.
fn parse_manifest_body(body: &str) -> Result<UpdateManifest, UpdateError> {
    if body.len() > MAX_MANIFEST_BYTES {
        return Err(UpdateError::InvalidManifest(
            "response body is too large".into(),
        ));
    }
    serde_json::from_str(body).map_err(|err| UpdateError::InvalidManifest(err.to_string()))
}

/// Compare a parsed manifest with the installed version.
pub fn evaluate_manifest(
    manifest: &UpdateManifest,
    current_version: &str,
) -> Result<UpdateStatus, UpdateError> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(UpdateError::UnsupportedSchema(manifest.schema));
    }
    if !is_valid_release_url(&manifest.release_url) {
        return Err(UpdateError::InvalidReleaseUrl);
    }

    let current = parse_version(current_version)?;
    let latest = parse_version(&manifest.version)?;
    if latest > current {
        Ok(UpdateStatus::Available(AvailableUpdate {
            version: manifest.version.clone(),
            release_url: manifest.release_url.clone(),
        }))
    } else {
        Ok(UpdateStatus::UpToDate)
    }
}

/// Only accept HTTPS release pages for this repository.
fn is_valid_release_url(release_url: &str) -> bool {
    let Some(rest) = release_url.strip_prefix(RELEASE_URL_PREFIX) else {
        return false;
    };
    // Require a concrete tag and reject query/fragment tricks in the prefix.
    !rest.is_empty() && !rest.contains(char::is_whitespace)
}

/// A minimal semantic version. Build metadata is ignored and prerelease
/// identifiers follow the usual numeric/lexical ordering rules.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Vec<PrereleaseId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleaseId {
    Numeric(u64),
    Text(String),
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| compare_prerelease(&self.prerelease, &other.prerelease))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(left: &[PrereleaseId], right: &[PrereleaseId]) -> Ordering {
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Ordering::Equal,
        // A release is newer than any prerelease of the same core version.
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (a, b) in left.iter().zip(right) {
                let ordering = match (a, b) {
                    (PrereleaseId::Numeric(a), PrereleaseId::Numeric(b)) => a.cmp(b),
                    (PrereleaseId::Numeric(_), PrereleaseId::Text(_)) => Ordering::Less,
                    (PrereleaseId::Text(_), PrereleaseId::Numeric(_)) => Ordering::Greater,
                    (PrereleaseId::Text(a), PrereleaseId::Text(b)) => a.cmp(b),
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            left.len().cmp(&right.len())
        }
    }
}

fn parse_version(raw: &str) -> Result<Version, UpdateError> {
    let raw = raw.trim();
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    if raw.is_empty() || raw.ends_with('-') || raw.ends_with('+') {
        return Err(UpdateError::InvalidVersion(raw.into()));
    }
    // Build metadata does not affect ordering.
    let without_build =
        raw.split_once('+').map_or(
            raw,
            |(version, build)| {
                if build.is_empty() {
                    ""
                } else {
                    version
                }
            },
        );
    if without_build.is_empty() {
        return Err(UpdateError::InvalidVersion(raw.into()));
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, ""), |(core, pre)| (core, pre));

    let mut parts = core.split('.');
    let major = parse_number(parts.next(), raw)?;
    let minor = parse_number(parts.next(), raw)?;
    let patch = parse_number(parts.next(), raw)?;
    if parts.next().is_some() {
        return Err(UpdateError::InvalidVersion(raw.into()));
    }

    let prerelease = if prerelease.is_empty() {
        Vec::new()
    } else {
        prerelease
            .split('.')
            .map(|part| {
                if part.is_empty() {
                    return Err(UpdateError::InvalidVersion(raw.into()));
                }
                Ok(match part.parse::<u64>() {
                    Ok(number) => PrereleaseId::Numeric(number),
                    Err(_) => PrereleaseId::Text(part.to_string()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    Ok(Version {
        major,
        minor,
        patch,
        prerelease,
    })
}

fn parse_number(part: Option<&str>, raw: &str) -> Result<u64, UpdateError> {
    part.and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| UpdateError::InvalidVersion(raw.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str) -> UpdateManifest {
        UpdateManifest {
            schema: MANIFEST_SCHEMA,
            version: version.into(),
            release_url: format!("{RELEASE_URL_PREFIX}v{version}"),
        }
    }

    #[test]
    fn manifest_and_release_urls_are_absolute() {
        // `CARGO_PKG_REPOSITORY` comes from the package manifest. A missing
        // repository field would turn these into relative paths and break the
        // update check at runtime.
        assert!(UPDATE_MANIFEST_URL.starts_with("https://github.com/"));
        assert!(RELEASE_URL_PREFIX.starts_with("https://github.com/"));
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(parse_version("0.3.10").unwrap() > parse_version("0.3.9").unwrap());
        assert_eq!(
            parse_version("0.3.7").unwrap(),
            parse_version("v0.3.7+build.5").unwrap()
        );
    }

    #[test]
    fn prerelease_ordering_follows_semver_rules() {
        assert!(parse_version("0.3.7-beta.2").unwrap() > parse_version("0.3.7-beta.1").unwrap());
        assert!(parse_version("0.3.7").unwrap() > parse_version("0.3.7-beta.2").unwrap());
        assert!(parse_version("0.3.7-beta").unwrap() > parse_version("0.3.7-1").unwrap());
        assert!(parse_version("0.3.7-alpha").unwrap() < parse_version("0.3.7-alpha.1").unwrap());
    }

    #[test]
    fn invalid_versions_are_rejected() {
        for version in ["", "1", "1.2", "1.2.3.4", "1.2.x", "1.2.3-"] {
            assert!(parse_version(version).is_err(), "{version}");
        }
    }

    #[test]
    fn manifest_reports_newer_release() {
        let status = evaluate_manifest(&manifest("0.3.7"), "0.3.6").unwrap();
        assert_eq!(
            status,
            UpdateStatus::Available(AvailableUpdate {
                version: "0.3.7".into(),
                release_url: format!("{RELEASE_URL_PREFIX}v0.3.7"),
            })
        );
    }

    #[test]
    fn same_or_older_release_is_up_to_date() {
        assert_eq!(
            evaluate_manifest(&manifest("0.3.6"), "0.3.6").unwrap(),
            UpdateStatus::UpToDate
        );
        assert_eq!(
            evaluate_manifest(&manifest("0.3.6"), "0.3.7").unwrap(),
            UpdateStatus::UpToDate
        );
        assert_eq!(
            evaluate_manifest(&manifest("0.3.7"), "0.3.7-beta.1").unwrap(),
            UpdateStatus::Available(AvailableUpdate {
                version: "0.3.7".into(),
                release_url: format!("{RELEASE_URL_PREFIX}v0.3.7"),
            })
        );
    }

    #[test]
    fn manifest_schema_and_release_url_are_validated() {
        let mut wrong_schema = manifest("0.3.7");
        wrong_schema.schema = MANIFEST_SCHEMA + 1;
        assert!(matches!(
            evaluate_manifest(&wrong_schema, "0.3.6"),
            Err(UpdateError::UnsupportedSchema(_))
        ));

        for url in [
            "https://example.com/releases/tag/v0.3.7",
            "http://github.com/playhard-pro/net-tools/releases/tag/v0.3.7",
            "",
        ] {
            let mut bad_url = manifest("0.3.7");
            bad_url.release_url = url.into();
            assert!(
                matches!(
                    evaluate_manifest(&bad_url, "0.3.6"),
                    Err(UpdateError::InvalidReleaseUrl)
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn manifest_url_must_use_https() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime
            .block_on(check_for_update("http://example.com/update.json", "0.3.6"))
            .unwrap_err();
        assert!(matches!(error, UpdateError::InsecureManifestUrl));
    }
}
