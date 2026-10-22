#!/usr/bin/env bash
#
# Generate the update manifest attached to every GitHub release.
#
# The manifest lives at a fixed release asset URL:
#   https://github.com/<owner>/<repo>/releases/latest/download/update.json
#
# GitHub resolves that URL against the latest non-prerelease release, so a
# testing build can carry the asset without ever being advertised to users.
#
# Usage:
#     scripts/generate_update_manifest.sh <tag> [output]
#     GITHUB_REPOSITORY=owner/repo scripts/generate_update_manifest.sh v1.2.3
#
# In GitHub Actions `GITHUB_REPOSITORY` is set automatically. Locally the
# repository is read from the Cargo manifest.

set -euo pipefail

tag="${1:?usage: generate_update_manifest.sh <tag> [output]}"
output="${2:-dist/update.json}"

# The workspace version is the first `version = "..."` line in Cargo.toml;
# member crates inherit it through `version.workspace = true`.
version="$(grep -m1 -E '^version[[:space:]]*=[[:space:]]*"[^"]+"' Cargo.toml \
    | sed -E 's/^[^"]*"([^"]+)".*/\1/')"
if [[ -z "$version" ]]; then
    echo "could not read the workspace version from Cargo.toml" >&2
    exit 1
fi

if [[ "$tag" != "v${version}" ]]; then
    echo "release tag '$tag' does not match workspace version '$version'" >&2
    exit 1
fi

repo="${GITHUB_REPOSITORY:-}"
if [[ -z "$repo" ]]; then
    repo_url="$(grep -m1 -E '^repository[[:space:]]*=[[:space:]]*"[^"]+"' Cargo.toml \
        | sed -E 's/^[^"]*"([^"]+)".*/\1/')"
    repo="${repo_url#https://github.com/}"
    repo="${repo%.git}"
fi
if [[ -z "$repo" || "$repo" == */*/* ]]; then
    echo "could not determine the GitHub repository" >&2
    exit 1
fi

release_url="https://github.com/${repo}/releases/tag/${tag}"

mkdir -p "$(dirname "$output")"
cat >"$output" <<EOF
{
  "schema": 1,
  "version": "${version}",
  "release_url": "${release_url}"
}
EOF

printf 'wrote %s for %s\n' "$output" "$tag" >&2
