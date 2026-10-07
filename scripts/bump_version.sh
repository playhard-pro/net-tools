#!/usr/bin/env bash
#
# Bump the project version everywhere it is declared.
#
# The version lives in the workspace `Cargo.toml` and in the cargo-packager
# `packager.toml`. Member crates inherit the workspace version and the scripts
# read it back from `Cargo.toml`, so those two files are the only ones to
# touch. This script also refreshes `Cargo.lock`.
#
# Usage:
#     scripts/bump_version.sh <version>
#
# The version may be given with or without a leading `v`.

set -euo pipefail

new="${1:?usage: bump_version.sh <version>}"
new="${new#v}"

if [[ ! "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+].+)?$ ]]; then
    echo "invalid version: $new" >&2
    exit 1
fi

# Replace the version only inside the [workspace.package] table, so unrelated
# dependency requirements are left untouched.
awk -v v="$new" '
    /^\[/ { in_section = ($0 == "[workspace.package]") }
    in_section && /^version[[:space:]]*=/ { sub(/=.*/, "= \"" v "\""); in_section = 0 }
    { print }
' Cargo.toml > Cargo.toml.tmp
mv Cargo.toml.tmp Cargo.toml

# Replace the leading version key of the packager configuration.
awk -v v="$new" '
    !done && /^version[[:space:]]*=/ { sub(/=.*/, "= \"" v "\""); done = 1 }
    { print }
' packager.toml > packager.toml.tmp
mv packager.toml.tmp packager.toml

# Refresh the lock file entries for the workspace crates.
cargo update -p net-tools -p net-tools-core

echo "version bumped to $new"
