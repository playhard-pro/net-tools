#!/usr/bin/env bash
#
# Insert a platform identifier into cargo-packager artifact names.
#
# cargo-packager names its output `{product}_{version}_{arch}.{ext}`, which
# does not tell which operating system a package targets. The Windows archive
# is assembled by package_windows.ps1 and already carries the platform, so this
# script brings the Linux and macOS artifacts in line with that scheme.
#
# Usage:
#     scripts/rename_artifacts.sh <platform> [out_dir]
#
# The platform argument matches the values used in the release workflow matrix
# (for example `linux` or `macos`).

set -euo pipefail

platform="${1:?usage: rename_artifacts.sh <platform> [out_dir]}"
out_dir="${2:-dist}"

# Read the workspace version from Cargo.toml. As in package_windows.ps1, the
# first matching `version = "..."` line belongs to `[workspace.package]`;
# member crates inherit it through `version.workspace = true`.
version="$(grep -m1 -E '^version[[:space:]]*=[[:space:]]*"[^"]+"' Cargo.toml \
    | sed -E 's/^[^"]*"([^"]+)".*/\1/')"
if [[ -z "$version" ]]; then
    echo "could not read the workspace version from Cargo.toml" >&2
    exit 1
fi

prefix="net-tools_${version}_"
for src in "$out_dir/${prefix}"*; do
    [[ -e "$src" ]] || continue

    name="$(basename "$src")"
    remainder="${name#"$prefix"}"

    # Leave files alone that already carry the platform, so the script is safe
    # to run more than once.
    if [[ "$remainder" == "${platform}_"* ]]; then
        continue
    fi

    dest="${out_dir}/${prefix}${platform}_${remainder}"
    mv "$src" "$dest"
    echo "renamed $name -> $(basename "$dest")"
done
