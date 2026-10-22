#!/usr/bin/env bash
#
# Read the release channel from release.toml and print it on stdout.
#
# The file is intentionally tiny and has a fixed shape, so a shell parser is
# enough and avoids adding a TOML dependency to the release workflow. An
# unknown or missing channel is an error: publishing a release is never a good
# default when the configuration is broken.
#
# Usage:
#     scripts/release_channel.sh [release.toml]

set -euo pipefail

config="${1:-release.toml}"

if [[ ! -f "$config" ]]; then
    echo "release config not found: $config" >&2
    exit 1
fi

channel="$(sed -n -E 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$config" | head -n 1)"

case "$channel" in
    testing|stable)
        printf '%s\n' "$channel"
        ;;
    "")
        echo "missing release.channel in $config" >&2
        exit 1
        ;;
    *)
        echo "invalid release.channel '$channel' in $config (expected testing or stable)" >&2
        exit 1
        ;;
esac
