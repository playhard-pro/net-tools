#!/usr/bin/env bash
#
# Build the macOS application bundle and disk image.
#
# The script always packages the `.app` with cargo-packager and then creates the
# `.dmg` itself. Doing the disk image in a separate step keeps the bundle that
# was verified (and, when credentials are available, notarized) intact.
#
# Signing is optional but strongly recommended:
#
#   APPLE_SIGNING_IDENTITY   "Developer ID Application: ..." identity.
#   APPLE_CERTIFICATE        Base64 encoded `.p12` certificate (CI only).
#   APPLE_CERTIFICATE_PASSWORD  Password of the `.p12` certificate.
#   APPLE_ID / APPLE_PASSWORD / APPLE_TEAM_ID  Apple ID notarization credentials.
#   APPLE_KEYCHAIN_PROFILE   Alternative notarytool keychain profile.
#   APPLE_API_KEY / APPLE_API_ISSUER / APPLE_API_KEY_PATH  API key credentials.
#
# Without an identity the bundle is ad-hoc signed. An ad-hoc signature is still
# a valid signature, so Gatekeeper reports an unidentified developer instead of
# a broken bundle, which lets the user approve the app explicitly.
#
# Usage:
#     scripts/package_macos.sh

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "this script must run on macOS" >&2
    exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# CI secrets that are not configured arrive as empty environment variables.
# cargo-packager treats any present variable as usable credentials, so drop the
# empty ones before it inspects the environment.
for name in \
    APPLE_SIGNING_IDENTITY \
    APPLE_CERTIFICATE \
    APPLE_CERTIFICATE_PASSWORD \
    APPLE_ID \
    APPLE_PASSWORD \
    APPLE_TEAM_ID \
    APPLE_KEYCHAIN_PROFILE \
    APPLE_API_KEY \
    APPLE_API_ISSUER \
    APPLE_API_KEY_PATH; do
    if [[ -z "${!name:-}" ]]; then
        unset "$name"
    fi
done

read_packager_value() {
    sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" \
        packager.toml | head -n 1
}

product_name="$(read_packager_value product_name)"
version="$(read_packager_value version)"
out_dir="$(read_packager_value out_dir)"
: "${product_name:?could not read product_name from packager.toml}"
: "${version:?could not read version from packager.toml}"
: "${out_dir:?could not read out_dir from packager.toml}"

identity="${APPLE_SIGNING_IDENTITY:-}"

# cargo-packager names macOS architecture identifiers differently from uname.
case "$(uname -m)" in
    x86_64) arch="x64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *)
        echo "unsupported macOS architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

config="packager.toml"
if [[ -n "$identity" ]]; then
    # The signing identity is supplied through the environment in CI, while
    # cargo-packager reads it from the configuration file. Generate a temporary
    # configuration so the checked-in file stays identity-agnostic.
    config="$tmp_dir/packager.toml"
    cp packager.toml "$config"
    cat >>"$config" <<EOF

[macos]
signingIdentity = "$identity"
EOF
fi

app_path="$out_dir/$product_name.app"

# Package the bundle. When an identity is configured, cargo-packager signs the
# bundle and notarizes it if Apple credentials are available.
cargo packager -c "$config" -f app

# Without an identity, apply an ad-hoc signature to the whole bundle. Signing
# sidecar binaries is unnecessary here because the bundle contains only the
# main executable, but `--deep` keeps this correct if nested code is added.
if [[ -n "$identity" ]]; then
    echo "verifying Developer ID signature on $app_path"
else
    echo "no Developer ID identity configured; ad-hoc signing $app_path"
    codesign --force --deep --sign - "$app_path"
fi

codesign --verify --deep --strict --verbose=2 "$app_path"

# Assemble a Finder-friendly disk image from the verified bundle. `ditto`
# preserves the bundle metadata that the code signature seals.
staging="$tmp_dir/dmg"
mkdir -p "$staging"
ditto "$app_path" "$staging/$(basename "$app_path")"
ln -s /Applications "$staging/Applications"

mkdir -p "$out_dir"
dmg_path="$out_dir/${product_name}_${version}_${arch}.dmg"
hdiutil create \
    -volname "$product_name" \
    -srcfolder "$staging" \
    -ov \
    -format UDZO \
    "$dmg_path"

# Sign the disk image as well when a Developer ID is available, matching the
# cargo-packager behaviour for the bundle.
if [[ -n "$identity" ]]; then
    codesign --force --sign "$identity" --timestamp "$dmg_path"
fi

echo "wrote $dmg_path"
