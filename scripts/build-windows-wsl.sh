#!/usr/bin/env bash
#
# Build the Windows executable, MSI installer and portable zip from WSL/Linux,
# without a Windows toolchain installed.
#
# Requirements:
#   - Rust (stable)
#   - cargo-xwin:        cargo install cargo-xwin --locked
#   - clang and lld-link (Debian/Ubuntu: apt install clang lld)
#   - wixl/msitools, or apt-get + dpkg-deb for an automatic local bootstrap
#
# Usage:
#     scripts/build-windows-wsl.sh
#
# Outputs:
#     dist/windows/net-tools_<version>_windows_x64.msi
#     dist/windows/net-tools_<version>_windows_x64.zip
#     dist/windows/*.sha256

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

TARGET=x86_64-pc-windows-msvc
ARCH=x64
VERSION=$(awk '
  /^\[workspace.package\]/ { in_package=1; next }
  /^\[/ { in_package=0 }
  in_package && /^version[[:space:]]*=/ {
    gsub(/.*=[[:space:]]*"/, "");
    gsub(/".*/, "");
    print;
    exit
  }
' Cargo.toml)
if [[ -z "$VERSION" ]]; then
  echo "Could not read the workspace version from Cargo.toml" >&2
  exit 1
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "MSI requires a numeric major.minor.patch version, got '$VERSION'" >&2
  exit 1
fi

DIST="$ROOT/dist/windows"
TOOLS="$ROOT/target/wixl-tools"
EXE="$ROOT/target/$TARGET/release/net-tools.exe"
ICON="$ROOT/assets/icon.ico"
WXS="$ROOT/packaging/windows/net-tools.wxs"
LICENSE_RTF="$ROOT/packaging/windows/License.rtf"
LICENSE_FILE="$ROOT/LICENSE"
THIRD_PARTY_LICENSE="$ROOT/THIRD_PARTY_LICENSES.md"
MSI="$DIST/net-tools_${VERSION}_windows_${ARCH}.msi"
ZIP="$DIST/net-tools_${VERSION}_windows_${ARCH}.zip"

if ! command -v cargo-xwin >/dev/null 2>&1; then
  echo "cargo-xwin is required: cargo install cargo-xwin --locked" >&2
  exit 1
fi
for tool in clang lld-link; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required (install clang/lld)" >&2
    exit 1
  fi
done
for file in "$ICON" "$WXS" "$LICENSE_RTF" "$LICENSE_FILE" "$THIRD_PARTY_LICENSE"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing $file" >&2
    exit 1
  fi
done

# The Rust standard library for the Windows target is needed by cargo-xwin.
if command -v rustup >/dev/null 2>&1; then
  if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "Installing Rust target $TARGET ..."
    rustup target add "$TARGET"
  fi
fi

# Link the MSVC CRT statically so the installed executable does not depend on
# the Visual C++ redistributable being present on the target machine.
export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"

echo "Building net-tools for $TARGET ..."
cargo xwin build --release --locked --target "$TARGET" -p net-tools

if [[ ! -f "$EXE" ]]; then
  echo "Build finished but $EXE was not produced" >&2
  exit 1
fi

# Download one package by trying distribution-specific alternatives. Debian
# and Ubuntu renamed several time_t-sensitive libraries, so the script accepts
# both spellings instead of assuming one distribution's package names.
download_package() {
  local package
  for package in "$@"; do
    if apt-cache show "$package" >/dev/null 2>&1; then
      apt-get download "$package" >/dev/null
      return 0
    fi
  done
  echo "None of these packages are available: $*" >&2
  return 1
}

prepare_wixl() {
  WIXL_LIBDIR=""

  if command -v wixl >/dev/null 2>&1; then
    WIXL=$(command -v wixl)
    WIXL_DATA=$(find /usr/share -maxdepth 1 -type d -name 'wixl-*' | head -n 1)
  elif [[ -x "$TOOLS/usr/bin/wixl" ]]; then
    WIXL="$TOOLS/usr/bin/wixl"
    WIXL_LIBDIR="$TOOLS/usr/lib/x86_64-linux-gnu"
    WIXL_DATA=$(find "$TOOLS/usr/share" -maxdepth 1 -type d -name 'wixl-*' | head -n 1)
  else
    if ! command -v apt-get >/dev/null 2>&1 || ! command -v dpkg-deb >/dev/null 2>&1; then
      echo "wixl is missing and automatic bootstrap requires apt-get + dpkg-deb" >&2
      echo "Install wixl/msitools or run scripts/package_windows.ps1 on Windows." >&2
      exit 1
    fi

    echo "Bootstrapping wixl into $TOOLS ..."
    local downloads
    downloads=$(mktemp -d)
    (
      cd "$downloads"
      download_package wixl
      download_package wixl-data
      download_package libmsi-1.0-0 libmsi-1.0-0t64
      download_package libgcab-1.0-0 libgcab-1.0-0t64
      download_package libgsf-1-114 libgsf-1-114t64
    )

    mkdir -p "$TOOLS"
    local package
    for package in "$downloads"/*.deb; do
      dpkg-deb -x "$package" "$TOOLS"
      rm -f "$package"
    done
    rmdir "$downloads"

    WIXL="$TOOLS/usr/bin/wixl"
    WIXL_LIBDIR="$TOOLS/usr/lib/x86_64-linux-gnu"
    WIXL_DATA=$(find "$TOOLS/usr/share" -maxdepth 1 -type d -name 'wixl-*' | head -n 1)
  fi

  if [[ -z "${WIXL_DATA:-}" ]]; then
    echo "wixl data directory not found" >&2
    exit 1
  fi
}

prepare_wixl
mkdir -p "$DIST"

echo "Building MSI with wixl ..."
if [[ -n "${WIXL_LIBDIR:-}" ]]; then
  export LD_LIBRARY_PATH="$WIXL_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
WIXL_LOG=$(mktemp)
# The wixl UI extension opens License.rtf by its relative name, so run wixl
# from the directory that contains the checked-in license document.
if ! (
  cd "$ROOT/packaging/windows"
  "$WIXL" \
    --ext ui \
    --extdir "$WIXL_DATA/ext" \
    --wxidir "$WIXL_DATA/include" \
    -D "Version=$VERSION" \
    -D "AppPath=$EXE" \
    -D "IconPath=$ICON" \
    -D "LicensePath=$LICENSE_FILE" \
    -D "ThirdPartyLicensePath=$THIRD_PARTY_LICENSE" \
    -a "$ARCH" \
    -o "$MSI" \
    "$WXS"
) >"$WIXL_LOG" 2>&1; then
  cat "$WIXL_LOG" >&2
  rm -f "$WIXL_LOG"
  echo "wixl failed to build the MSI" >&2
  exit 1
fi
cat "$WIXL_LOG"
if grep -qE '(CRITICAL|ERROR) \*\*' "$WIXL_LOG"; then
  rm -f "$WIXL_LOG"
  echo "wixl reported an error; refusing to publish an incomplete MSI" >&2
  exit 1
fi
rm -f "$WIXL_LOG"

echo "Building portable zip ..."
python3 - "$DIST" "$EXE" "$VERSION" "$ROOT" <<'PY'
import sys
import zipfile
from pathlib import Path

dist, exe, version, root = sys.argv[1:]
dist = Path(dist)
root = Path(root)
out = dist / f"net-tools_{version}_windows_x64.zip"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
    archive.write(exe, "net-tools.exe")
    archive.write(root / "README.md", "README.md")
    archive.write(root / "LICENSE", "LICENSE")
    archive.write(root / "THIRD_PARTY_LICENSES.md", "THIRD_PARTY_LICENSES.md")
print(out)
PY

sha256sum "$MSI" > "$MSI.sha256"
sha256sum "$ZIP" > "$ZIP.sha256"

echo "Windows packages written to $DIST"
ls -lh "$DIST"
