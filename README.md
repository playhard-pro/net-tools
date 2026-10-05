# net-tools

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A cross-platform (Windows / macOS / Linux) desktop network diagnostics tool built
with Rust and egui. Each network feature lives in its own tab, and probes in
different tabs run **simultaneously and independently**.

## Features

| Tab | Description | Probe modes |
|-----|-------------|-------------|
| Ping | Continuous probing with a live chart, loss rate and min/avg/max/jitter | ICMP, UDP |
| MTR | Hop-by-hop routing with loss and avg/best/worst/stdev per hop | ICMP, UDP |
| HTTP Ping | Multi-method requests with per-stage timing (DNS/connect/TLS/TTFB/total) | GET/HEAD/POST/PUT/DELETE/OPTIONS/PATCH |
| Port Scan | TCP connect / SYN half-open / UDP, with banner grabbing | — |

### Common settings

- Target (host name or IP address)
- IPv4 / IPv6 / auto resolution
- Timeout
- Probe interval
- Packet size
- PTR reverse lookup (whether to resolve the domain name for an IP)

Every feature provides **Start / Pause / Stop** controls. Pausing stops issuing
new probes while keeping existing results; resuming continues.

### Other

- Bilingual UI (English / Chinese), extensible: adding a language is just a new
  YAML file under `locales/`.
- **Bundled CJK font** (WenQuanYi Micro Hei, Apache-2.0), so Chinese and other
  CJK text renders without any system font installation — see `assets/fonts/`.
- Results can be **copied** and **exported** (CSV / JSON / HTML).
- Table columns auto-size to fit the latest content.
- Configuration is saved to the platform config directory and restored on the
  next launch.

## Build and run

```bash
# Install Rust (rustup): https://rustup.rs
cargo run --release -p net-tools
```

### Linux runtime dependencies

On Linux, egui (glow backend) needs X11/Wayland and OpenGL client libraries, for
example on Debian/Ubuntu:

```bash
sudo apt-get install -y libxkbcommon0 libxkbcommon-x11-0 libxcursor1 libxi6 \
  libxrandr2 libxfixes3 libxinerama1 libwayland-client0 libgl1 libegl1 xkb-data
```

On WSL2, install the same packages if they are missing. Windows and macOS need no
extra dependencies.

## Privileges (unprivileged, best effort)

The tool tries to run unprivileged. Capabilities that require a raw socket (raw
ICMP, SYN scan, UDP MTR) show a clear message with guidance when unavailable:

| Platform | Available unprivileged | Requires privileges |
|----------|------------------------|---------------------|
| Linux | ICMP ping (ping socket), UDP ping, TCP connect scan | ICMP MTR, SYN scan, UDP MTR |
| macOS | UDP ping, TCP connect scan | ICMP, MTR, SYN |
| Windows | ICMP ping (system API) | SYN scan, UDP MTR |

### Granting privileges

- **Linux**: prefer granting only the raw-socket capability instead of running as
  root:

  ```bash
  sudo setcap cap_net_raw+ep "$(readlink -f "$(which net-tools)")"
  ```

  or simply `sudo ./net-tools`.
- **macOS**: `sudo ./net-tools`.
- **Windows**: right-click and choose "Run as administrator".

The status bar at the top shows "raw socket: OK / limited"; when limited it
offers a one-click copy of the authorization command.

## Packaging installers

Using [cargo-packager](https://github.com/crabnebula-dev/cargo-packager):

```bash
cargo install cargo-packager --locked
cargo build --release
# Linux
cargo packager -c packager.toml -f deb,appimage   # needs patchelf squashfs-tools file
# Windows
cargo packager -c packager.toml -f wix,nsis
# macOS
cargo packager -c packager.toml -f app,dmg
```

Artifacts are written to `dist/`.

## CI and releases

- `.github/workflows/ci.yml`: build, test, clippy and format checks on
  ubuntu / windows / macos.
- `.github/workflows/release.yml`: on a `v*` tag, build installers on native
  runners and publish them to a GitHub Release.

> Cross-platform builds run on each platform's own CI runner. Local cross
> compilation from Linux to Windows/macOS requires extra toolchains, so no local
> cross step is provided.

## Project layout

```
crates/core    # probing engines and config models (no UI), independently testable
crates/app     # egui desktop application
locales/       # i18n locale files (en / zh-CN, extensible)
assets/        # icons and the bundled font (assets/fonts/)
packager.toml  # cargo-packager configuration
.github/       # CI / release workflows
```

## Testing

```bash
cargo test --workspace
```

The probe engines have loopback-based integration tests (ICMP/UDP ping, MTR,
HTTP, port scanning). SYN scan and UDP MTR require a raw socket, so those tests
are skipped automatically when privileges are missing.

Dependency, license and advisory checks are configured with
[cargo-deny](https://embarkstudios.github.io/cargo-deny/) (`deny.toml`):

```bash
cargo install cargo-deny --locked
cargo deny check
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, coding conventions and pull request checklist.

## Third-party licenses

- **WenQuanYi Micro Hei** (`assets/fonts/wqy-microhei.ttc`) — Apache License 2.0.
  It is dual-licensed "Apache-2.0 OR GPL-3.0-or-later with Font exception"; this
  project redistributes it under Apache-2.0. Attribution is in
  `assets/fonts/LICENSE-wqy-microhei.txt` and the license text in
  `assets/fonts/APACHE-2.0.txt`. Both files are also shipped inside the
  generated installers.

Rust dependencies are licensed under their respective terms (predominantly
MIT / Apache-2.0). A complete, generated list of every dependency and its
license text is in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md), produced
with [cargo-about](https://github.com/EmbarkStudios/cargo-about).

## License

net-tools is released under the MIT License — see [LICENSE](LICENSE). The
bundled font remains under Apache-2.0 as described above.
