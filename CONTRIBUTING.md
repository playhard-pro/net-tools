# Contributing to net-tools

Thanks for your interest in improving net-tools! This document explains how to
set up the project, run it, and submit changes.

By participating, you agree to keep the discussion respectful and constructive.

## Prerequisites

- **Rust** (stable) via [rustup](https://rustup.rs):
  ```bash
  rustup toolchain install stable
  rustup component add rustfmt clippy
  ```
- **Linux only**: GUI runtime libraries (egui uses the glow/OpenGL backend). On
  Debian/Ubuntu:
  ```bash
  sudo apt-get install -y libxkbcommon0 libxkbcommon-x11-0 libxcursor1 libxi6 \
    libxrandr2 libxfixes3 libxinerama1 libwayland-client0 libgl1 libegl1 xkb-data
  ```
  Windows and macOS need no extra dependencies.

## Getting started

```bash
git clone <your-fork-url>
cd net-tools

cargo build                 # debug build
cargo run -p net-tools      # run the app
cargo build --release       # optimized build
```

## Project layout

```
crates/core    # probing engines and config models (no UI), independently testable
crates/app     # egui desktop application (tabs and widgets)
locales/       # i18n locale files (en / zh-CN, extensible)
assets/        # icons and the bundled CJK font
scripts/       # helper scripts (icon generation)
packager.toml  # cargo-packager configuration
deny.toml      # cargo-deny configuration
```

## Before you open a pull request

Please make sure the following all pass locally:

```bash
cargo fmt --all -- --check      # formatting
cargo clippy --workspace --all-targets   # lints (should be warning-free)
cargo test --workspace          # unit + integration tests

# Dependency, license and advisory checks (install once):
cargo install cargo-deny --locked
cargo deny check
```

### Application icon

`assets/icon.png` is the master icon (an 8-bit RGBA PNG). The Windows `.ico` is
generated from it and committed:

```bash
python3 scripts/generate_icons.py
```

Run this whenever the master icon changes. See the README section
"Application icon" for where each file is used.

### Tests

The probe engines have loopback-based integration tests (ICMP/UDP ping, MTR,
HTTP, port scanning). SYN scan and UDP MTR require a raw socket, so those tests
skip automatically when privileges are missing. Prefer adding focused tests next
to the code you change.

### Third-party license list

`THIRD_PARTY_LICENSES.md` is generated and must be regenerated whenever the
dependency graph changes:

```bash
cargo install cargo-about --locked --features cli
cargo about generate about.md.hbs -o THIRD_PARTY_LICENSES.md
```

## Coding conventions

- **Comments and docs in English.**
- Do not put specific numeric values in comments. Comments should stay correct
  when constants change.
- Prefer the existing crates and helpers over adding new dependencies. Avoid
  adding a dependency for something that can be done simply.
- Do **not** use wildcard dependency requirements (`*`); path dependencies must
  also declare a `version`.
- Keep the per-tab independence guarantee: each tab owns its own
  `TaskController`, cancellation token and channel.
- Run `cargo fmt` before committing.

## Extending the app

### Adding a language

1. Copy `locales/en.yml` to `locales/<locale>.yml` (for example `locales/ja.yml`).
2. Translate the values (keys stay unchanged).
3. That's it — the language appears in the top-bar selector automatically, and
   the choice is persisted.

### Adding a tab

1. Add a module under `crates/app/src/tabs/` and register it in `tabs/mod.rs`.
2. Give it a `TaskController<ProbeEvent>`, plus `start` / `drain` / `ui` methods,
   following the existing tabs.
3. Put the probing logic in `crates/core/src/net/` so it stays testable without a
   UI.
4. Add the tab to the top bar in `crates/app/src/app.rs` and add the needed i18n
   keys.

## Commit messages

- Use short, imperative subjects, e.g. `fix: avoid panic when starting a task`.
- Describe *why* in the body when the change is non-obvious.
- Keep unrelated changes in separate commits.

## Pull requests

- Keep PRs focused; one logical change per PR is easiest to review.
- Describe what changed and how you verified it (commands, environment).
- Link any related issue.
- Make sure CI (build, test, clippy, fmt, `cargo deny`) is green.

## Reporting bugs

Please include:

- Your OS and version (Windows / macOS / Linux distribution).
- How you ran the app (installed package, `cargo run`, elevated or not).
- The exact steps to reproduce.
- Expected vs. actual behavior, and any console output or logs
  (`RUST_LOG=debug` increases verbosity).

## License of contributions

By submitting a contribution you agree that it is licensed under the project's
dual [MIT OR Apache-2.0](README.md#license) terms, and that you have the right
to do so. Bundled third-party assets keep their own licenses (see the README
"Third-party licenses" section).
