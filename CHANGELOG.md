# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Store::copy(src, dst, CopyOptions)` and the `hasp cp <src> <dst>`
  CLI subcommand for cross-backend secret migration. Defaults
  `if_exists = Fail` (refuses to clobber, opt-in via `--force` /
  `--if-exists=overwrite`), refuses cross-environment copies between
  profiles carrying mismatched `environment` labels without `--yes`,
  refuses to run through a plain-http proxy without
  `HASP_ALLOW_HTTP_PROXY=1`, supports `--verify` (constant-time
  readback compare via `subtle::ConstantTimeEq`), and `--explain`
  acts as dry-run. Emits one-line JSON audit events
  (`cp.start` / `cp.done`) to stderr with no value or length data.
- `hasp-core::hardening` module called at CLI process start. Refuses
  on injection-style env vars (`LD_PRELOAD`, `LD_AUDIT`,
  `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`,
  `DYLD_FALLBACK_*`) and `geteuid() != getuid()`. Applies best-effort
  platform mitigations:
  - Linux: `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)`.
  - macOS: `setrlimit(RLIMIT_CORE, 0)`.
  - Windows: `SetErrorMode(NOGPFAULTERRORBOX | FAILCRITICALERRORS |
    NOOPENFILEERRORBOX)`, `WerAddExcludedApplication`,
    `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)`,
    `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)`,
    `SetDefaultDllDirectories(SEARCH_SYSTEM32)`.
- `environment = "..."` field for profile entries in `profiles.toml`,
  consumed by `hasp cp` for cross-environment refusal.
- `docs/internal/research/RESEARCH-cp-threat-model.md` documenting the
  threat model, mitigations, and deferred hardening work.
- `StoreBuilder::with_retry(max_retries, base_delay)` wrapping HTTP-backed
  default backends (`aws-sm`, `aws-ssm`, `vault`, `gcp-sm`, `azure-kv`) in a
  `RetryBackend` decorator with exponential backoff + jitter for transient
  failures. Local backends (`env`, `file`, `keyring`, `op`, `bw`) are never
  wrapped.
- `Store::batch_get(urls)` and `Store::bulk_put(items)` for multi-secret
  operations with per-item error collection and URL deduplication.
- `Store::resolve(url)` for dry-run diagnostics (scheme, backend name,
  cache hit status) powering the CLI `--explain` flag.
- `hasp init` CLI subcommand generating a commented `profiles.toml` template
  in the platform config directory, with `--force` to overwrite.
- SOCKS5 proxy support alongside HTTP CONNECT in `ProxyConfig`.
- `deny.toml` workspace policy (`cargo deny check`) and `rust-toolchain.toml`
  pinning stable with rustfmt + clippy.
- `[workspace.dependencies]` table consolidating shared crate versions.
- Per-backend `README.md` files documenting URL grammar and feature flags.
- CI matrix testing `--all-features`, `default-only`, and `minimal-backends`
  to prevent `#[cfg]` rot.
- Property-based URL parsing tests (`proptest`) for scheme validation.

### Dependencies

- `subtle = "2.6"` — constant-time comparison for `--verify`.
- `libc` (Unix targets) — `prctl`, `setrlimit`, `geteuid`/`getuid`
  for the hardening module.
- `windows-sys` (Windows targets, feature-gated) — `SetErrorMode`,
  `SetProcessMitigationPolicy`, `WerAddExcludedApplication`,
  `SetDefaultDllDirectories`.

### Changed

- `Backend` newtype removed in favor of `pub type Backend = Arc<dyn hasp_core::Backend>`;
  factory functions (`hasp::env()`, `hasp::file()`, etc.) replace enum
  constructors. Breaking change for `0.1.0-alpha` consumers.
- `StoreBuilder::build()` backend registration extracted into
  `register_default_backends()` helper, reducing inline `#[cfg]` churn.
- `AwsSmBackend` and `AwsSsmBackend` no longer mutate process-wide
  `HTTP(S)_PROXY` env vars; proxy config is passed at construction time.

### Fixed

- `cargo deny check` now enforced in CI with explicit `cargo-deny` 0.19.1
  installation.
- `tempfile` added to `hasp-core` dev-dependencies so `test_utils.rs`
  compiles when `test-utils` feature is disabled.

## [0.1.0-alpha] — 2026-04-27

### Added

- Unified `get` / `put` / `list` / `delete` / `exists` over ten secret backends.
- URL addressing: `env://`, `file://`, `keyring://`, `aws-sm://`, `aws-ssm://`,
  `vault://`, `gcp-sm://`, `azure-kv://`, `op://`, `bw://`.
- Profile aliases via `profiles.toml` (`@profile/key`) with self-key shorthand.
- Feature-gated backends so the default binary stays small and pure-Rust.
- Hidden `complete` subcommand generating AOT shell completions for bash, zsh,
  fish, and PowerShell.
- Dynamic shell completions via `clap_complete::CompleteEnv` completing URL
  schemes, profile aliases, and `file://` paths at tab-press time.
- Full mdbook user guide covering installation, quick start, concepts,
  profile aliases, backends, shell completions, CLI reference, and
  troubleshooting.
- Integration testing suite for CLI features using `env://` and `file://`
  backends only, requiring no ambient credentials.
- CLI global flags `--quiet` / `--verbose` for controlling output noise.
- Hidden `man` subcommand generating ROFF man pages via `clap_mangen`.
- GitHub Actions CI pipeline testing fmt, clippy, tests, docs, and mdbook.
- GitHub Actions release pipeline building and publishing binaries for
  Linux x64, macOS x64, macOS ARM64, and Windows x64.

### Fixed

- `--quiet` now correctly suppresses `--verbose` diagnostic traces.
