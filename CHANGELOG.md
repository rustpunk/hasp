# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `hasp run -e KEY=URL [...] -- <cmd>` subprocess env injection (#2).
  Resolves each `KEY=URL` pair through `Store::get`, exports the
  values as environment variables, and execs the command, preserving
  the child's exit code verbatim. All-or-nothing: a missing secret
  short-circuits before the child is spawned. Duplicate `-e` keys are
  refused at startup. Stdout-is-TTY refusal by default prevents
  accidental echo of injected secrets to scroll buffers; bypass with
  `--allow-tty`. Emits `run.start` / `run.done` audit events.
  Threat note: `/proc/<pid>/environ` is same-uid readable on Linux —
  the fundamental cost of env injection; documented in
  `docs/src/cli-reference.md#run`. PTY masking deferred.
- `hasp_core::audit`: `AuditSink` trait + `AuditEvent` struct (#12).
  Every `Store` verb now emits `*.start` / `*.done` structured
  one-line JSON events to the configured `AuditSink`. Built-in sinks:
  `StderrSink` (default, preserves existing `cp` behavior), `FileSink`
  (append, `0600` on Unix), `NoopSink` (silent). CLI sink is
  configured via `HASP_AUDIT` / `HASP_AUDIT_PATH`. The sink is
  installed at CLI startup via `StoreBuilder::with_audit_sink`.
  Security invariant: `AuditEvent` is `#[non_exhaustive]` with only
  `'static` classifier strings and a timestamp — values, lengths, and
  value-derived material cannot appear in any serialized event (a
  proptest in `crates/hasp-core/tests/audit_no_leak.rs` enforces
  this). `Error::kind() -> &'static str` added for stable audit
  classification, replacing the former CLI-only `error_kind` function.
  Threat-model note (same-uid tamperability) documented in
  `docs/src/cli-reference.md#threat-model`. **Deferred:** the
  `SyslogSink` and `audit.toml` config items from the #12 acceptance
  list. Env-var configuration (`HASP_AUDIT`/`HASP_AUDIT_PATH`)
  covers the common ops use cases; a TOML-backed sink configuration
  and a syslog binding land in a follow-up.
- `file://` `list` with Unix shell glob semantics (#10). The path
  component of a `file://` URL may now contain `*`, `**`, `?`, and
  `[...]` patterns; `hasp list 'file:///etc/secrets/**/*.key'` lists
  all matching regular files. Symlink traversal and dotfile inclusion
  are both off by default; opt in with `?follow_symlinks=1` and
  `?hidden=1`. Only regular files are emitted; every returned entry
  URL is `get`-able. Depends on `glob = "0.3"` (rust-lang/glob, zero
  advisories, MIT OR Apache-2.0).

### Changed

- Audit events for `cp.start` / `cp.done` are now emitted by
  `Store::copy` (library side) rather than the CLI. The wire format
  and field set are identical; the only behavioral difference is that
  library consumers using `StoreBuilder::with_audit_sink` now receive
  `cp` events for free. **Soft behavioral change:** `cp.start` now
  appears after the `--explain` plan lines instead of before (previous
  order was undocumented). Scripts parsing `cp.start` events in order
  relative to the plan lines should be updated.
- All verbs (`get`, `put`, `list`, `delete`, `exists`, `cp`) emit
  `*.start` / `*.done` audit events to stderr by default. **Soft
  breaking change:** scripts that grep stderr will now see new JSON
  lines for verbs other than `cp`. Suppress with `HASP_AUDIT=off`.

### Dependencies

- `glob = "0.3"` — Unix shell glob matching for `file://` list.
  Vetted: rust-lang/glob, zero RustSec advisories, MIT OR Apache-2.0.

- SLSA v1.0 build provenance attestations for every release artifact,
  signed via GitHub OIDC and sigstore. The release workflow now runs
  `actions/attest-build-provenance@v1` per matrix target and publishes
  the `.intoto.jsonl` bundle alongside the binary. Verification
  documented in `docs/src/installation.md` (both `gh attestation
  verify` and `slsa-verifier verify-artifact`). Defends against the
  supply-chain class demonstrated by the Bitwarden CLI 2026.4.0 npm
  compromise.
- `?field=<path>` URL query parameter on `vault://`, `aws-sm://`,
  `gcp-sm://`, and `azure-kv://` extracts a single scalar from a
  JSON-encoded secret payload before the value crosses the
  `SecretString` boundary. Supports flat keys (`password`) and dotted
  nested paths (`.credentials.api_key`). CLI sugar: `hasp get -F
  <path>`. Backed by the new `hasp_core::extract_field` / `extract_field_from_str`
  helpers, which all four backends share so the contract stays uniform.
  Vault's existing flat-field extraction is now backed by the same
  helper and gains dotted-path support.
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

- CLI exit codes are now granular: 0 success, 1 usage/local, 2 not-found,
  3 permission-denied, 4 transport, 5 auth-failed, 6 precondition, 7
  backend (permanent / unexpected response). `hasp exists` preserves the
  0/1 boolean (present/absent), but backend errors during `exists` flow
  through the standard table. **Soft breaking change** for scripts that
  grep on a specific non-zero exit code — every prior failure was code 1;
  now failures fan out into 1–7.
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
