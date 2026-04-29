# Ideation: hasp
_Unified secret-store library + CLI with 10 feature-gated backends, trait-object dispatch, and optional memoization._
_Generated: 2026-04-29 | Prior ideation: .hermes/ideations/ideate-2026-04-28-rust-secrets-unified.md_

## Refactoring

### Extract `DeferredTokioRuntime` for the four cloud SDK backends
- **Where:** `crates/hasp-backend-aws-sm/src/lib.rs` lines 102-145, `crates/hasp-backend-aws-ssm/src/lib.rs` lines 102-145, `crates/hasp-backend-gcp-sm/src/lib.rs` lines 81-133, `crates/hasp-backend-azure-kv/src/lib.rs` lines 79-131
- **What:** Each cloud backend duplicates `init: Result<tokio::runtime::Runtime, Error>`, `runtime()`, and `block_on<F>()`, plus identical error mapping into `Error::Backend { kind: Permanent, .. }`. AWS `with_proxy` stubs are no-ops that delegate to `new()`.
- **Why it fits:** `hasp-core` owns the error taxonomy; a shared `DeferredRuntime` wrapper removes ~80 lines of boilerplate across four crates and eliminates the fiction of uniform constructors.
- **Effort:** S

### Unify subprocess timeout/runner logic for `op` and `bw` backends
- **Where:** `crates/hasp-backend-op/src/lib.rs` lines 292-357 (`run_op_with_timeout`), `crates/hasp-backend-bw/src/lib.rs` lines 284-345 (`run_bw_with_timeout`)
- **What:** Both CLI-tool backends contain near-identical ~60-line functions that spawn a subprocess, pipe stdout/stderr, start reader threads, poll `try_wait` against a deadline, kill on timeout, and wrap errors. Only the binary name (`"op"` vs `"bw"`), `scheme` string, and timeout constant differ.
- **Why it fits:** `hasp-core` already provides `test_utils::EnvGuard`; a generic `run_subprocess_with_timeout` helper is the natural next extraction. Centralizing fixes divergence risk (`op` error formatting already drifts from `bw`).
- **Effort:** S

## Documentation

### Add per-crate READMEs with minimal usage examples
- **Where:** `crates/hasp/Cargo.toml`, `crates/hasp-core/Cargo.toml`, `crates/hasp-cli/Cargo.toml`, and each `crates/hasp-backend-*/Cargo.toml`
- **What:** No crate-level `README.md` exists. A visitor browsing the workspace on crates.io or GitHub sees only the root `README.md` (87 lines of high-level description). Each backend crate should expose its URL grammar, feature flag name, and a 5-line example so consumers know what to `cargo add`.
- **Why it fits:** The root README lists all backends but gives no per-crate install snippet. This is the natural sibling to the existing `docs/src/backends.md` user docs.
- **Effort:** XS

### Add mdbook linkcheck enforcement in CI
- **Where:** `.github/workflows/ci.yml` lines 42-43 (`mdbook build docs`)
- **What:** CI builds the mdbook but never validates internal links. Adding `mdbook-linkcheck` (or `lychee`) as a step catches broken SUMMARY.md entries, moved files, and stale cross-references before merge.
- **Why it fits:** The docs are user-facing; broken links only surface when a human reads them. CI already installs mdbook — linkcheck is a marginal add.
- **Effort:** XS

## Scope gaps

### Correct `Store::list` doc comment — "all backends" claim is false
- **Where:** `crates/hasp/src/lib.rs` lines 388-393
- **What:** The doc states "For backends that support prefix filtering (all backends), the path component...". In reality, 5 of 10 backends (`env://`, `file://`, `keyring://`, `op://`, `bw://`) return `UnsupportedOperation { operation: "list" }`. This dangling reference misleads consumers about actual capability.
- **Why it fits:** A scope gap that contradicts the public API contract. Fixing the comment (or adding `list` to all backends) aligns docs with code.
- **Effort:** XS

### Runtime backend registration beyond compile-time features
- **Where:** `crates/hasp/src/lib.rs` lines 230-257 (`StoreBuilder::build`)
- **What:** All backends are wired via `#[cfg(feature = "...")]` at compile time. No dynamic `Store::register("scheme", Backend::custom(...))` or plugin mechanism exists. Users cannot inject backends without recompilation.
- **Why it fits:** The `Backend::custom` constructor hints at runtime extensibility, but `Store` never exposes a string-keyed registry. Closing the gap makes the trait-object architecture fully dynamic.
- **Effort:** M

## Feature enrichment

### `RetryBackend` decorator — make the error taxonomy actionable
- **Where:** `crates/hasp-core/src/error.rs` (`BackendFailureKind::{Transient,Throttled,Permanent}`), `crates/hasp/src/lib.rs` (`Store`)
- **What:** `Error::is_transient()` exists but nothing calls it. A `RetryBackend<B: Backend>` wrapper in `hasp` (or `hasp-core`) would retry on `Transient`/`Throttled` with exponential backoff + jitter, parsing `Retry-After` from `Backend.message` when `kind == Throttled`.
- **Why it fits:** The error taxonomy already classifies retryability. A decorator needs no backend changes and gives `StoreBuilder` a `.retries(n)` method. CLI consumers get resilience for free.
- **Effort:** M

### `Store::batch_get` / `Store::bulk_put` conveniences
- **Where:** `crates/hasp/src/lib.rs` lines 279-491 (no batch methods on `Store`)
- **What:** `Store` exposes single-item `get`/`put`. Add `batch_get(urls: &[&str]) -> Vec<Result<SecretString, Error>>` and `bulk_put(items: &[(&str, &SecretString)]) -> Vec<Result<(), Error>>` that deduplicate cache hits, dispatch per-backend, and collect per-item errors without short-circuiting.
- **Why it fits:** Multi-secret pipelines (the stated consumer pattern) currently loop manually. A bounded cache + batch dispatch is the natural sibling to existing TTL memoization.
- **Effort:** M

### SOCKS5 proxy support via `reqwest/socks` feature
- **Where:** `crates/hasp-core/src/proxy.rs` (rejects `socks5://` with `"must be http:// or https://"`), `crates/hasp-backend-vault/src/lib.rs`, `crates/hasp-backend-gcp-sm/src/lib.rs`, `crates/hasp-backend-azure-kv/src/lib.rs`
- **What:** `reqwest` supports SOCKS5 natively via its `socks` feature. `ProxyConfig::parse` and `build_client` helpers artificially restrict the scheme. Lift the restriction and gate SOCKS5 behind a `socks5-proxy` Cargo feature in the HTTP-backed crates.
- **Why it fits:** `proxy.rs` already stores `scheme: String`; the HTTP client builders already use `reqwest`. A scheme check removal + feature gate is minimal surface change.
- **Effort:** XS

## Quality

### Property-based URL parser tests for every backend
- **Where:** `crates/hasp-backend-env/src/lib.rs`, `crates/hasp-backend-file/src/lib.rs`, `crates/hasp-backend-vault/src/lib.rs`, etc. (sparse `#[cfg(test)]` blocks)
- **What:** Add `proptest` as a workspace dev-dependency and create `crates/hasp/tests/url_parsing.rs`. Generate valid and malformed URLs per scheme; assert parsers return `Ok` or `Error::InvalidUrl` without panics, and ensure secret values never appear in error messages.
- **Why it fits:** No property or fuzz tests exist. URL parsing is the primary attack surface; this hardens it mechanically.
- **Effort:** M

### Feature-gated CI matrix to exercise disabled-backend paths
- **Where:** `.github/workflows/ci.yml` (`cargo test --all-features`), `crates/hasp/tests/integration.rs` (`#[cfg(not(feature = "file"))]`, etc.
- **What:** CI only runs `--all-features`, so `#[cfg(not(feature))]` modules are compiled out. Add matrix jobs for `cargo test` (default features only) and `cargo test --no-default-features --features env,file,keyring` so disabled-backend paths run in CI.
- **Why it fits:** The integration tests explicitly verify `UnknownScheme` when features are off, but CI never builds them. This is a coverage hole.
- **Effort:** XS

## DX / UX

### Global `--explain` / `--dry-run` flag for `hasp` CLI
- **Where:** `crates/hasp-cli/src/main.rs` lines 106-167 (direct store dispatch), `run()` function
- **What:** Destructive commands (`delete`, `put`) give no preview. A global `--explain` flag (or per-command `--dry-run`) resolves the URL, prints the chosen backend scheme, proxy decision, and cache state, then exits 0 without mutating.
- **Why it fits:** The CLI already resolves addresses and proxies; a preview layer is a thin conditional early-return. This is symmetric to the planned `--explain` for the sibling `clinker` pipeline.
- **Effort:** S

### `hasp config init` interactive setup wizard
- **Where:** `crates/hasp-cli/src/profiles.rs` (`load_profiles` returns empty when missing), `docs/src/quickstart.md` (manual `mkdir` + heredoc)
- **What:** A `ConfigInit` subcommand that creates the platform config dir, writes a commented `profiles.toml` template, and optionally prompts for the first alias via `rpassword`-style TTY interaction.
- **Why it fits:** The quickstart documents manual steps; a CLI wizard removes the "empty file, cryptic error" first-run experience.
- **Effort:** M

## Hygiene

### Add `deny.toml` for advisory / unmaintained / yanked enforcement
- **Where:** No `deny.toml` found at workspace root; `CLAUDE.md` states "`cargo deny check` at pre-commit enforces..." but no configuration file exists to drive it.
- **What:** Create a workspace `deny.toml` with `unmaintained`, `yanked`, and `bans` sections so `cargo deny check` (already mentioned in CLAUDE.md) has a policy to enforce. Add it to CI.
- **Why it fits:** The policy requires verification but the tool config is missing. This closes the loop between rule and enforcement.
- **Effort:** XS

### Pin toolchain with `rust-toolchain.toml`
- **Where:** No `rust-toolchain.toml` at workspace root; `Cargo.toml` declares `edition = "2021"`.
- **What:** Add a `rust-toolchain.toml` pinning `channel = "stable"` (or the project's preferred version) so CI and local builds use the same compiler.
- **Why it fits:** The workspace has no toolchain lock; edition alone does not guarantee `cargo` version. This is a standard Rust hygiene practice.
- **Effort:** XS

## Open questions
- Is `lancedb/` at the repo root a leftover from `spall` integration, and should it be `.gitignore`-d or removed?
- Are `op://` and `bw://` backends intentionally read-only, or is `put` support planned? The `Backend` contract is silent on subprocess-backend writes.
- Should `Store::list` skip client-side filtering for backends that natively support prefix queries (SSM, Vault) to avoid redundant work?

## Out of scope
- **Async `Backend` trait rewrite** — scaffold explicitly locks sync-first; async is a future feature, not a current gap.
- **Auth bootstrap / token rotation** — README lists out of scope.
- **Binary secret values (non-UTF8)** — AWS SM already rejects `SecretBinary`; extending to bytes needs library-level contract change.
- **Keyring `list` enumeration** — `keyring-core` v1 has no portable list API; this is an upstream limitation.
