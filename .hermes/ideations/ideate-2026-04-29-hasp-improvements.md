# Ideation: hasp
_Unified secret-store library + CLI with 10 feature-gated backends, trait-object dispatch, and optional TTL memoization._
_Generated: 2026-04-29 | Prior ideation: .hermes/ideations/ideate-2026-04-29-hasp-deltas.md, .hermes/ideations/ideate-2026-04-28-rust-secrets-unified.md_

## Refactoring

### Collapse `StoreBuilder::build()` feature-gate churn into a registry table
- **Where:** `crates/hasp/src/lib.rs` lines 230-257 (`StoreBuilder::build`)
- **What:** Adding a default backend requires 3 lines: a `#[cfg(feature = "...")]` block, a `store.register(...)` call, and a constructor call in the `Backend` enum. A registry table (e.g. `phf` map or `LazyLock<HashMap>`) mapping scheme strings to `fn() -> Backend` constructors would let each backend crate self-register via a `#[link_section]` or `inventory` submit, reducing `build()` to a loop.
- **Why it fits:** The `Backend::custom` constructor already proves runtime registration works; built-in backends are the only hard-coded remaining dispatch site. Closing the gap makes built-in and custom backends symmetric.
- **Effort:** M

### Merge `Backend` newtype into `Arc<dyn hasp_core::Backend>` directly
- **Where:** `crates/hasp/src/lib.rs` lines 75-171 — `pub struct Backend(Arc<dyn hasp_core::Backend>)` delegates every method.
- **What:** The `Backend` newtype's only value is feature-gated constructors (`env()`, `file()`, `op()`, etc.). Move these onto a `BackendExt` trait implemented for `Arc<dyn hasp_core::Backend>`, or make `Backend` implement `Deref<Target = dyn hasp_core::Backend>`. Every consumer site that calls `backend.get(url)` through the newtype pays for indirection with no added behaviour.
- **Why it fits:** `hasp_core::Backend` is the real contract; the wrapper is pure boilerplate. Removing it aligns with the greenfield rip-and-replace policy (LD-011).
- **Effort:** S

## Documentation

### Every backend crate lacks a README
- **Where:** `crates/hasp-backend-*/Cargo.toml` (10 backend crates), `crates/hasp/Cargo.toml`
- **What:** No per-crate README exists. A visitor on crates.io or GitHub sees only the workspace root README. Each backend crate should carry a 10-line README showing the URL grammar, feature flag name, and a one-line `cargo add` example.
- **Why it fits:** The root README lists all backends but provides no per-crate entry point. Backend consumers need to know the exact feature name and URL shape without opening source.
- **Effort:** XS

### CI does not verify mdbook links
- **Where:** `.github/workflows/ci.yml` (mdbook build step), `docs/src/SUMMARY.md`
- **What:** CI builds the mdbook but never runs `mdbook-linkcheck` or `lychee`. Broken internal links (e.g. `getting-started/concepts.md` moved to `key-concepts.md`) only surface when a human reads the rendered book.
- **Why it fits:** The docs are user-facing; link rot is a silent quality drain. CI already installs mdbook — adding linkcheck is marginal cost.
- **Effort:** XS

## Scope gaps

### `Store::list` doc comment overstates capability
- **Where:** `crates/hasp/src/lib.rs` lines 388-393
- **What:** The doc states "For backends that support prefix filtering (all backends)...". In reality `env://`, `file://`, `keyring://`, `op://`, and `bw://` return `UnsupportedOperation { operation: "list" }`. This contradicts the public contract.
- **Why it fits:** A scope gap between documentation and implementation. Either the comment must narrow to "backends that support listing" or `list` must be implemented for the remainder.
- **Effort:** XS

### No dynamic backend registration beyond compile-time features
- **Where:** `crates/hasp/src/lib.rs` lines 313-316 (`Store::register`), lines 230-257 (`StoreBuilder::build`)
- **What:** `Store::register(backend)` accepts a `Backend` (the newtype), but there is no `Store::register_by_scheme(&mut self, scheme: &str, factory: fn() -> Arc<dyn hasp_core::Backend>)`. Users cannot inject a backend at runtime without recompilation.
- **Why it fit:** `Backend::custom` hints at runtime extensibility, but the `Store` API never exposes string-keyed registration. Closing the gap completes the trait-object architecture.
- **Effort:** M

## Feature enrichment

### `RetryBackend` decorator using existing `is_transient()` taxonomy
- **Where:** `crates/hasp-core/src/error.rs` lines 75-89 (`Error::is_transient`), `crates/hasp/src/lib.rs` (`Store`)
- **What:** `BackendFailureKind::{Transient, Throttled}` exist and `Error::is_transient()` classifies them, but no retry logic consumes it. A `RetryBackend<B: Backend>` wrapper in `hasp-core` (or `hasp`) would retry on transient errors with exponential backoff + jitter, parsing `Retry-After` when `kind == Throttled`.
- **Why it fits:** The error taxonomy already classifies retryability; a decorator needs no backend contract changes and gives `StoreBuilder::retries(n)` for free.
- **Effort:** M

### Bulk fetch / store conveniences
- **Where:** `crates/hasp/src/lib.rs` lines 328-491 (no batch methods)
- **What:** `Store` exposes single-item `get`/`put`/`exists`. Add `batch_get(urls: &[&str]) -> Vec<Result<SecretString, Error>>` and `bulk_put(items: &[(&str, &SecretString)]) -> Vec<Result<(), Error>>` that de-duplicate cache hits, dispatch per-backend, and collect per-item errors without short-circuiting.
- **Why it fits:** Multi-secret pipelines (the stated consumer pattern) currently loop manually. A bounded cache + batch dispatch is the natural sibling to the TTL memoization already in `get`/`put`/`exists`.
- **Effort:** M

### SOCKS5 proxy support
- **Where:** `crates/hasp-core/src/proxy.rs` (rejects `socks5://` with "must be http:// or https://"), `crates/hasp-backend-vault/src/lib.rs`, `crates/hasp-backend-gcp-sm/src/lib.rs`, `crates/hasp-backend-azure-kv/src/lib.rs`
- **What:** `reqwest` supports SOCKS5 natively via its `socks` feature. `ProxyConfig::parse` and `build_client` artificially restrict the scheme. Lift the restriction and gate SOCKS5 behind a `socks5-proxy` Cargo feature in the HTTP-backed crates.
- **Why it fits:** `proxy.rs` already stores `scheme: String`; the HTTP client builders already use `reqwest`. A scheme check removal + feature gate is minimal surface change.
- **Effort:** XS

## Quality

### Property-based URL parsing tests
- **Where:** `crates/hasp-backend-env/src/lib.rs`, `crates/hasp-backend-file/src/lib.rs`, `crates/hasp-backend-vault/src/lib.rs`, etc. (sparse `#[cfg(test)]` blocks)
- **What:** Add `proptest` as a workspace dev-dependency and create `crates/hasp/tests/url_parsing.rs`. Generate valid and malformed URLs per scheme; assert parsers return `Ok` or `Error::InvalidUrl` without panics, and ensure secret values never appear in error messages.
- **Why it fits:** No property or fuzz tests exist. URL parsing is the primary attack surface; this hardens it mechanically.
- **Effort:** M

### Feature-gated CI matrix for disabled-backend paths
- **Where:** `.github/workflows/ci.yml` (`cargo test --all-features`), `crates/hasp/tests/integration.rs` (`#[cfg(not(feature = "file"))]`, etc.)
- **What:** CI only runs `--all-features`, so `#[cfg(not(feature))]` paths are compiled out. Add matrix jobs for `cargo test` (default features only) and `cargo test --no-default-features --features env,file,keyring` so disabled-backend paths run in CI.
- **Why it fits:** The integration tests explicitly verify `UnknownScheme` when features are off, but CI never builds them. This is a coverage hole.
- **Effort:** XS

## DX / UX

### `--explain` / `--dry-run` preview for destructive commands
- **Where:** `crates/hasp-cli/src/main.rs` lines 106-167 (direct store dispatch), `run()` function
- **What:** Destructive commands (`delete`, `put`) give no preview. A global `--explain` flag (or per-command `--dry-run`) resolves the URL, prints the chosen backend scheme, proxy decision, and cache state, then exits 0 without mutating.
- **Why it fits:** The CLI already resolves addresses and proxies; a preview layer is a thin conditional early-return. This is symmetric to the planned `--explain` for the sibling `clinker` pipeline.
- **Effort:** S

### `hasp config init` interactive wizard
- **Where:** `crates/hasp-cli/src/profiles.rs` (`load_profiles` returns empty when missing), `docs/src/quickstart.md` (manual `mkdir` + heredoc)
- **What:** A `ConfigInit` subcommand that creates the platform config dir, writes a commented `profiles.toml` template, and optionally prompts for the first alias via `rpassword`-style TTY interaction.
- **Why it fits:** The quickstart documents manual steps; a CLI wizard removes the "empty file, cryptic error" first-run experience.
- **Effort:** M

## Hygiene

### `deny.toml` missing despite policy mention
- **Where:** Workspace root (no `deny.toml`), `CLAUDE.md` ("`cargo deny check` at pre-commit enforces...")
- **What:** Create a workspace `deny.toml` with `unmaintained`, `yanked`, and `bans` sections so `cargo deny check` (already in CI) has a policy to enforce. Add a CI step if missing.
- **Why it fits:** The policy requires verification but the tool config is missing. This closes the loop between rule and enforcement.
- **Effort:** XS

### Pin toolchain with `rust-toolchain.toml`
- **Where:** Workspace root (no `rust-toolchain.toml`); `Cargo.toml` declares `edition = "2021"`.
- **What:** Add a `rust-toolchain.toml` pinning `channel = "stable"` so CI and local builds use the same compiler. Edition alone does not guarantee `cargo` version.
- **Why it fits:** Standard Rust hygiene; the workspace currently lacks toolchain lock.
- **Effort:** XS

## Open questions
- Should `Store::list` skip client-side filtering for backends that natively support prefix queries (SSM, Vault) to avoid redundant work?
- Is the `lancedb/` directory at the repo root a leftover from spall integration, and should it be `.gitignore`-d or removed?

## Out of scope
- **Async `Backend` trait rewrite** — scaffold explicitly locks sync-first; async is a future feature, not a current gap.
- **Auth bootstrap / token rotation** — README lists out of scope.
- **Binary secret values (non-UTF8)** — AWS SM already rejects `SecretBinary`; extending to bytes needs library-level contract change.
- **Keyring `list` enumeration** — `keyring-core` v1 has no portable list API; this is an upstream limitation.
