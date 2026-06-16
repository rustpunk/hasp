# Architecture

## What This Project Appears To Be

Verified: `hasp` is a Rust 2021 Cargo workspace for a unified secrets library and CLI. Root `README.md` describes a Rust library crate (`hasp`) and CLI binary crate (`hasp-cli`) for URL-addressed keyed secret stores. Root `Cargo.toml` declares `members = ["crates/*"]`.

## Major Subsystems

- `hasp-core`: core contracts, shared errors, audit events, cache, hardening, proxy parsing, retry, field extraction, and test utilities.
- `hasp`: public library facade. It builds `Store`, registers feature-gated default backends, dispatches operations by URL scheme, emits audit events, owns cache integration, and exposes free functions.
- `hasp-cli`: `hasp` binary. It owns `clap` parsing, profiles, profile-allow trust, CLI exit codes, audit sink configuration, cache policy configuration, `run`, completions, and man-page generation.
- `hasp-backend-*`: backend crates implementing `hasp_core::Backend` for environment variables, files, OS keyrings, 1Password CLI, Bitwarden CLI, Vault, AWS Secrets Manager, AWS SSM Parameter Store, GCP Secret Manager, and Azure Key Vault.
- `docs/src`: mdbook user documentation.
- `.github/workflows`: CI and release automation.
- `docs/internal/research` and `notes`: design research, handoffs, and unresolved validation tasks.

## Data And Control Flow

Verified flow for library use:

1. Caller constructs a `Store` via `Store::with_defaults()`, `Store::builder()`, or `Store::with_backends()`.
2. Caller invokes `get`, `put`, `list`, `delete`, `exists`, `copy`, `compare`, batch, or bulk APIs with URL strings.
3. `hasp` parses URLs with `url::Url`, locates a backend by scheme, and calls the `hasp_core::Backend` trait method.
4. Backend crates validate backend-specific URL grammar and map native results into `SecretString`, `Entry`, or `hasp_core::Error`.
5. `Store` emits value-free audit events and invalidates or reads cache where applicable.

Verified flow for CLI use:

1. `hasp-cli` installs process hardening before parsing arguments.
2. CLI parses commands and global flags.
3. CLI loads profiles, enforces profile-allow unless bypassed, resolves aliases and proxy/cache/audit configuration.
4. CLI builds `StoreBuilder::with_defaults()` and delegates backend operations to the library.
5. CLI maps `hasp::Error` to stable exit codes and prints secrets only on explicit stdout paths.

## Important Boundaries

- `hasp-core` must not own CLI, profile, TTY, or config logic. Evidence: `crates/hasp-core/src/lib.rs` says those live in `hasp-cli`.
- Backend crates own URL grammar. `hasp-core::scheme_from_url` only extracts the scheme.
- `hasp` owns feature-gated default backend registration and dispatch.
- `hasp-cli` owns aliases, interactive prompting, profile trust, process exit, and command presentation.
- User docs live in `docs/src`; AI onboarding lives in `doc/ai`.

## Public API Surfaces

- Core trait: `hasp_core::Backend`.
- Core types: `Entry`, `Error`, `BackendFailureKind`, `AuditEvent`, `AuditSink`, `CachePolicy`, `ProcessCache`, `HardeningToken`, `ProxyConfig`, `RetryBackend`, `SecretString`.
- Library facade: `hasp::Store`, `StoreBuilder`, `CopyOptions`, `CopyOutcome`, `IfExists`, `DiffOutcome`, backend constructors, and free functions `get`, `put`, `list`, `delete`, `exists`.
- CLI binary: `hasp` with `get`, `put`, `list`, `delete`, `exists`, `cp`, `diff`, `run`, `init`, `profile`, `cache`, hidden `man`, hidden `complete`.

## Ownership, State, And Concurrency

Verified:

- `hasp::Backend` is `Arc<dyn hasp_core::Backend>`.
- `Backend` requires `Send + Sync`.
- `Store` keeps backends in a `HashMap<&'static str, Backend>`.
- Later backend registration replaces earlier registration for the same scheme.
- The in-process cache stores `Arc<SecretString>` in `moka::sync::Cache`.
- `ProcessCache` construction requires a `HardeningToken`.
- `RetryBackend` sleeps synchronously with `std::thread::sleep`.

Strong inference: the public API is intentionally synchronous even when some backends internally use async SDKs. AWS/GCP/Azure backends bridge async auth or SDK work through current-thread Tokio runtimes or blocking clients.

## Configuration And Resource Loading

Verified:

- Profiles and profile allow-listing are CLI concerns.
- Audit sink configuration uses CLI environment variables and/or TOML config.
- Proxy configuration is represented by `ProxyConfig` and resolved from flags, profiles, and environment.
- `HASP_CACHE_TTL`, `HASP_NO_CACHE`, and `CI` affect CLI cache policy.
- Backend auth is ambient: environment, cloud default credential chains, local tokens, or installed CLIs.

## Error Handling Strategy

Verified:

- `hasp_core::Error` is a flat, non-exhaustive public error enum.
- Backends map native errors into shared variants, including `NotFound`, `PermissionDenied`, `AuthenticationFailed`, `PreconditionFailed`, and `Backend { kind }`.
- `BackendFailureKind::{Transient, Throttled, Permanent}` guides retries.
- CLI maps errors to stable exit codes 0 through 7.
- Audit uses `Error::kind()` classifiers rather than parsing display strings.

## Extension Boundaries

Verified:

- New backends should implement `hasp_core::Backend` in a backend crate and be registered behind a Cargo feature in `hasp`.
- `StoreBuilder::register` supports custom externally supplied backends.
- Backend dependencies should stay optional unless required by core.

## Areas Of Uncertainty

- Existing docs disagree about exact backend operation support.
- Live cloud error mappings are explicitly deferred in `notes/TODO-live-error-mapping.md`.
- `RetryBackend::base_delay()` appears inconsistent with hard-coded backoff behavior; this is recorded as a hypothesis, not a confirmed bug.
- Persistent cache is scaffolded but not implemented as on-disk persistence.
