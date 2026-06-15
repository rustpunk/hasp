# Performance Notes

## Process Cache

- Area/module: `hasp-core/src/cache.rs`, `hasp/src/lib.rs`, `hasp-cli/src/main.rs`.
- Why sensitive: caches `SecretString` values in process memory to avoid repeated backend calls in one invocation.
- Existing choices: `moka::sync::Cache`, 5-minute default TTL, 1024-entry default capacity, hardening token required, cache disabled in CI and by `HASP_NO_CACHE` or `HASP_CACHE_TTL=0`.
- Avoid: bypassing `HardeningToken`; documenting on-disk persistence as implemented; widening cache keys to include secret material.
- Hooks: `cli_cache.rs`, `hasp` integration cache tests, `audit_no_leak.rs`.
- Confidence: High.
- Evidence: `CachePolicy`, `ProcessCache`, `StoreBuilder::with_cache_policy`, CLI cache policy resolver.

## Backend Calls And Batch Deduplication

- Area/module: `hasp::Store::batch_get`.
- Why sensitive: external secret store calls can be slow or rate-limited.
- Existing choices: identical URLs are deduplicated with a `HashMap`, but calls are sequential.
- Avoid: claiming concurrency; changing output length or per-input error behavior.
- Hooks: `crates/hasp/tests/batch_tests.rs`.
- Confidence: High.
- Evidence: `batch_get` implementation and tests.

## CLI Subprocess Backends

- Area/module: `hasp-backend-op`, `hasp-backend-bw`.
- Why sensitive: `op` and `bw` spawn external processes and may be slow or hang.
- Existing choices: ambient auth preflight, version checks, wall-clock timeouts, separate stdout/stderr reads to avoid pipe deadlock.
- Avoid: unbounded subprocess waits; relying on real CLIs in default tests; logging raw stderr without checking redaction.
- Hooks: fake CLI helpers in `hasp-core/src/test_utils.rs`, backend inline tests, `hasp` integration tests.
- Confidence: High.
- Evidence: timeout constants and fake CLI tests.

## Cloud And Vault HTTP Backends

- Area/module: `hasp-backend-vault`, `hasp-backend-gcp-sm`, `hasp-backend-azure-kv`, AWS backend crates.
- Why sensitive: network latency, pagination, retries, auth, and throttling dominate runtime.
- Existing choices: 10-second blocking HTTP client timeouts for REST backends; `MAX_PAGES = 500` for cloud list operations; retry wrapper for transient/throttled failures; AWS SDK bridges async work through a current-thread runtime.
- Avoid: removing pagination limits; retrying permanent errors; treating live cloud mappings as verified without credentials.
- Hooks: backend inline tests; `notes/TODO-live-error-mapping.md`.
- Confidence: Medium because live cloud behavior was not validated.
- Evidence: `MAX_PAGES`, `map_*_error`, `RetryBackend`, backend constructors.

## File Backend Glob Traversal

- Area/module: `hasp-backend-file`.
- Why sensitive: recursive `**` globbing can traverse large trees and symlink behavior can be security-sensitive.
- Existing choices: shell-style glob support, regular-file entries, symlink traversal controls, returned entries must be gettable.
- Avoid: following symlinks by default; emitting entries that cannot be fetched; broad trimming of secret file content.
- Hooks: `file_backend_tests.rs`, inline file backend tests.
- Confidence: High.
- Evidence: file backend tests and README.

## Audit Emission

- Area/module: `hasp-core/src/audit.rs`, `hasp/src/lib.rs`, `hasp-cli/src/audit_config.rs`.
- Why sensitive: audit runs on secret operation paths and must not leak.
- Existing choices: closed event labels, value-free fields, infallible sinks, no-leak property tests.
- Avoid: adding URL paths, secret-derived fields, runtime-built event labels, or fallible audit behavior.
- Hooks: `crates/hasp-core/tests/audit_no_leak.rs`, `cli_audit.rs`.
- Confidence: High.
- Evidence: `AuditEvent`, `AuditSink`, no-leak tests.

## Retry Backoff

- Area/module: `hasp-core/src/retry.rs`.
- Why sensitive: retry behavior affects latency and backend load.
- Existing choices: retry only transient/throttled backend errors, exponential backoff with deterministic jitter, synchronous sleeps.
- Avoid: retrying non-transient errors; using retry in latency-sensitive call paths without accounting for blocking sleeps.
- Hooks: retry unit tests should be added if behavior changes.
- Confidence: Medium.
- Evidence: `RetryBackend` implementation. Hypothesis: configured `base_delay` may not currently affect actual backoff.

## CI Feature Matrix

- Area/module: `.github/workflows/ci.yml`.
- Why sensitive: all-features builds include cloud and platform backends.
- Existing choices: matrix covers all-features, default-only, minimal backends, and memory-lock.
- Avoid: adding default features without considering CI cost and binary footprint.
- Hooks: CI workflow.
- Confidence: High.
- Evidence: CI matrix.
