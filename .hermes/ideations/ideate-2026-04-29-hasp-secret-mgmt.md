# Ideation: hasp secret-management unification
_A unified `get` / `put` / `list` / `delete` / `exists` library and CLI over 11+ secret backends, with trait-object dispatch, TTL memoization, and fake-binary integration tests._
_Generated: 2026-04-29 | Prior ideation: none_

## Refactoring

### Extract `Store` into its own crate
- **Where:** `crates/hasp/src/lib.rs` lines 272-490 — `Store`, `StoreBuilder`, `CacheEntry`, and the `Backend` newtype all live in the facade crate.
- **What:** `hasp` is the user-facing facade crate; `hasp-core` is the contract crate. `Store` is the orchestration logic. It should live in `hasp-core` or a new `hasp-store` crate so that CLI-only consumers don't pull the entire backend ecosystem.
- **Why it fits:** The facade currently owns dispatch, caching, and builder logic — three responsibilities. Splitting `Store` into `hasp-core` lets `hasp-cli` depend only on `hasp-core` instead of `hasp` (which re-exports every backend).
- **Effort:** M

### Merge `Backend` newtype and `BackendTrait` into a single coherent surface
- **Where:** `crates/hasp/src/lib.rs` lines 75-171 — `pub struct Backend(Arc<dyn hasp_core::Backend>)` delegates every method to `self.0`.
- **What:** The `Backend` newtype exists solely to provide feature-gated constructors (`env()`, `file()`, `op()`, etc.). `hasp_core::Backend` is the trait. Consumers call `Backend::env()` which returns `Backend` which deref's to `Arc<dyn hasp_core::Backend>`. This is two layers of indirection for marginal benefit. Move the constructors onto `Arc<dyn hasp_core::Backend>` directly, or make `Backend` implement `Deref<Target = dyn hasp_core::Backend>`.
- **Why it fits:** Reduces boilerplate; every new backend adds one line, not six.
- **Effort:** S

## Documentation

### Every backend crate needs a one-line "URL Grammar" README supplement
- **Where:** `crates/hasp-backend-*/README.md` — each backend README repeats the grammar from the lib.rs doc comment. Only `hasp-backend-bw/README.md` and `hasp-backend-op/README.md` exist; the other 8 backends have no README.
- **What:** Add a 3-line README to each backend crate: grammar, env vars needed, and one usage example. This makes crates.io pages useful.
- **Why it fits:** A backend consumer shouldn't need to open the source to learn the URL format.
- **Effort:** XS (copy from lib.rs doc headers)

### `docs/src/backends.md` is referenced in SUMMARY.md but may be empty or stale
- **Where:** `docs/src/SUMMARY.md` line 14 references `backends.md`. The file was not read during orientation.
- **What:** Verify content exists and covers all 11 backends. If incomplete, document the missing ones.
- **Why it fits:** The mdbook is the primary user docs; a backends reference page is expected.
- **Effort:** S (verification + fill gaps)

## Scope gaps

### `op://` fake-binary tests still fail — argument order mismatch between real backend and fake script
- **Where:** `crates/hasp/tests/integration.rs` lines 265-296 and `crates/hasp-core/src/test_utils.rs` lines 65-113.
- **What:** The real `OpBackend::get` calls `run_op_with_timeout(&["read", "--no-color", &reference], ...)` (3 args starting with "read"). The fake script checks `if [ "$1" = "read" ] && [ "$2" = "--no-color" ]` then uses `$3` for the ref. But the test failures show "unexpected op read: op://<redacted>" — meaning `$3` is receiving the full reference and matching the `*)` fallback. The fake script's case statement uses `op://test-vault/test-item/field1)` without quoting — the `)` is part of the pattern, but the reference string contains `op://...` without trailing `)`.
- **Why it fits:** Fake binaries must match the real CLI contract exactly or tests are noise.
- **Effort:** XS (fix the case pattern)

### `bw://` fake-binary tests fail on `NotFound` mapping
- **Where:** `crates/hasp/tests/integration.rs` lines 698-705; `crates/hasp-backend-bw/src/lib.rs` lines 247-282 `get_item_envelope`.
- **What:** The fake `bw` script for "missing-item" echoes "not found" to stderr and exits 1. `get_item_envelope` parses `--response` JSON. On failure it calls `map_bw_response_error`. The `bw_not_found` test expects `Error::NotFound` but apparently gets something else.
- **Why it fits:** Integration tests must assert correct error taxonomy.
- **Effort:** XS

## Feature enrichment

### `Store::list` memoization is explicitly excluded from caching
- **Where:** `crates/hasp/src/lib.rs` lines 386-397 — comments say `list` is not memoized because results change frequently.
- **What:** Add a `list_cache` with a separate, shorter TTL (e.g., 5s) for `list` results. The comment already rationalizes omitting it; implementing it would match the ambition of a fully memoized store.
- **Why it fits:** Natural extension of the TTL cache pattern already in `get`/`put`/`exists`.
- **Effort:** S

### `exists` should leverage `get` cache when a fresh entry exists
- **Where:** `crates/hasp/src/lib.rs` lines 414-438.
- **What:** `exists` currently always hits the backend. If the URL has a fresh cached `get` entry, `exists` can return `true` without spawning a subprocess or HTTP call.
- **Why it fits:** A `get` cache hit implies existence; `exists` should be free in that case.
- **Effort:** XS (3 lines in `exists`)

## New features (scope-aligned)

### Request chaining / pipelining for `Store`
- **Where:** `crates/hasp/src/lib.rs` — `Store` is request-scoped; no batch API exists.
- **What:** A `store.get_multi(&[&str]) -> Vec<Result<SecretString, Error>>` method that dispatches in parallel via `rayon` or `std::thread::scope`. This fits the project ambition (unified over many backends) and is a common CLI need (`hasp get a b c`).
- **Why it fits:** `ferrule` sibling has batch fetch semantics; `hasp` should too.
- **Effort:** M

### `hasp-cli` shell alias expansion
- **Where:** `crates/hasp-cli/src/profiles.rs` — aliases are `@profile/key`; no shell alias support.
- **What:** Allow `~/.config/hasp/shell-aliases.toml` mapping `gp` -> `get @prod/db-password` so users can define short commands.
- **Why it fits:** Profiles already collapsed common URLs; shell aliases are the next UX layer.
- **Effort:** S

## Quality

### `ENV_LOCK` `PoisonError` recovery is `unwrap_or_else` but not documented
- **Where:** `crates/hasp/tests/integration.rs` — every test now uses `ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())`.
- **What:** Add a helper `fn env_lock() -> MutexGuard<'static, ()>` in `test_utils.rs` that encapsulates the poison recovery, so tests read `let _lock = env_lock();`.
- **Why it fits:** Reduces noise; the recovery pattern is correct but duplicated 31 times.
- **Effort:** XS

### No property-based tests for `Store` cache invalidation
- **Where:** `crates/hasp/tests/integration.rs` lines 127-156 — `put_invalidates_cache` uses hand-rolled temp files.
- **What:** Add `proptest` or `quickcheck` tests for TTL boundary conditions (entry expires exactly at TTL, eviction under concurrent write).
- **Why it fits:** The cache is the newest complex state; property tests are the right tool.
- **Effort:** M

## DX / UX

### `hasp-cli` `--backend` flag to override per-command backend selection
- **Where:** `crates/hasp-cli/src/main.rs` — CLI resolves aliases then dispatches to `Store`.
- **What:** `hasp get --backend op secret` forces the `op` backend even if `env://` would match first. Useful for debugging a specific backend.
- **Why it fits:** The CLI is a thin shell over the library; this exposes library capability directly.
- **Effort:** S

### `cargo hasp` subcommand discovery via `cargo-hasp`
- **Where:** No `cargo-hasp` binary exists.
- **What:** A `cargo-hasp` crate so `cargo hasp get @prod/db` works natively in Cargo's plugin namespace.
- **Why it fits:** `cargo` plugin convention reduces friction for Rust developers.
- **Effort:** M

## Hygiene

### `hasp/Cargo.toml` re-exports every backend crate
- **Where:** `crates/hasp/Cargo.toml` — 10 optional backend dependencies.
- **What:** Verify each dependency is actually used in `src/lib.rs`. `gcp-sm` and `azure-kv` backends are re-exported but may not have constructors called in `StoreBuilder::with_defaults`.
- **Why it fits:** Dead dependencies bloat compile times and binary size.
- **Effort:** XS (audit only)

### `docs/internal/research/` has 12 files but no index
- **Where:** `docs/internal/research/` contains 12 `RESEARCH-*.md` files.
- **What:** Add an `INDEX.md` listing each research note with one-line summary and status. Prevents research from becoming a graveyard.
- **Why it fits:** Research is only useful if discoverable.
- **Effort:** XS

## Open questions
- Is `secrecy::SecretString::clone()` sufficient for the cache, or should entries wrap `Arc<SecretString>`? `secrecy` 0.10's `SecretString` is `Clone`; verify once more.
- Does `cargo test --all-features` pass on a clean TMPDIR (not mounted `noexec`)? The fake binaries were moved to `target/` for this, but CI may differ.

## Out of scope
- Rewrite any backend in async — the project deliberately uses sync APIs for simplicity.
- Add secret rotation or generation — explicitly out of scope per README.
- GUI / TUI interface — no evidence of demand; CLI is the intended surface.