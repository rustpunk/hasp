# Plan: hasp retryBackend Integration + Documentation + Hygiene

2026-05-02

## Goal

Close the remaining open loops from the 2026-04-29 ideation batch. Every item in this plan is concrete, scoped, and verifiable.

## Current Context

- Branch: `main` (commit `002e6eb`)
- `RetryBackend` exists in `crates/hasp-core/src/retry.rs` but is not wired into `StoreBuilder` or documented.
- `CHANGELOG.md` stops at `0.1.0-alpha` and omits every feature shipped in commits `72771e9`–`002e6eb`.
- `docs/src/concepts.md` covers `batch_get`/`bulk_put` but never mentions `RetryBackend` or `Store::resolve`.
- Every `hasp-backend-*` crate has zero unit-test directory; only `hasp/tests/` has integration tests.
- Empty `lancedb/` directory exists at repo root (gitignored but present on disk).

## Prior Art Decision: RetryBackend is Opt-In

**Rationale:** Rust ecosystem patterns (reqwest `ClientBuilder::timeout`, rusoto `Region::new`) favor explicit opt-in for behavior that adds latency. Automatic retry would violate the principle of least surprise — a CLI user calling `hasp get` does not expect hidden sleeps on transient failures. The builder will expose `StoreBuilder::with_retry(max_retries, base_delay)` for users who want it; defaults remain unwrapped.

## Step-by-Step Plan

### 1. Wire RetryBackend into StoreBuilder (Refactoring — S)

**What:** Add `StoreBuilder::with_retry(max_retries: u32, base_delay: Duration)` that, when called, wraps every subsequently registered default backend in a `RetryBackend`.

**Files:**
- `crates/hasp/src/lib.rs` — add `retry: Option<(u32, Duration)>` field to `StoreBuilder`; in `build()`, if retry is set, wrap each backend via `RetryBackend::new(inner).max_retries(n).base_delay(d)` before registering.

**API sketch:**
```rust
impl StoreBuilder {
    pub fn with_retry(mut self, max_retries: u32, base_delay: Duration) -> Self {
        self.retry = Some((max_retries, base_delay));
        self
    }
}
```

In `register_default_backends`, wrap each HTTP-backed backend (`aws-sm`, `aws-ssm`, `vault`, `gcp-sm`, `azure-kv`) only when `retry` is `Some`. Local backends (`env`, `file`, `keyring`, `op`, `bw`) never need retry — their failures are not transient.

**Validation:** `cargo check --workspace --all-features` passes. No new tests needed — the decorator is already tested implicitly by `retry.rs` compile success.

---

### 2. Update CHANGELOG.md (Documentation — XS)

**What:** Append an `[Unreleased]` section capturing everything shipped since the last entry.

**Entries to add:**
- `StoreBuilder::with_retry` (after step 1)
- `Store::batch_get`, `Store::bulk_put`
- `Store::resolve` + CLI `--explain`
- `hasp init` config wizard
- SOCKS5 proxy support
- Registry refactor (`register_default_backends`)
- `deny.toml` + `rust-toolchain.toml`
- Workspace dependency consolidation
- CI matrix (`all-features`, `default-only`, `minimal-backends`)
- Per-backend READMEs
- `Backend` newtype removal (type alias to `Arc<dyn Backend>`)
- `tempfile` dev-dependency fix in `hasp-core`
- Proptest URL parsing tests

**Validation:** `cargo build` not needed; markdown lint only.

---

### 3. Document RetryBackend and Store::resolve in mdbook (Documentation — XS)

**What:** Update `docs/src/concepts.md` to include:
- A "Retry Decorator" subsection showing `StoreBuilder::with_retry(3, Duration::from_millis(100))`.
- A "Diagnostics" subsection explaining `Store::resolve` and its use in `--explain`.

Also update `docs/src/cli-reference.md` to document `--explain` output format (URL, Backend, Proxy, Cache, Operation) if not already present.

**Validation:** `mdbook build docs` passes locally.

---

### 4. Add per-backend unit-test stubs (Quality — M)

**What:** Create `tests/` directories inside backend crates for the two simplest backends: `env` and `file`. These do not require ambient credentials, mock binaries, or network access.

**Files:**
- `crates/hasp-backend-env/tests/env_tests.rs`
  - `get_existing_env_var_returns_secret`
  - `get_missing_env_var_returns_not_found`
  - `put_sets_env_var`
  - `delete_unsets_env_var`
  - `exists_returns_true_for_existing_false_for_missing`
- `crates/hasp-backend-file/tests/file_tests.rs`
  - `get_existing_file_returns_contents`
  - `get_missing_file_returns_not_found`
  - `put_writes_file`
  - `delete_removes_file`
  - `exists_checks_file_presence`

Use `tempfile` and `hasp_core::test_utils::EnvGuard` / `ENV_LOCK` as needed. Keep tests hermetic — no shared mutable state between tests.

**Validation:** `cargo test -p hasp-backend-env` and `cargo test -p hasp-backend-file` pass.

**Note:** Do not add tests for `aws-sm`, `gcp-sm`, `azure-kv`, `vault`, `op`, `bw` in this batch — those require mocks, fake binaries, or live credentials and belong in a later plan.

---

### 5. Remove empty `lancedb/` directory (Hygiene — XXS)

**What:** `rm -rf lancedb/`. The directory is empty and already ignored by `.gitignore` (`/lancedb/`). No code references it.

**Validation:** `git status` shows the directory removed from the working tree.

---

## Execution Order

1 → 5 → 2 → 3 → 4

Rationale: Step 1 changes the public API (new builder method), so it should land first. Step 5 is zero-risk cleanup. Steps 2 and 3 are documentation that references the new API, so they follow step 1. Step 4 is the longest but lowest risk — it touches only test files in two backend crates.

## Risks & Tradeoffs

| Risk | Mitigation |
|---|---|
| `with_retry` changes `StoreBuilder` layout, breaking downstream consumers who construct it with struct literal syntax | `StoreBuilder` fields are not `pub`; only builder methods are public API. Safe. |
| Wrapping local backends (`env`, `file`) in `RetryBackend` adds useless sleeps | Only wrap backends whose constructors take `proxy` (HTTP-backed). Document this rule. |
| Per-backend tests duplicate logic already covered in `hasp/tests/integration.rs` | These are *unit* tests — they exercise the backend in isolation without the `Store` dispatch layer. Different coverage surface. |

## Open Questions

- Should `with_retry` accept `impl Into<Option<Duration>>` for `base_delay` to allow `with_retry(3, None)`? No — explicit `Duration` is clearer. Revisit if users complain.
- Should `RetryBackend` implement `Clone` so it can be reused across `StoreBuilder` calls? Not needed — `Arc<dyn Backend>` handles sharing.

## Acceptance Criteria

- `cargo test --workspace --all-features`: all tests green.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: clean.
- `cargo fmt --check`: clean.
- `mdbook build docs`: clean.
- `git status`: `lancedb/` no longer appears.
