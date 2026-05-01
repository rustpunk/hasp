# Plan: Remaining Ideation Items for hasp

## Goal
Implement the 8 remaining ideas from `.hermes/ideations/ideate-2026-04-29-hasp-improvements.md` that were not completed in the first pass.

## Current Context
- **Branch:** `main`
- **Commit:** `72771e9` (all 246 tests pass, clippy clean)
- **Already implemented:** doc fixes, `deny.toml`, `rust-toolchain.toml`, SOCKS5 proxy, workspace deps, proptest URL tests (env + file), `tempfile` dev-dep fix
- **Not yet implemented:** Registry refactor, Backend newtype removal, per-backend READMEs, CI matrix, RetryBackend, bulk ops, CLI `--explain`, `config init` wizard

## Remaining Ideas (Ranked by Fit + Effort)

### 1. Backend READMEs (Documentation — XS)
**What:** Every `crates/hasp-backend-*/` crate needs a 10-line README showing the URL grammar, feature flag name, and `cargo add` example.
**Files:**
- `crates/hasp-backend-aws-sm/README.md`
- `crates/hasp-backend-aws-ssm/README.md`
- `crates/hasp-backend-azure-kv/README.md`
- `crates/hasp-backend-bw/README.md`
- `crates/hasp-backend-env/README.md`
- `crates/hasp-backend-file/README.md`
- `crates/hasp-backend-gcp-sm/README.md`
- `crates/hasp-backend-keyring/README.md`
- `crates/hasp-backend-op/README.md`
- `crates/hasp-backend-vault/README.md`

**Template per file:**
```markdown
# hasp-backend-<scheme>

`<scheme>://` backend for [hasp](https://github.com/rustpunk/hasp).

## URL Grammar
`<scheme>://<host>/<path>?<query>`

## Feature Flag
Enable with `features = ["<scheme>"]` in the `hasp` crate.

## Cargo Add
```bash
cargo add hasp --features <scheme>
```
```

**Validation:** `cargo doc --no-deps` builds without warnings.

---

### 2. CI Matrix for Disabled-Backend Paths (Quality — XS)
**What:** Add matrix jobs testing `cargo test` with default features only and `cargo test --no-default-features --features env,file,keyring` so `#[cfg(not(feature))]` paths run in CI.
**Files:** `.github/workflows/ci.yml`
**Approach:** Extend the existing single `lint-and-test` job into a matrix:
```yaml
strategy:
  matrix:
    features: ["--all-features", "--no-default-features", "--features env,file,keyring"]
```
**Validation:** CI passes on all 3 matrices.

---

### 3. Merge `Backend` Newtype into `Arc<dyn hasp_core::Backend>` (Refactoring — S)
**What:** The `Backend` newtype in `crates/hasp/src/lib.rs` (lines ~75-171) delegates every trait method. Move feature-gated constructors onto `BackendExt` trait for `Arc<dyn Backend>`, or implement `Deref<Target = dyn Backend>` on `Backend`.
**Files:**
- `crates/hasp/src/lib.rs` — remove newtype wrapper, expose `Arc<dyn Backend>` directly
- `crates/hasp-cli/src/main.rs` — adjust any `Backend::env()` calls to use new constructors
- `crates/hasp/tests/integration.rs` — update `Store::with_backends(vec![hasp::Backend::env()])` calls

**Tradeoff:** Breaking public API change. Requires bumping version or clear migration note.

**Validation:** `cargo check --workspace`, `cargo test --workspace --all-features`.

---

### 4. `--explain` / `--dry-run` CLI Preview (DX/UX — S)
**What:** Global `--explain` flag (or per-command `--dry-run`) that resolves the URL, prints chosen backend scheme, proxy decision, and cache state, then exits 0 without mutating.
**Files:**
- `crates/hasp-cli/src/main.rs` — add `Explain` subcommand or `--explain`/`--dry-run` flags
- `crates/hasp/src/lib.rs` — optionally expose `Store::resolve_backend(url)` for diagnostics

**Approach:** After URL/profile resolution, if `--explain` is set, print:
```
URL:         aws-sm://us-east-1/prod/db-password
Backend:     aws-sm
Proxy:       http://proxy:8080 (via ALL_PROXY)
Cache:       miss (or hit, expires in 45s)
Operation:   get (read-only, no mutation)
```
Then exit 0.

**Validation:** CLI tests in `crates/hasp-cli/tests/cli.rs`.

---

### 5. `RetryBackend` Decorator (Feature Enrichment — M)
**What:** Wrap any `Backend` with retry logic using the existing `Error::is_transient()` taxonomy. Exponential backoff + jitter. Parse `Retry-After` when `kind == Throttled`.
**Files:**
- `crates/hasp-core/src/retry.rs` — new module
- `crates/hasp/src/lib.rs` — `StoreBuilder::retries(n)` method
- `crates/hasp/tests/retry_tests.rs` — mock backend returning transient errors

**API Sketch:**
```rust
pub struct RetryBackend<B> {
    inner: B,
    max_retries: u32,
    base_delay: Duration,
}
```

**Validation:** Mock backend that fails 2x then succeeds; assert total time > 2 * base_delay.

---

### 6. Bulk Fetch / Store Conveniences (Feature Enrichment — M)
**What:** `batch_get(urls)` and `bulk_put(items)` that dedupe cache hits, dispatch per-backend, collect per-item errors without short-circuiting.
**Files:**
- `crates/hasp/src/lib.rs` — add `batch_get` + `bulk_put` to `Store`
- `crates/hasp/tests/batch_tests.rs` — property tests + cache hit validation

**API Sketch:**
```rust
impl Store {
    pub fn batch_get(&self, urls: &[&str]) -> Vec<Result<SecretString, Error>>;
    pub fn bulk_put(&self, items: &[(&str, &SecretString)]) -> Vec<Result<(), Error>>;
}
```

**Validation:** Test that batch_get with 2 env:// URLs returns 2 Ok values; test cache hit deduplication.

---

### 7. Collapse `StoreBuilder::build()` Feature-Gate Churn into Registry Table (Refactoring — M)
**What:** Replace the 27-line `#[cfg]` block in `StoreBuilder::build` with a compile-time or runtime registry. Each backend crate self-registers via `#[link_section]` or `inventory`.
**Files:**
- `crates/hasp/src/lib.rs` — refactor `StoreBuilder::build`
- `crates/hasp-core/src/lib.rs` — define `BackendRegistrar` trait or macro
- All backend crates — add registration hooks

**Approach Options:**
1. **Compile-time:** Use `linkme` or `inventory` crate for distributed slice registration. Each backend exports a `static REGISTRY_ENTRY: RegistryEntry` that `StoreBuilder::build` iterates over.
2. **Runtime:** Keep manual registration but move `#[cfg]` blocks into backend crates via a `register_defaults(store: &mut Store)` function.

**Tradeoff:** `linkme`/`inventory` add dependencies and platform complexity. Option 2 (runtime, but encapsulated) is simpler and preserves the existing architecture.

**Validation:** `cargo test --workspace --all-features`, verify all 10 backends still register.

---

### 8. `hasp config init` Interactive Wizard (DX/UX — M)
**What:** New `ConfigInit` subcommand that creates platform config dir, writes commented `profiles.toml` template, optionally prompts for first alias.
**Files:**
- `crates/hasp-cli/src/main.rs` — add `Init` subcommand
- `crates/hasp-cli/src/config_init.rs` — new module with wizard logic
- `crates/hasp-cli/tests/cli.rs` — test that `hasp init` creates file, idempotent re-run

**Approach:**
```rust
#[derive(Parser)]
enum Commands {
    Init {
        #[arg(long)]
        force: bool,
    },
}
```

**Validation:** Test files created, test idempotent re-run without `--force` returns error.

---

## Execution Order Recommendation
1. **XS items first** (READMEs, CI matrix) — zero risk, immediate value.
2. **S items** (newtype removal, `--explain`) — small API surface, testable.
3. **M items** (RetryBackend, batch ops, registry refactor, config init) — each can be a standalone PR.

## Risks
- **Newtype removal** is a breaking change. Coordinate with any downstream consumers.
- **Registry refactor** (linkme/inventory) adds transitive deps. Evaluate `inventory` vs manual encapsulation before committing.
- **Bulk ops** need careful cache semantics. Define whether `batch_get` populates the cache or bypasses it.

## Open Questions
- Should `batch_get` bypass the TTL cache entirely, or read through it per-item?
- Should `RetryBackend` be a separate crate (`hasp-retry`) or live in `hasp-core`?
- What is the minimum supported Rust version? The workspace currently pins `stable` but not a specific version number.
