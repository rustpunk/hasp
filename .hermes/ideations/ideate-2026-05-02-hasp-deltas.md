# Ideation: hasp
_Unified secret-store library + CLI with 10 feature-gated backends, trait-object dispatch, and optional TTL memoization._
_Generated: 2026-05-02 | Prior ideation: .hermes/ideations/ideate-2026-04-29-hasp-improvements.md_

## Status

**No new deltas.** Every idea from the 2026-04-29 ideation has been implemented in commits `72771e9` through `002e6eb`. The codebase is in a post-fix state.

**Evidence:**
- **Idea 1 (Registry refactor)** — `register_default_backends()` extracted in `crates/hasp/src/lib.rs` lines 223-244; committed `6b1f8a1`.
- **Idea 2 (Backend newtype removal)** — `pub type Backend = Arc<dyn hasp_core::Backend>` live; factory functions `hasp::env()`, `hasp::file()`, etc.; committed `dd8a7dd`.
- **Idea 3 (Per-backend READMEs)** — 11 `README.md` files present across `crates/hasp-backend-*/`; committed `dd8a7dd`.
- **Idea 4 (CI matrix)** — `.github/workflows/ci.yml` runs `--all-features`, `default-only`, and `minimal-backends`; committed `dd8a7dd`.
- **Idea 5 (RetryBackend)** — `crates/hasp-core/src/retry.rs` exists with exponential backoff + jitter; committed `6b1f8a1`.
- **Idea 6 (Bulk fetch/store)** — `Store::batch_get` and `Store::bulk_put` in `crates/hasp/src/lib.rs` lines 494-520+; `batch_tests.rs` covers dedup and failure collection; committed `6b1f8a1`.
- **Idea 7 (SOCKS5 proxy)** — `ProxyConfig::parse` now accepts `socks5://`; committed `72771e9`.
- **Idea 8 (`--explain`)** — `hasp get --explain` prints scheme, backend, proxy, cache state; CLI tests `cli_explain_env`; committed `dd8a7dd`.
- **Idea 9 (`hasp init`)** — `config_init.rs` writes commented `profiles.toml`; `--force` override; CLI tests `cli_init_creates_config_file`; committed `6b1f8a1`.
- **Idea 10 (`deny.toml`)** — workspace policy with license whitelist + advisory ignore; committed `72771e9`.
- **Idea 11 (`rust-toolchain.toml`)** — pins stable with rustfmt + clippy; committed `72771e9`.
- **Idea 12 (Workspace deps)** — `[workspace.dependencies]` table in root `Cargo.toml`; committed `72771e9`.
- **Idea 13 (Proptest URL tests)** — `crates/hasp/tests/url_parsing.rs`; committed `72771e9`.
- **Idea 14 (Backend READMEs)** — already counted above.

## Open questions

- `RetryBackend` is exported from `hasp-core` but not yet wired into `StoreBuilder`. Should `StoreBuilder::retries(n)` wrap every default backend, or should it be an explicit opt-in API (`StoreBuilder::register(RetryBackend::new(inner))`) ?
- Documentation drift detection: mdbook source is updated but CI does not build it (mdbook missing on runner). Should a pre-commit hook run `mdbook build docs` to catch drift before push?

## Out of scope

- **Async `Backend` trait rewrite** — README lists sync-first as deliberate.
- **Auth bootstrap / token rotation** — README lists out of scope.
- **Binary secret values (non-UTF8)** — needs library-level contract change beyond current scope.
- **Keyring `list` enumeration** — upstream `keyring-core` v1 limitation.
