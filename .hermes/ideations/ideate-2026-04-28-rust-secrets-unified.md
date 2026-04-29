# Ideation: hasp
_Unified `get`/`put`/`list`/`delete`/`exists` library + CLI for URL-addressed secret stores, shipping as a Cargo workspace with 11 backend crates._
_Generated: 2026-04-28 | Prior ideation: none_

## Refactoring

### Extract a built-in backend registry to eliminate N+1 feature-gate churn
- **Where:** `crates/hasp/src/lib.rs` lines 77–198 (`Backend` enum + `dispatch_backend!` macro), `StoreBuilder::build()` lines 242–298
- **What:** Adding a new backend currently requires editing four sites in `lib.rs` (enum variant, macro arm, `scheme()`, and builder). A compile-time registry (e.g., `inventory`-based or a `link_section`-collected table) would let each `hasp-backend-*` crate register itself with a single `ctor` attribute, keeping `lib.rs` closed for modification.
- **Why it fits:** The scaffold.md already anticipates a "custom" runtime-registration slot; the built-in backends are the only ones still hard-coded. This closes the gap between built-in and custom ergonomics.
- **Effort:** M

### Stop mutating process-wide `HTTP(S)_PROXY` env vars in `AwsSmBackend::block_on`
- **Where:** `crates/hasp-backend-aws-sm/src/lib.rs` lines 143–168
- **What:** `block_on` sets `HTTPS_PROXY`/`HTTP_PROXY` for the duration of every async call, then restores them. This is a race in multi-threaded library consumers (e.g., Spall). The AWS SDK supports explicit proxy configuration via `aws_config::Builder::http_connector`; use that instead of env-var surgery.
- **Why it fits:** Multi-threaded library consumers are an explicit target audience (Spall integration notes). Env-var mutation is a latent data race.
- **Effort:** S

### Centralise error-mapper boilerplate for cloud SDK backends
- **Where:** `crates/hasp-backend-aws-sm/src/lib.rs` lines 406–500; `crates/hasp-backend-aws-ssm/src/lib.rs`; `crates/hasp-backend-gcp-sm/src/lib.rs`; `crates/hasp-backend-azure-kv/src/lib.rs`
- **What:** Each cloud backend repeats ~20 lines of `if let Some(service_err) = err.as_service_error() { ... } map_generic_error(err)` per operation. Extract a `CloudErrorMapper` trait or helper in `hasp-core` that accepts `code` + `message` and returns `Error`, cutting duplication by ~60 %.
- **Why it fits:** `hasp-core` already owns the error taxonomy; the mapping logic is purely structural. The `TODO(#4)` markers flag this as known duplication.
- **Effort:** S

## Documentation

### Document `file://?raw=true` and `keyring://?target=...` in the mdbook quickstart
- **Where:** `docs/src/quickstart.md` (references only `env://` and `file://`), `docs/src/backends.md`
- **What:** The quickstart is deliberately limited to pure-std backends, but it omits the `?raw=true` and `?target=` query parameters that are already implemented and tested (see `file` backend tests, `keyring` URL parser tests). Add a "Query parameters" subsection to each backend page.
- **Why it fits:** These parameters are part of the public API surface; leaving them undocumented makes them appear accidental rather than intentional.
- **Effort:** S

### Add a "Backend capabilities matrix" to the mdbook
- **Where:** `docs/src/backends.md` or new `docs/src/capabilities.md`
- **What:** A table showing which verbs each backend supports (e.g., `op://` and `bw://` are read-only, `env://` is read-only, `keyring://` has no `list`, etc.). This is implied by the verb-per-backend docs but never collated.
- **Why it fits:** Consumers deciding which backends to compile in need this at a glance. It also surfaces gaps (e.g., no `list` on `keyring://`) as intentional rather than missing.
- **Effort:** S

## Scope gaps

### No integration tests for `bw://` and `op://` backends
- **Where:** `crates/hasp/tests/integration.rs` (975 lines, zero `op` or `bw` tests)
- **What:** Both backends are ~700 LOC each with subprocess calls, timeouts, and error mapping, yet `integration.rs` only tests `env://`. Add `#[cfg(feature = "op")]` and `#[cfg(feature = "bw")]` tests that inject a fake binary via `$PATH` (a shell script echoing canned JSON/stderr) so CI can exercise them without real 1Password / Bitwarden accounts.
- **Why it fits:** The scaffold mentions feature-combinatoric CI; omitting two compiled backends leaves a 2/10 hole in confidence.
- **Effort:** M

### No integration tests for `vault://` or `keyring://`
- **Where:** `crates/hasp/tests/integration.rs`; `crates/hasp-backend-vault/src/lib.rs`
- **What:** `vault` has zero tests in `integration.rs` despite being a full CRUD REST backend. `keyring` is also absent. Both can be covered with a lightweight mock server (`httptest` or `mockito` for Vault; `tempfile` + `keyring-core::mock` for keyring).
- **Why it fits:** Spall depends on `keyring` + `env`; shipping `0.1.0-alpha.1` without integration coverage for the Spall-unlock backend defeats the release intent.
- **Effort:** M

### `Cargo.lock` commitment vs `.gitignore` / CLAUDE.md stale guidance
- **Where:** `CLAUDE.md` line: "`Cargo.lock` is currently git-ignored. Once the `[[bin]]` target lands, switch to committing it"; `.gitignore` (no `Cargo.lock` entry); `git ls-files Cargo.lock` (file is tracked)
- **What:** The guidance is stale — the `[[bin]]` target exists and `Cargo.lock` is already tracked. Update `CLAUDE.md` and, if desired, move `Cargo.lock` out of `.gitignore` formally. This is a hygiene gap, not a feature.
- **Why it fits:** In-flight documentation that contradicts reality is a trap for the next contributor.
- **Effort:** XS

## Feature enrichment

### Add `--raw` / `--binary` stdout flag to `hasp get`
- **Where:** `crates/hasp-cli/src/main.rs` line 113 (`println!("{}", secret.expose_secret());`); `docs/src/cli-reference.md`
- **What:** `println!` always appends a newline; some secrets are multi-line files (e.g., PEM keys) where an extra newline breaks the output. `--raw` should write via `io::stdout().write_all(bytes)` without a trailing newline. This mirrors `curl --data-binary` / `cat` conventions.
- **Why it fits:** The `file://` backend already supports `?raw=true` for reads; the CLI output side has no equivalent affordance.
- **Effort:** S

### Memoize per-Store `get`/`exists` results for library consumers
- **Where:** `crates/hasp/src/lib.rs` (`Store` struct, line 307)
- **What:** `Store` dispatches directly to backends on every call. For N sequential lookups in the same process (Spall's pattern), this repeats keyring unlocks, subprocess spawns, and HTTP handshakes. A simple `HashMap<String, (SecretString, Instant)>` behind a `RwLock` with a short TTL (e.g., 60 s) would absorb fetch loops without leaking long-term.
- **Why it fits:** Spall handoff notes the need to avoid "partial-rotation glitches across multi-secret fetches"; a bounded memoization layer is the natural sibling to that concern.
- **Effort:** M

### Add `--format json` to `get`, `put`, and `exists` CLI verbs
- **Where:** `crates/hasp-cli/src/main.rs` (`Command::Get`, `Command::Put`, `Command::Exists`)
- **What:** Only `list` supports `--format json`. For scripting pipelines, `get` needs JSON wrapping (e.g., `{"url": "...", "value": "..."}`) to handle multi-line secrets safely. This is explicitly a shell UX concern, not a library change.
- **Why it fits:** CLI is already a thin shell; adding output formatting is its job. The `list_format` module can be generalised.
- **Effort:** S

## New features (scope-aligned)

### `hasp validate <address>` — lint a URL or alias against backend grammar without fetching
- **Where:** `crates/hasp-cli/src/main.rs`; `hasp-core` trait extensions
- **What:** A CLI subcommand `hasp validate @prod/db-password` that resolves the alias and runs the backend URL parser, returning which backend would handle it (or why it is malformed). Useful in CI to catch typos in `profiles.toml` before deployment.
- **Why it fits:** Profiles are loaded from a user file with no URL validation at load time; runtime failure is the only signal. A `validate` verb is a natural extension of the existing `resolve` helper.
- **Effort:** S

### `hasp copy <address>` — copy secret to clipboard with auto-clear
- **Where:** New module in `hasp-cli` (behind a feature gate)
- **What:** Cross-platform clipboard integration (`arboard` or `clipboard`) that copies the secret value and clears it after 30 s. This is the kind of surface-level UX enhancement that fits the CLI ambition — one more layer on top of `get`.
- **Why it fits:** The CLI already wraps `rpassword` for TTY input; clipboard output is the symmetric UX affordance for the "copy password" workflow.
- **Effort:** M

## Quality

### Add mock-subprocess tests for `op` and `bw` backends
- **Where:** `crates/hasp-backend-op/src/lib.rs`; `crates/hasp-backend-bw/src/lib.rs`
- **What:** Both backends spawn external binaries. Unit tests can be written by temporarily overriding `$PATH` to a shell script that emits known stdout/stderr/exit codes, verifying error mapping (`AuthenticationFailed`, `NotFound`, timeouts) without real credentials.
- **Why it fits:** `hasp-core` already provides `test_utils::EnvGuard` for env manipulation; `$PATH` manipulation is the natural next step for subprocess backends.
- **Effort:** S

### Add macOS + Windows CI runners for `keyring` backend
- **Where:** `.github/workflows/ci.yml`
- **What:** The CI currently runs only on `ubuntu-latest`. `keyring-core` uses platform-specific stores (macOS Keychain, Windows Credential Manager). At minimum one macOS and one Windows runner with `cargo test --features keyring` would catch platform-specific regressions.
- **Why it fits:** `keyring-core` v4 was released days ago; platform coverage is more valuable than ever.
- **Effort:** S

## DX / UX

### `profiles.toml` URL validation at load time
- **Where:** `crates/hasp-cli/src/profiles.rs` (`load_profiles`)
- **What:** Currently `load_profiles` never validates that a stored URL string is syntactically valid. A malformed `aws-sm:///missing-region` stored in the profile file will only error on first use. Call `url::Url::parse` on each value during load and surface a parse error immediately.
- **Why it fits:** The `profiles` module already depends on `url` transitively; adding eager validation prevents silent misconfiguration.
- **Effort:** XS

### Document how to install `hasp-cli` with a subset of backends
- **Where:** `docs/src/installation.md`; `crates/hasp-cli/README.md`
- **What:** The default `hasp-cli` features compile all ten backends. A user who only needs `env://` + `file://` can save ~80 % compile time with `--no-default-features --features env,file`. Document the feature names and the dependency cost of each cloud backend.
- **Why it fits:** The Cargo features exist; the knowledge does not. This is a pure-documentation DX win.
- **Effort:** XS

## Hygiene

### Commit `Cargo.lock` formally or update `CLAUDE.md` guidance
- **Where:** `CLAUDE.md`, `.gitignore`, `Cargo.lock`
- **What:** `CLAUDE.md` states `Cargo.lock` is git-ignored and should be committed once the `[[bin]]` target lands. The `[[bin]]` target exists in `hasp-cli/Cargo.toml`, and `Cargo.lock` is already tracked by git. Update `CLAUDE.md` to reflect reality.
- **Why it fits:** Stale guidance in the repository's canonical developer doc is a recurring tax on every new contributor.
- **Effort:** XS

### Cache mdbook in CI instead of building from source
- **Where:** `.github/workflows/ci.yml` lines 42–43
- **What:** `cargo install mdbook` adds ~90 s to every CI run. Switch to `cargo install mdbook --locked` with `Swatinem/rust-cache`, or use `cargo-binstall` / a prebuilt GitHub Action.
- **Why it fits:** The docs are already built on every PR; the cost is pure waste.
- **Effort:** XS

## Open questions
- Does `lancedb/` at the repo root belong to a different project (spall?), and should it be `.gitignore`-d or removed? It is listed in `.gitignore` but exists as an untracked directory.
- Are `op://` and `bw://` backends expected to remain read-only (`get`/`exists` only), or is `put` support planned for a future wave? The scaffold defers KV field-level semantics for Vault, but is silent on subprocess-backend writes.
- What is the intended mechanism for `Store::list` on backends that natively filter by prefix (SSM, Vault) versus those that return flat scopes (AWS SM, GCP SM)? The current `Store::list` applies client-side filtering to all backends, which is redundant for the prefix-capable ones.

## Out of scope
- **Async `Backend` trait rewrite** — scaffold.md explicitly locks sync-first core trait; optional async is a future feature, not a current gap.
- **Auth bootstrap / token rotation** — listed as out of scope in README; do not propose credential-management flows.
- **Binary secret values (non-UTF8)** — AWS SM backend already rejects SecretBinary; extending the `Backend` contract to bytes would require a library-level change beyond current ambition.
- **Keyring `list`** — `keyring-core` v1 has no portable enumeration API; this is a dependency limitation, not an unimplemented feature.
