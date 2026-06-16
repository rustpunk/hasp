# Common Patterns

## Backend URL Parser Struct

- Where it appears: every `crates/hasp-backend-*/src/lib.rs` defines a URL parser type such as `EnvUrl`, `FileUrl`, `AwsSmUrl`, or `VaultUrl`.
- Why it seems to exist: backend crates own grammar; core only knows schemes.
- How to copy it correctly: implement parsing from `&Url`, reject unsupported queries and missing required components, and have `Backend::validate()` delegate to the same parser.
- Common mistakes: adding ad hoc parsing in `hasp-core`; letting `--explain` accept URLs that real operations reject.
- Evidence: parser structs and `fn validate(&self, url: &Url)` across backend crates.

## `Backend` Trait Implementation

- Where it appears: every backend crate.
- Why it seems to exist: uniform `Store` dispatch over different secret stores.
- How to copy it correctly: implement `scheme`, operations, and `validate`; return `UnsupportedOperation` for unsupported verbs; map native failures into `hasp_core::Error`.
- Common mistakes: treating unsupported operations as unimplemented bugs; leaking native error text containing secret material.
- Evidence: `crates/hasp-core/src/lib.rs`, backend `impl Backend for ...` blocks.

## Feature-Gated Backend Registration

- Where it appears: `crates/hasp/Cargo.toml`, `crates/hasp/src/lib.rs`, `crates/hasp-cli/Cargo.toml`.
- Why it seems to exist: consumers pay only for enabled stores, and the CLI forwards backend features.
- How to copy it correctly: add optional dependency, feature name, constructor/re-export, and guarded registration in `register_default_backends`.
- Common mistakes: adding backend dependencies unconditionally; forgetting CLI feature forwarding.
- Evidence: `hasp` feature list and `register_default_backends`.

## Secret Wrapping At Boundary

- Where it appears: core trait docs, `EnvBackend`, `FileBackend`, backend `get` implementations.
- Why it seems to exist: prevent accidental secret display through public API types.
- How to copy it correctly: wrap raw strings as `SecretString` or `wrap_secret` before returning from `get`.
- Common mistakes: returning `String`; logging intermediate values; using `Debug` output in errors.
- Evidence: `Backend::get` docs and `hasp_core::secret_mem::wrap_secret`.

## Shared Error Mapping

- Where it appears: backend helper functions such as `map_*_error`, `map_http_status`, and `map_reqwest_error`.
- Why it seems to exist: stable library API and CLI exit-code mapping.
- How to copy it correctly: map not-found/auth/permission/precondition/transient/throttled/permanent cases to `hasp_core::Error`; avoid embedding secret values.
- Common mistakes: dumping raw stderr or SDK debug strings directly.
- Evidence: `crates/hasp-core/src/error.rs`, backend mapping helpers.

## Value-Free Audit Events

- Where it appears: `hasp-core/src/audit.rs`, `hasp/src/lib.rs`, CLI audit tests.
- Why it seems to exist: provide operational visibility without leaking secrets.
- How to copy it correctly: use stable event labels, schemes, outcomes, and error kinds only.
- Common mistakes: adding URL paths, values, lengths, hashes, or arbitrary runtime labels.
- Evidence: `AuditEvent`, `AuditSink`, `audit_no_leak.rs`.

## Hardening-Gated Cache

- Where it appears: `hasp-core/src/cache.rs`, `hasp/src/lib.rs`, `hasp-cli/src/main.rs`.
- Why it seems to exist: avoid repeated backend reads while requiring process hardening before storing secrets in memory.
- How to copy it correctly: require `HardeningToken` for explicit cache policy; disable cache in CI or with `HASP_NO_CACHE`/`HASP_CACHE_TTL=0`.
- Common mistakes: constructing cache without hardening; documenting persistent disk cache as implemented.
- Evidence: `ProcessCache::new`, `StoreBuilder::with_cache_policy`, CLI cache policy resolution.

## CLI Policy Before Store Operations

- Where it appears: `hasp-cli/src/main.rs`.
- Why it seems to exist: centralize hardening, profile trust, proxy, cache, and audit setup before secret operations.
- How to copy it correctly: new commands should pass through the shared setup unless they truly do not need profiles/store access.
- Common mistakes: bypassing profile allow checks or audit/cache configuration for new commands.
- Evidence: `main`, `run`, command dispatch in `hasp-cli/src/main.rs`.

## Fake External CLI Test Helpers

- Where it appears: `hasp-core/src/test_utils.rs`, `hasp` and CLI tests for `op`/`bw`.
- Why it seems to exist: test subprocess backends without requiring real 1Password/Bitwarden credentials.
- How to copy it correctly: use the test utilities and serialize environment mutations where required.
- Common mistakes: relying on real installed CLIs in default tests; failing to isolate `PATH` or env vars.
- Evidence: `FakeOpGuard`, `FakeBwGuard`, fake-CLI integration tests.

## Single Trailing Newline Handling

- Where it appears: `file://` and `op://` behavior notes.
- Why it seems to exist: common secret files and CLI output include one formatting newline.
- How to copy it correctly: strip exactly one trailing newline where the backend explicitly does so; use raw options when present.
- Common mistakes: using broad `trim()` and removing meaningful whitespace.
- Evidence: `hasp-backend-file` docs/source, `op` source comments.
