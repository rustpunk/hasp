# Design Rules

## Core Design Philosophy

- Verified: library and CLI are both first-class surfaces. Evidence: root `README.md` says the library is the source of truth and the CLI is a thin shell over the public library API.
- Verified: URL scheme is the primary backend identifier. Evidence: `hasp_core::Backend::scheme`, `hasp::Store` scheme dispatch, and README URL examples.
- Verified: auth bootstrap and secret rotation are out of scope. Evidence: root `README.md` out-of-scope list and backend ambient-auth behavior.

## Dependency Direction

- Verified: `hasp-core` must remain free of profile, TTY, and config dependencies. Evidence: `crates/hasp-core/src/lib.rs`.
- Verified: backend crates depend on `hasp-core`; `hasp` depends on optional backend crates; `hasp-cli` depends on `hasp`.
- Verified: backend dependencies are feature-gated at the `hasp` and `hasp-cli` layers.
- Strong inference: do not add cloud, OS keyring, CLI, or config dependencies to `hasp-core` unless a human explicitly approves a boundary change.

## Public API Rules

- Verified: backend implementations must implement `hasp_core::Backend`.
- Verified: backend URL grammar belongs in backend crates via their parser structs and `validate()`.
- Verified: `Entry.url` should be usable with `Store::get`.
- Verified: `Store::resolve` must validate backend grammar without doing I/O.
- Strong inference: adding a backend means adding a backend crate, feature flag, constructor/re-export, default registration, tests, and docs.

## Error Handling Rules

- Verified: use `hasp_core::Error`, not stringly typed library errors.
- Verified: classify retryable backend failures with `BackendFailureKind`.
- Verified: CLI maps `hasp::Error` to stable exit codes.
- Verified: audit events use `Error::kind()` classifier labels.
- Never include secret values or value-derived material in error messages.

## State, Ownership, And Concurrency Rules

- Verified: backends are `Arc<dyn Backend>` and must be `Send + Sync`.
- Verified: `Store` registration replaces an existing backend for the same scheme.
- Verified: cache entries are `Arc<SecretString>` in `moka::sync::Cache`.
- Verified: constructing `ProcessCache` requires `HardeningToken`.
- Strong inference: synchronous blocking behavior is intentional at the public API boundary; async SDK work is hidden inside backends.

## Secret Handling Rules

- Verified: fetched secrets cross backend boundaries as `SecretString`.
- Verified: audit event types are closed-shape and value-free.
- Verified: `diff` and `copy --verify` compare without exposing mismatch details.
- Never log secret values, lengths, hashes, byte positions, common prefixes, suffixes, or field-derived material.
- Never add `Debug` or `Display` paths that reveal secrets.

## CLI Rules

- Verified: hardening runs before CLI argument parsing.
- Verified: profile allow enforcement is default-on in code and CLI tests, with opt-out via `HASP_REQUIRE_PROFILE_ALLOW=0` or `--no-profile-allow`.
- Verified: `run` resolves all secrets before spawning and refuses stdout TTY unless `--allow-tty`.
- Verified: `exists` absent and `diff` different both use exit code 1, which also overlaps some usage failures.
- Verified: `cp` and `diff` reject plain-http proxies unless `HASP_ALLOW_HTTP_PROXY=1`.

## Testing Rules

- Verified: CI runs format, build, clippy, tests, docs, and cargo-deny across feature sets.
- Strong inference: backend URL grammar and error mapping changes need parser tests and focused backend tests.
- Strong inference: CLI behavior changes need integration tests under `crates/hasp-cli/tests`.
- Strong inference: audit changes need no-leak tests.
- Strong inference: cloud error mapping should not be marked fully verified without live credential-backed validation.

## Performance Rules

- Verified: `batch_get` deduplicates identical URLs but is sequential.
- Verified: process cache is per-invocation and hardening-gated.
- Verified: remote list operations cap pagination at `MAX_PAGES = 500`.
- Verified: CLI subprocess backends enforce wall-clock timeouts.
- Hypothesis: retry backoff may ignore configured `base_delay`; do not rely on that knob without checking source and tests.

## Documentation Rules

- Update `doc/ai/` when architecture, commands, invariants, tests, local guidance, or uncertainty changes.
- Update `docs/src` and crate READMEs when public user behavior changes.
- Do not present a claim as project-wide unless it appears repeatedly.
- Prefer source/tests over stale docs, and record conflicts in [80_OPEN_QUESTIONS.md](80_OPEN_QUESTIONS.md).

## Never Do This Unless Explicitly Approved

- Modify `Cargo.lock`.
- Add dependencies.
- Change `deny.toml`, CI, release attestations, or toolchain policy.
- Move profile/config/TTY logic into `hasp-core`.
- Make backend crates unconditional dependencies.
- Weaken audit redaction, profile trust, cache hardening, or proxy refusal behavior.
- Add auth-bootstrap, secret rotation, password generation, bulk file encryption, or certificate lifecycle features.

## Ask The Human Before Changing These Areas

- Public `hasp-core::Backend` trait shape.
- `hasp_core::Error` variants or CLI exit-code table.
- Cache persistence or on-disk secret storage.
- Release workflow and attestation pinning.
- Dependency/license/advisory policy.
- Cross-backend `cp` or `diff` security semantics.
- Live cloud behavior that requires real credentials to verify.
