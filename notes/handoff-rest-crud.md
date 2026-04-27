# hasp handoff: REST backend CRUD completion

## Prime directive
Always choose the correct long-term architectural solution, even if it takes more code. Never cut corners for speed. When a design decision has implications for future backends, the CLI, or the public API, surface the trade-off explicitly and choose the path that preserves invariants rather than the fastest path.

## What was completed
All five REST/SOA backends were promoted from get/exists-only to full CRUD:

| backend | put | list | delete | notes |
|---|---|---|---|---|
| azure-kv | yes | one-page | 202/204 | 409 mapped to PreconditionFailed |
| vault | deferred | LIST metadata | 204 | KV-v2 field-level semantics not defined yet |
| aws-sm | CreateSecret fallback | one-page | soft-delete | EncryptionFailure mapped |
| aws-ssm | PutParameter SecureString | hierarchical | irreversible | module docs note delete behavior |
| gcp-sm | create + add base64 version | one-page | DELETE | tolerates 409 on create |

Tests pass: `cargo test --all-features` 287/287, `cargo clippy --all-targets -- -D warnings` clean.

## Design choices locked in
- Library is source of truth; CLI is a shell. No `anyhow` in library code.
- Secrets wrapped in `secrecy::SecretString` at backend boundary. No `Display`/`Debug` on secret types.
- URL is the primary identifier. `Entry` list URLs are canonical (no `?field=` for Vault list).
- Feature-gated backends; no unconditional cloud SDK dependencies.
- Stateless wrt auth; no auth-bootstrap flows.

## Explicit trade-offs surfaced
- **Pagination not followed**: Azure KV `nextLink` and GCP `nextPageToken` are documented but not chased. Future `list` may need an async stream.
- **Vault `put` deferred**: KV v2 field-level `put` (`?field=`) needs read-modify-write semantics. Defining this behavior belongs to a future design pass on `Backend::put` semantics.
- **AWS SSM `DeleteParameter` is final**: Removes all versions; native behavior is documented.

## What's still open / natural next steps
1. **CLI wiring**: `hasp-cli` currently only implements `get`. `put`, `list`, `delete` need args, error handling, and output formatting. CLI sits behind the `cli` feature gate; it must convert concrete `hasp_core::Error` variants to human strings, never `anyhow::Error`.
2. **Pagination**: Follow `nextLink`/`nextPageToken` in Azure KV and GCP SM list responses. This likely changes the return type from `Vec<Entry>` to an iterator/stream or requires adding a `limit` parameter.
3. **Vault `put`**: Define KV-v2 field-level update semantics. Options: (a) `put` always writes the whole JSON object, dropping `?field=`; (b) `put` with `?field=` does read-modify-write transparently; (c) introduce a new verb. Whatever is chosen must be documented and applied consistently.
4. **Version management**: AWS SM version stages, GCP version labels, Azure KV version IDs. None of the new verbs expose version control; callers use native URLs for that. Decide if hasp should surface version listing/rollback.
5. **Backend trait ergonomics**: Consider whether `list` should take a URL prefix or a scheme-only URL. Currently each backend interprets the URL differently (Azure lists by vault, AWS by region, GCP by project).
6. **Error mapping completeness**: The new SDK operations may surface error codes not yet mapped. Running against real AWS/GCP/Azure accounts would reveal gaps.

## Files touched (head SHA: ec68e07)
- `crates/hasp-backend-azure-kv/src/lib.rs`
- `crates/hasp-backend-vault/src/lib.rs`
- `crates/hasp-backend-aws-sm/src/lib.rs`
- `crates/hasp-backend-aws-ssm/src/lib.rs`
- `crates/hasp-backend-gcp-sm/src/lib.rs`
- `crates/hasp/tests/integration.rs`
- `crates/hasp-core/src/lib.rs` (derive Debug on Entry)

## Running the build
```bash
cargo test --all-features
cargo clippy --all-targets -- -D warnings
```