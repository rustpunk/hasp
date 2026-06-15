# AGENTS.md

## Purpose

`hasp-backend-azure-kv` implements the `azure-kv://` Azure Key Vault backend.

## Responsibilities

Use Azure auth and blocking HTTP calls for Key Vault secret operations.

## Important Public APIs

`AzureKvBackend`, `AzureKvUrl`, and `impl hasp_core::Backend for AzureKvBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, auth/client setup, REST calls, pagination, HTTP error mapping, and tests.

## Dependency Rules

Keep Azure dependencies isolated here and optional through `hasp` features. Do not add Azure dependencies to core.

## Invariants

Respect proxy configuration. Use ambient Azure credentials. Map HTTP statuses into shared errors. Live cloud behavior remains medium confidence until credential-backed validation.

## Common Mistakes

Do not mark status/error mappings fully verified from unit tests alone. Do not bypass `SecretString` on get.

## Local Commands

```bash
cargo test -p hasp-backend-azure-kv
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, `docs/src/proxy.md`, and `doc/ai/80_OPEN_QUESTIONS.md` if Azure behavior changes.

## Unclear / Ask Human

Ask before changing vault URL grammar, auth behavior, proxy behavior, or HTTP status classification.

## Evidence

`crates/hasp-backend-azure-kv/src/lib.rs`, `notes/TODO-live-error-mapping.md`, root `Cargo.toml`.
