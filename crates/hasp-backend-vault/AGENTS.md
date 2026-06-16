# AGENTS.md

## Purpose

`hasp-backend-vault` implements the `vault://` HashiCorp Vault KV backend.

## Responsibilities

Use blocking HTTP calls with ambient Vault configuration to get, put, list, delete, and exist-check secrets.

## Important Public APIs

`VaultBackend`, `VaultUrl`, and `impl hasp_core::Backend for VaultBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, HTTP client construction, KV path handling, field extraction, status/error mapping, and tests.

## Dependency Rules

Keep Vault-specific HTTP and auth behavior here. Do not add profile or CLI policy logic.

## Invariants

Respect proxy configuration. Map HTTP status to shared errors. Field-level `put` is read-modify-write without CAS, so concurrency semantics are sensitive.

## Common Mistakes

Do not assume user docs are current for Vault operation support. Do not treat field-level updates as atomic unless CAS is added and tested.

## Local Commands

```bash
cargo test -p hasp-backend-vault
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, `docs/src/proxy.md`, and `doc/ai/80_OPEN_QUESTIONS.md` if Vault behavior changes.

## Unclear / Ask Human

Ask before changing KV version assumptions, CAS behavior, proxy behavior, or field-level put semantics.

## Evidence

`crates/hasp-backend-vault/src/lib.rs`, `notes/proxy-plan.md`, `crates/hasp/tests/integration.rs`.
