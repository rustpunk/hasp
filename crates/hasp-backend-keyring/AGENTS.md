# AGENTS.md

## Purpose

`hasp-backend-keyring` implements the `keyring://` OS keyring backend.

## Responsibilities

Map `keyring://service/account` URLs to platform keyring operations for get, put, delete, and exists. Listing is unsupported.

## Important Public APIs

`KeyringBackend`, `KeyringUrl`, and `impl hasp_core::Backend for KeyringBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, platform store initialization, backend implementation, keyring error mapping, and tests.

## Dependency Rules

Keep OS keyring dependencies isolated here. Do not move platform stores into `hasp-core`.

## Invariants

Use `SecretString` for fetched values. Map native keyring errors into shared `hasp_core::Error`. Return `UnsupportedOperation` for list.

## Common Mistakes

Do not assume a real desktop keyring is available in tests. Do not add auth bootstrap or credential migration behavior here.

## Local Commands

```bash
cargo test -p hasp-backend-keyring
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, and `doc/ai/20_PROJECT_MAP.md` if keyring URL grammar or operation support changes.

## Unclear / Ask Human

Ask before changing platform store dependencies or service/account URL grammar.

## Evidence

`crates/hasp-backend-keyring/src/lib.rs`, `crates/hasp/tests/integration.rs`.
