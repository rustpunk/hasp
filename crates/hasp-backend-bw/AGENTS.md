# AGENTS.md

## Purpose

`hasp-backend-bw` implements the `bw://` Bitwarden CLI backend.

## Responsibilities

Wrap the `bw` CLI for URL-addressed get and exists behavior. Current source indicates put, list, and delete are unsupported.

## Important Public APIs

`BwBackend`, `BwUrl`, and `impl hasp_core::Backend for BwBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, version/auth checks, subprocess execution, JSON field extraction, error mapping, and tests.

## Dependency Rules

Keep Bitwarden CLI behavior isolated here. Do not add write/list/delete behavior without matching tests and docs.

## Invariants

Enforce subprocess timeouts. Use `SecretString` for values. Unsupported operations return `UnsupportedOperation`. Avoid raw stderr leaks.

## Common Mistakes

Do not assume `bw` is installed or logged in during tests. Do not claim write support unless source/tests implement it.

## Local Commands

```bash
cargo test -p hasp-backend-bw
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, and `doc/ai/80_OPEN_QUESTIONS.md` if operation support changes.

## Unclear / Ask Human

Ask before adding write/delete/list semantics or changing field extraction grammar.

## Evidence

`crates/hasp-backend-bw/src/lib.rs`, `hasp-core/src/test_utils.rs`, `crates/hasp/tests/integration.rs`.
