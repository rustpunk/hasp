# AGENTS.md

## Purpose

`hasp-backend-op` implements the `op://` 1Password CLI backend.

## Responsibilities

Wrap the `op` CLI for URL-addressed get, put, list, delete, and exists behavior using ambient CLI authentication and subprocess timeouts.

## Important Public APIs

`OpBackend`, `OpUrl`, `OpListUrl`, and `impl hasp_core::Backend for OpBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, version/auth checks, subprocess execution, JSON parsing, error mapping, and tests.

## Dependency Rules

Keep 1Password CLI behavior isolated here. Do not add persistent caching or auth bootstrap without an approved design.

## Invariants

Enforce subprocess timeouts. Strip only intentional formatting newlines. Avoid leaking raw values or unsafe stderr. `op delete` deletes an entire item, not a single field.

## Common Mistakes

Do not pass tests by requiring a real `op` install. Use fake CLI helpers. Do not assume field-level delete exists.

## Local Commands

```bash
cargo test -p hasp-backend-op
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, CLI docs, and `doc/ai/60_PERFORMANCE_NOTES.md` if subprocess behavior changes.

## Unclear / Ask Human

Ask before changing delete semantics, timeout values, auth preflight, or argv exposure tradeoffs.

## Evidence

`crates/hasp-backend-op/src/lib.rs`, `hasp-core/src/test_utils.rs`, `crates/hasp/tests/integration.rs`.
