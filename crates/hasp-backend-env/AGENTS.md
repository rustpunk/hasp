# AGENTS.md

## Purpose

`hasp-backend-env` implements the `env://` backend.

## Responsibilities

Read secrets from environment variables and report existence. `put`, `list`, and `delete` are unsupported because a child process cannot mutate its parent environment.

## Important Public APIs

`EnvBackend`, `EnvUrl`, and `impl hasp_core::Backend for EnvBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, backend implementation, unsupported operation behavior, and unit tests.

## Dependency Rules

Keep dependencies minimal: `hasp-core` and `url`. Do not add config/profile logic here.

## Invariants

Wrap fetched values with `wrap_secret`. Validate URL grammar through `EnvUrl`. Unsupported operations return `Error::UnsupportedOperation`.

## Common Mistakes

Do not log environment values. Do not add write semantics. Do not accept malformed env variable URLs just because `url::Url` parses them.

## Local Commands

```bash
cargo test -p hasp-backend-env
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, and `doc/ai/20_PROJECT_MAP.md` if operation support or grammar changes.

## Unclear / Ask Human

Ask before changing operation support or variable-name grammar.

## Evidence

`crates/hasp-backend-env/src/lib.rs`, `crates/hasp-backend-env/tests/env_backend_tests.rs`.
