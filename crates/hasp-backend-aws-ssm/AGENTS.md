# AGENTS.md

## Purpose

`hasp-backend-aws-ssm` implements the `aws-ssm://` AWS SSM Parameter Store backend.

## Responsibilities

Use AWS SDK clients behind the synchronous `Backend` trait for Parameter Store operations.

## Important Public APIs

`AwsSsmBackend`, `AwsSsmUrl`, and `impl hasp_core::Backend for AwsSsmBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, runtime/client construction, SDK calls, pagination, SDK error mapping, and tests.

## Dependency Rules

Keep AWS SDK dependencies isolated here and optional through `hasp` features. Do not add AWS dependencies to `hasp-core`.

## Invariants

Use ambient AWS credentials. Leading slash handling in parameter paths is part of URL grammar. Explicit proxy configuration is currently unsupported/no-op for AWS SDK backends. Live error mapping is not fully verified.

## Common Mistakes

Do not confuse `aws-ssm://region/name` with paths that require an encoded leading slash. Do not mark live cloud errors verified from unit tests only.

## Local Commands

```bash
cargo test -p hasp-backend-aws-ssm
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, `docs/src/proxy.md`, and `doc/ai/80_OPEN_QUESTIONS.md` if AWS SSM behavior changes.

## Unclear / Ask Human

Ask before changing parameter path grammar, proxy support, or SDK error classification.

## Evidence

`crates/hasp-backend-aws-ssm/src/lib.rs`, `notes/TODO-live-error-mapping.md`, root `Cargo.toml`.
