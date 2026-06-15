# AGENTS.md

## Purpose

`hasp-backend-aws-sm` implements the `aws-sm://` AWS Secrets Manager backend.

## Responsibilities

Use AWS SDK clients behind the synchronous `Backend` trait for Secrets Manager operations.

## Important Public APIs

`AwsSmBackend`, `AwsSmUrl`, and `impl hasp_core::Backend for AwsSmBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, runtime/client construction, SDK calls, pagination, field extraction, SDK error mapping, and tests.

## Dependency Rules

Keep AWS SDK dependencies isolated here and optional through `hasp` features. Do not add AWS dependencies to `hasp-core`.

## Invariants

Use ambient AWS credentials. Explicit proxy configuration is documented as unsupported/no-op for AWS SDK backends; use env proxy configuration unless that design changes. Live error mapping is not fully verified.

## Common Mistakes

Do not mark cloud error behavior fully verified without live account tests. Do not assume source and README operation support agree.

## Local Commands

```bash
cargo test -p hasp-backend-aws-sm
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, `docs/src/proxy.md`, and `doc/ai/80_OPEN_QUESTIONS.md` if AWS behavior changes.

## Unclear / Ask Human

Ask before changing proxy support, region/secret URL grammar, or SDK error classification.

## Evidence

`crates/hasp-backend-aws-sm/src/lib.rs`, `notes/TODO-live-error-mapping.md`, root `Cargo.toml`.
