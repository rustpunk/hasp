# AGENTS.md

## Purpose

`hasp-core` is the shared contract crate for backend implementations and the `hasp` facade.

## Responsibilities

Defines `Backend`, `Entry`, `Error`, audit events/sinks, cache policy, hardening, proxy parsing, retry, field extraction, secret wrapping, and test utilities.

## Important Public APIs

`Backend`, `Entry`, `Error`, `BackendFailureKind`, `AuditEvent`, `AuditSink`, `CachePolicy`, `ProcessCache`, `HardeningToken`, `ProxyConfig`, `RetryBackend`, `SecretString`, `extract_field`.

## Internal Module Map

- `lib.rs`: exports and backend trait.
- `error.rs`: error taxonomy.
- `audit.rs`: value-free audit events.
- `cache.rs`: hardening-gated cache.
- `hardening.rs`: process mitigations.
- `proxy.rs`: proxy config.
- `retry.rs`: retry wrapper.
- `field.rs`: JSON field extraction.
- `secret_mem.rs`: secret wrapping.
- `test_utils.rs`: fake CLI/env test helpers.

## Dependency Rules

Do not add CLI, profile, TTY, cloud, or config dependencies here without explicit approval. Keep optional/test-only helpers behind features.

## Invariants

Secret values must not appear in errors, debug output, or audit events. Cache construction requires `HardeningToken`. Core extracts URL schemes only; backend grammar stays in backend crates.

## Common Mistakes

Do not widen `AuditEvent` with value-derived fields. Do not treat `CachePolicy::Persistent` as implemented disk persistence. Do not bypass hardening for cache construction.

## Local Commands

```bash
cargo test -p hasp-core
cargo test -p hasp-core --all-features
cargo test -p hasp-core --features memory-lock
```

## Documentation Updates

Update `doc/ai/10_ARCHITECTURE.md`, `30_DESIGN_RULES.md`, `40_COMMON_PATTERNS.md`, and `60_PERFORMANCE_NOTES.md` for core contract changes.

## Unclear / Ask Human

Ask before changing `Backend`, `Error`, audit fields, cache persistence, or hardening refusal behavior.

## Evidence

`crates/hasp-core/src/lib.rs`, `audit_no_leak.rs`, `memory_lock_tests.rs`.
