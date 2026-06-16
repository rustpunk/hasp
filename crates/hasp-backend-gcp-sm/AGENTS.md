# AGENTS.md

## Purpose

`hasp-backend-gcp-sm` implements the `gcp-sm://` Google Cloud Secret Manager backend.

## Responsibilities

Use GCP auth and blocking HTTP calls for Secret Manager get, put, list, delete, and exists behavior.

## Important Public APIs

`GcpSmBackend`, `GcpSmUrl`, and `impl hasp_core::Backend for GcpSmBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, auth/client setup, REST calls, pagination, field extraction, HTTP error mapping, and tests.

## Dependency Rules

Keep GCP auth/HTTP dependencies isolated here and optional through `hasp` features.

## Invariants

Respect proxy configuration. Use ambient GCP credentials. Live error mapping is not fully verified. Secret ID grammar may differ between README wording and source behavior.

## Common Mistakes

Do not rely on stale README grammar without checking parser tests. Do not mark cloud status mappings verified without live tests.

## Local Commands

```bash
cargo test -p hasp-backend-gcp-sm
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, `docs/src/proxy.md`, and `doc/ai/80_OPEN_QUESTIONS.md` if GCP behavior changes.

## Unclear / Ask Human

Ask before changing secret ID grammar, auth behavior, proxy behavior, or HTTP status mapping.

## Evidence

`crates/hasp-backend-gcp-sm/src/lib.rs`, `notes/TODO-live-error-mapping.md`, backend README.
