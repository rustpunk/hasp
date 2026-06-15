# AGENTS.md

## Purpose

`hasp` is the public Rust library facade over `hasp-core` and feature-gated backend crates.

## Responsibilities

Owns `Store`, `StoreBuilder`, default backend registration, cache/audit integration, URL dispatch, copy, compare, batch/bulk operations, and convenience free functions.

## Important Public APIs

`Store`, `StoreBuilder`, `CopyOptions`, `CopyOutcome`, `IfExists`, `DiffOutcome`, backend constructors, and free functions `get`, `put`, `list`, `delete`, `exists`.

## Internal Module Map

`src/lib.rs` is a single-file facade: re-exports, constructors, builder, registration, store operations, copy/diff, options/outcomes, and default store.

## Dependency Rules

Keep backend crates optional and feature-gated. Do not add CLI dependencies. Coordinate internal dependency version changes from root `Cargo.toml`.

## Invariants

Dispatch by URL scheme. Later backend registration replaces earlier registration. `resolve` validates grammar without I/O. `copy` and `compare` must not reveal secret values or mismatch details. `batch_get` returns one result per input URL.

## Common Mistakes

Do not claim `batch_get` is concurrent. Do not assume default `hasp` enables every backend; default feature is `env`. Do not add value-derived audit or error fields.

## Local Commands

```bash
cargo test -p hasp
cargo test -p hasp --all-features
cargo test -p hasp --test copy_tests --features env,file
cargo test -p hasp --test diff_tests --features env,file
cargo test -p hasp --test url_parsing
```

## Documentation Updates

Update `doc/ai/10_ARCHITECTURE.md`, `20_PROJECT_MAP.md`, `40_COMMON_PATTERNS.md`, and user docs for public behavior changes.

## Unclear / Ask Human

Ask before changing `Store` public behavior, copy/diff semantics, default features, cache behavior, or backend registration policy.

## Evidence

`crates/hasp/src/lib.rs`, `crates/hasp/Cargo.toml`, `crates/hasp/tests/*`.
