# AGENTS.md

## Purpose

Guidance for workspace crates under `crates/`.

## Responsibilities

Preserve crate boundaries, feature wiring, workspace dependency policy, tests, and no-secret-leak invariants.

## Important Entry Points

- `hasp-core`: shared contracts.
- `hasp`: public facade and backend registration.
- `hasp-cli`: binary and CLI policy.
- `hasp-backend-*`: backend implementations.

## Internal Module Map

Each crate has its own `Cargo.toml`, README, and `src`. Most backend crates are single-file `src/lib.rs` implementations with inline tests.

## Dependency Rules

Internal dependency versions are managed from root `Cargo.toml`. Keep backend dependencies optional through `hasp`/`hasp-cli` feature flags. Do not add dependencies or modify `Cargo.lock` without approval.

## Invariants

Secrets cross API boundaries as `SecretString`. Backend URL grammar belongs in backend crates. CLI/profile/config behavior belongs in `hasp-cli`, not `hasp-core`.

## Common Mistakes

Do not assume all backends are enabled. Do not treat stale README operation tables as source of truth. Do not use broad string trimming for secret values unless the backend already does so deliberately.

## Local Commands

```bash
cargo test -p <crate>
cargo clippy -p <crate> --all-targets --all-features -- -D warnings
```

## Documentation Updates

Update `doc/ai/20_PROJECT_MAP.md`, `doc/ai/30_DESIGN_RULES.md`, and crate README/user docs when crate behavior changes.

## Unclear / Ask Human

Ask before changing public traits, error variants, feature defaults, workspace dependency policy, or release/security policy.

## Evidence

Root `Cargo.toml`, `.github/workflows/ci.yml`, `doc/ai/20_PROJECT_MAP.md`.
