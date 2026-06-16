# AGENTS.md

## Project Summary

`hasp` is a Rust 2021 Cargo workspace for a unified URL-addressed secrets library and CLI. It has a core contract crate, a public facade crate, a CLI binary crate, and one crate per backend.

## Read First

- `doc/ai/00_READ_THIS_FIRST.md`
- `doc/ai/10_ARCHITECTURE.md`
- `doc/ai/30_DESIGN_RULES.md`
- `doc/ai/50_TESTING_AND_COMMANDS.md`
- The nearest local `AGENTS.md` for files you touch.

## Repository Layout

- `crates/hasp-core`: core `Backend` trait, errors, audit, cache, hardening, proxy, retry, field extraction.
- `crates/hasp`: public `Store` facade and feature-gated backend registration.
- `crates/hasp-cli`: `hasp` binary, profiles, CLI policy, commands, exit codes.
- `crates/hasp-backend-*`: backend implementations.
- `docs/src`: mdbook user docs.
- `docs/internal/research` and `notes`: research and planning.
- `doc/ai`: durable AI onboarding docs.

## High-Level Design Rules

- Keep `hasp-core` free of CLI/profile/TTY/config concerns.
- Keep backend URL grammar in backend crates.
- Preserve `SecretString` boundaries and redacted audit/error behavior.
- Keep backends feature-gated; do not add dependencies without approval.
- Treat existing user docs as secondary to source/tests when they conflict; record conflicts in `doc/ai/80_OPEN_QUESTIONS.md`.

## Commands

- Format: `cargo fmt --check`
- Build: `cargo build --all-features`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test: `cargo test --all-features`
- Docs: `cargo doc --no-deps`
- Policy: `cargo deny check`

See `doc/ai/50_TESTING_AND_COMMANDS.md` for focused and feature-matrix commands.

## Safety Rules

- Do not log or document secret values, lengths, hashes, prefixes, suffixes, byte positions, or derived material.
- Do not weaken hardening, cache, audit, profile trust, proxy refusal, or release attestation behavior without explicit approval.
- Do not run release/upload commands, push, or commit without explicit approval.
- Do not modify `Cargo.lock` unless explicitly approved.

## Coding Conventions

- Use existing crate patterns and tests before introducing abstractions.
- Backend operations return `hasp_core::Error` and wrap fetched secrets as `SecretString`.
- CLI behavior belongs in `hasp-cli`; library consumers should not pay for CLI dependencies.
- Unsupported backend verbs should return `UnsupportedOperation`, not placeholders.

## Dependency And Change Approval

Ask before adding dependencies, changing feature defaults, changing public traits/errors/exit codes, changing CI/release/security policy, or implementing on-disk cache persistence.

## Documentation Updates

Update `doc/ai/` for architecture, command, invariant, or local guidance changes. Update `docs/src` and crate READMEs for public behavior changes.

## Definition Of Done

Run focused checks for the changed area, or state clearly why they were not run. Keep the change scoped, preserve secret-handling invariants, update docs when behavior changes, and record unresolved uncertainty.
