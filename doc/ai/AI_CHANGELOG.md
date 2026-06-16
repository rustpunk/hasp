# AI Changelog

## Purpose

This file is lightweight architecture memory for future agents. Update it when repository architecture, important design rules, command policy, backend behavior, or AI onboarding docs change.

Do not invent past decisions. Record only what was observed or what changed in the current work.

## 2026-06-15 - Initial AI Onboarding Set

Created root and local agent guidance plus `doc/ai/` onboarding docs from read-only repository discovery and subsystem explorer reports.

Major architecture facts discovered:

- The project is a Rust 2021 Cargo workspace for a URL-addressed secrets library and CLI.
- `hasp-core` owns shared contracts: `Backend`, `Entry`, `Error`, audit, cache, hardening, proxy, retry, field extraction, and test utilities.
- `hasp` owns the public `Store` facade, feature-gated backend registration, cache/audit integration, copy/diff, batch/bulk operations, and free functions.
- `hasp-cli` owns CLI parsing, profiles, profile allow, cache policy, audit sink config, proxy policy, `run`, completions, man generation, and exit-code mapping.
- Backend crates own URL grammar, native error mapping, and `Backend` trait implementations.
- User docs are under `docs/src`; generated docs are under `docs/book`; AI onboarding docs are under `doc/ai`.
- CI runs format, build, clippy, tests, docs, and cargo-deny across a feature matrix.
- Release workflow builds multi-platform binaries and emits SLSA attestations.

Major unresolved questions:

- Some user docs and crate READMEs appear stale relative to source/tests, especially backend operation support and profile allow defaults.
- Live cloud error mappings still need credential-backed validation.
- Persistent cache is scaffolded, not implemented as disk persistence.
- Retry backoff tuning may not honor configured `base_delay`.

Future update instructions:

- Append dated entries. Do not rewrite history unless correcting a documented error.
- Link changed architecture docs when relevant.
- Record verification commands and whether they passed.
- Move unresolved uncertainty into `80_OPEN_QUESTIONS.md`.
