# Local Agent Plan

## Recommended Local `AGENTS.md` Locations

| Location | Priority | Why local guidance is needed | Rules to include | Local commands | Risk if absent | Evidence | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `crates/AGENTS.md` | High | Applies to all workspace crates and backend feature wiring. | Keep internal dependency policy, feature gating, tests, and no-secret rules visible. | Workspace and per-package cargo commands. | Agents may add unconditional deps or miss feature matrices. | root `Cargo.toml`, CI. | High |
| `crates/hasp-core/AGENTS.md` | High | Core contract crate has strict dependency and secret redaction boundaries. | No CLI/profile/config deps; preserve `Backend`, `Error`, audit, cache hardening. | `cargo test -p hasp-core`, feature variants. | Boundary violations affect every backend and public API. | `hasp-core/src/lib.rs`, tests. | High |
| `crates/hasp/AGENTS.md` | High | Public facade owns dispatch, default registration, cache/audit integration. | Preserve feature-gated backends, `Store` behavior, copy/diff secrecy. | `cargo test -p hasp`, focused tests. | Agents may break public API or mis-register backends. | `hasp/src/lib.rs`, `hasp` tests. | High |
| `crates/hasp-cli/AGENTS.md` | High | CLI owns security policy and user-facing behavior. | Preserve hardening, profile allow, cache, audit, exit codes, stdout/stderr split. | `cargo test -p hasp-cli`, focused CLI tests. | Agents may bypass security setup or break scripts. | `hasp-cli/src/main.rs`, CLI tests. | High |
| `crates/hasp-backend-*/AGENTS.md` | High | Backend crates own URL grammar, native error mapping, and secret boundaries. | Keep parser/validate aligned; no secret leaks; ambient auth; operation support truth. | `cargo test -p <backend>`. | Agents may copy stale docs, leak errors, or parse URLs inconsistently. | Backend `src/lib.rs` files and tests. | High |

## Suggested Creation Batches

1. Root and `doc/ai/` core docs.
2. `crates/AGENTS.md`, `crates/hasp-core/AGENTS.md`, `crates/hasp/AGENTS.md`, `crates/hasp-cli/AGENTS.md`.
3. Backend crate `AGENTS.md` files sharing concise backend-specific guidance.
4. Consistency review across all created docs.

## Directories Where Local `AGENTS.md` Is Probably Unnecessary

| Location | Reason | Confidence |
| --- | --- | --- |
| `docs/src` | User docs are already covered by root and `doc/ai`; no source code invariants unique enough for local guidance yet. | Medium |
| `docs/internal/research` | Research notes are historical/contextual; root guidance is enough unless active research workflow expands. | Medium |
| `notes` | Scratch/handoff notes; not a stable implementation area. | High |
| `.github` | CI/release rules are covered in root and `doc/ai`; changes should ask human before editing. | Medium |
| `docs/book` | Generated mdbook output; agents should avoid manual edits. | High |
| `target` | Build output; never hand-edit. | High |

## Evidence And Confidence

The plan is based on root manifest layout, crate boundaries, subagent read-only discovery, `hasp-core` public contract, `hasp` feature registration, CLI policy code, backend parser patterns, CI matrix, and tests. Confidence is high for crate-local guidance and medium for not adding `.github`/docs local guidance.
