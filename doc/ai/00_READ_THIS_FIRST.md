# Read This First

## Purpose

This repository is a Rust workspace for `hasp`, a unified secrets library and CLI. It exposes a URL-addressed `Store` facade, a `hasp-core` contract crate, a `hasp-cli` binary crate, and one crate per backend.

These docs guide future agents without requiring them to rediscover the whole workspace.

## Status

Created from read-only discovery on 2026-06-15. No application/source code was modified. Some existing user docs conflict with source and tests; those conflicts are tracked in [80_OPEN_QUESTIONS.md](80_OPEN_QUESTIONS.md).

## Evidence Labels

- Verified: directly observed in source, manifest, tests, CI, or existing docs.
- Strong inference: supported by several pieces of evidence, but not explicitly stated as policy.
- Hypothesis: plausible from the evidence, but weak or contradicted elsewhere.
- Open question: requires human decision, live credentials, or source changes to resolve.

## Reading Order

- Any code edit: read this file, root [../../AGENTS.md](../../AGENTS.md), [30_DESIGN_RULES.md](30_DESIGN_RULES.md), [50_TESTING_AND_COMMANDS.md](50_TESTING_AND_COMMANDS.md), and the nearest local `AGENTS.md`.
- Backend work: also read [10_ARCHITECTURE.md](10_ARCHITECTURE.md), [40_COMMON_PATTERNS.md](40_COMMON_PATTERNS.md), and `crates/AGENTS.md`.
- CLI work: also read `crates/hasp-cli/AGENTS.md` and `docs/src/cli-reference.md`.
- Public API work: also read `crates/hasp/AGENTS.md`, `crates/hasp-core/AGENTS.md`, and the relevant tests.
- Docs-only work: read [20_PROJECT_MAP.md](20_PROJECT_MAP.md), [80_OPEN_QUESTIONS.md](80_OPEN_QUESTIONS.md), and [AI_CHANGELOG.md](AI_CHANGELOG.md).

## Minimum Checklist Before Editing Code

- Confirm the intended crate and feature set.
- Check for a local `AGENTS.md` in or above the path.
- Identify whether the change touches secret material, audit output, cache behavior, URL grammar, profile trust, proxy policy, or release/security policy.
- Inspect tests for the exact behavior before changing it.
- Do not modify `Cargo.lock`, add dependencies, or alter CI/release policy without explicit approval.
- Do not log secret values, lengths, hashes, prefixes, suffixes, or derived material.

## Repository Memory Model

Treat durable knowledge in this order:

1. Source code and tests.
2. Root `AGENTS.md` and local `AGENTS.md`.
3. `doc/ai/` onboarding docs.
4. `docs/src/` user docs and crate READMEs.
5. `docs/internal/research/` and `notes/` for research, plans, and historical context.

When these disagree, prefer source and tests, then record the disagreement in [80_OPEN_QUESTIONS.md](80_OPEN_QUESTIONS.md) instead of silently picking a side.

## Rules For Future AI Agents

- Keep `hasp-core` free of CLI/profile/TTY/config dependencies.
- Keep backend URL grammar inside backend crates.
- Preserve `SecretString` boundaries and redacted audit/error behavior.
- Keep CLI-specific behavior in `hasp-cli`; the library should remain useful independently.
- Keep backend crates feature-gated through `hasp` and `hasp-cli`.
- Never treat live cloud behavior as fully verified unless real-account tests were run and documented.
- Prefer deleting weak documentation claims over making them sound certain.

## Definition Of Done

- The change is scoped to the requested area.
- Relevant tests or checks were run, or skipped with a concrete reason.
- Public docs and AI docs are updated if behavior, commands, invariants, or architecture changed.
- Open questions are recorded rather than buried.
- No secrets or value-derived material appear in logs, test output, audit events, errors, or docs.

## Documentation Map

- [10_ARCHITECTURE.md](10_ARCHITECTURE.md): system overview and boundaries.
- [20_PROJECT_MAP.md](20_PROJECT_MAP.md): factual repo map.
- [30_DESIGN_RULES.md](30_DESIGN_RULES.md): practical rules and approval gates.
- [40_COMMON_PATTERNS.md](40_COMMON_PATTERNS.md): repeated implementation patterns.
- [50_TESTING_AND_COMMANDS.md](50_TESTING_AND_COMMANDS.md): command guide.
- [60_PERFORMANCE_NOTES.md](60_PERFORMANCE_NOTES.md): performance-sensitive areas.
- [70_GLOSSARY.md](70_GLOSSARY.md): project terms.
- [80_OPEN_QUESTIONS.md](80_OPEN_QUESTIONS.md): uncertainty and conflicts.
- [90_LOCAL_AGENT_PLAN.md](90_LOCAL_AGENT_PLAN.md): local `AGENTS.md` plan.
- [AI_CHANGELOG.md](AI_CHANGELOG.md): architecture-memory log.

## When To Update Which Doc

- Architecture or crate boundaries: update `10_ARCHITECTURE.md`, `20_PROJECT_MAP.md`, `30_DESIGN_RULES.md`, and `AI_CHANGELOG.md`.
- Commands, CI, test strategy, or toolchain: update `50_TESTING_AND_COMMANDS.md` and root `AGENTS.md`.
- Repeated implementation style: update `40_COMMON_PATTERNS.md`.
- Performance behavior or benchmarks: update `60_PERFORMANCE_NOTES.md`.
- New term, backend, feature, or acronym: update `70_GLOSSARY.md`.
- Unresolved conflict or risky assumption: update `80_OPEN_QUESTIONS.md`.
- Local guidance placement: update `90_LOCAL_AGENT_PLAN.md`.

## Known Limitations

- Commands in `50_TESTING_AND_COMMANDS.md` are mostly inferred from CI and manifests unless marked Verified.
- Live AWS/GCP/Azure/Vault behavior was not validated during this documentation pass.
- Existing `README.md`, crate READMEs, and `docs/src/*` contain some contradictions with source and tests.

## First Prompt For A New Codex Session

Read `AGENTS.md`, `doc/ai/00_READ_THIS_FIRST.md`, and the nearest local `AGENTS.md` for the files you will touch. Then inspect source and tests for the exact behavior. Keep changes scoped, preserve secret redaction invariants, and update `doc/ai/` when architecture or workflow knowledge changes.
