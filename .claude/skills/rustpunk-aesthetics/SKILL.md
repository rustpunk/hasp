---
name: rustpunk-aesthetics
description: "Design system for rustpunk.rs and the rustpunk ecosystem. Apply this skill whenever creating, styling, or reviewing any artifact branded as rustpunk — including web UI (HTML/CSS/React/Dioxus), Word documents (.docx), PDFs, SVG diagrams, presentations, or brand collateral. Triggers on: any mention of 'rustpunk', references to rustpunk.rs, Clinker docs, spall docs, dioxus-nox docs, or requests to style output in the rustpunk aesthetic. Also triggers when creating documents for any crate or project in the rustpunk ecosystem. Do NOT use for generic dark-theme styling unrelated to rustpunk."
---

# Rustpunk Aesthetics

Design system for rustpunk.rs and all crates in the ecosystem. Reference for Claude Code, Claude.ai artifacts, CLAUDE.md, and manual implementation. Covers web (HTML/CSS/React), documents (.docx/.pdf), and brand collateral.

## Philosophy

Rustpunk UI is the visual language of systems that work *despite themselves*. Every design choice communicates: this was built from salvage, it has survived exposure, and it still functions. Patina is proof of endurance, not neglect. Imperfection is intentional — uniformity implies fabrication capacity that doesn't exist in this world.

**Core rule**: if two adjacent elements look like they were manufactured together, something is wrong.

## Progressive Loading — Read Before Building

This skill uses progressive disclosure. **Do not rely on this file alone.** Before producing any output, load the reference files relevant to the task.

### Routing Table

| Task | Load these references |
|------|-----------------------|
| Any rustpunk output | `references/colors.md` (always) |
| Web UI — Oxide (default) | `references/typography.md` → `references/web.md` |
| Web UI — Blueprint sub-aesthetic | `references/typography.md` → `references/blueprint.md` |
| Web UI — Blueprint + Oxide hybrid | `references/typography.md` → `references/web.md` → `references/blueprint.md` |
| Word document (.docx) or PDF | `references/typography.md` → `references/documents.md` |
| SVG diagram or architecture visual | `references/colors.md` → `references/web.md` (SVG section) |
| Reviewing or auditing existing output | `references/anti-patterns.md` (+ `references/blueprint.md` anti-patterns section if blueprint) |
| Full system overview or onboarding | All files |

**Blueprint detection**: If the task involves the Blueprint sub-aesthetic — indicated by mention of "blueprint", verdigris accent, technical drawings, schematics, engineering diagrams, or drafting-paper aesthetic — always load `references/blueprint.md`. Blueprint has its own color overrides, typography, components, motion, and anti-patterns that supersede the oxide defaults in `web.md`.

**Minimum load for any task**: `colors.md` + the domain-specific file. Typography is required for both web and document work. Anti-patterns should be loaded for review tasks or when generating complex output.

### Reference Files

| File | Contents | Lines |
|------|----------|-------|
| `references/colors.md` | Full color system — web palette, document palette, contrast rules, sub-aesthetic mapping | ~80 |
| `references/typography.md` | Font stacks, weight/size scales (web + doc), rules, fallback chains, font embedding | ~80 |
| `references/web.md` | Oxide surface treatment, backgrounds/texture, motion, layout, component catalog, SVG diagrams, CSS variables template | ~240 |
| `references/blueprint.md` | **Full Blueprint sub-aesthetic** — teal-black color overrides, Share Tech Mono typography, engineering drawing components (corner marks, dimension lines, title blocks, numbered callouts, crosshair marks, dep pills, section headers, margin annotations), blueprint motion (blueprintIn, drawIn, fadeUp), anti-patterns, quick reference card | ~310 |
| `references/documents.md` | Document strategy, template architecture, page setup, cover page, headers/footers, heading styles, tables, code blocks, callouts, section dividers, maker's mark, color application, status indicators, lists, document variables | ~350 |
| `references/anti-patterns.md` | Web anti-patterns, document anti-patterns — the global "never do" list (blueprint has additional anti-patterns in its own file) | ~35 |

## Quick Color Reference

Use this for trivial tasks only. For any real output, load `references/colors.md`.

| Token | Hex | Role |
|-------|-----|------|
| `oxide-red` | `#B7410E` | Primary accent, brand color |
| `ember` | `#C75B2A` | Hover/active states |
| `bone` | `#C4A882` | Primary text (web) |
| `char` | `#0D0A08` | Primary background (web) |
| `doc-text` | `#1C1610` | Primary text (documents) |

## Quick Font Reference

| Font | Role |
|------|------|
| Saira Stencil One | Brand mark, hero titles, cover page title only |
| Chakra Petch | Section headers, UI labels, document headings |
| JetBrains Mono | Body text (web), code blocks (everywhere) |
| Calibri | Body text (documents only — fallback, not aesthetic) |

## Sub-Aesthetics

Three variants share the background scale but swap accent families. Never mix accents in the same component (with narrow exceptions — see blueprint cross-cutting rules).

| Variant | Accent | Body Font | Brand Mark | Use Case |
|---------|--------|-----------|------------|----------|
| **Oxide** (default) | `#B7410E` / `#C75B2A` | JetBrains Mono | Saira Stencil One | Landing pages, brand, cards |
| **Blueprint** | `#43B3AE` | Share Tech Mono | Dela Gothic One (outline) | Technical docs, schematics, drafting |
| **Phosphor** | `#D4A017` | VT323 | — | Terminal UIs, CRT, CLI output |

**Blueprint** is not just a color swap — it has its own background (teal-black + SVG grid paper, not warm char + noise grain), its own typography (Share Tech Mono, not JetBrains Mono), its own component vocabulary (corner registration marks, dimension lines, title block stamps, numbered callouts, crosshair center marks, dashed dep pills), its own motion (blueprintIn, drawIn), and its own anti-patterns. **Always load `references/blueprint.md` when building blueprint surfaces.**

Documents default to Oxide. Blueprint is for technical reference appendices. Phosphor is not used in documents.
