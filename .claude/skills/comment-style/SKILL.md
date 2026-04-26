---
name: comment-style
description: Rust comment discipline for the hasp crate. Prefer WHY over WHAT; short WHAT is okay when it adds precision the signature can't express (invariants, units, sync vs async, redaction posture, secret lifetime, threat-model boundaries). Ban ephemeral process references — phase/task/wave/drill labels, locked-decision codes, internal-doc paths. Auto-invokes when writing, editing, or reviewing any .rs file. Triggers on: rust comment, /// doc comment, //! module doc, rustdoc, code comment, comment review, writing Rust.
allowed-tools: Read, Edit, Write, Grep, Glob, Bash
---

# Comment style

## Core principle (Ousterhout)

Comments are an **abstraction mechanism**. A public item's doc comment is
the abstraction its callers see; if the comment is absent or wrong, the
abstraction leaks. Code tells you *how*. Comments tell you *why* — and,
when useful, *what* at a higher level of precision than the signature can
express. If you feel the need to comment a block to make it
understandable, refactor the block first (Fowler's "comments as
deodorant").

## The rules

1. **Public item summary (`///`).** Every `pub` item gets a one-sentence
   summary in third-person present indicative ("Returns", not "Return").
   Skip only when the summary would just restate the identifier and type
   — those are rustdoc noise, not discipline. *(rustdoc book; RFC 505.)*

2. **Failure sections.** Include `# Errors` on `Result`-returning
   functions, `# Panics` on functions that may panic, `# Safety` on
   `unsafe fn`. *(Rust API Guidelines C-FAILURE.)*

3. **`//!` is module/crate-only.** Never use `//!` for anything else.
   Earn its keep only when it frames a subsystem or lists invariants that
   span multiple items. Delete `//!` blocks that just restate the module
   path. *(rustdoc book; rustc-dev-guide.)*

4. **Prefer WHY over WHAT.** Comments explain *why* the code is the way
   it is. *(Ousterhout ch.13; Linux kernel ch.8; Stack Overflow blog.)*

5. **Short WHAT is allowed when:**
   - It adds precision the signature can't express (invariants, units,
     ownership, streaming vs blocking, memory model, complexity,
     thread-safety).
   - It orients a reader to a non-obvious idiom so the next reader
     doesn't "simplify" it into a bug. *(Stack Overflow rule 5.)*
   - It's the project-specific rule: public secret-handling items document
     redaction posture (Debug-safe?), zeroize-on-drop semantics, whether
     the value crosses a process boundary, and which backend it came from.

6. **Ban ephemeral process references in source AND in commit messages.**
   Commit messages are public on GitHub; the artifacts they point at are
   not. Same ban applies to both:
   - Phase / task / wave / drill-pass labels: `Phase 2`, `Task 1.4.3`,
     `Wave 1.5`.
   - Locked-decision codes (`LD-001`, etc.) — encoded shorthand belongs
     in the artifact that defines it, not in source.
   - Paths into gitignored planning artifacts: `docs/internal/research/*`,
     `docs/internal/plans/*`, any `*-LOG.md` / `LOCKED-DECISIONS.md`.

   *(Sveljko, "No ticket numbers in comments"; SE.SE consensus.)*

7. **Allowed references.** Stable public artifacts: RFC numbers, CVEs,
   vendor-bug URLs, published spec sections, GitHub issue URLs on
   upstream crates. Cite the URL, not a ticket ID. *(Stack Overflow
   rule 7.)*

8. **No deletion tombstones.** When you remove code, remove it. Don't
   leave `// X was removed because Y` / `// See RIP-LOG` / `// Replaced
   by Z` residue. The commit message is the record. *(Project rule;
   global CLAUDE.md.)*

9. **No unlinked `TODO`s.** A bare `TODO` with no tracked issue and no
   owner is noise. Either track it and cite a stable URL, or don't merge
   it. *(Fowler; Horm Codes.)*

10. **If the block needs a comment to be understood, refactor first.**
    Rename the function, extract a helper, tighten the type — then see
    whether the comment is still needed. *(Fowler; Linux kernel ch.8.)*

## Before / after

### Pure process noise → delete

```rust
//! Phase 2 end-to-end integration tests for AWS Secrets Manager.
```
↓
```rust
//! End-to-end integration tests for AWS Secrets Manager.
```

### Mixed: phase label + load-bearing WHY → rewrite (keep the WHY)

```rust
// Wave 1.5 / Task 4.2: cache layer wraps the resolver. Returns Hit
// even when the underlying backend has rotated the secret, because we
// pin to version-at-fetch-time per LD-007 in the credential policy
// doc. Caches sit in front of every backend; see RESOLVER-NOTES.md
// for the staleness window decision.
```
↓
```rust
// Cache layer wraps the resolver and pins to version-at-fetch-time —
// a rotated upstream secret returns the cached value until the entry
// expires, on purpose. Callers needing freshness must invalidate
// explicitly. Pinning prevents partial-rotation glitches across
// multi-secret fetches in one CLI invocation.
```

### Build-once invariant → keep the invariant, drop the drill code

```rust
// Backend dispatch table (D12 / Task 3.1.4). Built once at startup,
// shared by every URL parse below.
```
↓
```rust
// Backend dispatch table: built once at startup, shared by every URL
// parse below. Cheap to clone — backends are `Arc<dyn Backend>`.
```

### Gitignored research-doc path → inline the key insight or delete

```rust
//! See `docs/internal/research/RESEARCH-vault-token-renewal.md`
//! (Approach B) and `docs/internal/research/RESEARCH-aws-sdk-credential-chain.md`
//! for the reasoning.
```
↓
```rust
//! Vault tokens are renewed lazily on the first 403 inside a TTL
//! window; AWS uses the SDK's default credential chain unmodified.
//! See backend modules for renewal-edge cases.
```
Or, if the key insight is already expressed in the surrounding code,
just delete the block.

### Tombstone → just remove

```rust
// Ripped in wave 1.5. See REFACTOR-LOG.md.
// Legacy KeyringOnlyResolver / SimpleProfile / FlatConfig deleted.
// Resolution now handled by Resolver::resolve() in resolver.rs.
```
↓
**Delete the file entirely** (if the file is only a tombstone), or delete
the comment block (if legitimate content remains). The git history is
the record.

## Positive examples (target patterns)

Preserve patterns like these — they are what comments should look like:

```rust
// SecretString wraps the raw bytes so Debug never prints the value
// and Drop zeroizes the buffer. Anything that escapes this module
// MUST stay inside SecretString — leaks here become CVEs.
```
Threat boundary named, redaction posture stated. No process label.

```rust
// Vault token renewal is lazy: we only refresh on the first 403
// inside the renewal window. Eager refresh would multiply token
// renewals across short-lived CLI invocations.
```
Defense-in-depth rationale, concrete and self-contained.

```rust
// AWS Secrets Manager returns SecretString for text and SecretBinary
// for bytes — we route by `Value` variant rather than asking the API
// for both. Asking for both costs two GetSecretValue calls per fetch.
```
Cost model named, choice justified.

## Banned-pattern regex (grep your own diff before committing)

```text
\bPhase\s+\d+[a-z]?\b
\bTask\s+\d+[a-z]?\.\d+(\.\d+)*\b
\bWave\s+\d+(\.\d+)?\b
\bD\d{2,3}\b          # drill codes
\bQ\d+\s*=            # drill-remediation labels
\bLD-\w+\b
\bhard-gate\b
\bdrill pass\b
\bdrill remediation\b
docs/internal/research/
docs/internal/plans/
RIP-LOG
REFACTOR-LOG
LOCKED-DECISIONS
```

Workspace grep before commit:

```bash
rg -n --type rust '^\s*(///?|//!).{0,400}$' | \
  grep -Ei '(\bPhase\s+\d|\bWave\s+\d|\bTask\s+\d|docs/internal|RIP-LOG|REFACTOR-LOG|LOCKED-DECISIONS|\bLD-\w|hard-gate|drill pass|\bD\d{2,3}\b)'
```

Zero hits is the gate.

## When you feel the need to cite a phase

Don't. **Distill the reasoning behind that phase item and write *that*
into the comment or commit message.** The phase label is a pointer to a
real rationale; replace the pointer with the rationale. A reader on
GitHub must be able to understand the change without access to any
internal doc.

Examples:

- Instead of `// LD-007: pin to version-at-fetch-time` → `// Pin to
  version-at-fetch-time so a multi-secret fetch in one CLI invocation
  can't see a partial rotation.`
- Instead of `// Wave 1.5 cache layer added this` → explain *what the
  decision actually was*: `// Cache TTL is 60s by default — long enough
  to absorb a fetch loop, short enough that an explicit rotation is
  visible within a minute.`
- Instead of commit message `feat(wave-1.5): 1.5.2 add Vault backend` →
  `feat(vault): add Vault KV v2 read/write with token-renewal-on-403`.

## Scope

Applies to `.rs` files in the workspace's crates, integration tests
under `tests/`, benchmarks under `benches/`, and any Rust files under
`examples/`. Does **not** apply to markdown under `docs/`, YAML/TOML
fixtures, or this skill's own doc. Does **not** rename test functions
or files — renaming breaks `cargo test --filter` workflows; handle
renames in a separate, scoped task if ever needed.

## Sources

- [Rust API Guidelines — Documentation](https://rust-lang.github.io/api-guidelines/documentation.html)
- [rustdoc book — How to write documentation](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html)
- [RFC 505 — API comment conventions](https://rust-lang.github.io/rfcs/0505-api-comment-conventions.html)
- [rustc-dev-guide — Conventions](https://rustc-dev-guide.rust-lang.org/conventions.html)
- Ousterhout, *A Philosophy of Software Design*, ch. 12–15.
- Kernighan & Pike, *The Practice of Programming*, ch. 1.
- Fowler, *Refactoring* — "Comments as deodorant".
- [Linux kernel coding-style ch. 8](https://www.kernel.org/doc/html/latest/process/coding-style.html)
- [Stack Overflow blog — Best practices for writing code comments](https://stackoverflow.blog/2021/12/23/best-practices-for-writing-code-comments/)
- [Sveljko — No ticket numbers in comments](https://sveljko.github.io/no_ticket_numbers_in_comments/)
