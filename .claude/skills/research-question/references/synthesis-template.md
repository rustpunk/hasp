# Research Synthesis Template

Use this template to structure findings after all sub-agents return.
Synthesize around the core question, not around sources. Do not present
findings as "Agent 1 found X" — present as "the ecosystem shows
[pattern]."

---

## Research Findings: [Core question]

**Research date:** [date]
**Brief:** [one-sentence summary of what was researched]
**Saved to:** docs/internal/research/RESEARCH-[slug].md

---

### The landscape

[2-3 paragraphs synthesizing what the ecosystem looks like for this
problem. Name specific tools, crates, and systems. Note consensus where
it exists and genuine disagreement where it doesn't. Resolve
contradictions explicitly: if two sources disagree, name both and
explain why they diverge.]

**Existing-CLI findings (Agent 2)** must be given equal or greater
weight than cloud SDK / API findings (Agent 2-supp) for any question
that touches **user-facing CLI design**. If existing CLIs show a
different pattern than the underlying SDKs, lead with the CLI pattern —
it is closer to hasp's user surface.

---

### Approach A: [Name]
**Used by:** [tools / projects using this approach]
**How it works:** [concrete mechanism, not hand-wavy description]
**Strengths:**
- [specific, evidence-backed]
**Weaknesses / failure modes:**
- [specific, evidence-backed]
**Rust crates:** [if applicable, with maintenance status]
**Security implications:** [redaction posture, secret lifetime, threat
boundary it crosses, any known CVE / advisory in this space]
**Source:** [URL]

### Approach B: [Name]
[same structure]

### Approach C: [Name] (if applicable)
[same structure]

---

### Benchmark data

[Concrete numbers if found. "No benchmark data found for [topic] —
searched [what was searched]" if not. Never omit this section. Frame as
informational unless the brief explicitly asks for a perf decision.]

---

### Threat-model / standards anchors

| Source | Year | Body | Relevant insight | URL |
|--------|------|------|-----------------|-----|

[Include this section whenever the question touches credential
handling, redaction, transport, or auth bootstrap. Omit only for
purely-ergonomic questions.]

---

### Failure modes / CVEs to avoid

- [Specific failure mode]: [what causes it, who hit it, CVE / source URL]

[Omit if Agent 5 was not run and no failure modes surfaced. For
security-shaped questions, surfacing zero failure modes is itself a
finding worth stating explicitly.]

---

### Design insights for hasp

[3-5 bullet points translating findings into actionable guidance for
hasp specifically. This is mandatory — not optional commentary. Connect
each insight back to concrete constraints: the URL addressing scheme,
feature-gated backends, pure-Rust default, rustls-only TLS, secrecy +
zeroize discipline, redaction posture, exit codes. Generic research
that doesn't connect back to hasp is incomplete.]

---

### Decision criteria (enforced)

This is a **greenfield project with zero users and zero deployments**.
The following are **NOT valid factors** in the recommendation:

- Implementation complexity or effort
- Number of files touched or scope of change
- Breaking change risk (there are no consumers to break)
- "Pragmatic" or "incremental" alternatives that compromise architecture
  or weaken security
- Difficulty of the refactor

The **ONLY valid criteria** are:

- Architectural correctness (unified-CLI abstraction, no backend-leak
  into user surface)
- Threat-model soundness (secret lifetime, redaction, zeroize, no log /
  error / debug leaks)
- Long-term maintainability of the correct design
- Alignment with rustpunk identity (pure-Rust default, rustls-only,
  feature-gated backends, parallel to ferrule)

If an approach is architecturally correct but requires a large refactor,
that is a **point in its favor** (get it right now while there is no
debt), not a reason to defer. Security-sensitive code is particularly
hostile to "fix it later."

---

### Recommendation

**Approach:** [which approach or crate the research points toward]
**Confidence:** High / Medium / Low
**Rationale:** [2-3 sentences citing specific evidence — not opinion.
Name the source. Do NOT cite complexity, effort, or breaking-change
risk as factors.]
**Key risk:** [the one thing most likely to bite even with this
approach]
**Threat-model note:** [the security invariant this approach preserves
or threatens; required for any credential-handling decision]
**If wrong:** [what to try next if this recommendation turns out to be
mistaken]
**Rejected alternatives:** [name any expedient / shortcut options that
were considered and rejected. State the architectural or
threat-model reason for rejection. "Too complex" and "too much effort"
are NOT valid rejection reasons in this project — only "architecturally
inferior" or "weakens the threat model" qualifies.]

---

### Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| [name] | crate / project / paper / CLI / advisory / post / issue / RFC | [which decision it informed] | [url] |
