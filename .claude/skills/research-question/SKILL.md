---
name: research-question
description: "Structured research skill for informed technical decision-making in hasp. Investigates secrets / credential CLIs (chamber, aws-vault, vault CLI, pass, 1Password CLI, Bitwarden CLI, sops, summon, direnv, envchain, gopass, doppler, teller, infisical, akeyless, berglas), Rust crates (keyring, vaultrs, aws-sdk-secretsmanager, secrecy, zeroize), cloud secret-store APIs (AWS Secrets Manager, AWS SSM, HashiCorp Vault HTTP, GCP Secret Manager, Azure Key Vault), threat models, NIST/FIPS guidance, benchmarks, GitHub issues, RFCs, blog posts, and security advisories. Adapts to a topic, a specific task from a phase file, or the current conversation context. Output feeds directly into impl-planner, design decisions, or any ad-hoc choice. Saves findings to docs/internal/research/RESEARCH-<slug>.md. Triggers on: research, prior art, look this up, how does X handle Y, what does the ecosystem do for Z, research before I decide, threat model X, has anyone done Y."
argument-hint: "topic, question, or task reference (optional -- infers from context if omitted)"
allowed-tools: Read, Write, Glob, Bash, Task, WebFetch, WebSearch, AskUserQuestion, mcp__exa__web_search_exa, mcp__exa__web_fetch_exa, mcp__Ref__ref_search_documentation, mcp__Ref__ref_read_url, mcp__firecrawl__firecrawl_search, mcp__firecrawl__firecrawl_scrape, mcp__firecrawl__firecrawl_extract, mcp__firecrawl__firecrawl_crawl, mcp__firecrawl__firecrawl_map, mcp__context7__resolve-library-id, mcp__context7__query-docs, mcp__plugin_context7_context7__resolve-library-id, mcp__plugin_context7_context7__query-docs
---

# research

## ⛔ MANDATORY PRE-FLIGHT: SECRETS-CLI AGENT REQUIRED — NO EXCEPTIONS

**Before spawning ANY research agents, confirm ALL of the following:**

1. ✅ Agent 2 (existing secrets / credential CLIs) prompt is WRITTEN and READY
2. ✅ Agent 2 is in the SAME parallel `Agent()` batch as Agents 1, 2-supp, 3
3. ✅ Agent 2 prompt names specific secrets CLIs (chamber, aws-vault, vault CLI, pass, op, bw, sops, summon, direnv, envchain, gopass, doppler, teller, infisical, akeyless, berglas, etc.)
4. ✅ Agent 2 prompt explicitly distinguishes secret-CLI prior art from cloud-vendor SDK protocol research

**If ANY of these are unchecked, STOP. Do not proceed. Fix it first.**

This is not optional. Existing secrets CLIs are the **PRIMARY prior art**
for hasp — they have already solved URL addressing, profile config, auth
bootstrap, prompting, redaction, and exit codes. Cloud SDK / API research
(Agent 2-supp) is supplementary and informs *backend implementation*, not
*user-facing CLI design*. Do not collapse them into one agent.

---

Structured technical research producing decision-ready findings. Casts a
wide net: existing secrets / credential CLIs, Rust crates, cloud
secret-store APIs, benchmarks, RFCs, security advisories, NIST / FIPS
guidance, blog posts, and academic papers.

**Process: Detect → Scope → Research (parallel) → Synthesize → Output**

**Reference files** (read when indicated, not upfront):
- `references/project-context.md` — hasp's scope, threat model, and
  decision criteria; read before spawning agents
- `references/agent-briefs.md` — full sub-agent briefs; read before
  spawning
- `references/synthesis-template.md` — output format; read before
  synthesizing

---

## Step 0: Detect the research trigger

**Existing plan files:**
```
!`find docs/internal/plans -name "phase-*.md" 2>/dev/null | sort || echo "(none)"`
```

**Argument received:** `$ARGUMENTS`

| Situation | Action |
|-----------|--------|
| `$ARGUMENTS` contains a task reference (e.g. "Task 2.3", "phase 1 task 4") | Read the phase file, extract that task's description and implementation notes as the research brief |
| `$ARGUMENTS` contains a topic or question | Use it directly |
| `$ARGUMENTS` empty, clear question in conversation | Extract the question; state it explicitly before proceeding |
| `$ARGUMENTS` empty, ambiguous context | Ask: *"What should I research?"* |

---

## Step 1: Scope the research

Before spawning sub-agents, define the brief explicitly. Do not skip this.
A focused brief produces far better findings than a vague one.

```
## Research Brief

Core question:   [The specific decision or understanding this serves]
Why it matters:  [What will be decided or unblocked]
Scope:           [Problem domain -- not specific tools]
Out of scope:    [What to ignore to avoid rabbit holes]
Consumer:        [impl-planner / design-decision / ad-hoc]
Security lens:   [Threat-model concerns this research must address]
```

For task-based research also include:
```
Source task:     Phase [N], Task [N.X] -- [name]
Key decisions:   [what the task is trying to decide]
```

If the scope is very broad, narrow it first with `AskUserQuestion` before
researching. Vague briefs waste sub-agent cycles.

---

## Step 2: Parallel research

**Read `references/agent-briefs.md` now.** It contains the full brief for
each agent. **Also read `references/project-context.md`** and paste its
contents into every agent prompt where `[PASTE PROJECT CONTEXT]` appears
(as instructed in the briefs file). Then paste the research brief from
Step 1 where `[PASTE RESEARCH BRIEF]` appears.

### Which agents to run

Always run Agents 1, **2**, 2-supp, and 3 concurrently. Add Agents 4
and 5 based on the brief:

| Agent | Focus | Run when | Priority |
|-------|-------|----------|----------|
| **2 — Existing secrets / credential CLIs** | **chamber, aws-vault, vault CLI, pass, op, bw, sops, summon, direnv, envchain, gopass, doppler, teller, infisical, akeyless, berglas** | **ALWAYS** | **PRIMARY** |
| 1 — Rust ecosystem | Crates, Rust reference projects, GitHub issues/RFCs | Always | |
| 2-supp — Cloud secret-store APIs / SDKs | AWS SM API, AWS SSM API, Vault HTTP API, GCP SM gRPC, Azure KV REST | Always | Supplementary |
| 3 — Benchmarks | Concrete latency / throughput numbers, profiling data | Always | |
| 4 — Threat models / standards | NIST SP 800-57, FIPS 140-2/3, OWASP secrets cheat sheet, KMIP, papers | Question is security-design-shaped | |
| 5 — Failure modes / CVEs | What has failed, been abandoned, leaked credentials, caused incidents | Decision is risky or contested | |

**Agent 2 (existing CLIs) is listed FIRST because it is the PRIMARY prior
art. The secrets-CLI ecosystem has 10+ years of design lessons that hasp
can lean on. Cloud SDK research (Agent 2-supp) is for backend internals,
not for CLI surface design.**

**Spawn all applicable agents simultaneously. Never run sequentially.**

**Agent 2 and 2-supp MUST be separate agents.** Do not combine existing
CLIs and cloud SDK protocol research into one agent — protocol findings
crowd out CLI design findings every time. Agent 2 (CLIs) is the primary
prior art source; Agent 2-supp (SDKs / APIs) is supplementary.

### MANDATORY tool access for every spawned research agent

When spawning each sub-agent via the Task tool, you MUST explicitly grant
it web/doc research tools in the prompt. Sub-agents do NOT inherit MCP
tool access automatically — if you don't tell them which tools to use,
they will return zero-source "research" and claim success. This has
happened before and is unacceptable.

Include this block verbatim at the top of every research sub-agent prompt:

```
REQUIRED TOOLS — you have access to all of the following. You MUST use
at least WebSearch plus one MCP search tool (exa or firecrawl) before
returning. Returning findings with zero fetched URLs is a failure.

- WebSearch, WebFetch                    — baseline web search + fetch
- mcp__exa__web_search_exa               — semantic web search
- mcp__exa__web_fetch_exa                — fetch + clean page content
- mcp__firecrawl__firecrawl_search       — search with full-page extraction
- mcp__firecrawl__firecrawl_scrape       — scrape long-form posts/papers
- mcp__firecrawl__firecrawl_extract      — structured extraction
- mcp__Ref__ref_search_documentation     — official docs search
- mcp__Ref__ref_read_url                 — read doc URL
- mcp__context7__resolve-library-id      — find a library in context7
- mcp__context7__query-docs              — query current library docs

If a specific tool is not connected this session, skip it silently and
use the others. Do NOT skip research because "tools unavailable" — at
least WebSearch is always available.

Every claim in your return must cite a URL you actually fetched. No URL
= not a finding.
```

Each agent skips individual tools not connected without announcing it,
but MUST still perform real research using whatever is available.

---

## Step 3: Synthesize

**Read `references/synthesis-template.md` now.** Use it to structure the
combined findings. Key rules:

- Synthesize around the **core question**, not around which agent found what
- Every claim must be traceable to a source in the bibliography
- "Design insights for hasp" section is **mandatory** — translate findings
  into guidance specific to what is being built
- Resolve contradictions explicitly: name both sources, explain the divergence
- "No benchmark data found" is a valid finding — never omit the section
- Security implications are mandatory when the research touches credential
  handling, redaction, transport, or auth bootstrap
- Perplexity is last resort — preserve monthly PAI quota

---

## Step 4: Write and present

```
!`mkdir -p docs/internal/research`
```

Write to `docs/internal/research/RESEARCH-[slug].md` (2-4 word kebab-case slug).

Present the full synthesis inline — do not just confirm the file was
written. The user needs to read the findings immediately to act on them.

Use `AskUserQuestion` with "Where to next?" and options derived from the
findings — make each option specific to what the research actually
surfaced:

- Option A: the most natural follow-on (e.g. "Apply Approach B to Task 2.3")
- Option B: a related open question surfaced by the research
- Option C: "Run /impl-planner with these findings in context"
- Option D: "Your call — redirect me or give new instructions"
