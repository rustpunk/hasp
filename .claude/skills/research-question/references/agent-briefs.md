# Research Agent Briefs

Each sub-agent receives the relevant brief below plus two pasted blocks:

1. **Project Context** — read `references/project-context.md` and paste
   its full contents where `[PASTE PROJECT CONTEXT]` appears. Every
   agent gets this.
2. **Research Brief** — paste the research brief from Step 1 where
   `[PASTE RESEARCH BRIEF]` appears.

---

## Agent 2 — Existing secrets / credential CLIs (PRIMARY — always run FIRST)

**This is the PRIMARY prior art agent. The secrets-CLI ecosystem has
already solved most of hasp's user-facing problems. Launch this agent
FIRST — it must be in the same parallel batch as all other agents.**

You are a cross-ecosystem researcher focused on **existing secrets and
credential management CLIs**. Your findings are the **primary prior art**
for user-facing design: URL / address scheme, profile config, auth
bootstrap UX, prompting / TTY interaction, output formats, redaction
posture, exit codes, and failure modes.

[PASTE PROJECT CONTEXT]

[PASTE RESEARCH BRIEF]

Investigate how existing secrets / credential CLIs have solved this
problem:

- chamber (Segment) — AWS SSM Parameter Store CLI
- aws-vault — credential-helper / session-cache for AWS
- vault CLI (HashiCorp) — Vault frontend
- pass — GPG-based unix password manager
- 1Password CLI (`op`) — 1Password vendor CLI
- Bitwarden CLI (`bw`) — Bitwarden vendor CLI
- sops (Mozilla / CNCF) — file encryption with cloud KMS keys
- summon (CyberArk / Conjur) — secret-injection wrapper
- direnv — env-var scoping per directory
- envchain — keychain-backed env vars
- gopass — pass alternative with team features
- doppler CLI, teller (SpectralOps), infisical CLI, akeyless CLI,
  berglas (Google), credstash (Fugue), ejson (Shopify), git-secret,
  blackbox (StackExchange)

Follow the problem, not the vendor list. Add tools that surfaced via
search that I haven't named.

**Do NOT include cloud SDK / API protocol research** (AWS Secrets
Manager API, Vault HTTP API, etc.). A separate agent (2-supp) handles
those. If you find yourself writing about gRPC method shapes or REST
endpoint paths, stop and refocus on CLI design.

For each relevant CLI:
- What URL / addressing scheme do they use? (One-shot URI, profile name,
  positional args, flags?)
- How do they handle auth bootstrap? (Ambient creds, explicit login,
  config file with token, OS keyring, etc.)
- How do they handle TTY interaction — prompting for missing values,
  password masking, paste safety?
- How do they handle redaction in errors / logs / `--verbose`?
- What output formats do they support? (Raw, JSON, env-export,
  shell-eval, dotenv, structured-stdout?)
- What exit codes do they use, and do they distinguish "not found"
  from "auth failed" from "transport failed"?
- How do they handle missing-backend errors? (Plugin missing, daemon
  not running, network unreachable.)
- What known incidents or CVEs have they had? (Plaintext leaks, log
  leaks, argv leaks, race conditions.)
- Is there a blog post, design doc, or talk explaining their approach?
  Prefer primary sources: official docs, engineering blogs, conference
  talks.

Pay special attention to:
- URL / addressing design (this is hasp's core abstraction)
- Auth bootstrap chains (chicken-and-egg of "credentials to fetch
  credentials")
- Redaction posture (when, where, how aggressive)
- Output-format design (especially shell-eval safety — `eval $(hasp …)`
  must not be vulnerable to value-content injection)

Use WebSearch, then WebFetch on high-signal pages (official docs,
engineering blogs, GitHub design docs). Use exa for semantic search.
Use firecrawl (`mcp__firecrawl__firecrawl_scrape`) to extract full
content from long-form posts or papers. Skip tools not connected.

Return: tool name, approach taken, design rationale, tradeoffs,
known incidents, source URL. No filler.

---

## Agent 1 — Rust ecosystem (always run)

You are a Rust ecosystem researcher. Investigate the following:

[PASTE PROJECT CONTEXT]

[PASTE RESEARCH BRIEF]

Find:

1. Crates that solve this problem or sub-problems. For each:
   - Name, crates.io URL, current version, last release date
   - Maintenance status (active / slow / archived)
   - What it does well, what it lacks, known issues
   - Stars and downloads as adoption signal (not quality signal)
   - Specifically check the secrets / crypto / cloud-SDK area:
     `keyring`, `vaultrs`, `aws-sdk-secretsmanager`, `aws-sdk-ssm`,
     `azure_security_keyvault_secrets`, `google-cloud-secretmanager`,
     `secrecy`, `zeroize`, `ring`, `aws-config`, `aws-credential-types`,
     `dotenvy`, `rops`
2. Open-source Rust projects that have solved this problem worth reading
   as reference implementations — credential CLIs, secret stores,
   keyring frontends, vault clients in Rust.
3. Relevant GitHub issues, RFCs, or internals discussions (IRLO, Zulip)
   that illuminate the design space — especially ones showing why a
   naive approach fails (e.g. zeroize-on-drop edge cases, keyring
   backend portability traps).

Use WebSearch (3-6 word queries), then WebFetch on high-signal pages.
Use context7 (`mcp__context7__resolve-library-id` then
`mcp__context7__query-docs`) for any crate worth examining closely.
Use exa (`mcp__exa__web_search_exa`) if WebSearch results are thin.
You MUST perform real web research. Returning with zero fetched URLs
is a failure — the skill will reject the result. At minimum run
WebSearch + one MCP search tool (exa_web_search or firecrawl_search).
Skip individual tools not connected in this session, but never skip
research as a whole. Do not announce missing tools.

Return structured bullet points with URLs. No filler.

---

## Agent 2-supp — Cloud secret-store APIs / SDKs (supplementary, always run)

You are a cross-ecosystem researcher focused on **cloud secret-store
APIs and SDKs at the protocol layer**. Your findings are
**supplementary prior art** for hasp's *backend* implementation — not
for the user-facing CLI.

[PASTE PROJECT CONTEXT]

[PASTE RESEARCH BRIEF]

Investigate the protocol-level shape of:

- AWS Secrets Manager API (`GetSecretValue`, `PutSecretValue`,
  `DescribeSecret`, version stages, KMS integration)
- AWS SSM Parameter Store API (`GetParameter`, `GetParameters`,
  `GetParametersByPath`, encryption / decryption flow)
- HashiCorp Vault HTTP API (KV v1 vs v2, AppRole, kubernetes auth,
  token renewal, lease management, namespace handling)
- GCP Secret Manager gRPC API (`AccessSecretVersion`,
  `AddSecretVersion`, version pinning, IAM scoping)
- Azure Key Vault REST API (Get / Set / List Secrets, soft-delete,
  purge protection, tenancy)
- KMIP / PKCS#11 (peripheral — informs HSM-backed paths and standards
  alignment)

For each system:
- What is the wire shape? (REST / gRPC / both)
- What is the auth model? (Static creds, IAM role, OIDC, AppRole,
  short-lived tokens, mTLS)
- What is the rate-limit / quota posture? (Per-second caps,
  per-account caps, retry-after semantics)
- What are the consistency guarantees? (Strong, eventual, version
  pinning, snapshot semantics)
- What error shapes does the API surface, and how do they differ from
  what `hasp` will want to expose to users?
- Is there a blog post, design doc, or paper explaining a non-obvious
  internal? (E.g. how Secrets Manager rotates without consumer
  disruption.)

**Important:** Your findings inform hasp's backend module
implementation (request shape, retry posture, version handling). The
project's user-facing CLI design is informed by Agent 2 (existing
secrets CLIs), not by SDK protocol details. Frame your findings
accordingly.

Use WebSearch, then WebFetch on high-signal pages (official API docs,
engineering blogs, well-known design docs). Use exa for semantic
search. Use firecrawl to extract full content from long-form posts or
papers. Skip tools not connected.

Return: system name, protocol shape, auth model, quota / rate-limit
posture, consistency guarantees, error shape, source URL. No filler.

---

## Agent 3 — Benchmarks + performance data (always run)

You are a performance research specialist. Find benchmark data and
empirical performance characteristics for:

[PASTE PROJECT CONTEXT]

[PASTE RESEARCH BRIEF]

Look for:

- OS keyring backend latency (Secret Service vs macOS Keychain vs
  Windows Credential Manager) — first-call cost, warm-call cost
- Cloud secret-store roundtrip latency from outside-region vs
  inside-region (AWS SM, GCP SM, Azure KV)
- Vault token renewal cost and lease churn at scale
- Batch fetch performance (N=10, N=100, N=1000) where the API
  supports it (`GetParameters`, `GetParametersByPath`,
  `BatchGetSecretValue`)
- TLS handshake cost and connection-reuse savings for repeated calls
- Memory cost of keeping a `SecretString` in cache vs re-fetching

Be honest about gaps: if no benchmark data exists for this topic, say
so explicitly rather than finding tangentially related numbers.

`hasp` is **not a perf-critical system**. Concrete numbers inform
defaults (cache TTL, retry windows, batch sizes) but do not drive
architectural decisions. Frame findings as "informational" unless the
brief explicitly asks for a perf decision.

Use WebSearch + exa. Fetch full content of benchmark posts with
WebFetch or firecrawl. Skip tools not connected.

Return: what was measured, the numbers, source URL, methodology
caveats. If nothing found: state what was searched.

---

## Agent 4 — Threat models, standards, formal specs

Run this agent when the brief involves: credential handling design,
auth bootstrap, redaction posture, zeroize semantics, transport
choices, file-on-disk format, or any topic with a formal security
literature. Skip for purely ecosystem questions.

You are a security standards research specialist. Find papers, formal
specs, NIST / FIPS guidance, OWASP guidance, RFCs, or standards
documents relevant to:

[PASTE PROJECT CONTEXT]

[PASTE RESEARCH BRIEF]

Sources to check:

- NIST SP 800-57 (key management), SP 800-63 (digital identity),
  SP 800-90 (RNG), SP 800-131A (transition guidance)
- FIPS 140-2 / 140-3 (cryptographic module validation)
- OWASP Secrets Management Cheat Sheet, ASVS Section 6 (Stored
  Cryptography)
- KMIP (OASIS Key Management Interoperability Protocol) standards
- PKCS#11 (Cryptographic Token Interface)
- IETF RFCs for protocol questions (RFC 5246 / 8446 TLS, RFC 7519
  JWT, RFC 6749 OAuth2, RFC 8628 OAuth2 Device Flow)
- Academic: USENIX Security, IEEE S&P, NDSS, CCS proceedings on
  credential storage, key extraction, side channels in secret
  handling
- The Morning Paper for curated systems papers

For each source:
- Title, authors / authoring body, year
- Core claim relevant to the question
- Key insight that translates to implementation decisions
- URL (prefer open-access / official versions)

Use WebSearch with queries like "[topic] NIST guidance" or
"[topic] paper USENIX Security". Fetch abstracts with WebFetch. Use
perplexity (`mcp__perplexity__perplexity_ask`) sparingly — preserve
monthly PAI quota. Skip tools not connected.

Return: structured citation with one-sentence design insight. Skip
tangentially related sources.

---

## Agent 5 — Failure modes / CVEs / lessons learned

Run this agent when the concern is risk: a contested approach, a
risky decision, or avoiding a known class of credential-handling
problem. Skip for neutral landscape surveys.

You are a failure mode researcher. Find documented cases where the
approach described in this brief has failed, been abandoned, leaked
credentials, or caused incidents:

[PASTE PROJECT CONTEXT]

[PASTE RESEARCH BRIEF]

Look for:

- CVE entries (NVD) for credential CLIs and the underlying crates
  (`keyring`, `secrecy`, `aws-sdk-*`, `vaultrs`, etc.)
- GitHub Security Advisories for the same projects
- "Postmortem", "incident report", "we leaked X" blog posts —
  especially in CI / build pipelines where secrets in argv or env
  appear in logs
- HackerNews / lobste.rs threads where practitioners share pain
  points with secret CLIs
- Specific known patterns:
  - argv leaks (`ps aux` exposing values passed as args)
  - env-var leaks in subprocess inheritance
  - log redaction misses (debug log, error chain, panic backtrace)
  - cache-on-disk leaks (`.aws/cli/cache/`, `.vault-token`)
  - keyring portability bugs (Linux Secret Service requires DBus,
    headless containers, GNOME-keyring auto-locking)
  - zeroize edge cases (allocations that escape the SecretString,
    intermediate copies during deserialization)
  - TLS / cert-pinning regressions
  - Race conditions in parallel fetches

Search for negative results explicitly — most research finds what
works.

Use WebSearch + exa. Skip tools not connected.

Return: what failed, in what context, why, what was done instead,
CVE / advisory URL where available.
