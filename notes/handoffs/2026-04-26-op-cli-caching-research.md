# Handoff: op-cli-caching-research

Written: 2026-04-26 05:21 EDT on branch `main` (HEAD: dd0ede3).
Resume with: "Read /home/glitch/code/rustpunk/hasp/notes/handoffs/2026-04-26-op-cli-caching-research.md. Continue from the 'Exact next action' section."

## 1. Commits landed this session

No commits — research-only session. The single artifact is unstaged in the working tree (see §5).

## 2. Architectural decisions locked in

- **`op://` Wave 2 backend will subprocess-wrap `op` directly via `std::process::Command`.** Connect HTTP and FFI to Python SDK shared lib both rejected for Wave 2. Codified in `docs/internal/research/RESEARCH-op-cli.md` §5.
- **`op://` will produce `Error::{NotFound, AuthenticationFailed, Backend{Transient|Throttled|Permanent}}` only.** `Error::PermissionDenied` is unreachable from `op read` — 1Password's server returns 404 for both missing-and-no-permission, and `op` faithfully reflects this. Mirrors the Vault precedent in `RESEARCH-error-taxonomy.md` §Design insights point 3. Codified in `RESEARCH-op-cli.md` §1.5 + §5.1.
- **`exists` will use `op item list --vault VAULT --format=json`, not `op item get`.** `op item get --format=json` includes the field `value` strings even when called for metadata — `--reveal` only conceals human-readable output, not JSON. `op item list` returns title-grade metadata only and never crosses secret material into hasp's address space. Codified in `RESEARCH-op-cli.md` §5.3.
- **Stderr is parsed by case-insensitive substring match on stable noun phrases** (not full sentences); unmatched stderr falls through to `Backend{Permanent}`, never to `NotFound`. Pin minimum `op` version ≥ 2.30.0. Codified in `RESEARCH-op-cli.md` §2 + §5.2 + §5.5.
- **In-process secret caching is deferred to a separate research note.** Cache design touches the redaction posture (cached secrets are a new boundary), interacts with mlock decisions (also deferred), and merits its own decision pass before implementation. Codified in `RESEARCH-op-cli.md` §5.10.

## 3. Open blockers

- **Blocker:** `RESEARCH-op-caching.md` does not yet exist. The `op://` Wave 2 backend can ship without it (uncached path is the v0 default), but the cache is an explicit follow-on per `RESEARCH-op-cli.md` §5.10 and the latency baseline (§1.8) makes a strong case for it (raw `op read` is 700ms–2s; `op-fast` shows 90× speedup with OS-keyring cache).
- **Proposed resolution:** invoke `/research-question` with the brief outlined in §4.
- **Evidence:** `docs/internal/research/RESEARCH-op-cli.md` §1.8 (latency table) and §5.10 (deferral list).

## 4. Exact next action

Invoke `/research-question` with this brief verbatim:

> Research the design space for an in-process secret cache for hasp's `op://` backend (and potentially other backends). Output: `docs/internal/research/RESEARCH-op-caching.md`.
>
> Core question: should hasp's `op://` backend ship a caching layer? If yes, what backend (OS keyring vs in-RAM only vs encrypted file), what TTL policy, what cache key, what scope, what invalidation rules, what threat-model boundary, what library-API exposure?
>
> Why it matters: raw `op read` is 700ms–2s per call; CI workflows fanning 5–20 secrets eat 5–40s just on auth handshake. Existing prior art (`op-fast` 90× speedup with OS keyring; `op-cache` daemon with in-RAM 1–2ms hits) shows the speedup is large and the implementation space is small but contested.
>
> Eight open design questions to investigate:
>   1. Cache backend: OS keyring vs in-RAM only vs encrypted file. Tradeoffs in offline access, restart survival, redaction posture, attack surface.
>   2. TTL policy: single global vs per-URL pattern (op-fast model) vs per-backend default.
>   3. Cache key: full `op://` URL vs (vault_uuid, item_uuid, field) tuple. Resolution-stability implications when item titles are renamed.
>   4. Cache scope: per-process (in-memory only) vs per-user daemon vs per-session.
>   5. Invalidation: on `op item rotate` detection? Manual `hasp cache clear`? TTL-only?
>   6. Threat model: cached secrets as a new redaction boundary; what happens on hasp panic; mlock interaction (deferred decision per `CLAUDE.md` Secrets-handling posture).
>   7. Whether caching applies to all backends (one cache layer at the dispatch level) or is backend-specific (each backend decides).
>   8. Whether the cache is exposed via the public library API or stays internal.
>
> Spawn agents in parallel:
>   - **Agent 2 (existing CLIs — PRIMARY)**: `op-fast`, `op-cache`, `chamber` (does it cache?), `aws-vault` (session caching), `vault` agent (token caching), `pass` (no cache), `bw` (session lifetime). Focus on UX choices around invalidation and "stale secret" semantics.
>   - **Agent 1 (Rust ecosystem)**: `keyring` v4 / `keyring-core` v1 (already established as canonical taxonomy reference); in-memory cache crates (`moka`, `cached`, `quick_cache`, `mini-moka`); TTL-eviction patterns; `secrecy::SecretBox` composability with cache values.
>   - **Agent 4 (threat models / standards)**: in-memory secret cache standards (NIST SP 800-57 on key lifetimes; OWASP Secrets Management Cheat Sheet on cache TTLs); guidance on "cached credentials" risk class.
>   - **Agent 5 (failure modes)**: known cache-leak incidents (`.aws/cli/cache/` plaintext, `~/.vault-token` permissions, `keyring` library bugs that exposed cleartext to other apps, GNOME-keyring auto-locking races).
>
> Cite and build on, do not duplicate:
>   - `docs/internal/research/RESEARCH-op-cli.md` §1.8 (latency baseline) and §5.10 (deferral)
>   - `docs/internal/research/RESEARCH-error-taxonomy.md` (locked Error enum)
>   - `docs/internal/research/RESEARCH-secrets-zeroization.md` (existing zeroize / secret-lifetime decisions)
>   - `docs/internal/research/RESEARCH-keyring-v3-vs-v4.md` (existing keyring decisions)
>   - `CLAUDE.md` (project) Secrets-handling posture section.

After the brief is dispatched, the synthesis follows the `RESEARCH-question` skill's standard `§1–§6` template.

## 5. Files touched (with current state)

- `docs/internal/research/RESEARCH-op-cli.md` — **unstaged, untracked** (the entire `docs/` tree is untracked per `git status`). Newly written this session. ~25 KiB. Contains §1 Observed behavior, §2 Exit code map, §3 Stdout conventions, §4 Auth model, §5 Design insights for hasp, §6 Bibliography. Self-contained spec for the `op://` Wave 2 backend implementer.
- `notes/handoffs/2026-04-26-op-cli-caching-research.md` — this file. Newly created.

No source code touched. `Cargo.toml` and `src/lib.rs` show in `git status` from before this session and are not relevant to this session's work.

## 6. Running background tasks / processes

None running. All five research subagents (`Agent 2`, `Agent 1`, `Agent 2-supp`, `Agent 3`, `Agent 5`) completed and returned results in the just-finished session; their findings are synthesized into `RESEARCH-op-cli.md`.
