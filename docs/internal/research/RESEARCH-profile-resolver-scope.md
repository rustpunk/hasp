# RESEARCH-profile-resolver-scope

> Decision: where does `ProfileResolver` (alias-to-URL expansion) live? Where does TTY prompt logic live?
>
> Date: 2026-04-26
> Audience: hasp-core authors, hasp-cli authors
> Status: recommendation — **conflicts with locked scaffold decision; requires user adjudication**

---

## Core question

Both Ferrule and Spall WISHLISTs explicitly do not need profile aliases — they construct full hasp URLs directly. Should `ProfileResolver` (currently slated for `hasp-core`) move to `hasp-cli` only? Should `rpassword`-style TTY prompt logic also live in `hasp-cli` only, or in the library?

The current scaffold (`notes/scaffold.md` row 1, "Profile resolution") states: *"Explicit `ProfileResolver` in `hasp-core`. Callers load `profiles.toml` and expand `@profile/key` before passing a canonical URL to `hasp::get()`. The CLI loads from `~/.config/hasp/profiles.toml`."*

The research below challenges that placement.

---

## The landscape

The Agent 2 prior-art survey examined 19 secrets / credential CLIs spanning ten years of design choices. The finding on alias-and-profile placement is **unanimous**: in every tool surveyed, alias / profile expansion lives in the CLI binary. The library API (where one exists) consumes resolved identifiers. No tool exposes alias expansion through its library surface.

| Tool | Profile / alias system | Where it lives |
|------|-----------------------|----------------|
| chamber (Segment) | shell aliases only | CLI / shell |
| aws-vault (99designs) | `~/.aws/config` profile names | CLI |
| HashiCorp `vault` CLI | none (path-based addressing) | CLI |
| `pass` | filesystem hierarchy | CLI/shell |
| `op` (1Password) | none in URL syntax; vault references inline | CLI |
| `bw` / `bws` (Bitwarden) | named profiles in `~/.config/bws/config` (TOML) | CLI |
| `sops` (Mozilla / CNCF) | none — file-keyed | CLI |
| `summon` (CyberArk) | provider config in `secrets.yml` | CLI |
| `direnv` | per-directory `.envrc` | CLI hook |
| `envchain` | namespace-arg only | CLI |
| `gopass` | mount points | CLI |
| `doppler` | project + config setup via `doppler setup` (writes `.doppler.yaml`) | CLI |
| `teller` (SpectralOps) | `.teller.yml` (CWD) | CLI |
| `infisical` | `.infisical.json` (project-local) | CLI |
| `akeyless` | `~/.akeyless/profiles/*.toml` | CLI |
| `berglas` (Google) | none | CLI |
| `credstash` | none | CLI |
| `ejson` (Shopify) | none | CLI |
| `git-secret`/`blackbox` | filesystem | CLI |

Source: [Agent 2 prior-art findings synthesized in `notes/RESEARCH-cli-prior-art.md`](file:///home/glitch/code/rustpunk/hasp/notes/RESEARCH-cli-prior-art.md), with per-tool URLs in the bibliography section below.

The TTY-prompt finding is identical: **no tool exposes prompt logic through a library API.** Where prompting exists (interactive `vault login`, `op signin`, `pass insert`), it is implemented in the CLI binary using `getpass`/`/dev/tty` directly. The library APIs of these tools (where they exist as Go modules, Rust crates, etc.) accept already-collected secrets as parameters; they do not call out to the terminal.

The motivation is consistent across the ecosystem: alias config and TTY interaction are **CLI concerns**, not **library concerns**. A library called from a long-running daemon, a web service, a CI pipeline, or another CLI tool has no `~/.config/hasp/profiles.toml` to read (whose home? whose config?), no `/dev/tty` to prompt against (often there isn't one), and no business hijacking the embedder's I/O. Pushing these into the library wastes compile-time on dead dependencies (`dirs`, `toml`, `rpassword`) for every consumer.

---

## Approach A: ProfileResolver in `hasp-core`, optional Cargo feature

**As currently planned in `notes/scaffold.md`.**

**How it works:** `hasp-core` ships a `ProfileResolver` struct that loads `profiles.toml` and expands `@profile/key` aliases to canonical URLs. Behind a `profiles` Cargo feature so library consumers who don't want it don't pay. CLI uses it.

**Strengths:**
- Future libraries that want alias expansion get it from `hasp-core`. (Hypothetical — none of the existing or planned consumers want this.)
- Centralized definition of the alias grammar.

**Weaknesses / failure modes:**
- **Solves no real problem.** The two named consumers (Ferrule, Spall) explicitly construct full URLs. Future consumers can be expected to follow the ecosystem norm of constructing URLs from their own config files (Ferrule's `password_url` field; Spall's `[auth].token` field).
- Adds `toml`, `serde`, and disk-IO dependencies to `hasp-core`. Even feature-gated, this is an attractive nuisance: the moment someone enables it for one workflow, every consumer's compile time grows.
- Imposes a config-file location and format on library consumers. Whose `~/.config/hasp/profiles.toml`? An embedded server may run as a service account with no `$HOME`. The library has to either invent a config-loading API or punt — and punting it back to the CLI defeats the purpose.
- Couples the alias grammar to the library's release cadence. A change to alias syntax (adding `@@profile/key` for environment-aware variants, say) is a `hasp-core` semver bump that ripples through every consumer.

**Source:** [chamber, aws-vault, doppler, teller, akeyless, bws design notes — all CLI-only alias systems](#bibliography).

---

## Approach B: ProfileResolver in `hasp-cli` only

**How it works:** `hasp-core` has no profile or alias concept. URL-in, secret-out. `hasp-cli` owns the alias grammar, the config-file loading, and the expansion logic. Other library consumers construct URLs themselves from whatever config they already have (Ferrule's `.ferrule.toml`, Spall's per-API TOML).

**Strengths:**
- **Matches the entire surveyed ecosystem.** Every tool puts alias config in the CLI; no library exposes it. Following the norm produces the least-surprise design.
- `hasp-core` stays minimal: `url`, `thiserror`, `secrecy`, the trait. No `toml`/`serde`/`dirs` deps that consumers don't need.
- Changes to alias syntax are CLI-only — they don't ripple through library consumers.
- The CLI becomes the single locus of "user UX" — alias expansion, TTY prompting, color output, exit codes, shell completions. This is exactly what `hasp-cli` *is*.
- Library consumers (Ferrule, Spall) construct URLs from their existing config files — they don't need yet another config file to manage.
- Cleanly answers the question that drove this research: yes, the ProfileResolver is *not* worth maintaining in the library if only the CLI uses it.

**Weaknesses / failure modes:**
- Two consumers in different processes that want shared aliases (`@prod/db-password` on a developer's laptop, used by Ferrule REPL and Spall CLI in the same shell session) cannot share a config. They each load their own (Ferrule from `.ferrule.toml`, Spall from its own TOML). That's a feature, not a bug — it preserves project-scoping.
- If a third-party builds a hasp-using CLI (`my-tool`) and wants the same `@prod/db-password` alias UX, they'd reimplement the alias loader. **Mitigation:** ship the alias-loading logic as a small support crate (`hasp-cli-support` or `hasp-profiles`) that other CLIs can opt into — a building block, not a library forced on everyone.

**Source:** [Same as Approach A bibliography.]

---

## Where TTY prompt logic belongs

Same finding. Of the 19 surveyed tools, **none** put TTY prompt logic in their library surface. The mechanism is OS-specific but the placement (CLI, not library) is universal:

- **Linux / macOS / BSD:** open `/dev/tty` directly to bypass redirected stdin, `tcsetattr` with `~ECHO` to disable echo, restore on completion. Falls back to stderr+stdin with a warning if `/dev/tty` is unavailable.
- **Windows:** open the console via `CONIN$`, call `SetConsoleMode(... & ~ENABLE_ECHO_INPUT)`, restore on completion.

The `rpassword` crate (which Ferrule uses today and which `hasp-cli` will use) handles all three OSes behind one cross-platform API — no `cfg(target_os = ...)` in calling code. The CLI/library boundary recommendation does not change per OS; the implementation primitives differ but both still belong in `hasp-cli`, never in `hasp-core`.

Ferrule's WISHLIST §1 P0 explicitly says: *"Out of scope for ferrule: We do not need `hasp` to own the interactive password prompt — ferrule already uses `rpassword` and prefers to keep the TTY prompt in its own CLI layer."* This matches the broader ecosystem; it is not a Ferrule quirk.

For hasp specifically:
- The `hasp put <url>` command needs to prompt for a value when stdin is a TTY and no `-` or `--from-file` flag is given. That's a `hasp-cli` feature using `rpassword` (or equivalent). The `Backend::put` library trait accepts a `&SecretString`; the CLI is responsible for constructing it.
- The `hasp get <url>` command may need to prompt for a keyring unlock passphrase if the platform requires it — but that prompt is owned by the OS keyring daemon (gnome-keyring's GUI dialog, macOS Keychain's UI), not by hasp. hasp does not prompt; it propagates the daemon's response.

**TTY prompt logic lives in `hasp-cli`. `hasp-core` has no `rpassword`-shaped dependency.**

---

## Benchmark data

Not applicable. Both alias expansion and TTY prompting are user-time operations; latency is dominated by user response.

---

## Threat-model / standards anchors

| Source | Year | Body | Relevant insight | URL |
|--------|------|------|-----------------|-----|
| OWASP Secrets Management Cheat Sheet | 2023 | OWASP | Recommends keeping secret-acquisition (prompts, file reads, env reads) at the application boundary, not the library | [link](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |

---

## Failure modes / CVEs to avoid

- **CVE-2023-36052 / "LeakyCLI" (Azure CLI; AWS CLI / GCloud CLI analogous).** Azure CLI commands that echo environment variables (including secret values) into CI build logs. Mechanism: a CLI mode that prints user-supplied input (env vars) to stdout/stderr unredacted. **Implication for hasp-cli's interactive features:** any CLI prompt that echoes input is a potential leak vector. `rpassword`-style no-echo is the floor. Errors raised during `hasp put` must not echo the value the user typed. ([Orca security analysis](https://orca.security/resources/blog/leakycli-aws-google-cloud-command-line-tools-can-expose-sensitive-credentials-build-logs/))
- **`/proc/<pid>/environ` exposure** of secrets injected as env vars (summon, doppler run, op run all have this footprint). Not a hasp-cli failure mode per se, but worth noting that the prompt-and-inject-into-subprocess pattern (if hasp ever adds an `exec` subcommand) inherits the same exposure.
- **`/dev/tty` unavailability in containers.** Falling back to stderr+stdin without warning would be a CVE-class regression — a non-interactive caller would unknowingly send the secret over an unredacted channel. Pattern: warn loudly on stderr, then fall back, OR fail loudly and require `--from-file=-`.

---

## Design insights for hasp

1. **Move `ProfileResolver` out of `hasp-core` to `hasp-cli` (or to a small `hasp-profiles` support crate that `hasp-cli` depends on).** This contradicts the current scaffold; surfacing as a blocking decision below. The motivation is unanimous ecosystem prior art and the explicit non-need from the two named consumers.
2. **`hasp-core` has no `toml`/`serde`/`dirs`/`rpassword` deps.** The library is `url`, `thiserror`, `secrecy`, the trait. Anything ergonomic-shaped goes in `hasp-cli`.
3. **TTY prompt logic lives in `hasp-cli`** using `rpassword` (or a comparable maintained crate; vetting at `Cargo.toml` edit time per `crate-vetting` skill). The library never reads `/dev/tty`.
4. **`hasp-cli` exposes CLI-style alias config** at `~/.config/hasp/profiles.toml` (Linux/macOS XDG, Windows AppData). Format and grammar live in the CLI's docs, not in the library's docs.
5. **If a future library consumer genuinely needs alias expansion** (an unexpected scenario given the ecosystem), they can copy the small `hasp-profiles` support crate, or hasp can promote the alias logic to a small crate that lives outside `hasp-core`. Either way, the *default* library footprint stays minimal.
6. **Document the boundary in `CLAUDE.md`:** "the library has no concept of users, configs, or terminals; the CLI has all three." Codify it so a future contributor doesn't quietly add a `prompt_password()` helper to `hasp-core`.

---

## Decision criteria (enforced)

NOT valid: minimizing changes to the current scaffold; preserving symmetry with prior planning.

ONLY valid:
- Architectural correctness (the library should not have UX concepts; the CLI should)
- Threat-model soundness (libraries that read `/dev/tty` or `~/.config` from arbitrary contexts are a leak surface)
- Long-term maintainability (CLI-only alias logic doesn't ripple into library semver)
- Alignment with rustpunk identity (minimal default-feature library; CLI is the user-facing surface)

The scaffold's current placement of `ProfileResolver` in `hasp-core` is a planning artifact, not an architectural commitment. The research universally says the placement is wrong.

---

## Recommendation

**Approach B — `ProfileResolver` and TTY prompt logic both live in `hasp-cli`. `hasp-core` has neither.**

**Confidence:** High.

**Rationale:**
- Unanimous prior art across 19 surveyed tools (Agent 2 findings). No counter-example was found.
- Both named consumers (Ferrule, Spall) explicitly do not need alias expansion in the library.
- `hasp-core` stays at the minimal dep set the locked architecture targets.
- Eliminates a class of footguns (whose home? which TTY?) that would surface the moment a library consumer ran in an unexpected context.

**Key risk:** Future library consumer X wants alias expansion via library API. **Mitigation:** publish `hasp-profiles` (or `hasp-cli-support`) as a small public crate that any other CLI can pull in — alias logic is reusable infrastructure, just not via the *core* library API. This preserves the option to share without forcing it.

**Threat-model note:** Approach B keeps `hasp-core` free of `/dev/tty`, `~/.config`, and disk-IO surface. Library consumers cannot accidentally invoke prompt or config-load behavior; they have to opt in by depending on a separate crate. This is the threat-model-clean posture.

**If wrong:** If a real consumer surfaces who insists on library-side alias expansion, promote `hasp-profiles` to a stable public crate and document its use — without retrofitting `hasp-core`. Library boundary stays minimal.

**Rejected alternatives:**
- **Approach A (ProfileResolver in `hasp-core` behind a feature):** rejected because the ecosystem unanimously puts this in the CLI, the named consumers don't want it, and `hasp-core` cleanliness is more valuable than centralizing alias logic at the library layer. "Future consumers might want it" is not a sufficient reason to import it now — `hasp-profiles` as a separate crate is the better extension point.

---

## ⚠️ Surfacing to user (architect-mode requirement)

This recommendation **contradicts** the locked decision in `notes/scaffold.md` row 1:

> *"Profile resolution: Explicit `ProfileResolver` in `hasp-core`. Callers load `profiles.toml` and expand `@profile/key` before passing a canonical URL to `hasp::get()`."*

The user explicitly asked this question (deliverable D5) — *"is the ProfileResolver worth maintaining if only the hasp-cli ever uses it? Or should it live in hasp-cli only?"* — so this is exactly the kind of conclusion the research was meant to surface.

**Decision required:** keep ProfileResolver in `hasp-core` (scaffold as written), or move it to `hasp-cli` per this research. Recommendation is the latter; it requires a one-line edit to the scaffold's row 1.

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| Ferrule WISHLIST §1 P0 | doc | "We do not need hasp to own the interactive password prompt" | `docs/internal/ferrule/WISHLIST.md` |
| Spall WISHLIST | doc | Constructs URLs directly; no profile alias needed in library | `docs/internal/spall/WISHLIST.md` |
| chamber README | doc | Service-name-as-prefix; alias is shell-side | [github](https://github.com/segmentio/chamber/blob/master/README.md) |
| aws-vault USAGE.md | doc | `~/.aws/config` profile system, CLI-only | [github](https://github.com/99designs/aws-vault/blob/master/USAGE.md) |
| HashiCorp `vault` CLI | docs | Path-based; no library alias concept | [link](https://developer.hashicorp.com/vault/docs/commands) |
| 1Password CLI ref | doc | Inline `op://...` references; no alias config | [link](https://developer.1password.com/docs/cli/secret-reference-syntax/) |
| Bitwarden Secrets Manager CLI | doc | Profiles in `~/.config/bws/config`, CLI-only | [link](https://bitwarden.com/help/secrets-manager-cli/) |
| Doppler CLI docs | doc | `doppler setup` writes `.doppler.yaml`, CLI-only | [link](https://docs.doppler.com/docs/cli) |
| teller GitHub | repo | `.teller.yml` (CWD); CLI-only | [link](https://github.com/tellerops/teller) |
| akeyless CLI docs | doc | `~/.akeyless/profiles/*.toml`, CLI-only | [link](https://docs.akeyless.io/docs/cli) |
| OWASP Secrets Mgmt Cheat Sheet | guide | Application boundary owns acquisition | [link](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| LeakyCLI / CVE-2023-36052 | advisory | CLI-side echo as leak vector | [link](https://orca.security/resources/blog/leakycli-aws-google-cloud-command-line-tools-can-expose-sensitive-credentials-build-logs/) |
| `notes/scaffold.md` row 1 | source | Current locked decision being challenged | `notes/scaffold.md` |
