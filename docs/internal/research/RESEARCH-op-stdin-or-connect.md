# RESEARCH-op-stdin-or-connect

**Research date:** 2026-05-15
**Brief:** **YES — both `op item edit` / `op item create` and `bw edit item` / `bw create item` accept the encoded JSON payload via stdin in May 2026.** `op` reads the JSON template from stdin when invoked as `op item edit <item> -` (since v2.6.x for `edit`, v2.3.0 for `create`; piping form generalized in v2.23.0, 2023-11-16). `bw edit item <id>` and `bw create item` read base64-encoded JSON from stdin when the positional `<encodedJson>` argument is empty (canonical pipe is `… | jq … | bw encode | bw edit item <id>`). The in-sprint deliverable can switch both backends off argv onto stdin and close issue #27 substantively — *not* contract to doc-only. Connect-HTTP / Vault-Management-API remain valuable follow-up issues but are not gating.
**Saved to:** `docs/internal/research/RESEARCH-op-stdin-or-connect.md`
**Cites and builds on:** `RESEARCH-op-cli.md` (§4.4 Connect, §4.7 argv hygiene), `RESEARCH-bw-cli.md` (`bw encode` workflow), `CLAUDE.md` secrets-handling posture.

---

## §1 The argv-exposure threat

### 1.1 What hasp ships today

`crates/hasp-backend-op/src/lib.rs:324` builds `let assignment = format!("{}={}", op_url.field, value.expose_secret());` and passes it as positional argv to `op item edit` (line 332) and to `op item create` (line 368). The secret bytes are on `op`'s argv from `fork`/`execve` until `wait`.

The shipped backend itself documents this — `crates/hasp-backend-op/src/lib.rs:319-323`:

```
// Argv exposure: the secret value lives on `op`'s argv for the
// life of the subprocess. On Linux, `/proc/<pid>/cmdline` is
// same-uid readable — the documented cost of the
// `op item edit|create` API surface (no stdin variant for
// field values).
```

The negative claim in that comment ("no stdin variant for field values") is **wrong as of May 2026**. This research note corrects it: the stdin variant exists and is documented by 1Password itself; the in-sprint switch is mechanically straightforward.

For `bw`, the shipped backend declines to implement `put` (`crates/hasp-backend-bw/src/lib.rs:192-197`); issue #23 is the in-flight write path. Without intervention #23 would replicate #7's argv exposure, since the in-progress design also passes `<encodedJson>` positionally. This note prevents that replication.

### 1.2 The Linux exposure surface, precisely

`/proc/<pid>/cmdline` is world-readable by default on Linux ([proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)). A same-uid attacker on the host can `cat /proc/<pid>/cmdline` for the full lifetime of the subprocess — typically 700 ms – 5 s for `op` ([`RESEARCH-op-cli.md` §1.8](./RESEARCH-op-cli.md)), low hundreds of ms for `bw`. The argument bytes also surface in `ps`, `pgrep -f`, audit logs, command-history files when the user shells out manually, and any same-user observer that polls `/proc`.

`hidepid=2` mount option mitigates by restricting `/proc/<pid>` visibility to the owning UID, but is not the default on any major distro and hasp cannot rely on it. The threat-model boundary established in [`CLAUDE.md`](../../CLAUDE.md) ("treat every secret value as untrusted-output-grade") makes this a first-class issue regardless of distro hardening.

### 1.3 What "fix" means concretely

A real fix moves the secret bytes off argv. Three categories of mitigation:

1. **Subprocess stdin** — feed the JSON template to `op`/`bw` over a pipe. Secret transits stdin once; argv carries no secret bytes. *Cheapest fix; this note's primary finding is that this is available.*
2. **HTTP backend (Connect / `bw serve`)** — bypass the CLI entirely. Secret transits an in-process TLS or localhost HTTP body. *Eliminates the subprocess entirely; bigger refactor.*
3. **Memfd / file-descriptor passing** — write the secret to a sealed `memfd` and pass `/dev/fd/N` to the CLI. *Neither CLI accepts a file-descriptor flag for field values; non-starter without upstream changes.*

§§2–3 establish (1) is in-bound. §§4–5 cover (2) as the deferred follow-up. (3) is parked.

---

## §2 `op item edit` / `op item create` — May 2026 surface

### 2.1 Bottom line

**Both commands accept the JSON template via stdin.** The CLI surface for sensitive-value writes is:

```
op item template get Login \
  | jq '.fields[] |= (if .id=="password" then .value="<SECRET>" else . end)' \
  | op item create --vault <vault> -

op item get <item> --vault <vault> --format=json \
  | jq '.fields[] |= (if .id=="password" then .value="<SECRET>" else . end)' \
  | op item edit <item> --vault <vault> -
```

The literal `-` final positional reads the JSON template from stdin. Since v2.23.0, the `-` is also optional — if stdin is non-TTY the CLI auto-detects piped input ([1Password CLI v2 release notes](https://app-updates.agilebits.com/product_history/CLI2)).

**1Password explicitly recommends this path for sensitive values.** The docs on [op item edit](https://developer.1password.com/docs/cli/item-edit/) and the [item command reference](https://developer.1password.com/docs/cli/reference/management-commands/item/) carry the verbatim warning:

> "Command arguments get logged in your command history, and can be visible to other processes on your machine. If you're assigning sensitive values, use a JSON template instead."

This is the same warning quoted in [`RESEARCH-op-cli.md` §4.7](./RESEARCH-op-cli.md) — but the prior research did not test whether the template path was reachable via stdin (without a file on disk). It is. This is the load-bearing finding.

### 2.2 Mechanism details — `op item edit`

Reads JSON template from stdin when invoked with `-` as the final positional (or, since v2.23.0, when stdin is piped without `-`). The JSON shape is the same as `op item get --format=json` output: a `FullItem`-like object with `fields[]` carrying the field values. Field assignment statements may follow the `-` to overlay additional fields without modifying the template — but **the value bytes must be in the JSON template, not in argv**, for the secret to stay off argv.

**Constraint (cited verbatim by the 1Password docs):** "You can't combine piped input and the `--template` flag in the same command, to avoid collisions." This means hasp must pick one of: (a) `--template /dev/stdin` (which on Linux is a regular FD path; not actually piped — see §2.4 below for the subtle but exploitable workaround), or (b) the `-` positional with piped stdin. Option (b) is canonical; choose (b).

### 2.3 Mechanism details — `op item create`

Same shape, different release date. v2.3.0 added the `-` positional that reads a JSON template from stdin. The canonical example from the docs:

```
op item template get Login | op item create --vault personal -
```

For hasp's `put` path the create branch is reached when `op item edit` returns NotFound (`crates/hasp-backend-op/src/lib.rs:346-369`). Both branches must use the stdin form; mixing argv on the create branch would defeat the fix.

### 2.4 Subtle implementation note: `/dev/stdin` vs `-` positional

`op` documents the `-` positional. It does **not** document `--template /dev/stdin` (which on Linux is `/proc/self/fd/0`, a symlink to the pipe). Both work in practice in current `op` versions, but the supported, version-stable surface is the `-` positional. The hasp implementation should use `-`, not `/dev/stdin`, to avoid coupling to undocumented behavior.

### 2.5 Version floor

- `op item create` stdin: v2.3.0 (2022 timeframe, pre-dates hasp's 2.30.0 floor from `RESEARCH-op-cli.md` §5.5).
- `op item edit` stdin via `-`: v2.6.x.
- Auto-detect piped stdin without `-`: v2.23.0 (2023-11-16).

Hasp's existing minimum `op` version of v2.30.0 (per `RESEARCH-op-cli.md` §5.5) is comfortably past all three milestones. **No version-floor bump required.**

### 2.6 What argv still carries

After the stdin switch, `op item edit` argv carries: the binary name, `item`, `edit`, the item identifier (UUID or title), `--vault <name>`, `--format=json`, `--no-color`, and `-`. None of these is a secret value. The vault name, item identifier, and field name are *references* — not secrets — and are already part of the hasp URL grammar (per [`CLAUDE.md`](../../CLAUDE.md): "the URL/key, never the bytes").

---

## §3 `bw edit item` / `bw create item` — May 2026 surface

### 3.1 Bottom line

**Both commands accept the base64-encoded JSON payload via stdin** when the positional `<encodedJson>` argument is empty. Confirmed by reading the upstream source.

Canonical pipe (from [bitwarden.com/help/cli](https://bitwarden.com/help/cli/)):

```
bw get item <id> \
  | jq '.login.password="<SECRET>"' \
  | bw encode \
  | bw edit item <id>
```

`bw encode` itself is **stdin-only** (no argv input path; confirmed against `apps/cli/src/commands/encode.command.ts`). The final `bw edit item <id>` receives base64-encoded JSON on its stdin and does **not** see the secret on its own argv.

### 3.2 Source confirmation

`EditCommand.run(object, id, requestJson, cmdOptions)` in the upstream Bitwarden clients monorepo:

```typescript
async run(object: string, id: string, requestJson: any, cmdOptions: Record<string, any>): Promise<Response>
// ...
if (process.env.BW_SERVE !== "true" && (requestJson == null || requestJson === "")) {
  requestJson = await CliUtils.readStdin();
}
// ...
const reqJson = Buffer.from(requestJson, "base64").toString();
req = JSON.parse(reqJson);
```

The stdin path is taken whenever the positional `requestJson` is null or empty. `CreateCommand.run(...)` has the symmetric structure. Source: `bitwarden/clients`, `apps/cli/src/commands/edit.command.ts` and `create.command.ts` (confirmed via WebFetch May 2026).

**Implementation rule for hasp's `bw` backend:** spawn `bw edit item <id>` with `Stdio::piped()` on stdin, write the base64-encoded JSON, close stdin, wait for exit. Do **not** pass the encoded JSON as a positional argv argument.

### 3.3 The `bw encode` problem — and why hasp should not use it

The shell-level idiom relies on a *three-process pipeline*: `bw get item` → `jq` → `bw encode` → `bw edit item`. From hasp's perspective this is wasteful and adds the `bw encode` subprocess as a dependency the library doesn't need.

`bw encode` is base64 encoding of stdin. Base64-encoding a UTF-8 JSON string is trivial in Rust (`base64::engine::general_purpose::STANDARD.encode(json_bytes)`). **Hasp should construct the JSON payload in-process, base64-encode it in-process, and pipe the result directly to `bw edit item <id>` on stdin.** This eliminates `bw encode` from the pipeline entirely and reduces the attack surface to one subprocess.

Crate vetting: `base64` v0.22 (or v0.21) is a no-deps, actively maintained crate widely used in rustls and the broader Rust security stack. The auto-loading `crate-vetting` skill will not flag it.

### 3.4 Version floor

The `requestJson == null || requestJson === ""` stdin fallback has been in the Bitwarden CLI since at least the 2021-era `bitwarden/cli` repo (now archived in favor of the `bitwarden/clients` monorepo). `RESEARCH-bw-cli.md` recommends `bw >= 2024.x` for stable JSON shape; that is well past the stdin-fallback introduction. **No version-floor bump required.**

### 3.5 What argv still carries

After the stdin switch, `bw edit item` argv carries: `bw`, `edit`, `item`, the item id (UUID), and the standard `--response --nointeraction` flags. The item id is an opaque UUID; not a secret value. `bw create item` argv is even shorter (`bw create item`) — the entire payload is on stdin.

### 3.6 The "secret in the encoded JSON" cross-check

The base64 payload that hasp pipes to `bw edit item` contains the secret. **The encoding does not protect it** — base64 is reversible. The protection comes from putting the payload on stdin instead of argv. This is the whole point of §6's threat-model boundary: argv is `/proc/<pid>/cmdline` (same-uid readable for the full lifetime); stdin (a pipe) is `/proc/<pid>/fd/0` (per-FD readability check, narrower exposure window). See §6.

---

## §4 1Password Connect — long-term follow-up (not gating)

§§2 closes the in-sprint argv gap. Connect remains worth a separate issue because it (a) recovers the 401/403/404 distinction the subprocess collapses (per `RESEARCH-op-cli.md` §4.4), (b) eliminates the `op` binary as a runtime dependency for self-hosted Connect users, (c) avoids the 700 ms – 2 s subprocess startup cost (`RESEARCH-op-cli.md` §1.8). It is **not** required to fix #27.

### 4.1 Auth model (cross-check against `RESEARCH-op-cli.md` §4.4)

Confirmed accurate:
- Connect tokens are JWT-shaped bearer credentials, scoped per-vault, issued via the 1Password admin UI per Connect server.
- `Authorization: Bearer <connect-token>` is the only auth header.
- Disjoint from service-account tokens (`OP_SERVICE_ACCOUNT_TOKEN`, `ops_…` format).
- Connect tokens **only** work against a self-hosted Connect server; service-account tokens only work against 1Password.com. There is no documented direct HTTP path for service-account tokens (the SRPx handshake is required, only the shared Rust core compiled to WASM speaks it).

The 1Password SDKs (Go, Python, JS — no Rust) and the open Connect OpenAPI spec are the only sanctioned HTTP surfaces.

### 4.2 Connect write API

From `RESEARCH-op-cli.md` §4.4 plus this round's research:

| Method | Path | Body | Purpose |
|---|---|---|---|
| `POST` | `/v1/vaults/{vaultUuid}/items` | `FullItem` JSON | Create a new item (full payload) |
| `PUT` | `/v1/vaults/{vaultUuid}/items/{itemUuid}` | `FullItem` JSON | Replace entire item |
| `PATCH` | `/v1/vaults/{vaultUuid}/items/{itemUuid}` | RFC 6902 JSON Patch | Add/remove/replace fields surgically |
| `DELETE` | `/v1/vaults/{vaultUuid}/items/{itemUuid}` | empty | Delete item |

For hasp's `put`, the natural mapping is `PATCH` with an `op: "replace"` on `/fields/<id>/value` when the field exists, falling back to `POST` (new item) when the item doesn't. This is symmetric to the current `op item edit` → `op item create` fallback in `lib.rs:340-374`.

**Required pre-work for a Connect backend (not in scope for this sprint):** name-to-UUID resolution. Connect operates on UUIDs only — the URL `op://Vault/Item/field` requires `GET /v1/vaults?filter=name eq "Vault"` then `GET /v1/vaults/{vaultUuid}/items?filter=title eq "Item"` to resolve. `RESEARCH-op-cli.md` §4.4 already covers this. The estimated implementation cost is meaningful (likely a few hundred lines, plus a new feature-gated dep on a Rust HTTP client) — defer to its own issue.

### 4.3 Suggested follow-up issue

File a new issue **"#XX: `op-connect://` HTTP backend (recovers 401/403/404 distinction, eliminates `op` binary dependency)"** with:
- Feature gate: `connect` (additive to existing `op` feature; not a replacement).
- Auth: `OP_CONNECT_HOST` + `OP_CONNECT_TOKEN` (already detected in the existing pre-flight check at `lib.rs` ambient-credentials path).
- Scope: `get` / `put` / `delete` / `list` / `exists` symmetric with the subprocess backend.
- Dep: `reqwest` with `rustls-tls` (per `RESEARCH-op-cli.md` §4.5 the only credible rustls-aligned crate; the bsodmike `connect-1password` crate is stale and not recommended).
- Out of scope: replacing the `op://` subprocess backend. Connect is opt-in.

---

## §5 Bitwarden write surface — long-term follow-up (not gating)

§§3 closes the in-sprint argv gap for `bw`. The HTTP alternatives are weaker than 1Password's Connect because Bitwarden's server-side HTTP API has no first-class personal-vault-item write surface.

### 5.1 What Bitwarden does and does not expose

| Surface | Personal-vault item writes? | Auth | Notes |
|---|---|---|---|
| **Public API** (`bitwarden.com/help/public-api/`) | **No.** Organization-only: members, collections, groups, event logs, policies. | OAuth2 client credentials (`client_id` + `client_secret`) | Useless for hasp's `put` on personal items. |
| **Vault Management API** (`bw serve`) | Yes, but **only locally** | None at the HTTP layer; `BW_SESSION` already unlocked the CLI process | Wraps the same `bw` codebase behind a localhost Express server. |
| **Direct cloud REST** | Undocumented internal API used by the official clients | Master-password-derived session token + per-request auth | Reverse-engineering territory (e.g. `vaultwarden` decoded it); not a sanctioned surface. |

### 5.2 `bw serve` is not an argv mitigation

Issuing `POST http://localhost:8087/object/item` from hasp to a `bw serve` instance moves the secret onto the HTTP body — which is good. But: the `bw serve` process *is itself* a `bw` subprocess. The `bw serve` HTTP handler internally calls the same `EditCommand.run(...)` code path. The secret never crosses argv on the `bw serve` path **only because the HTTP handler hands it to `EditCommand.run` as `requestJson` directly, not via fork/exec**. So `bw serve` does eliminate the per-call argv exposure — at the cost of a long-running daemon holding the unlocked vault in memory.

For hasp, the simpler win is **stdin to a one-shot `bw edit item`** (§3) — no daemon, no port binding, no `--disable-origin-protection` flag to misconfigure. Defer `bw serve` to a separate issue.

### 5.3 Suggested follow-up issue

File **"#XX: `bw-serve://` long-lived-daemon backend (eliminates per-call `bw` startup latency, exposes localhost HTTP)"**:
- Feature gate: `bw-serve`.
- Auth: ambient (`BW_SESSION` already unlocks the daemon at startup; hasp itself is unauthenticated to localhost).
- Scope: `get` / `put` / `delete` / `list` / `exists` against `localhost:8087` (configurable).
- Dep: `reqwest` (shared with the `op-connect://` follow-up).
- Threat-model note: leaves the unlocked vault accessible to every process on the host that can reach localhost:8087 (mitigated by the default Origin-header check, which hasp must rely on). Document explicitly.

The Bitwarden Public API does **not** justify a follow-up issue for hasp — its write surface is organization administration only, not vault items.

---

## §6 Threat-model: argv vs stdin — the residual exposure analysis

### 6.1 What changes when we move from argv to stdin

| Channel | What Linux exposes | Who can read it | Window |
|---|---|---|---|
| argv (current `#7` shipped code) | `/proc/<pid>/cmdline` | Any same-uid process | Full subprocess lifetime (~700 ms – 5 s for `op`; ~200 ms – 1 s for `bw`) |
| stdin (this note's recommendation) | `/proc/<pid>/fd/0` symlink to the pipe inode | Caller and callee processes (FD is in their respective fd tables); same-uid third parties only via `ptrace_may_access` checks (which include `PTRACE_MODE_READ_FSCREDS`) | Until the byte is consumed and the pipe drains — typically microseconds |
| env var (rejected, see below) | `/proc/<pid>/environ` | Same-uid only (per [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)); a `PTRACE_MODE_READ_FSCREDS` check applies on modern kernels | Full subprocess lifetime |
| file FD via `--in-file <path>` (not offered by `op`/`bw`) | inode contents | filesystem ACL | until unlink |

Sources: [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html), [smallstep "How to handle secrets on the command line"](https://smallstep.com/blog/command-line-secrets/), [GitGuardian "Secrets at the command line"](https://blog.gitguardian.com/secrets-at-the-command-line/), [Yama LSM docs](https://www.kernel.org/doc/Documentation/security/Yama.txt).

### 6.2 Why stdin is meaningfully better than argv (not just trivially better)

The dominant practical difference is **exposure window**.

- **argv** sits in `/proc/<pid>/cmdline` for the entire subprocess lifetime. A naive `while sleep 0.1; do cat /proc/<pid>/cmdline; done` loop run by any same-uid attacker observes the bytes within the window with near-certainty.
- **stdin pipe** appears in `/proc/<pid>/fd/0` as a symlink to a pipe inode (`pipe:[…]`). A same-uid attacker who has not already inherited the FD can attempt to `open()` the symlink target, but on a modern kernel the `proc_pid_follow_link` path performs a `ptrace_may_access` check with `PTRACE_MODE_READ_FSCREDS` (per [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) and [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)). With `yama.ptrace_scope=0` (default on most distros) same-uid ptrace is allowed and the symlink can be followed; with `yama.ptrace_scope >= 1` (default on Ubuntu and Container-Optimized OS), it cannot be followed without an explicit prctl from the target. Even when followable, the pipe drains to empty as the callee consumes the bytes — the attacker must poll faster than the callee reads, which is hard to do reliably given microseconds-scale consumption.

The argv-to-stdin switch therefore narrows the exposure window from **seconds (argv) to microseconds (stdin)** *and* in some configurations (ptrace_scope=1) closes it entirely from third-party same-uid attackers.

This is the threat-model claim the brief asked for. It's not "stdin is bulletproof"; it's "stdin is bounded-exposure where argv is unbounded-exposure-within-process-lifetime."

### 6.3 What stdin does **not** fix

Documented residual exposures, all carried over from the current shipped surface:

1. **Bytes still cross the process boundary.** Same-user trust applies. `RESEARCH-op-cli.md` §4.6 already states: "any same-user process can invoke `op` and use the active session." A malicious same-user process can simply call `op read` or `bw get item` itself; it doesn't need to scrape hasp's stdin pipe. Reduces #27's mitigation to a defense-in-depth measure, not a primitive.
2. **Bytes are in hasp's address space.** The `SecretString` wrapper (per `secrecy`) protects against `Display`/`Debug` leakage but not against `mlock`-grade RAM scraping or core-dumps. Out of scope per `RESEARCH-secrets-zeroization.md`.
3. **Bytes are in the `op`/`bw` subprocess's address space.** Same caveat. We chose to delegate to these tools; we inherit their hygiene posture.
4. **The base64-encoded JSON payload for `bw` is itself secret-bearing.** It transits stdin — same threat-model as a raw `op` JSON template. Base64 is not encryption; it's a wire encoding. Hasp must capture and zeroize the encoded buffer at the boundary, identical to how it captures `op read`'s stdout (`RESEARCH-op-cli.md` §3.5).
5. **Subprocess inherits the controlling TTY by default.** Hasp must explicitly null out stdin (after writing), stdout, and stderr to avoid leaking the secret into any inherited TTY (`Command::stdin(Stdio::piped())` + `stdout(Stdio::piped())` + `stderr(Stdio::piped())`).
6. **The argv-still-visible `/proc/<pid>/cmdline` contains the JSON-template *flag combinations* and the item identifier.** The item identifier is part of the URL grammar already (a reference, not a value). No new leakage.
7. **Wrapper-script translation.** If hasp ever invokes a wrapper (e.g. `sh -c "op item edit … -"`), the wrapper's argv contains the literal `op item edit … -`. The wrapper does not see the secret; the wrapper's grandchild (`op`) consumes stdin. **Hasp must avoid `sh -c`** and `bash -c` for any command that passes secrets — invoke the binary directly via `Command::new("op")`. `Command::new` is already the pattern in `crates/hasp-backend-op/src/lib.rs` per the `RESEARCH-op-cli.md` §5.8 guidance. The same rule applies to `bw`.

### 6.4 Reference for the argv-vs-stdin threat model

- **smallstep, "How to handle secrets on the command line"** ([smallstep.com/blog/command-line-secrets/](https://smallstep.com/blog/command-line-secrets/)) — the canonical Rust-ecosystem-adjacent treatment. Argues for file-or-stdin over argv/env; explicitly cites `/proc/<pid>/cmdline` as the argv-leak channel. Already cited by `RESEARCH-op-cli.md` §4.7.
- **GitGuardian, "How to Handle Secrets at the Command Line"** ([blog.gitguardian.com/secrets-at-the-command-line/](https://blog.gitguardian.com/secrets-at-the-command-line/)) — provides the cheat-sheet table comparing argv/env/stdin/file. Same conclusions.
- **OWASP Cheat Sheet, "OS Command Injection Defense"** ([cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)) — adjacent; covers command injection more than secret-on-argv, but cites the same `/proc` exposure.
- **Lobste.rs discussion, "Handling secrets (somewhat) securely in shells"** ([lobste.rs/s/hmlt2f](https://lobste.rs/s/hmlt2f/handling_secrets_somewhat_securely)) — practitioner-level commentary, useful as a sanity check that the field treats argv-to-stdin as the canonical fix.
- **NIST SP 800-63B** does not address command-line secret hygiene directly; the closest formal guidance is OWASP's. No CIS Benchmark or DISA STIG directly addresses argv-vs-stdin for credential CLI tools. The smallstep article is the de-facto industry reference.

---

## §7 Failure modes / known incidents

- **Argv leak via shell history.** `histcontrol=ignorespace` and `set +o history` are bash mitigations, but they protect only the *interactive* shell history. Hasp's subprocess argv goes via `execve` and is fully visible in `/proc/<pid>/cmdline` regardless of any shell-history setting. There is no `histcontrol` for `/proc`.
- **Bitwarden CLI supply-chain attack (April 2026)** — already cataloged in `RESEARCH-op-cli.md` (Bibliography); the `bw encode` removal recommendation in §3.3 further reduces the trusted-binary surface (one less binary in the pipeline).
- **`op` v2.6.0 piped-JSON regression** ([1Password community: cli v2.6.0 editing items with `op item get | jq | op item edit` does not create new fields](https://1password.community/discussion/131985/cli-v2-6-0-editing-items-with-op-item-get-jq-op-item-edit-does-not-create-new-fields)) — adding a *new* field via piped JSON was broken in v2.6.0; existing-field updates worked. Fixed in v2.6.2. Hasp's v2.30.0 minimum (per `RESEARCH-op-cli.md` §5.5) is past this. Documenting it in case anyone tests against older `op` builds.
- **`op item edit` overwrites passkeys when using `--template`** ([1Password CLI docs, item-edit page](https://developer.1password.com/docs/cli/item-edit/)): "JSON item templates do not support passkeys. If you use a JSON template to update an item that contains a passkey, the passkey will be overwritten." Hasp's `put` path on `op://` already uses JSON-template-grade input after the stdin switch; we inherit this footgun. **Mitigation:** before invoking `op item edit`, check whether the item contains a passkey by reading `op item get --format=json` and inspecting fields; refuse to overwrite if so. This is a follow-up; not blocking #27.
- **`bw encode` "no stdin piped in" error** ([community.bitwarden.com/t/bw-encode-no-stdin-was-piped-in/39736](https://community.bitwarden.com/t/bw-encode-no-stdin-was-piped-in/39736)) — only a failure mode if `bw encode` is used in a TTY without piped input. Hasp's recommendation in §3.3 is to do base64 encoding in-process, avoiding `bw encode` entirely. Side-benefit: this failure mode disappears.

---

## §8 Design insights for hasp (mapped to actual files + line numbers)

### 8.1 `crates/hasp-backend-op/src/lib.rs:306-378` (`fn put`)

**Current state (May 2026):** the `put` function builds `assignment = format!("{}={}", op_url.field, value.expose_secret())` at line 324 and passes it positionally to both `op item edit` (line 332) and `op item create` (line 368).

**Target state:** construct the JSON template in-process (do not build `assignment`); invoke `op item edit <item> --vault <vault> --format=json --no-color -` with `Stdio::piped()` stdin; write the JSON template to the child's stdin; close stdin; wait. On `Error::NotFound`, invoke `op item create --vault <vault> --title <item> --category password --format=json --no-color -` symmetrically.

JSON-template shape (minimal, for a single-field write):

```json
{
  "title": "<item>",
  "category": "PASSWORD",
  "fields": [
    { "id": "<field>", "type": "CONCEALED", "value": "<SECRET>" }
  ]
}
```

For `edit`, hasp must first `op item get` the item, mutate the matching field's `value`, and pipe the modified JSON back. For `create`, hasp constructs the template from scratch. Both paths require a `serde_json::Value`-based pipeline (already a transitive dep via existing backends; confirmed in `Cargo.lock`).

**Argv after the switch (for `edit`):** `op`, `item`, `edit`, `<item>`, `--vault`, `<vault>`, `--format=json`, `--no-color`, `-`. None of these is a secret.

**Function signature is unchanged.** `fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error>` remains the public surface.

**Existing redaction posture is unchanged.** `value.expose_secret()` is called exactly once — in the JSON-template construction step — and its result is written directly to the child's stdin, never into argv, never into a long-lived buffer that survives the call. Zeroize the template buffer at function exit (per `RESEARCH-secrets-zeroization.md` posture).

### 8.2 `crates/hasp-backend-bw/src/lib.rs:192-197` (`fn put` — currently `UnsupportedOperation`)

Issue #23 is the in-flight implementation. **The implementation should land directly on the stdin path; do not implement an argv-passing intermediate.** Sketch:

```rust
fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
    let bw_url = BwUrl::try_from(url)?;
    // 1. Fetch existing item JSON via `bw get item <name> --response`.
    // 2. Mutate the field at field_path via serde_json::Pointer.
    // 3. Serialize the mutated JSON, base64-encode it in-process.
    // 4. Spawn `bw edit item <id> --response --nointeraction`
    //    with Stdio::piped() stdin; write the base64 bytes; close stdin; wait.
    // 5. Parse the response envelope; map errors per the §error map.
    // On NotFound: fall back to `bw create item` (symmetric).
}
```

`base64` v0.22 is the recommended encoder crate. Do not use `bw encode` as a subprocess.

### 8.3 `crates/hasp-backend-op/README.md` ("Argv exposure on `put`" section, lines 27-36)

Update the section to reflect the new posture. Current text claims "this is the documented cost of the `op` CLI surface and applies to every op-based tool." Replace with a paragraph that:

- Describes the stdin-via-`-` template path.
- Notes the bounded residual exposure (§6.3 above).
- Cross-links to this research note and to the Connect follow-up issue.

Same change to `crates/hasp-backend-bw/README.md` once #23 lands.

### 8.4 `CHANGELOG.md` (Unreleased entry)

Add an entry under Unreleased noting the argv-exposure mitigation, e.g.:

```
- `op://` and `bw://` `put` now feed the JSON template to the
  subprocess via stdin instead of positional argv (#27). Same-uid
  attackers can no longer read the secret value from
  `/proc/<pid>/cmdline` for the lifetime of the subprocess. The
  residual exposure (microseconds, pipe-FD scope, gated by
  `yama.ptrace_scope`) is documented in
  `docs/internal/research/RESEARCH-op-stdin-or-connect.md` §6.
```

The wording in this changelog entry should not promise more than the threat-model boundary delivers. "Argv exposure closed" is accurate; "secret never leaves hasp's process" is **not** accurate (the byte still crosses to the `op`/`bw` subprocess — that's the whole point of delegating).

### 8.5 New unit tests

- `op_backend::put` should be testable with the existing `fake-op` test harness (per `RESEARCH-op-cli.md` §5.2 unit-test discipline). Extend the fake-op binary to record its stdin and assert that the JSON template appears there and *not* in argv. The test fixture asserts `argv` does not contain the secret substring and that stdin does.
- Symmetric test for `bw_backend::put` once #23 lands.

### 8.6 Decision fork (explicit)

This research note answers the gating question for issue #27 as: **in-sprint scope is the stdin switch**, not the doc-only contingent. Specifically:

- **Wave 4 deliverable:** patch `crates/hasp-backend-op/src/lib.rs:306-378` to use stdin; patch `crates/hasp-backend-bw/src/lib.rs:192-197` (currently #23 scope) to land directly on stdin; patch both READMEs; patch CHANGELOG; add tests.
- **Two new issues filed** (not blocking #27):
  - `op-connect://` HTTP backend (per §4.3) — feature-gated.
  - `bw-serve://` daemon backend (per §5.3) — feature-gated.
- **Issue #27 closes as fixed**, not `not planned`.

---

## §9 Recommendation

**Land the stdin switch this sprint.** Both CLIs ship the mechanism. The hasp version floors already cover the relevant `op` and `bw` releases. The argv-to-stdin transition is a localized edit to two `fn put` bodies plus README/CHANGELOG/test updates — comfortably within sprint scope.

**Do not** contract to a doc-only deliverable. The doc-only path would (a) ship a known-leaky `put` indefinitely, (b) require us to position #27 as a `not planned` close, which contradicts the threat-model posture in `CLAUDE.md`, (c) defer the obvious fix while waiting on a larger Connect-HTTP refactor that has its own design-space cost. The Connect/Vault-API HTTP backends are good follow-ups for a future wave; they are not prerequisites.

**Sequence:**

1. Patch `op` backend (one-day task once the stdin/JSON-template plumbing is in place; touches `fn put` only).
2. Patch `bw` backend implementation in #23 to land directly on stdin (do not implement argv-passing as an intermediate state — there's no value in landing the leak just to fix it).
3. README + CHANGELOG + tests in the same PR.
4. File the two follow-up issues (`op-connect://`, `bw-serve://`).
5. Close #27.

**Risk most likely to bite:** the JSON-template path on `op item edit` requires fetching the existing item, mutating in-Rust, and piping back. The `op item get` call adds a second subprocess to the `put` operation — doubling the latency from ~1 s to ~2 s for the common case. If the latency hit is unacceptable, the alternative is to send a minimal partial template containing only the changed field; `op item edit` is documented to merge partials. Validate this against the live `op` binary in a smoke test before locking in the implementation; if partial merge does not work as documented, fall back to the get-mutate-pipe pattern and accept the latency.

A secondary risk: the v2.30.0 minimum from `RESEARCH-op-cli.md` §5.5 is past the stdin-feature introduction *for the canonical case*, but if 1Password ever reverts piped-JSON support in a future release (they have a track record of wording-drift per §1.7 of that note), hasp would regress. The `--version` pre-flight check at backend init should be extended to test stdin handling explicitly (a one-time `echo '{}' | op item edit --help` smoke check at first invocation), so a future regression surfaces as a clear `Backend{Permanent}` error rather than a silent argv leak.

**Confidence: High.** The mechanism is documented by 1Password, confirmed in Bitwarden upstream source, has been in the wild for years, and is the explicitly-recommended path in 1Password's own docs ("If you're assigning sensitive values, use a JSON template instead"). The threat-model improvement (window from seconds to microseconds) is supported by independent industry references (smallstep, GitGuardian, OWASP) and the Linux proc/ptrace semantics.

---

## §10 Bibliography

| Source | Type | Relevance | URL |
|---|---|---|---|
| 1Password CLI v2 release notes | Official changelog | `op item create` stdin (v2.3.0), `op item edit` piping (v2.23.0), wording-drift catalog | https://app-updates.agilebits.com/product_history/CLI2 |
| 1Password CLI release-notes index | Official | Per-version notes; v2.23.0 piping | https://releases.1password.com/developers/cli/ |
| 1Password developer: Edit items with 1Password CLI | Official docs | `op item edit` stdin variant, JSON template warning | https://developer.1password.com/docs/cli/item-edit/ |
| 1Password developer: Create items with 1Password CLI | Official docs | `op item create` stdin via `-`, template via `--template` | https://developer.1password.com/docs/cli/item-create/ |
| 1Password developer: item management commands | Official docs | "Command arguments get logged in your command history…" warning | https://developer.1password.com/docs/cli/reference/management-commands/item/ |
| 1Password developer: Item JSON template | Official docs | Template shape for `fields[]` write path | https://developer.1password.com/docs/cli/item-template-json/ |
| 1Password developer: Connect API reference | Official docs | POST/PUT/PATCH on `/v1/vaults/{vaultUuid}/items` | https://developer.1password.com/docs/connect/api-reference/ |
| 1Password developer: Connect overview | Official docs | Connect token model, OpenAPI spec location | https://developer.1password.com/docs/connect/ |
| `1Password/connect` repo | Repo | OpenAPI spec + deployment manifests (server closed-source) | https://github.com/1Password/connect |
| `1Password/connect` issue #58: PATCH for password items | Issue | RFC6902 patch on `/fields/password/value` | https://github.com/1Password/connect/issues/58 |
| 1Password community: cli v2.6.0 piped JSON does not create new fields | Forum | v2.6.0 regression on piped new-field creation; fixed v2.6.2 | https://1password.community/discussion/131985/cli-v2-6-0-editing-items-with-op-item-get-jq-op-item-edit-does-not-create-new-fields |
| 1Password community: cannot create item from template and stdin simultaneously | Forum | Constraint: `--template` and piped stdin are mutually exclusive | https://1password.community/discussion/140523/cannot-create-an-item-from-template-and-stdin-at-the-same-time |
| 1Password community: change password using `op item edit` without having it on the command line | Forum | Confirms the JSON-template-via-stdin pattern is the official recommendation | https://1password.community/discussion/133552/change-password-using-op-item-edit-without-having-it-on-the-command-line |
| Bitwarden Password Manager CLI docs | Official docs | `bw encode`, `bw edit item`, canonical `get \| jq \| encode \| edit` pipe | https://bitwarden.com/help/cli/ |
| Bitwarden Public API docs | Official docs | Public API is org-only, not personal vault items | https://bitwarden.com/help/public-api/ |
| Bitwarden APIs overview | Official docs | Distinguishes Public API (admin) from Vault Management API (`bw serve`) | https://bitwarden.com/help/bitwarden-apis/ |
| Bitwarden Vault Management API: visual guide | Forum (official-adjacent) | `bw serve` endpoint catalog | https://community.bitwarden.com/t/the-vault-management-api-a-visual-guide/85500 |
| Bitwarden: bringing a RESTful API to the Bitwarden CLI | Official blog | `bw serve` announcement and rationale | https://bitwarden.com/blog/bringing-restful-api-to-the-bitwarden-cli/ |
| Bitwarden community: bw encode "no stdin piped in" | Forum | `bw encode` failure mode (avoided by encoding in-process) | https://community.bitwarden.com/t/bw-encode-no-stdin-was-piped-in/39736 |
| Bitwarden community: API support for managing items | Forum | Confirms Public API does not cover personal items | https://community.bitwarden.com/t/api-support-for-managing-items/42574 |
| `bitwarden/clients` `edit.command.ts` (via WebFetch) | Source | `requestJson == null \|\| === "" → CliUtils.readStdin()`, base64-decode then parse | https://github.com/bitwarden/clients/tree/main/apps/cli/src/commands |
| `bitwarden/clients` `encode.command.ts` (via WebFetch) | Source | `bw encode` is stdin-only (`process.stdin.isTTY`, `CliUtils.readStdin`) | https://github.com/bitwarden/clients/tree/main/apps/cli/src/commands |
| `bitwarden/cli` (archived) | Source (historical) | Stdin-fallback pattern present since ~2021 | https://github.com/bitwarden/cli |
| smallstep: How to handle secrets on the command line | Blog | Canonical industry treatment of argv-vs-stdin secret hygiene | https://smallstep.com/blog/command-line-secrets/ |
| GitGuardian: How to handle secrets at the command line | Blog | Cheat-sheet comparing argv/env/stdin/file | https://blog.gitguardian.com/secrets-at-the-command-line/ |
| OWASP: OS Command Injection Defense | Cheat sheet | Adjacent — argv injection vs argv leakage | https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html |
| Lobste.rs: handling secrets (somewhat) securely in shells | Discussion | Community confirmation of argv-to-stdin as canonical fix | https://lobste.rs/s/hmlt2f/handling_secrets_somewhat_securely |
| proc(5) Linux man page | Man page | `/proc/<pid>/cmdline` permissions; `ptrace_may_access` on `/proc/<pid>/fd` | https://man7.org/linux/man-pages/man5/proc.5.html |
| proc_pid_fd(5) Linux man page | Man page | `/proc/<pid>/fd/N` semantics, `PTRACE_MODE_READ_FSCREDS` check | https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html |
| ptrace(2) Linux man page | Man page | `PTRACE_MODE_READ_FSCREDS` semantics for fd-symlink follow | https://man7.org/linux/man-pages/man2/ptrace.2.html |
| Yama LSM kernel docs | Kernel docs | `kernel.yama.ptrace_scope` defaults across distros | https://www.kernel.org/doc/Documentation/security/Yama.txt |
| `RESEARCH-op-cli.md` | Internal | §4.4 Connect, §4.7 argv hygiene, §5.5 version floor | ./RESEARCH-op-cli.md |
| `RESEARCH-bw-cli.md` | Internal | `bw encode` workflow, error envelope, auth model | ./RESEARCH-bw-cli.md |
| `RESEARCH-secrets-zeroization.md` | Internal | Buffer-zeroization posture for the template buffer | ./RESEARCH-secrets-zeroization.md |
| `RESEARCH-failure-modes.md` | Internal | Cross-cutting failure-mode taxonomy | ./RESEARCH-failure-modes.md |
| `CLAUDE.md` (project) | Internal | URL-redaction posture; "treat every secret value as untrusted-output-grade" | ../../CLAUDE.md |
| `crates/hasp-backend-op/src/lib.rs` | Source | `fn put` at lines 306-378; argv-build at line 324 | ../../crates/hasp-backend-op/src/lib.rs |
| `crates/hasp-backend-bw/src/lib.rs` | Source | `fn put` stub at lines 192-197 (in-flight #23) | ../../crates/hasp-backend-bw/src/lib.rs |
| `crates/hasp-backend-op/README.md` | Source | "Argv exposure on `put`" section, lines 27-36 (needs update) | ../../crates/hasp-backend-op/README.md |
| `CHANGELOG.md` (Unreleased) | Source | #7 entry documents the shipped argv exposure (needs Unreleased entry for the fix) | ../../CHANGELOG.md |
