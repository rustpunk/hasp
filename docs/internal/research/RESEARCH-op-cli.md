# RESEARCH-op-cli

> Decision: error-mapping table and subprocess-handling contract for the `op://` backend that wraps the 1Password CLI (`op`) via `std::process::Command`.
>
> Date: 2026-04-26
> Audience: hasp-core authors, `op://` backend implementer
> Status: research, feeds impl-planner for the `op://` backend

---

## Core question

What are the exact exit codes, stderr messages, stdout conventions, and auth failure modes of `op read op://Vault/Item/field` so a subprocess backend can map them deterministically into hasp's locked error taxonomy `Error::{NotFound, AuthenticationFailed, PermissionDenied, PreconditionFailed, Backend{kind}}` (per `RESEARCH-error-taxonomy.md`)?

This research answers four sub-questions:

1. What is the **observable contract** of `op read` and `op item get` across success, missing, auth, permission, and network failures?
2. What is the **stability of that contract** across `op` v2.x minor releases?
3. What **auth modes** does `op` support and how do they affect the subprocess surface?
4. How should hasp **map outcomes into the locked Error variants** without inventing signal that `op` does not provide?

---

## §1 Observed behavior

### 1.1 The exit-code substrate is binary

`op` v2.x uses **only `0` (success) and `1` (failure)**. There is no documented exit-code namespace. A community feature request asking for granular exit codes received a 1Password staffer (April) reply: "I can see where this would be useful and will be sure to bring this up with the team" — no commitment ([1Password community: exit code documentation](https://www.1password.community/discussions/developers/exit-code-documentation/80288), [1Password community: CLI error codes documentation](https://1password.community/discussion/114287/cli-error-codes-documentation)).

A single official exit-code change is recorded in the release history:

> v2.32.1 (2026-02-04): "1Password CLI now correctly exits with code 1 instead of 0 when encountering server error codes that are not recognized by the CLI." {DG-682}

Source: [1Password CLI 2 release notes](https://app-updates.agilebits.com/product_history/CLI2).

**Implication:** before v2.32.1, `op` could exit `0` on server errors that the CLI didn't recognize. `Output::status.success()` is therefore necessary but historically not sufficient — a defensive backend must also treat empty stdout + non-empty stderr as failure even on `exit 0` for older `op` versions.

### 1.2 Stderr format is the Go `log.LstdFlags` shape

Failures emit a single line prefixed `[ERROR] YYYY/MM/DD HH:MM:SS <message>` (Go's default `log` package format). Verbatim community-quoted examples:

```
[ERROR] 2025/08/08 15:24:36 could not read secret op://Private/{Item}/{Field}: could not get item Private/{Item}: "Private" isn't a vault in this account. Specify the vault with its ID or name.
[ERROR] 2024/12/29 23:17:25 could not find item MyItem in vault MyVault, because it has been deleted or archived.
[ERROR] 2025/07/11 10:16:41 authorization timeout
[ERROR] 2022/07/06 23:28:40 "-" isn't an item. Specify the item with its UUID, name, or domain.
```

Sources: [Reference for Private vault thread](https://www.1password.community/discussions/developers/reference-for-private-vault-copied-from-gui-doesnt-work-in-cli/160562), [authorization-timeout thread](https://www.1password.community/discussions/developers/authorization-timeout-when-using-cli/159177), [TTY fussiness thread](https://1password.community/discussion/131365/1password-cli-is-fussy-about-ttys), [item missing thread](https://www.1password.community/discussions/developers/item-missing-from-some-commands/28206).

A non-`[ERROR]`-prefixed parenthesized form also appears in some auth paths:

```
(ERROR) You are not currently signed in.
```

Source: [1Password community thread 94643](https://1password.community/discussion/94643/error-you-are-not-currently-signed-in).

**Implication:** stderr line shape is consistent enough to recognize a failure marker, but the **noun phrase after the timestamp is the only stable identifier** — full sentences shift release-to-release (see §1.7). The `op` reference URL is often echoed back inside the message, which means hasp must redact when logging.

### 1.3 Success path

`op read op://<vault>/<item>/<field>` on a healthy vault prints the field value to stdout and exits `0`. **Stdout always carries a trailing `\n`** by default; the documented suppression flag is `op read -n` (long form `--no-newline`), confirmed by community usage `git crypt unlock <(op read -n …)` in the [op-read-mistreats-binary-content thread](https://www.1password.community/discussions/developers/op-read-mistreats-binary-content/159981).

The same thread documents a **binary-content corruption hazard**: when `op read` writes stdout to a non-pipe FD (e.g. `op read … > file`), the CLI applies UTF-8 validation that replaces invalid bytes with U+FFFD (`ef bf bd`) and strips DEL (`0x7f`). Piping (`| cat > file`) and process substitution (`<(op read …)`) bypass the corruption. **Implication:** hasp must capture stdout via `Command::output()` (pipe-backed) and never give `op` a raw `File` FD as stdout.

### 1.4 Item not found / vault not found

Exit `1`. Stderr substring anchor: `could not find item` (Item-level), `isn't a vault` / `isn't an item` (CLI argument validation level).

Verbatim:
```
[ERROR] 2024/12/29 23:17:25 could not find item MyItem in vault MyVault, because it has been deleted or archived.
[ERROR] 2025/08/08 15:24:36 ... "Private" isn't a vault in this account.
```

The "deleted or archived" suffix appears only when the item exists in trash/archive; never-existed items omit it. **The same stderr is emitted whether the item is missing or the caller has no permission to see it** — see §1.5.

Field-level not-found: per release note v2.27.0 (2024-04-15), "`op read` will now output an error message **consistent with the secret reference provided**, when no matching field or section is found within the item." {3592}. Pre-v2.27 the message could omit the field name; post-v2.27 it includes the reference.

Sources: [item missing thread](https://www.1password.community/discussions/developers/item-missing-from-some-commands/28206), [CLI2 release notes](https://app-updates.agilebits.com/product_history/CLI2).

### 1.5 Permission denied is unreachable from `op read`

**Critical finding:** 1Password's server returns `404` for both "missing" and "no permission to see". The CLI faithfully reflects this — there is no stderr substring that distinguishes "the item doesn't exist" from "the item exists but your token can't see it". This is a deliberate authorization-aware design that prevents existence oracles, identical to HashiCorp Vault's 403/404 collapse documented in [`RESEARCH-error-taxonomy.md`](./RESEARCH-error-taxonomy.md) §The landscape, point 1.

I could not find a single community thread quoting a verbatim "permission denied" stderr from `op read`. The only documented permission-flavored error from `op` is `[ERROR] … access denied` from administrative paths (`op user`, `op group`), not from `op read`.

**Implication:** hasp's `op://` backend physically cannot map to `Error::PermissionDenied` from `op read` alone. These will surface as `Error::NotFound`. This matches the existing project guidance for `vault://` (`RESEARCH-error-taxonomy.md` §Design insights, point 3) and is **the honest mapping** rather than a loss of signal. Document this in the `op://` backend rustdoc.

The Connect HTTP API path (§4.4) is the only way to recover the `404` vs `403` vs `401` distinction; Connect returns distinct HTTP statuses ([connect-sdk-go errors.go](https://github.com/1Password/connect-sdk-go/blob/main/onepassword/errors.go), confirmed by Agent 2-supp).

### 1.6 Auth failure modes

Three distinct phrasings observed in the wild:

| Anchor substring | Meaning | Source |
|------------------|---------|--------|
| `not currently signed in` | No `OP_SESSION_*` and no service-account token | [community thread 94643](https://1password.community/discussion/94643/error-you-are-not-currently-signed-in) |
| `authorization timeout` | App-integration grant expired (10-min idle default; 12-hr hard cap; 30-min idle for classic `op signin`) | [authorization-timeout thread](https://www.1password.community/discussions/developers/authorization-timeout-when-using-cli/159177) |
| `connecting to desktop app` (often `: read: connection reset`) | Desktop app integration enabled but desktop app is closed/crashed/missing | [cli-cant-connect thread](https://www.1password.community/discussions/developers/cli-cant-connect-to-desktop-app-despite-having-biometric-unlock-enabled/91634) |
| `Signin credentials are not compatible with the provided user auth from server` | Service-account token's embedded device UUID disagrees with `OP_DEVICE` | [service-account bug report](https://www.1password.community/discussions/developers/1password-cli-service-account-bug-report/167222) |

**Across-mode inconsistency**: the `authorization timeout` vs `not currently signed in` split is reliable only on the app-integration path. For the classic `OP_SESSION_*` path, both expired-and-never-set produce the generic "not signed in" wording (no `OP_SESSION_*` env var → no signal to discriminate). Therefore hasp should **collapse all four into `Error::AuthenticationFailed`** rather than try to distinguish — `op` does not give a stable cross-mode signal for the subdivision, and forcing the distinction would make hasp lie in the common token-based case.

### 1.7 Version drift across `op` v2.x

Stderr wording and exit-code semantics have shifted repeatedly. Filtered from the [CLI2 release notes](https://app-updates.agilebits.com/product_history/CLI2) for changes that touch the parseable surface:

| Version | Date | Change relevant to a stderr/exit-code parser |
|---|---|---|
| 2.5.0 | 2022-06-21 | Debug messages moved from stdout → stderr |
| 2.5.0 | 2022-06-21 | Multi-match secret references now error instead of silently returning the first match (semantics flip) |
| 2.7.1 | 2022-09-08 | "Sign in" prompt replaces panic when no creds available |
| 2.20.0 | 2023-08-24 | Stops crashing on invalid service-account tokens |
| 2.20.0 | 2023-08-24 | Fixed `op run` masking gap where secrets were not correctly masked |
| 2.22.0 | 2023-10-24 | `op whoami` JSON keys partially restored from uppercase rename in 2.20.0 |
| 2.26.0 | 2024-03-19 | Typo correction in `user suspend` error message |
| 2.27.0 | 2024-04-15 | `op read` field-not-found message rewording {3592} |
| 2.30.0 | 2024-07-29 | Sensitive values in human-readable item-management output now concealed; requires `--reveal` to display |
| 2.32.1 | 2026-02-04 | Exit code corrected from `0` → `1` for unrecognized server errors {DG-682} |
| CLI 1 → 2 | 2022-03 | Whole new command schema; pre-CLI-2 parsing is dead |

**Implication:** anchor on **stable noun phrases** (`could not find item`, `not currently signed in`, `authorization timeout`, `isn't a vault`, `isn't an item`, `connection reset`), not on full sentences. **Pin a minimum supported `op` version**; v2.30.0 is the natural floor (gets concealed-by-default human output, post-typo fixes, reasonable JSON shape). Reject older versions at startup via `op --version` parsing; warn (don't reject) on unknown-newer versions so hasp doesn't ossify against `op`'s release cadence.

### 1.8 Latency profile

Per-call cost on a healthy desktop-app setup is **~700ms–2s wall-clock**, dominated by `op`'s own auth/cache initialization handshake — not by fork/exec, not by network. Concrete measurements:

| Setup | Mean | Source |
|---|---|---|
| `op read` warm, M3 Max + macOS, op 8.10.30, hyperfine warmup=3 | 717.2 ms ± 46.6 ms (10 runs) | [community: 700ms per invocation thread](https://www.1password.community/discussions/developers/op-read-is-pretty-slow-700ms-per-invocation/25907) |
| `op read`, M2 MBP, gigabit | 1.925 s ± 0.043 s, max 5s | [community: speed concerns](https://www.1password.community/discussions/developers/speed-concerns/26678) |
| `op read` Sydney → us-east-1, cache hit | 1.2–1.3 s | [cli-cache thread](https://www.1password.community/discussions/developers/cli-cache-is-either-not-working-or-not-significantly-reducing-time-to-return-a-s/91089) |
| `op-fast read` (OS-keyring cache hit) | 22.6 ms ± 1.7 ms (~90× faster than baseline) | [github.com/cometkim/op-fast](https://github.com/cometkim/op-fast) |
| `op-cache` (in-RAM daemon, hit) | 1–2 ms | [Deploy Linux Blog: op-cache](https://deploymentfromscratch.com/blog/op-cache) |
| Worst observed: mise integration, 3 secrets, biometric prompt | ~12 s first call; ~6 ms with tmpfs cache | [jdx/mise discussion #3542](https://github.com/jdx/mise/discussions/3542) |

A 1Password staffer (Andi_t_1P) confirmed in the 700ms thread that the slowness sits in cache initialization and account-metadata retrieval. **The `--cache` flag does not enable caching; caching is on by default — the flag only lets you disable it via `--cache=false`.** Recent macOS Tahoe regression caused indefinite hangs; `--cache=false` is the documented workaround ([openclaw/openclaw#55459](https://github.com/openclaw/openclaw/issues/55459)).

Rust `std::process::Command::spawn` + `wait` is **~540 µs/iteration** on a modern Linux laptop with glibc ≥ 2.24 (uses `posix_spawn` → `clone3(CLONE_VM|CLONE_VFORK)`). Three orders of magnitude smaller than `op`'s own overhead — fork/exec is not a meaningful design driver here ([Kobzol: process spawning performance in Rust](https://kobzol.github.io/rust/2024/01/28/process-spawning-performance-in-rust.html)).

**Implication:** hasp should expose a per-call **timeout** (default 10–30s for `read`) so that pathological cases (Tahoe regression, biometric blocking, network stall) fail-fast. `op` has no `--no-prompt` or `--non-interactive` flag — there is no way to make biometric prompts fail-fast from the `op` side; only timeout works.

---

## §2 Exit code map

Single integer-exit table. Every row anchored to a verbatim quote or release-note URL.

| Scenario | `op` exit | Stderr anchor (case-insensitive substring) | hasp `Error` variant | Confidence | Source |
|---|---|---|---|---|---|
| `op read` success (existing field) | `0` | empty | `Ok(SecretString)` | High | [op-read-mistreats-binary-content thread](https://www.1password.community/discussions/developers/op-read-mistreats-binary-content/159981) |
| `op read` exits `0` but stderr non-empty (pre-v2.32.1) | `0` | non-empty | `Backend{kind: Permanent, message: <stderr>}` | Medium | v2.32.1 release note {DG-682} |
| `op` binary not on `$PATH` | spawn err | `io::ErrorKind::NotFound` from `Command::spawn` | `Backend{kind: Permanent, message: "op binary not found in PATH"}` | High | [std::process::Command docs](https://doc.rust-lang.org/std/process/struct.Command.html) |
| Item not found / vault not found | `1` | `could not find item`, `isn't a vault`, `isn't an item` | `NotFound(<reference>)` | High | [item missing thread](https://www.1password.community/discussions/developers/item-missing-from-some-commands/28206), [Private vault thread](https://www.1password.community/discussions/developers/reference-for-private-vault-copied-from-gui-doesnt-work-in-cli/160562) |
| Field not found | `1` | (post-v2.27.0) message includes the secret reference, e.g. `could not read secret op://… could not find … field` | `NotFound(<reference>)` | High (≥ v2.27.0) | v2.27.0 release note {3592} |
| Multi-match (ambiguous reference) | `1` | `more than one item matches` (or similar; semantics introduced 2.5.0) | `NotFound(<reference>)` (collapse) — see §5.4 | High | v2.5.0 release note; [onepassword-cli error.rs substring map](https://docs.rs/onepassword-cli/latest/src/onepassword_cli/error.rs.html) |
| Permission denied (item exists, no access) | `1` | **identical to "not found"** — server returns 404 for both | `NotFound(<reference>)` (collapse — see §1.5) | High | Vault precedent in `RESEARCH-error-taxonomy.md` §Design insights point 3; absence of distinguishing community quote is itself the finding |
| Not signed in (no `OP_SESSION_*`, no service-account token) | `1` | `not currently signed in` | `AuthenticationFailed(<msg>)` | High | [community 94643](https://1password.community/discussion/94643/error-you-are-not-currently-signed-in) |
| Session expired (app integration) | `1` | `authorization timeout` | `AuthenticationFailed(<msg>)` (collapse — see §1.6) | High | [authorization-timeout thread](https://www.1password.community/discussions/developers/authorization-timeout-when-using-cli/159177) |
| Desktop app unavailable | `1` | `connecting to desktop app`, `connection reset` | `AuthenticationFailed(<msg>)` (collapse) | High | [cli-cant-connect thread](https://www.1password.community/discussions/developers/cli-cant-connect-to-desktop-app-despite-having-biometric-unlock-enabled/91634) |
| Service-account device-UUID mismatch | `1` | `signin credentials are not compatible` | `AuthenticationFailed(<msg>)` | High | [service-account bug report](https://www.1password.community/discussions/developers/1password-cli-service-account-bug-report/167222) |
| Network failure (transient) | `1` | `connection reset`, `dial`, `getaddrinfo`, `i/o timeout`, `EOF`, `no such host` | `Backend{kind: Transient, message: <stderr>}` | Medium | Inferred from Go `net.OpError` text; [bitwarden/clients#18373](https://github.com/bitwarden/clients/issues/18373) shows comparable Go-CLI pattern; `op` follows same Go log idiom |
| Rate limit (service account) | `1` | (1Password documents per-token hourly + per-account daily limits; no `Retry-After` header at the CLI surface) | `Backend{kind: Throttled, message: <stderr>}` | Low — unverified anchor wording | [service account rate limits](https://developer.1password.com/docs/service-accounts/rate-limits/) |
| Biometric prompt declined / timed out | `1` | `authorization timeout` after the prompt is dismissed | `AuthenticationFailed` | High | [CLI hangs thread](https://www.1password.community/discussions/developers/cli-hangs-when-requesting-items/95850) |
| Biometric prompt not answered (headless / SSH / container) | hangs indefinitely | n/a (no output until timeout from caller) | `Backend{kind: Transient, message: "op invocation timeout"}` after caller-side timeout | High | [CLI hangs thread](https://www.1password.community/discussions/developers/cli-hangs-when-requesting-items/95850); hasp must impose its own timeout |
| Unknown / unanchored failure | `1` | unmatched | `Backend{kind: Permanent, message: <stderr>}` (intentionally fail-loud — never fall through to `NotFound`) | High | Defensive default per Agent 5 §2 wording-drift caveats |

**Mapping rule:** match in **first-anchor-wins** priority order from this table. Any unmatched stderr falls through to `Backend{kind: Permanent, message: <raw stderr>}` so a future `op` rewording surfaces as a backend error rather than a silently mis-classified `NotFound`. The `Backend.message` field carries the redacted-as-needed stderr so callers can debug without consulting `op` directly.

`op`'s stderr often echoes the secret-reference URL back inside the message (e.g. `could not read secret op://Private/{Item}/{Field}: …`). **Hasp must apply its URL redaction posture to the captured stderr before any logging, even at trace level.** The reference itself is not a secret, but it identifies one and follows the URL-redaction discipline established in `CLAUDE.md`.

---

## §3 Stdout conventions

### 3.1 Trailing newline

`op read` appends a single trailing `\n` to every value it prints. The documented suppression flag is `op read -n` (`--no-newline`).

**Recommendation for hasp:** do **not** pass `-n`. Always strip the suffix client-side via `bytes.strip_suffix(b"\n").unwrap_or(bytes)` after capture. Reason: `-n` is per-call; centralizing the strip in one place is cheaper and lets us preserve a legitimate trailing newline if the field contains one (extremely rare for credentials, but possible for free-form notes). **Do not use `String::trim` or `String::trim_end`** — both strip arbitrary whitespace, which would corrupt secrets that legitimately end in spaces or tabs.

### 3.2 Binary content corruption when stdout is not a pipe

Documented in [op-read-mistreats-binary-content](https://www.1password.community/discussions/developers/op-read-mistreats-binary-content/159981): when `op read` writes stdout to a non-pipe FD (`>file`, redirection to a regular file), the CLI applies UTF-8 validation that replaces invalid bytes with U+FFFD (`ef bf bd`) and strips DEL (`0x7f`). Pipe-backed stdout (`| cat > file`, process substitution `<( … )`) bypasses the corruption.

**Hasp must capture stdout via `Command::output()`** (or equivalent `.stdout(Stdio::piped()).spawn()` + `wait_with_output()`). Never give `op read` a raw `File` FD or inheriting stdout when the caller wants the raw bytes. This is critical for SSH private keys, certificate bytes, and any binary secret.

### 3.3 Color / ANSI

`op` strips ANSI when stdout is not a tty by default and supports `--no-color` to force-disable. **Hasp should pass `--no-color` belt-and-suspenders** on every invocation in case `op` ever changes the auto-detection rules ([TTY thread](https://1password.community/discussion/131365/1password-cli-is-fussy-about-ttys)).

### 3.4 JSON output

Every command that supports a tabular default also supports `--format json` (and the `OP_FORMAT=json` env var). The official CLI reference page lists this as one of two formally-documented env vars ([CLI reference](https://developer.1password.com/docs/cli/reference/)). **For every command hasp shells out to except `op read`, pass `--format=json --no-color`** to stabilize the parseable surface and disable ANSI bleed.

`op read` itself has no JSON variant — it prints the raw field value to stdout. That's the right shape for hasp's `get` operation; nothing to change there.

### 3.5 Capture buffer hygiene

`std::process::Output::stdout` is a `Vec<u8>` populated by a `read_to_end`-style growth loop. Per [zeroize crate docs](https://docs.rs/zeroize/latest/zeroize/), `Vec<u8>::zeroize` only zeroes the **current backing buffer** — it cannot reach copies left in pages freed during prior reallocations. Per [Rust users forum](https://users.rust-lang.org/t/vec-with-capacity-read-to-end-overallocation/65023), even pre-sized buffers can get reallocated by `read_to_end` because the implementation reserves more space, then EOFs on the last `read`.

**Mitigation:** read into a manually-managed `Vec::with_capacity(MAX_SECRET_LEN)` (a few MiB upper bound) using a `Read::read` loop that calls **no further `reserve`**, so the buffer stays at one allocation. The Linux pipe buffer is 64 KiB, so secrets ≤ 64 KiB fit in a single `read` and a single allocation; SSH keys (~3 KiB) and certificates (~5 KiB) are well under this. Move the captured `Vec<u8>` into `secrecy::SecretBox<[u8]>` exactly once at the backend boundary.

This is a known limitation, not a hard guarantee — page-level concerns (RAM scraping, swap, core dumps) are explicitly out of scope for `zeroize`. Document that the `op://` backend's secret-lifetime guarantee is "current backing buffer is zeroized at drop; pre-sized capture bounds the realloc-leak window." A future research note on `mlock`-grade protection (`secmem-alloc`, `memsecurity`) can tighten this further; out of scope for Wave 2.

### 3.6 Stderr is also secret-sensitive

There is at least one historical case (release 2.20.0) of `op run` masking gap where secrets were not correctly masked. Plus the ongoing finding that `op` echoes the secret-**reference** (not the value) back in error messages. **Wrap captured stderr in the same redaction discipline** as captured stdout: capture into `Vec<u8>`, redact the URL portion before logging, never relay verbatim into hasp's `tracing` output even at trace level. If a debug-mode dump is wanted, gate it behind an explicit `--unsafe-debug` flag that warns loudly on stderr.

---

## §4 Auth model

### 4.1 Three distinct modes

| Mode | Auth source | Headless? | Blocks on prompt? | Failure phrasing |
|------|------------|-----------|-------------------|-------------------|
| Service Account | `OP_SERVICE_ACCOUNT_TOKEN` env | Yes (designed for it) | No | Generic 401-style; or `signin credentials are not compatible` if device-UUID mismatch |
| Interactive `op signin` | `OP_SESSION_<acct>` env (after `op signin` in shell) | Yes if env var present | No | `not currently signed in` |
| Desktop App integration | macOS Keychain / Touch ID / Windows Hello / Polkit | **No** — biometric chain broken in headless contexts | **Yes** (indefinite hang on missing GUI) | `authorization timeout` after dismissal; `connecting to desktop app: read: connection reset` if app unavailable |

The desktop-integration **indefinite hang** is documented in [CLI hangs when requesting items](https://www.1password.community/discussions/developers/cli-hangs-when-requesting-items/95850) — the debug log stalls at `NmRequestDelegatedSession`. There is no `--no-prompt` flag; 1Password has stated removing the prompt is "not on the short-term roadmap" ([disable biometric prompt thread](https://1password.community/discussion/140411/disable-biometric-prompt-if-authenticated-in-1password-ui)).

**Implication:** hasp must pre-flight detect ambient credentials before spawning `op`. If `OP_SERVICE_ACCOUNT_TOKEN` is unset *and* `OP_SESSION_*` (any variant) is unset *and* the caller has not opted into interactive mode, return `Error::AuthenticationFailed("no ambient 1Password credentials detected")` without spawning. This prevents the indefinite-hang case in CI runners and headless containers.

In addition, every `op` invocation must impose a **wall-clock timeout** on the caller side (10–30s default for `read`). This is the only mitigation against the Tahoe-regression hang ([openclaw/openclaw#55459](https://github.com/openclaw/openclaw/issues/55459)) and the biometric-not-answered-after-dismissal hang.

### 4.2 Environment variables `op` respects

Reconstructed from [CLI reference](https://developer.1password.com/docs/cli/reference/), [app integration docs](https://developer.1password.com/docs/cli/app-integration/), [service accounts CLI docs](https://developer.1password.com/docs/service-accounts/use-with-1password-cli/), and the service-account-bug-report community thread:

| Var | Documented? | Effect |
|-----|-------------|--------|
| `OP_SERVICE_ACCOUNT_TOKEN` | Yes (service accounts page) | Service-account auth; mutually exclusive with `OP_SESSION_*` in practice |
| `OP_SESSION_<account>` | Yes (signin docs) | Session token from `op signin` |
| `OP_CONNECT_HOST` | Yes (Connect docs) | URL to a self-hosted Connect server |
| `OP_CONNECT_TOKEN` | Yes (Connect docs) | Bearer token for Connect server; **takes precedence over `OP_SERVICE_ACCOUNT_TOKEN`** |
| `OP_ACCOUNT` | Yes (CLI reference) | Pick which signed-in account when multiple are present |
| `OP_DEVICE` | Partial (only documented in error-context pages) | Device UUID; mismatch with service-account token's embedded UUID → "signin credentials are not compatible" |
| `OP_BIOMETRIC_UNLOCK_ENABLED` | Yes (app integration page) | Toggle desktop-app biometric path on/off |
| `OP_FORMAT` | Yes (CLI reference) | Equivalent to `--format`; values `human-readable`, `json` |
| `OP_CACHE` | Yes (CLI reference) | `false` to disable cache, equivalent to `--cache=false` |

The official CLI reference page formally enumerates only `OP_FORMAT` and `OP_CACHE`. The rest are documented across feature-specific pages or only mentioned in error contexts. **Implication for hasp:** do not rely on `OP_*` semantics being formally specified — pass everything hasp cares about explicitly via flags whenever possible (`--format=json`, `--vault=…`, `--account=…`).

### 4.3 Service account token format and the "no direct HTTP" finding

Service-account tokens begin with `ops_` and are described by 1Password as "a serialized, Base64-URL-encoded SRPx object" — they carry cryptographic material, not a simple bearer credential ([service-account token format detector docs](https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/1password_service_account_token)).

There is **no documented service-account HTTP API**. Service-account tokens can be consumed only via the `op` CLI or the official SDKs (Go/Python/JS), all of which load a shared Rust core (compiled to WASM via wasm-bindgen + Extism) that performs the SRP handshake locally and talks to 1Password.com over an undocumented internal protocol. **Implication:** a third-party HTTP client cannot speak directly to 1Password.com using a service-account token. The only HTTP-direct path is Connect (§4.4), which uses Connect tokens — not service-account tokens.

### 4.4 Connect HTTP API (alternative backend for self-hosted Connect)

Per [Connect API reference](https://developer.1password.com/docs/connect/api-reference/) and the open OpenAPI spec at [github.com/1Password/connect](https://github.com/1Password/connect):

- REST over HTTPS, base path `/v1`.
- Auth: `Authorization: Bearer <connect-token>`. Connect tokens are issued in the 1Password admin UI per Connect server, are scoped to a list of vaults, and are JWT-shaped. **Disjoint from service-account tokens** — Connect tokens only work against your Connect server; service-account tokens only work against 1Password.com.
- Error envelope ([connect-sdk-go errors.go](https://github.com/1Password/connect-sdk-go/blob/main/onepassword/errors.go)):
  ```go
  type Error struct { StatusCode int `json:"status"`; Message string `json:"message"` }
  ```
  HTTP status carries meaning: `400` invalid input, `401` invalid/missing token, `403` unauthorized to access this vault/item, `404` not found, `413` file too large.
- **`op://` URL resolution is NOT supported by Connect.** Connect operates on UUIDs only — a client wanting to honor `op://Vault/Item/field` must (a) `GET /vaults?filter=name eq "Vault"`, (b) `GET /vaults/{vaultUuid}/items?filter=title eq "Item"`, (c) walk fields locally. The official `connect-sdk-go` does this in `restClient.GetItem()` via `getVaultUUID()` + `getItemUUID()` helpers.
- **Server is closed-source.** Connect repo contains only OpenAPI spec + deployment manifests + SDK clients; issue [#37 "Open Source"](https://github.com/1Password/connect/issues/37) is still open with no commitment.

**Implication:** Connect is an optional `op://` backend mode worth enabling behind a future feature flag. When `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` are both set, an HTTP path can use `reqwest` (rustls-aligned) and recover the `404` vs `401` vs `403` distinction that the subprocess path collapses. Cost: hasp must implement the name→UUID resolution dance. Not in scope for Wave 2's first cut; document the deferral with rationale.

### 4.5 Official Rust SDK status

**There is no first-party Rust SDK.** 1Password ships official SDKs for Go, JavaScript, and Python only ([SDKs landing page](https://developer.1password.com/docs/sdks/)). 1Password's Rust open-source presence is `passkey-rs`, `electron-hardener`, `password-rules-parser`, and `Typeshare` — none are a secrets-access SDK ([github.com/1password?language=rust](https://github.com/1password?language=rust)).

Two community alternatives, both unsuitable for hasp's hard dependencies:
- `connect-1password` v2.0.1 — bsodmike, last release ~mid-2022, **stale**. Built on hyper 0.14 + hyper-rustls 0.23 (rustls-aligned, but every dep is now obsolete). Useful as an API-shape reference; not a viable cargo-add. ([github.com/bsodmike/connect-sdk-rust](https://github.com/bsodmike/connect-sdk-rust))
- `onepassword-sys` / `onepassword` / `onepassword-async` v0.1.1 (André Vennberg, Feb 2026) — FFI bindings to the dynamic library 1Password ships with their **Python SDK** (downloaded from `1Password/onepassword-sdk-python/tree/main/src/onepassword/lib`). Couples hasp to a non-Rust binary downloaded from another project's repo. **Reject** — supply-chain risk and packaging complexity for one backend; defeats hasp's "single static binary" identity.

The most credible production wrapper of `op` in the Rust ecosystem is **`cargo-credential-1password`** (Cargo team, MIT/Apache, current). Pure subprocess wrapper of `op`, no FFI, no Connect. This is the right precedent for hasp's `op://` backend.

A relevant negative finding: **even the official 1Password SDKs only typify two errors.** From `onepassword-sdk-go/errors.go`, `onepassword-sdk-python/src/onepassword/errors.py`, `onepassword-sdk-js/client/src/errors.ts` — all three are tagged `Code generated by op-codegen - DO NOT EDIT` and define exactly:

- `DesktopSessionExpired{Error,Exception}`
- `RateLimitExceeded{Error,Exception}`

Everything else — auth failure, not-found, permission-denied, network — collapses to a generic `errors.New(message)` / `Exception(message)`. **This validates hasp's choice to collapse `op`-CLI auth modes into `AuthenticationFailed`** — even 1Password's own SDKs do not expose finer granularity, and the `op` CLI cannot be expected to.

### 4.6 Session file location and trust model

- **Session file:** `~/.config/op/` (XDG); legacy `~/.op/`. The session token is an encryption key for the session file on disk. 1Password explicitly documents tightened "validation of config and session directories and files before reading from or writing to them" as a hardening change — implying earlier versions did less validation. No published CVE on the session file.
- **Desktop integration trust model** ([app integration security docs](https://developer.1password.com/docs/cli/app-integration-security/)):
  - macOS: NSXPCConnection + code-signature verification both directions.
  - **Linux: Unix socket owned by user; `op` binary is `setgid onepassword-cli`; the app verifies the connecting process's GID equals `onepassword-cli`.** This is the entire trust check on Linux.
  - Windows: named pipe + Authenticode signature.
- **Documented residual risks** (1Password's own words): "Processes with root/administrator privileges on the same system can bypass protections and obtain account access through the unlocked desktop app" and "macOS apps with accessibility permissions may circumvent the authorization prompt." Same-user-process isolation is also a non-property: 1Password's own service-account docs acknowledge that "processes on your computer can access the environment of other processes run by the same user."

**Implication for hasp:** when delegating to `op` we inherit the GID-only check on Linux. We do not make it worse, but the `op://` backend rustdoc must not market `op://` as stronger than it is — any same-user process can invoke `op` and use the active session.

### 4.7 Argv leakage hygiene

`/proc/<pid>/cmdline` is world-readable on Linux by default ([proc(5) man page](https://man7.org/linux/man-pages/man5/proc.5.html); [hidepid mount option](https://www.cyberciti.biz/faq/linux-hide-processes-from-other-users/)). Any `op` invocation that takes a token/passphrase as a positional arg would expose it.

`op` itself **does not accept secrets via argv** for reads. The secret-reference URL goes on argv (it is the *reference*, not the value), which is safe. For future `put`/`item edit` paths, [op's own docs warn](https://developer.1password.com/docs/cli/reference/management-commands/item/): "Command arguments get logged in your command history, and can be visible to other processes on your machine. If you're assigning sensitive values, use a JSON template instead." Use `op item edit`'s stdin-based JSON template path, never `field=value` on argv.

---

## §5 Design insights for hasp

### 5.1 Adopt the locked Approach B taxonomy from `RESEARCH-error-taxonomy.md`

Reuse the locked enum verbatim — do not invent op-specific variants:

```rust
pub enum Error {
    NotFound(String),
    PermissionDenied(String),                // unreachable from `op read` — see §1.5
    AuthenticationFailed(String),
    PreconditionFailed(String),              // unused on op:// path
    Backend { scheme: &'static str, kind: BackendFailureKind, message: String },
    // …other variants per RESEARCH-error-taxonomy.md
}
pub enum BackendFailureKind { Transient, Throttled, Permanent }
```

The `op://` backend produces (in Wave 2) only `NotFound`, `AuthenticationFailed`, and `Backend{Transient | Throttled | Permanent}`. **`PermissionDenied` is unreachable** because `op` (and 1Password's server) returns 404 for both missing and no-permission cases. This matches the existing `vault://` precedent (`RESEARCH-error-taxonomy.md` §Design insights point 3) and is the honest mapping rather than a loss of signal.

Each `op://` backend rustdoc must list **which variants this backend can produce** so consumers writing exhaustive `match` arms aren't surprised by `PreconditionFailed` they'll never see, or `PermissionDenied` they'll get only via the future Connect-HTTP path.

### 5.2 Implement the error-mapping table from §2 in one place

Centralize the (anchor → variant) table in a `op_backend::error_map` module. Properties:

- **First-anchor-wins** priority order matches §2 row order.
- **All comparisons case-insensitive** (`op` has had inconsistent case in past releases).
- **Anchors are noun phrases**, not full sentences (§1.7 wording-drift caveat).
- **Unmatched stderr falls through to `Backend{kind: Permanent}`** — never to `NotFound`. A future `op` rewording must surface as a backend error, not a silently mis-classified missing item.
- **Captured stderr is redacted** before being placed in `Backend.message` (mask `op://...` references following the `CLAUDE.md` URL-redaction posture).

A unit test file with verbatim stderr fixtures (one per row in §2's table) gives the table an executable spec. When `op` ships a new minor version, run those fixtures against the new binary in CI to catch wording drift before users do.

### 5.3 Implement `get` via `op read`, `exists` via `op item list`

**For `get(url)`:**

```
op read --no-color op://Vault/Item/field
```

Capture stdout via `Command::output()` (pipe-backed; §3.2 binary-corruption avoidance). Strip a single trailing `\n` via `bytes.strip_suffix(b"\n").unwrap_or(bytes)`. Move the `Vec<u8>` into `secrecy::SecretBox<[u8]>` at the boundary. Apply timeout (default 10–30s; configurable).

**For `exists(url)`:**

Prefer `op item list --vault VAULT --format=json --no-color` over `op item get`. Reason: `op item list` returns title/category/vault/id-grade metadata only — **no secret material is ever transferred to hasp's address space**. `op item get --format=json`, even when the caller intends to discard the JSON, **does include the field `value` strings** in the JSON body (the `--reveal` concealment applies only to human-readable output, not to JSON), so the secret crosses the process boundary just to be thrown away.

Sketch:
```
op item list --vault Vault --format=json --no-color | <client-side filter for title == "Item">
```

If the caller is querying `op://Vault/Item/field` and `Item` is found in the list, `exists()` returns `Ok(true)`. If `Item` is absent, return `Ok(false)`. If listing the vault fails, propagate via the same error-map table.

This is more network-expensive than `op item get` (returns all items in the vault), but the cost is operationally invisible (`op item list` is one request) and the secret-exposure win is decisive. Document the tradeoff.

The cheaper alternative (`op item get NAME --vault VAULT --fields label=username --format=json`) restricts the JSON payload to a single named field, but still returns that field's `value` — only useful if hasp is willing to declare a "harmless" canonical field per item, which it isn't. Reject this option.

### 5.4 Multi-match handling

`op` v2.5.0 changed the semantics of multi-match references from "silently return first match" to "error". A reference that resolves to multiple items emits a `more than one item matches` (or similar) stderr.

Per `RESEARCH-error-taxonomy.md`, hasp's locked enum has no `Ambiguous` variant. Two options:
- (a) Surface as `NotFound(<reference>)` with a message that mentions "multiple matches" — collapse, lossy but matches the locked taxonomy.
- (b) Surface as `Backend{kind: Permanent}` — preserves the distinct cause but loses the user-action signal ("you need to disambiguate").

**Recommendation: (a) `NotFound`** with the multi-match phrasing in the inner message. The user-action is the same as not-found (look at your vault, try a UUID), and the locked taxonomy's stability is more valuable than rescuing one variant. Document this collapse in the `op://` backend rustdoc.

### 5.5 Pin a minimum `op` version at backend init

Run `op --version` once at backend construction; parse the version with `semver`; refuse if `< 2.30.0` with a clear `Backend{kind: Permanent, message: "op CLI version X.Y.Z is unsupported; hasp requires op >= 2.30.0"}`. Why 2.30.0:

- Concealed-by-default human output (post-2.30.0 release note) means accidental human-format invocations don't dump secrets if a misconfiguration ever drops `--format=json`.
- Post 2.27.0 field-not-found wording stabilization.
- Post 2.20.0 service-account-token crash fix.
- Post 2.5.0 multi-match semantic flip.

For `> 2.32.x`, log a debug-level "unverified op version" but proceed. Hasp must not ossify against `op`'s release cadence.

### 5.6 Pre-flight auth detection

Before every `op read` spawn:

```rust
let has_service_token = env::var("OP_SERVICE_ACCOUNT_TOKEN").is_ok();
let has_session = env::vars().any(|(k, _)| k.starts_with("OP_SESSION_"));
let has_connect = env::var("OP_CONNECT_TOKEN").is_ok() && env::var("OP_CONNECT_HOST").is_ok();
let interactive = backend_config.allow_interactive_unlock;

if !(has_service_token || has_session || has_connect || interactive) {
    return Err(Error::AuthenticationFailed(
        "no ambient 1Password credentials detected; set OP_SERVICE_ACCOUNT_TOKEN, run `op signin`, or enable interactive mode".into()
    ));
}
```

Without this, hasp processes will hang indefinitely in CI / containers / SSH sessions on the desktop-app biometric path. There is no `op` flag to make biometric prompts fail-fast.

### 5.7 Always-on subprocess timeout

Every `Command::output()` for `op` must be wrapped in a wall-clock timeout. Recommended default: **15s for `read`, 10s for `exists`, 30s for `list`**. Override via backend config or env. Required for:

- macOS Tahoe regression hangs ([openclaw/openclaw#55459](https://github.com/openclaw/openclaw/issues/55459))
- Biometric prompt not answered after dismissal
- Network stall on `1password.com`

Note that killing the `op` PID does not necessarily kill its grandchild processes (biometric prompt helpers, polkit, gpg-agent integration) — this is unsolved on Unix without cgroups (Linux 5.14+) or Windows job objects ([duct gotchas: killing grandchild processes](https://github.com/oconnor663/duct.py/blob/master/gotchas.md)). Document this; hasp can clean up `op` itself but not necessarily the chain it spawned.

### 5.8 Subprocess implementation crate choice

Use `std::process::Command` directly. Do not pull in `duct`, `xshell`, `subprocess`, or `cmd_lib`:

- `duct` is excellent for general subprocess work but its default of "non-zero exit → error" doesn't match hasp's needs (we want to inspect the exit + stderr ourselves).
- `xshell` pulls `anyhow` (forbidden at the library boundary per `CLAUDE.md`).
- `cmd_lib` automatically routes stderr to the `log` crate — wrong for secret-bearing children.
- `subprocess` is a transitive-dep-heavier alternative to `std::process` with no benefit hasp uses.

Borrow [`shared_child`](https://docs.rs/shared_child/) only if hasp ever needs concurrent kill (e.g. timeout cancellation while another thread waits) — `shared_child` solves the documented `kill`/`waitpid` PID-reuse race that std doesn't.

### 5.9 Write hygiene checklist for the `op://` backend code

A small, enforceable checklist that any `op://` backend implementer should be able to point to in PR review:

1. ✅ Capture stdout via `Command::output()` (or piped-stdin equivalent), never inheriting / file-redirecting.
2. ✅ Strip exactly one trailing `\n` via `bytes.strip_suffix(b"\n").unwrap_or(bytes)`. Never `String::trim`.
3. ✅ Move stdout `Vec<u8>` into `secrecy::SecretBox<[u8]>` at the boundary; never log it; never include it in `Display`.
4. ✅ Capture stderr; redact `op://` URLs before placing it in `Backend.message`; never relay verbatim to `tracing` even at trace level.
5. ✅ Apply the §2 error-map table; unmatched stderr falls through to `Backend{kind: Permanent}`, never `NotFound`.
6. ✅ Pre-flight auth check before every spawn (§5.6).
7. ✅ Per-call timeout (§5.7).
8. ✅ Pass `--format=json --no-color` on every command except `op read` (which has no JSON form).
9. ✅ Pin minimum `op` version at backend init (§5.5).
10. ✅ Use `op item list` for `exists`, never `op item get` (§5.3).
11. ✅ Never pass a secret value on argv. References (`op://...`) are not secrets and may go on argv.
12. ✅ Unit-test the error-map with verbatim stderr fixtures from §2.

### 5.10 Document deferred features

Document explicitly (in `op://` backend rustdoc) what the Wave 2 backend does **not** implement, with reasons:

- **`put` / `delete`** — out of Wave 2 scope per the brief.
- **`Error::PermissionDenied`** — server collapses 404; `op` cannot distinguish; Connect HTTP path could but is deferred. Reaches `NotFound` instead.
- **Connect HTTP backend mode** — would recover 404/401/403 distinction. Deferred; needs a future feature flag plus name→UUID resolution dance.
- **Service-account direct HTTP** — not technically feasible without reverse-engineering 1Password's SRP handshake. Will not be implemented.
- **In-process secret cache** — `op-fast` and `op-cache` show this is operationally valuable (90× speedup for `op-fast`'s OS-keyring path). Defer to a separate decision after Wave 2; cache design touches the redaction posture and merits its own research note.
- **`mlock`-grade memory protection** — beyond zeroize-on-drop. Deferred to a separate research note per `CLAUDE.md` "decisions about zeroization, memory locking, and process-image hygiene belong in a research note before implementation."

---

## §6 Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| 1Password CLI 2 release notes | Official changelog | Version-drift catalog (§1.7) | https://app-updates.agilebits.com/product_history/CLI2 |
| 1Password developer: CLI reference | Official docs | Env vars (§4.2), flag forms | https://developer.1password.com/docs/cli/reference/ |
| 1Password developer: app integration | Official docs | `OP_BIOMETRIC_UNLOCK_ENABLED` (§4.1) | https://developer.1password.com/docs/cli/app-integration/ |
| 1Password developer: app integration security | Official docs | Trust model on macOS/Linux/Windows (§4.6) | https://developer.1password.com/docs/cli/app-integration-security/ |
| 1Password developer: service accounts | Official docs | `OP_SERVICE_ACCOUNT_TOKEN`; "Commands that make multiple requests" (§3) | https://developer.1password.com/docs/service-accounts/use-with-1password-cli/ |
| 1Password developer: service-account rate limits | Official docs | Per-token + per-account quotas (§2 throttle row) | https://developer.1password.com/docs/service-accounts/rate-limits/ |
| 1Password developer: Connect API reference | Official docs | Connect HTTP shape (§4.4) | https://developer.1password.com/docs/connect/api-reference/ |
| 1Password developer: secret reference syntax | Official docs | `op://` grammar | https://developer.1password.com/docs/cli/secret-reference-syntax/ |
| 1Password developer: SDKs landing | Official docs | No first-party Rust SDK (§4.5) | https://developer.1password.com/docs/sdks/ |
| 1Password developer: management commands - item | Official docs | `op item edit` argv warning (§4.7) | https://developer.1password.com/docs/cli/reference/management-commands/item/ |
| `1Password/connect` repo | Source code (deployment + OpenAPI only) | Connect server is closed-source (§4.4) | https://github.com/1Password/connect |
| `1Password/connect` issue #37 | GitHub issue | "Open source" still open | https://github.com/1Password/connect/issues/37 |
| `1Password/connect-sdk-go` errors.go | Source | Connect error envelope (§4.4) | https://github.com/1Password/connect-sdk-go |
| `1Password/onepassword-sdk-go` errors.go | Source | Official SDK only types 2 errors (§4.5) | https://github.com/1Password/onepassword-sdk-go |
| `1Password/onepassword-sdk-python` errors.py | Source | Same | https://github.com/1Password/onepassword-sdk-python |
| `1Password/onepassword-sdk-js` errors.ts | Source | Same | https://github.com/1Password/onepassword-sdk-js |
| 1Password community: exit code documentation | Forum thread | Only 0/1 exit codes (§1.1) | https://www.1password.community/discussions/developers/exit-code-documentation/80288 |
| 1Password community: CLI error codes documentation | Forum thread | Same | https://1password.community/discussion/114287/cli-error-codes-documentation |
| 1Password community: Reference for Private vault | Forum thread | Verbatim stderr (§1.2, §1.4) | https://www.1password.community/discussions/developers/reference-for-private-vault-copied-from-gui-doesnt-work-in-cli/160562 |
| 1Password community: authorization timeout | Forum thread | Verbatim auth-timeout stderr (§1.6) | https://www.1password.community/discussions/developers/authorization-timeout-when-using-cli/159177 |
| 1Password community: TTY fussiness | Forum thread | TTY/pipe behavior (§3.3) | https://1password.community/discussion/131365/1password-cli-is-fussy-about-ttys |
| 1Password community: item missing | Forum thread | Verbatim "could not find item" (§1.4) | https://www.1password.community/discussions/developers/item-missing-from-some-commands/28206 |
| 1Password community: ERROR you are not currently signed in | Forum thread | Verbatim "not currently signed in" (§1.6) | https://1password.community/discussion/94643/error-you-are-not-currently-signed-in |
| 1Password community: cli-cant-connect-to-desktop-app | Forum thread | "connecting to desktop app" stderr (§1.6) | https://www.1password.community/discussions/developers/cli-cant-connect-to-desktop-app-despite-having-biometric-unlock-enabled/91634 |
| 1Password community: service-account bug report | Forum thread | "signin credentials are not compatible" (§1.6) | https://www.1password.community/discussions/developers/1password-cli-service-account-bug-report/167222 |
| 1Password community: CLI hangs when requesting items | Forum thread | Indefinite biometric block (§4.1, §5.7) | https://www.1password.community/discussions/developers/cli-hangs-when-requesting-items/95850 |
| 1Password community: op read mistreats binary content | Forum thread | UTF-8 corruption when stdout not piped (§3.2) | https://www.1password.community/discussions/developers/op-read-mistreats-binary-content/159981 |
| 1Password community: op read 700ms per invocation | Forum thread | Latency baseline (§1.8) | https://www.1password.community/discussions/developers/op-read-is-pretty-slow-700ms-per-invocation/25907 |
| 1Password community: speed concerns | Forum thread | Latency on M2 (§1.8) | https://www.1password.community/discussions/developers/speed-concerns/26678 |
| 1Password community: cli-cache-is-either-not-working | Forum thread | Latency Sydney→useast1 (§1.8) | https://www.1password.community/discussions/developers/cli-cache-is-either-not-working-or-not-significantly-reducing-time-to-return-a-s/91089 |
| 1Password community: disable biometric prompt | Forum thread | Removing biometric prompt "not on roadmap" | https://1password.community/discussion/140411/disable-biometric-prompt-if-authenticated-in-1password-ui |
| 1Password community: how to use op read v2 with titles containing @ or ( | Forum thread | URL parser rejects `@` and `(` | https://1password.community/discussion/140050/how-using-op-read-in-cli-v2-with-titles-containing-or-characters |
| Tessl op-cli skill | Curated skill | "could not find item" canonical anchor | https://tessl.io/registry/skills/github/NeverSight/skills_feed/op-cli |
| `cometkim/op-fast` | Rust caching wrapper | OS-keyring cache, 90× speedup (§1.8) | https://github.com/cometkim/op-fast |
| `SamSaffron/op-cache` | Cache daemon | In-RAM cache, UNIX socket (§1.8) | https://github.com/SamSaffron/op-cache |
| Deploy Linux Blog: op-cache | Blog | Cache hit 1–2ms | https://deploymentfromscratch.com/blog/op-cache |
| `jdx/mise` discussion #3542 | GitHub discussion | 12s first-call → 6ms with tmpfs cache | https://github.com/jdx/mise/discussions/3542 |
| `openclaw/openclaw#55459` | GitHub issue | macOS Tahoe hang; `--cache=false` workaround (§5.7) | https://github.com/openclaw/openclaw/issues/55459 |
| `NixOS/nixpkgs#258139` | GitHub issue | Desktop integration regressions | https://github.com/NixOS/nixpkgs/issues/258139 |
| `NixOS/nixpkgs#373415` | GitHub issue | "1password cli stuck on read" | https://github.com/NixOS/nixpkgs/issues/373415 |
| Kobzol: Process spawning performance in Rust | Blog | std::process::Command spawn cost ~540 µs (§1.8) | https://kobzol.github.io/rust/2024/01/28/process-spawning-performance-in-rust.html |
| `oconnor663/duct.py` gotchas.md | Doc | Subprocess footguns; killing grandchildren (§5.7, §5.8) | https://github.com/oconnor663/duct.py/blob/master/gotchas.md |
| Rust users forum: Vec::with_capacity + read_to_end overallocation | Forum | `Vec` reallocation hazard (§3.5) | https://users.rust-lang.org/t/vec-with-capacity-read-to-end-overallocation/65023 |
| `zeroize` crate docs | Docs | Cannot zero freed reallocations (§3.5) | https://docs.rs/zeroize/latest/zeroize/ |
| `secrecy` crate docs | Docs | `SecretBox` / `SecretString` posture | https://docs.rs/secrecy/latest/secrecy/ |
| `keyring-core::Error` | Docs | Canonical `#[non_exhaustive]` enum reference (§5.1) | https://docs.rs/keyring-core/latest/keyring_core/error/enum.Error.html |
| `vaultrs::ClientError` | Docs | Vault Rust SDK error model | https://docs.rs/vaultrs/latest/vaultrs/error/enum.ClientError.html |
| `onepassword-cli` v0.3.4 (sinyo-matu) | Crate (stale) | Substring-match precedent; lessons (§5.2) | https://lib.rs/crates/onepassword-cli; https://docs.rs/onepassword-cli/latest/src/onepassword_cli/error.rs.html |
| `cargo-credential-1password` | Crate (Cargo team) | Most credible op-subprocess wrapper precedent (§4.5) | https://lib.rs/crates/cargo-credential-1password |
| `bsodmike/connect-sdk-rust` | Crate (stale) | Connect HTTP API shape reference (§4.5) | https://github.com/bsodmike/connect-sdk-rust |
| `lib.rs/crates/onepassword` | Crate (Feb 2026) | FFI to Python SDK shared lib; rejected (§4.5) | https://lib.rs/crates/onepassword |
| `lib.rs/crates/op-mcp` | Crate | Enumeration of `op` operation surface | https://lib.rs/crates/op-mcp |
| 1Password CVE-2024-42219 / 42218 | CVE | Local-attacker integration impersonation | https://www.helpnetsecurity.com/2024/08/09/cve-2024-42219-cve-2024-42218/ |
| Bitwarden CLI supply-chain attack (Apr 2026) | Incident | Pinning a CLI version is defensible | https://www.ox.security/blog/shai-hulud-bitwarden-cli-supply-chain-attack/ |
| `bitwarden/clients#18373` | GitHub issue | Bitwarden CLI binary 0/1 exit-code parallel | https://github.com/bitwarden/clients/issues/18373 |
| `actions/runner#2265` | GitHub issue | Mask-bypass via encoding | https://github.com/actions/runner/issues/2265 |
| smallstep: How to handle secrets on the command line | Blog | Argv-leak hazard primer (§4.7) | https://smallstep.com/blog/command-line-secrets/ |
| `proc(5)` man page | Man page | `/proc/<pid>/cmdline` semantics | https://man7.org/linux/man-pages/man5/proc.5.html |
| GitGuardian: 1Password service-account token detector | Docs | Service-account token format (§4.3) | https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/1password_service_account_token |
| `RESEARCH-error-taxonomy.md` | Internal doc | Locked Approach B taxonomy (§5.1) | ./RESEARCH-error-taxonomy.md |
| `RESEARCH-failure-modes.md` | Internal doc | Cross-cutting failure-mode catalog | ./RESEARCH-failure-modes.md |
| `CLAUDE.md` (project) | Internal doc | URL redaction posture; concrete-error-types-only at lib boundary | ../../CLAUDE.md |
