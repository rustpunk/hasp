# CLI Reference

```text
Unified secrets CLI.

`hasp` dispatches `get` / `put` / `list` / `delete` / `exists` to
multiple backends addressed by URL or alias.

Usage: hasp <COMMAND>

Commands:
  get     Fetch a secret
  put     Store a secret
  list    List entries matching a URL prefix or alias
  delete  Delete a secret
  exists  Check whether a secret exists
  cp      Copy a secret from one URL or alias to another
  run     Run a command with secrets injected as environment variables
  init    Create a starter profiles.toml
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help (see a summary with '-h')
```

## Exit codes

`hasp` uses a granular exit-code convention so scripts can distinguish
failure modes without parsing stderr.

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Usage or local error (bad flags, malformed URL, unknown scheme, unsupported operation, IO error). |
| 2 | Not found (the URL is well-formed; the secret does not exist). |
| 3 | Permission denied (the caller's credentials are valid but lack access). |
| 4 | Transport / network failure (transient or throttled). Retry may help. |
| 5 | Authentication failed (credentials missing, invalid, or expired). |
| 6 | Precondition failed (e.g. `cp` cross-environment refusal, plain-http proxy refusal, `--verify` mismatch, `--if-exists=fail` blocked). |
| 7 | Backend failure (permanent / unexpected backend response that doesn't fit a more-specific code). |

`hasp exists` is a special case: it overloads codes 0 and 1 to mean
`present` and `absent`. Backend errors during `exists` still flow
through the table above (auth=5, transport=4, …).

## `hasp get <address>`

Fetch a secret and print its value to stdout.

```bash
hasp get env://HOME
hasp get file:///etc/secrets/db-password
hasp get @prod/db_password
```

- **Stdout:** The secret value, verbatim.
- **Stderr:** Errors, hints, and warnings only.
- **Exit codes:** See [Exit codes](#exit-codes) above.

### `-F` / `--field <path>` — field extraction

For backends that store JSON payloads (`vault://`, `aws-sm://`,
`gcp-sm://`, `azure-kv://`), extract a single scalar from the payload
inside the backend, before the value crosses the `SecretString`
boundary. Avoids piping plaintext through `jq` (which leaks the parent
payload via pipe buffers and shell history).

```bash
hasp get -F password vault://kv/data/app/db
hasp get -F .credentials.api_key aws-sm://us-east-1/myapp
hasp get "aws-sm://us-east-1/myapp?field=.credentials.api_key"
```

- `<path>` accepts both flat keys (`password`) and dotted nested paths
  (`.credentials.api_key`). Leading `.` is optional.
- `-F` is sugar for the URL query parameter `?field=<path>`. Both forms
  on the same invocation are refused (exit code 1).
- Non-JSON payloads fail with `invalid URL for backend: secret is not
  JSON`. Missing keys fail with `not found: field '...' not found`
  (exit code 2). Non-scalar leaves (objects, arrays, null) fail with
  `invalid URL` (exit code 1).

### `hasp get --explain <address>`

Preview which backend will handle the address and whether the result
is already cached, without actually fetching the secret.

```bash
hasp get --explain env://HOME
# scheme=env backend=env cached=false
```

## `hasp put <address> [<value>]`

Store a secret.

```bash
hasp put file:///tmp/secret "my-value"
hasp put env://NEW_VAR "value"   # unsupported — env is read-only
hasp put file:///tmp/secret -     # read from stdin
hasp put file:///tmp/secret       # prompt securely in TTY
```

- **Arguments:**
  - `address` — URL or alias of the secret.
  - `value` — Value to store. Use `-` for stdin. Omit in a TTY to
    prompt securely via `rpassword`.

## `hasp list <address>`

List entries matching a URL prefix or alias.

```bash
hasp list vault://127.0.0.1/secret/
hasp list --format json vault://127.0.0.1/secret/ | jq '.[].name'
```

- **Arguments:**
  - `address` — URL or alias of the collection to list.
  - `--format` — Output style:
    - `plain` (default) — `name  url`, two-space separated
    - `table` — aligned columns, human-readable
    - `json` — compact JSON array of `{"name": "...", "url": "..."}` objects
- **Output:** Lines of entries, or an empty result when none match.

## `hasp delete <address>`

Delete a secret.

```bash
hasp delete file:///tmp/secret
hasp delete keyring://my-service/admin
```

## `hasp exists <address>`

Check whether a secret exists.

```bash
hasp exists env://HOME && echo "present" || echo "missing"
```

- **Exit code:** 0 if present, 1 if absent. Backend errors (auth,
  transport, etc.) use the standard table from [Exit codes](#exit-codes).

## `hasp cp <src> <dst>`

Copy a secret from one backend to another. `cp` is the only verb that
reads and writes a secret in a single invocation, so its security
model is documented inline below — read it before scripting production
migrations.

```bash
hasp cp file:///tmp/old.txt file:///tmp/new.txt
hasp cp env://OLD_NAME file:///etc/secrets/new
hasp cp @stage/db @prod/db --yes --verify
hasp cp --explain @stage/db @prod/db          # dry-run; resolves both
                                              # backends, prints plan,
                                              # does not read or write
```

- **Arguments:**
  - `src` — Source URL or alias. Backend must support `get`.
  - `dst` — Destination URL or alias. Backend must support `put`.
- **Flags:**
  - `--if-exists <fail|overwrite|skip>` — Disposition when `dst`
    already holds a value. Default `fail`.
  - `-f, --force` — Shorthand for `--if-exists=overwrite`.
  - `--verify` — Re-read `dst` after writing and constant-time compare
    against the source. Mismatch returns a precondition-failed exit
    with no byte-level information.
  - `-y, --yes` — Confirm a cross-environment copy (see "Security
    model" below).
  - `--explain` (global) — Treated as dry-run for `cp`: resolves both
    URLs and prints the plan; does not call `get` or `put`.
- **Exit codes:** Refusals (cross-environment, plain-http proxy,
  self-copy, `--verify` mismatch, `--if-exists=fail` blocked) return
  code 6 (precondition). See [Exit codes](#exit-codes).

### Security model

The defaults are deliberately stricter than Unix `cp`:

1. **`--if-exists=fail` is the default.** Silent clobbering of a
   production secret with a staging value is materially worse than a
   non-zero exit demanding `--force`. Pass `--force` (or
   `--if-exists=overwrite`) to opt in.
2. **Self-copy refused.** `hasp cp file:///x file:///x` returns an
   error. Prevents version-counter inflation on backends that version
   writes (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).
3. **Cross-environment refusal.** When both `src` and `dst` are
   profile aliases AND both profiles declare an `environment = "..."`
   key in `profiles.toml`, a mismatch refuses without `--yes`. Absent
   labels disable the check (backwards-compatible).
4. **Plain-http proxy refusal.** When `HTTP_PROXY` / `HTTPS_PROXY` /
   `--proxy-url` resolves to an `http://` URL, `cp` refuses unless
   `HASP_ALLOW_HTTP_PROXY=1` is set. The doubled-exposure window of
   `cp` makes MITM more costly than for other verbs.
5. **Audit events.** `cp.start` and `cp.done` are emitted by the
   library; see [Audit events](#audit-events) for the wire format and
   how to redirect or disable them.
6. **`--verify` uses constant-time comparison** via
   `subtle::ConstantTimeEq`. A failed verify returns a generic
   "verify failed: source and destination differ" message with no
   byte-level diff.
7. **No atomicity across backends.** A failed `put(dst)` after a
   successful `get(src)` leaves `dst` in an indeterminate state —
   either untouched or partially written, depending on the dst
   backend's semantics. `hasp` cannot promise two-phase commit
   across heterogeneous stores.
8. **`cp` copies the value, not the access policy.** Copying from a
   tightly-controlled store to a loosely-controlled one effectively
   widens access to the value. `hasp` has no view into either
   backend's IAM model.

For the full threat model and platform-hardening rationale, see
`docs/internal/research/RESEARCH-cp-threat-model.md`.

## `hasp diff <a> <b>`

Compare two secrets across (possibly different) backends without
revealing anything about their contents beyond a binary
match/differ verdict.

```bash
hasp diff @stage/db @prod/db                  # exits 0 on match, 1 on differ
hasp diff file:///tmp/a file:///tmp/b
hasp diff --explain @stage/db @prod/db        # dry-run; no fetch
```

- **Arguments:**
  - `a`, `b` — URLs or aliases. Both backends must support `get`.
- **Flags:**
  - `-y, --yes` — Confirm a cross-environment comparison (mirrors `cp`).
  - `--explain` (global) — Resolves both URLs and prints the plan; does
    not call `get`.
- **Exit codes:**
  - `0` — Both secrets compared byte-equal.
  - `1` — Secrets differ (length or content), OR a usage error (parallels
    `hasp exists`). Backend errors flow through the standard
    [Exit codes](#exit-codes) table — auth=5, transport=4, etc.
- **Security:** the verdict is binary by construction. Mismatch never
  reveals byte counts, common prefixes, diff positions, or hashes. The
  compare path uses `subtle::ConstantTimeEq` (the same crate `cp --verify`
  uses) so timing channels are not informative about a near-match. Both
  secret bodies stay inside `SecretString` end-to-end and are dropped
  before `diff` returns.
- **Audit events:** `diff.start` / `diff.done` with outcome
  `"match"` / `"differ"` / `"error"`. See [Audit events](#audit-events).
- **Cross-environment refusal:** same shape as `cp`. Aliases whose
  profiles declare mismatched `environment = "..."` labels require
  `--yes`; the refusal is not about safety (diff doesn't write) but
  about pulling secrets from two trust tiers into the same process.
- **Plain-http proxy refusal:** identical to `cp`; a MITM on the proxy
  can still observe the values pulled through it.

## `hasp run -e KEY=URL [...] -- <cmd> [args...]`

Fetch secrets by URL and inject them as environment variables into a
child process. The child inherits hasp's exit code verbatim.

```bash
hasp run -e DB_PASS=aws-sm://us-east-1/prod/db \
         -e API_TOKEN=vault://kv/data/app/api?field=token \
         -- ./my-app --serve

# Mix schemes; field extraction from #5 works here too
hasp run -e TOKEN=aws-sm://us-east-1/prod/creds?field=api_key \
         -- ./service
```

- **`-e KEY=URL`** is repeatable. Each URL is resolved through the
  configured `Store`; `-e DB_PASS=@prod/db` also works (profile
  alias).
- **All-or-nothing:** if any fetch fails, the child is never spawned
  and hasp returns the appropriate exit code (e.g. 2 for not-found).
- **Duplicate keys** are refused at startup (exit code 1).
- **TTY refusal:** neither stdout nor stderr may be a terminal when
  invoking `run` — accidental use like `hasp run -- echo $DB_PASS`
  would expose secrets in the terminal scroll buffer regardless of
  which stream the child writes to. Pass `--allow-tty` to override
  for interactive debugging.
- **`/proc/<pid>/environ` visibility:** on Linux, same-uid processes
  can read a child's environment via `/proc/<pid>/environ`. This is
  the inherent cost of env injection. For the highest-isolation
  workloads, consider named-pipe or tmpfs delivery instead.
- **PTY masking** (1Password's `op run` feature — intercepts the
  child's stdout to mask accidentally echoed secrets) is not yet
  implemented; scheduled as a follow-up.
- **Audit events:** `run.start` and `run.done` are emitted; each
  intermediate `get` emits its own `get.start`/`get.done` events.

## `hasp init`

Create a starter `profiles.toml` in the platform config directory.

```bash
hasp init
# Refuse to overwrite an existing file:
hasp init --force
```

- **Respects** `HASP_PROFILES_PATH` if set. Refuses to overwrite an
  existing file without `--force` (exit code 1).

## `hasp complete <shell>`

Generate a static completion script for the requested shell. Hidden
from `--help`.

```bash
hasp complete bash
hasp complete zsh
hasp complete fish
hasp complete powershell
```

## `hasp man`

Generate a man page in ROFF format. Hidden from `--help`.

```bash
hasp man > /usr/share/man/man1/hasp.1
```

## Global flags

| Flag | Description |
|---|---|
| `-h, --help` | Print help. Pass `-h` for a summary, `--help` for full help. |
| `-q, --quiet` | Suppress non-error informational output. |
| `-v, --verbose` | Increase output verbosity; prints operation traces to stderr. Can be used multiple times (`-vv`). |
| `--no-cache` | Disable the per-invocation in-process secret cache for this invocation. |
| `--no-profile-allow` | Skip `HASP_REQUIRE_PROFILE_ALLOW` enforcement for this invocation. |

## Caching

`hasp` memoizes fetched secrets for the lifetime of a single invocation
(5-minute TTL, 1024-entry capacity ceiling). This eliminates the
duplicate-URL footgun when a script issues several `hasp get` calls for
the same URL in one invocation or uses `Store::batch_get`.

The cache lives only in process memory. There is no on-disk
persistence, no daemon, no IPC. Cache lifetime ≤ process lifetime by
construction. Cached entries hold `Arc<SecretString>` references whose
inner heap buffer zeroizes on eviction.

### Disabling the cache

The cache is disabled when **any** of the following is true:

1. `--no-cache` is passed on the command line.
2. `HASP_NO_CACHE=1` is set in the environment (also accepts `true`,
   `yes`, `on`).
3. The `CI` environment variable is set. CI runners are the documented
   target of credential-cache-targeting supply-chain worms (Bitwarden
   CLI 2026.4.0 compromise; Mini Shai-Hulud / CanisterWorm worms in
   May 2026). Auto-disabling defends against the warm-cache exfil
   class without forcing every CI pipeline to remember the flag.

### Configuring the TTL envelope

`HASP_CACHE_TTL=<seconds>` overrides the default cache TTL. Valid
range: `1..=3600`. Values above 3600 are clamped to AWS Secrets
Manager Agent's published 1-hour ceiling. `HASP_CACHE_TTL=0` disables
the cache entirely (equivalent to `--no-cache`).

### Clearing the cache

```
hasp cache clear
```

Drops every cached entry within the current invocation. (The in-process
cache lives only for the current process, so the gesture is primarily
useful as a no-op exit; once the `cache-persistent` on-disk variant
ships, the same command will also remove the encrypted cache file and
the OS-keyring entry holding its symmetric key.)

### Persistent cache (`cache-persistent` Cargo feature, not yet implemented)

The `cache-persistent` Cargo feature is the opt-in cross-invocation
encrypted-file cache, currently scaffolded only. When the
implementation lands, the file will be at
`$XDG_CACHE_HOME/hasp/cache.bin` (mode `0o600`), encrypted with
XChaCha20-Poly1305 using a per-host symmetric key bound to the OS
keyring (Secret Service / Keychain / Credential Manager).

The verbatim threat-model warning from the AWS Secrets Manager Agent
applies and is reproduced here to set expectations:

> *After the secret value is pulled into the cache, any user with
> access to the compute environment can access the secret from the
> cache.*

The feature is off by default for a reason: any persistent cache file
inherits the threat surface that infostealers and supply-chain worms
target by name (Bitwarden CLI 2026.4.0; Mini Shai-Hulud /
CanisterWorm, May 2026). Enable only after considering the deployment
threat model.

### Cache audit events

Each cache decision emits a structured one-line JSON event via the
configured `AuditSink`:

```json
{"event":"cache.miss","ts":1747000000,"src_scheme":"vault","outcome":"miss"}
{"event":"cache.hit","ts":1747000001,"src_scheme":"vault","outcome":"hit"}
{"event":"cache.expire","ts":1747000300,"src_scheme":"vault","outcome":"expire"}
{"event":"cache.clear","ts":1747000400,"src_scheme":"all","outcome":"clear"}
```

The closed-shape `CacheEvent` enum prevents value bytes from ever
landing in the audit stream; the proptest in
`crates/hasp-core/tests/audit_no_leak.rs` enforces this.

### Threat model

The cache only protects against re-fetching from the backend. It does
**not** protect against:

- `/proc/<pid>/mem` inspection by a same-uid attacker
  (`PR_SET_DUMPABLE=0` mitigates this; the hardening token witnesses
   that the mitigation has been applied before any cache is
   constructed).
- A coredump triggered after a cache hit (mitigated by
  `RLIMIT_CORE=0`, also required by the hardening token).
- A debugger attached by the same user before cache construction.

For cross-invocation persistence (the encrypted-file-on-disk variant),
see the `cache-persistent` Cargo feature in the next sprint slot.

## Audit events

Every hasp verb emits structured `*.start` / `*.done` JSON events to
stderr (one line each). The wire format:

```json
{"event":"get.done","ts":1747612345,"src_scheme":"vault","outcome":"ok"}
{"event":"cp.done","ts":1747612346,"src_scheme":"vault","dst_scheme":"file","outcome":"copied"}
{"event":"get.done","ts":1747612347,"src_scheme":"env","outcome":"error","error_kind":"not_found"}
```

Fields: `event` (closed set), `ts` (UNIX seconds), `src_scheme`,
`dst_scheme` (cp/run only), `outcome`, `error_kind` (on failure).
**No values, no lengths, no value-derived material are ever emitted.**

### Controlling the sink

Resolution order (highest precedence first):
1. `HASP_AUDIT` env var.
2. `~/.config/hasp/audit.toml` (override location with
   `HASP_AUDIT_CONFIG_PATH`).
3. Default: stderr.

Env vars:

| Env var | Value | Behaviour |
|---|---|---|
| `HASP_AUDIT` | *(unset)* | Use `audit.toml` if present, else stderr |
| `HASP_AUDIT` | `off` | Suppress all audit output |
| `HASP_AUDIT` | `stderr` | Write JSON lines to stderr |
| `HASP_AUDIT` | `file` | Write to `HASP_AUDIT_PATH` (falls back to stderr if path is empty, `NoopSink` if open fails) |
| `HASP_AUDIT` | `syslog` | Forward to local syslog daemon (Unix only); ident from `HASP_AUDIT_IDENT` (default `"hasp"`). Falls back to stderr on Windows. |
| `HASP_AUDIT_PATH` | `/path/to/audit.log` | Log file for `file` mode (`0600` on Unix) |
| `HASP_AUDIT_IDENT` | `"hasp"` | Program ident shown in syslog entries (`syslog` mode) |
| `HASP_AUDIT_CONFIG_PATH` | `/path/to/audit.toml` | Override the default `audit.toml` location |

Example `~/.config/hasp/audit.toml`:

```toml
[audit]
sink = "file"
path = "/var/log/hasp/audit.log"

# Or:
# [audit]
# sink = "syslog"
# ident = "hasp-prod"
```

Library consumers: pass an `Arc<dyn hasp::AuditSink>` to
`StoreBuilder::with_audit_sink(...)` to install a custom sink.
`SyslogSink` is gated on `#[cfg(unix)]` and wraps the libc syslog
client (`openlog` / `syslog` / `closelog`) so it picks up the
platform's native socket path (`/dev/log` on Linux,
`/var/run/syslog` on macOS) without a third-party dependency.

### Threat model

The audit stream documents that an access happened — it is not a
forensic guarantee that one *will* happen for every secret retrieval.
Trust boundary:

- **Same-uid tampering.** A process running as the same uid as
  `hasp` can redirect or suppress the audit stream — for example by
  setting `HASP_AUDIT=off` before invoking `hasp`, by truncating the
  log file an earlier invocation wrote, or by overwriting the
  binary. Treat the stream as best-effort telemetry from a
  cooperating caller, not as a tamper-evident security log. For
  tamper-evident logging, ship the stream off-host (e.g. syslog
  forwarding to a write-once collector) or run `hasp` in a
  privilege-separated environment.
- **Concurrent writers.** `FileSink` serializes writes via an
  internal `Mutex<File>`; concurrent invocations of `hasp`
  writing to the same path will not interleave bytes within a
  single process but two separate hasp processes appending to the
  same path may produce events out of timestamp order. Sort by
  `ts` on ingest.
- **No value leakage.** `AuditEvent`'s field set is closed
  (`#[non_exhaustive]`) and every field is either a timestamp, a
  `&'static str` from a closed set, or a URL scheme. No
  implementation of `AuditSink` can leak a value or a
  value-derived length.

## Environment variables

| Variable | Effect |
|---|---|
| `HASP_PROFILES_PATH` | Override the default `profiles.toml` path. |
| `HASP_ALLOW_HTTP_PROXY` | Set to `1` to allow `hasp cp` through a plain-http proxy. |
| `HASP_AUDIT` | Audit sink mode: unset=stderr (or `audit.toml`), `off`=silent, `file`=log file, `syslog`=local syslog daemon (Unix). |
| `HASP_AUDIT_PATH` | Path for `HASP_AUDIT=file` mode (append, `0600` on Unix). |
| `HASP_AUDIT_IDENT` | Program ident for `HASP_AUDIT=syslog` mode (default `"hasp"`). |
| `HASP_AUDIT_CONFIG_PATH` | Override `~/.config/hasp/audit.toml` location. |

## Address argument

The `address` positional argument accepts:

- A full URL: `env://VAR`, `file:///path`, `aws-sm://region/name`
- A profile alias: `@profile/key` or `@profile` (when a self-key
  exists)

Tab completion is available for URL schemes, profile aliases, and
`file://` paths. See [Shell Completions](shell-completions.md).
