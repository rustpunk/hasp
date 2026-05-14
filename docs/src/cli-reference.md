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
5. **Audit events to stderr.** `cp.start` and `cp.done` are emitted
   as single-line JSON records (fields: `event`, `ts`, `src_scheme`,
   `dst_scheme`, `outcome`, optional `error_kind`). Values, lengths,
   and value-derived material are never emitted.
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

## Environment variables

| Variable | Effect |
|---|---|
| `HASP_PROFILES_PATH` | Override the default `profiles.toml` path. |
| `HASP_ALLOW_HTTP_PROXY` | Set to `1` to allow `hasp cp` through a plain-http proxy. |

## Address argument

The `address` positional argument accepts:

- A full URL: `env://VAR`, `file:///path`, `aws-sm://region/name`
- A profile alias: `@profile/key` or `@profile` (when a self-key
  exists)

Tab completion is available for URL schemes, profile aliases, and
`file://` paths. See [Shell Completions](shell-completions.md).
