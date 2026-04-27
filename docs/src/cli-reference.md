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
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help (see a summary with '-h')
```

## `hasp get <address>`

Fetch a secret and print its value to stdout.

```bash
hasp get env://HOME
hasp get file:///etc/secrets/db-password
hasp get @prod/db_password
```

- **Exit code:** 0 on success, non-zero on error.
- **Stdout:** The secret value, verbatim.
- **Stderr:** Errors, hints, and warnings only.

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
- **Exit code:** 0 on success, non-zero on error.

## `hasp list <address>`

List entries matching a URL prefix or alias.

```bash
hasp list vault://127.0.0.1/secret/
```

- **Output:** One line per entry: `name  url`.
- **Exit code:** 0 on success, non-zero if the backend does not
  support `list`.

## `hasp delete <address>`

Delete a secret.

```bash
hasp delete file:///tmp/secret
hasp delete keyring://my-service/admin
```

- **Exit code:** 0 on success, non-zero on error.

## `hasp exists <address>`

Check whether a secret exists.

```bash
hasp exists env://HOME && echo "present" || echo "missing"
```

- **Exit code:** 0 if present, 1 if absent, non-zero on error.

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

## Address argument

The `address` positional argument accepts:

- A full URL: `env://VAR`, `file:///path`, `aws-sm://region/name`
- A profile alias: `@profile/key` or `@profile` (when a self-key
  exists)

Tab completion is available for URL schemes, profile aliases, and
`file://` paths. See [Shell Completions](shell-completions.md).
