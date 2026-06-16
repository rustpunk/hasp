# Profile Aliases

Aliases let you type `@prod/db_password` instead of a 60-character
AWS ARN or a nested Vault path. They live in `profiles.toml`, are
resolved at runtime, and are entirely optional.

## Config file location

Hasp looks for `profiles.toml` in this order:

1. The path in the `HASP_PROFILES_PATH` environment variable.
2. The platform config directory:
   - Linux: `~/.config/hasp/profiles.toml`
   - macOS: `~/Library/Application Support/hasp/profiles.toml`
   - Windows: `%APPDATA%/hasp/profiles.toml`

If the file does not exist, aliases simply don't resolve (you'll get
`unknown profile alias` when you try to use one).

## File format

Profiles are flat TOML tables under `[profiles.<name>]`:

```toml
[profiles.prod]
db_password = "aws-sm://us-east-1/prod/db-password"
api_key     = "op://Production/API/credential"

[profiles.staging]
db_password = "aws-sm://us-east-1/staging/db-password"

[profiles.local]
db_password = "env://DB_PASSWORD"
```

Each key is a string value that must be a valid hasp URL.

## Alias resolution rules

The text after `@` is parsed as `profile[/key]`.

| Alias | Resolves to |
|---|---|
| `@prod/db_password` | `aws-sm://us-east-1/prod/db-password` |
| `@prod/api_key` | `op://Production/API/credential` |
| `@local/db_password` | `env://DB_PASSWORD` |

### Self-key shorthand

If a profile contains a key with the **same name as the profile
itself**, the bare alias `@name` resolves to that key:

```toml
[profiles.prod]
prod = "env://PROD_TOKEN"
db_password = "aws-sm://us-east-1/prod/db-password"
```

| Alias | Resolves to |
|---|---|
| `@prod` | `env://PROD_TOKEN` |
| `@prod/db_password` | `aws-sm://us-east-1/prod/db-password` |

Without a self-key, the bare alias is an error:

```toml
[profiles.local]
db_password = "env://DB_PASSWORD"
```

| Alias | Result |
|---|---|
| `@local` | Error: `unknown profile alias: @local` |
| `@local/db_password` | `env://DB_PASSWORD` |

This prevents ambiguity: a bare `@name` only works when you've
explicitly defined it as a shorthand.

## Trust model — `hasp profile allow`

A `profiles.toml` that was silently modified (by a compromised
installer, a synced dotfiles repo, or an over-broad `chmod`) can
redirect every `hasp` invocation to attacker-controlled URLs without
any visible warning. The `profile allow` model closes this gap.

### How it works

1. After writing or updating `profiles.toml`, run:

   ```bash
   hasp profile allow
   ```

   This records the file's mtime and SHA-256 fingerprint in
   `profiles.allowed` (same directory, `0600` on Unix).

2. To enforce the check for every subsequent invocation, set:

   ```bash
   export HASP_REQUIRE_PROFILE_ALLOW=1
   ```

   With this variable set, `hasp` refuses any command that would use
   profile aliases unless the current `profiles.toml` exactly matches
   the recorded fingerprint. Any modification invalidates trust — run
   `allow` again after reviewing the change.

3. Check the current status:

   ```bash
   hasp profile show
   ```

   Output:
   ```
   Path:    /home/user/.config/hasp/profiles.toml
   Mtime:   2026-05-14T12:34:56Z
   Allowed: yes (last allowed at 2026-05-14T12:34:56Z)
   ```

### CI environments

In a CI pipeline where `profiles.toml` is checked into source control
and cannot be re-allowed interactively, use:

```bash
# Either: bypass per-invocation
hasp --no-profile-allow get @ci/secret

# Or: do not set HASP_REQUIRE_PROFILE_ALLOW in CI at all
# (enforcement is opt-in; pipelines that never set the var are unaffected)
```

### Opt-in status

Enforcement is opt-in for the current release cycle. The intent is to
make it the default in a subsequent release after observing user
workflows. Profiles without any allow record are silently trusted when
`HASP_REQUIRE_PROFILE_ALLOW` is unset.

## No sensitive data in profiles.toml

Profile files contain only names and URLs. Never put secret values
in the file — that's what the backends are for. The file is safe to
check into a dotfiles repo or share across a team.

## Runtime override

You can point hasp at a different profile file per invocation:

```bash
HASP_PROFILES_PATH=/tmp/ci-profiles.toml hasp get @ci/secret
```

This is useful for CI pipelines that generate profiles dynamically
or for testing without touching your main config.

## Next steps

- [Supported Backends](backends.md) — what each backend URL looks
  like.
- [CLI Reference](cli-reference.md) — flags and subcommands.
