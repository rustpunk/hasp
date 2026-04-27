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
