# hasp-cli

Unified secrets CLI — a thin shell over the `hasp` library.

## Usage

```bash
hasp get env://HOME
hasp get file:///etc/secrets/db-password
hasp put file:///tmp/secret "my-value"
hasp exists keyring://service/account
hasp list env://
hasp delete file:///tmp/secret
```

## Profile aliases

Define shortcuts in `~/.config/hasp/profiles.toml`:

```toml
[profiles.prod]
db_password = "aws-sm://us-east-1/prod/db-password"
api_key     = "op://Production/API/credential"

[profiles.local]
db_password = "env://DB_PASSWORD"
```

Use them with `@profile/key`:

```bash
hasp get @prod/db_password
hasp put @local/db_password -   # prompt securely
```

If a profile contains a key with the same name as the profile
itself (e.g. `[profiles.foo]` with `foo = "file:///etc/foo"`), the
bare alias `@foo` resolves to that URL.

## Environment variable override

Set `HASP_PROFILES_PATH` to load profiles from a custom path instead
of the platform config directory.

## Supported operations per backend

| Backend | `get` | `put` | `list` | `delete` | `exists` |
|---------|-------|-------|--------|----------|----------|
| `env://`     | yes | no  | no  | no  | yes |
| `file://`    | yes | yes | no  | yes | yes |
| `keyring://` | yes | yes | no  | yes | yes |
| `op://`      | yes | no  | no  | no  | yes |
| `vault://`   | yes | no  | no  | no  | yes |
| `bw://`      | yes | no  | no  | no  | yes |
| `aws-sm://`  | yes | no  | no  | no  | yes |
| `aws-ssm://` | yes | no  | no  | no  | yes |

## Auth model

`hasp-cli` inherits the library's ambient-auth posture: no
auth-bootstrap flows, token rotation, or credential storage.  Each
backend expects its own ambient credentials (e.g. `VAULT_TOKEN`,
`AWS_ACCESS_KEY_ID`, `BW_SESSION`).

## Failure modes

| Symptom | Likely cause |
|---------|--------------|
| `unknown profile alias` | Alias not defined in `profiles.toml` |
| `unsupported scheme` | Backend Cargo feature not enabled |
| `not found` | Secret does not exist at the resolved URL |
| `authentication failed` | Missing or expired ambient credentials |
| `permission denied` | Credentials valid but not authorized for the resource |
| `backend failed` | Upstream SDK or network error (see message) |
