# Troubleshooting

## Common errors

### `unknown profile alias: @foo`

- The profile `foo` is not defined in `profiles.toml`, or the key
  `foo` doesn't exist in the profile.
- Check: `cat ~/.config/hasp/profiles.toml`
- For bare `@foo`, the profile must contain a self-key:
  ```toml
  [profiles.foo]
  foo = "env://FOO"
  ```

### `unsupported scheme: xyz`

- The scheme `xyz` has no registered backend.
- Check the scheme spelling. Valid schemes: `env`, `file`, `keyring`,
  `op`, `vault`, `bw`, `aws-sm`, `aws-ssm`, `gcp-sm`, `azure-kv`.
- If the scheme is correct, the backend may not be compiled in.
  Rebuild with the appropriate feature flag:
  ```bash
  cargo build --release --bin hasp --features aws-sm
  ```

### `not found: ...`

- The secret does not exist at the given URL.
- Verify the URL path/region/secret name.
- For cloud backends, verify the credentials have access.

### `authentication failed: ...`

- Missing or expired ambient credentials.
- Check the per-backend requirements:
  - `vault://` — `VAULT_ADDR` and `VAULT_TOKEN` (or `~/.vault-token`)
  - `op://` — `op` CLI signed in
  - `bw://` — `BW_SESSION` set
  - `aws-sm://` / `aws-ssm://` — `AWS_ACCESS_KEY_ID` or IAM role
  - `gcp-sm://` — `gcloud auth` or ADC
  - `azure-kv://` — Azure CLI login or managed identity

### `permission denied: ...`

- Credentials are valid, but not authorized for this resource.
- Check IAM / RBAC / key vault access policies / GCP IAM bindings.

### `env does not support put`

- `env://` is read-only. Set the variable through your shell before
  invoking hasp.

### `hasp init` says the file already exists

- `hasp init` refuses to overwrite an existing `profiles.toml` to
  prevent accidental data loss.
- Use `hasp init --force` to overwrite, or delete the file first.

### `does not support list`

- `env://` and `file://` do not support `list`. Use `list` with
  `vault://`, `aws-sm://`, or other backends that expose collections.

## Completions not appearing

### Static completions

- Ensure the script was written to the correct directory:
  - Bash: `~/.local/share/bash-completion/completions/hasp` or
    `/usr/share/bash-completion/completions/hasp`
  - Zsh: somewhere in `$fpath`
  - Fish: `~/.config/fish/completions/hasp.fish`
- Open a new shell or run the source command for your shell
  (`source ~/.bashrc`, `source ~/.zshrc`, etc.).

### Dynamic completions

- Ensure the registration snippet is sourced in your shell config:
  ```bash
  source <(COMPLETE=bash hasp)
  ```
- Check that `hasp` is on `$PATH` when the shell starts.
- Set `COMPLETE=` to disable and test raw:
  ```bash
  COMPLETE= bash
  # Now try completion
  ```

### `backend 'vault' failed: proxy error: ...`

- Vault (and other HTTP backends) can route through an HTTP CONNECT proxy.
- Quick fix: set standard environment variables:
  ```bash
  export HTTPS_PROXY=http://proxy.corp.example.com:8080
  export NO_PROXY="localhost,127.0.0.1"
  ```
- Or use the explicit `--proxy-url` flag:
  ```bash
  hasp get --proxy-url http://proxy:8080 vault://secret/data/db
  ```
- For authenticated proxies, see [HTTP CONNECT Proxy](proxy.md).
- AWS backends (`aws-sm://`, `aws-ssm://`) do not yet support explicit
  proxy configuration. Use `HTTPS_PROXY` env vars for those.

## Next steps

- [Installation](installation.md) — verify your build.
- [Supported Backends](backends.md) — per-backend auth details.
- [Profile Aliases](profiles.md) — config file format.
- [Shell Completions](shell-completions.md) — setup instructions.
