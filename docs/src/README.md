# Hasp

> One tool for every secret store.

Hasp is a unified command-line interface for reading, writing, listing,
and deleting secrets across multiple backends. Instead of learning a
different tool for every vault — AWS Secrets Manager, HashiCorp Vault,
1Password, Bitwarden, GCP Secret Manager, Azure Key Vault, your OS
keyring, local files, and environment variables — you use a single
consistent syntax.

## Why hasp?

Every secret store ships its own CLI: `aws secretsmanager`, `vault kv`,
`op read`, `bw get password`, `gcloud secrets`, `az keyvault`. Each has
its own auth dance, its own URL conventions, its own flags, and its
own output format. When your secrets live in three different clouds plus
a password manager plus CI env vars, you end up with a shell script full
of adapters.

Hasp trades backend-specific depth for **a single consistent interface
across all of them**:

- **One binary, one syntax.** `hasp get <url>`, `hasp put <url>`,
  `hasp list <url>`, `hasp delete <url>`, `hasp exists <url>` work the
  same way against every backend.
- **URL-addressed secrets.** Every secret is a URL: `env://VAR`,
  `file:///etc/secrets/db`, `aws-sm://us-east-1/prod/db-password`,
  `op://vault/item/field`. The scheme tells hasp which backend to use;
  the rest is backend-specific addressing.
- **Profile aliases.** Define shortcuts in `~/.config/hasp/profiles.toml`
  and type `@prod/db_password` instead of a 60-character AWS ARN.
- **Ambient credentials only.** Hasp never stores credentials, rotates
  tokens, or bootstraps auth. It reads what your environment already
  provides — IAM roles, `VAULT_TOKEN`, `BW_SESSION`, the OS keyring, or
  plain env vars.
- **Pipe-friendly output.** Secrets go to stdout; everything else goes to
  stderr. `hasp get @prod/api_key | curl ... -H "Authorization:Bearer
  $(cat -)"` just works.

## When to reach for something else

Hasp is not trying to replace the native CLIs when you need their
specialty features. Reach for:

- **`aws secretsmanager`** — when you need policy management, rotation
  configuration, or cross-account replication setup.
- **`vault kv`** — when you need namespace admin, PKI mounts, or
  dynamic database credential generation.
- **`op` / `bw`** — when you need to edit attachments, manage
  collections/organizations, or perform bulk imports.
- **`gcloud secrets` / `az keyvault`** — when you need IAM binding
  management, key rotation policy, or audit log export.
- **`sops` / `age` / `cocoon`** — when you need to encrypt whole
  files or TOML/JSON/YAML documents, not just individual key-value
  secrets.

Hasp is for **terminal-first, scriptable secret access**: fetching a
config value in a deploy script, checking whether a CI secret exists
before a job starts, rotating a local dev credential between
environment and file backends, or swapping a dozen `aws` / `vault` /
`op` calls in a runbook for a single predictable command.

## One-minute demo

```bash
# Read from the environment — zero setup
export MY_SECRET="hello-world"
hasp get env://MY_SECRET

# Write a secret to a file
hasp put file:///tmp/my-secret "shh"
hasp get file:///tmp/my-secret

# Check if a secret exists (exits 1 when missing)
hasp exists env://DEFINITELY_NOT_HERE || echo "not found"

# Define an alias so you don't type the full URL
mkdir -p ~/.config/hasp
cat > ~/.config/hasp/profiles.toml <<'EOF'
[profiles.local]
my_secret = "env://MY_SECRET"
EOF

hasp get @local/my_secret

# Clean up
hasp delete file:///tmp/my-secret
```

## Where to next

- **New here?** Start with [Installation](installation.md) and the
  [Quick Start](quickstart.md).
- **Want the mental model?** Read [How Hasp Thinks](concepts.md) -
  it's the conceptual map for everything else.
- **Looking for backend details?** See [Supported Backends](backends.md).
- **Want tab completion?** See [Shell Completions](shell-completions.md).
- **Looking up a flag?** Jump to the [CLI Reference](cli-reference.md).
- **Something broken?** Try [Troubleshooting](troubleshooting.md).
