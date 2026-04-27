# Supported Backends

Hasp supports ten secret stores. The default binary includes all of
them; you can trim the set at compile time via Cargo features.

## Operations matrix

| Backend | `get` | `put` | `list` | `delete` | `exists` |
|---|---|---|---|---|---|
| `env://` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `file://` | ✅ | ✅ | ❌ | ✅ | ✅ |
| `keyring://` | ✅ | ✅ | ❌ | ✅ | ✅ |
| `op://` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `vault://` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `bw://` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `aws-sm://` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `aws-ssm://` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `gcp-sm://` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `azure-kv://` | ✅ | ❌ | ❌ | ❌ | ✅ |

## `env://` — Environment variables

```bash
hasp get env://HOME
hasp exists env://NONEXISTENT || echo "missing"
```

- **Read-only.** `put` and `delete` are unsupported; set or unset
  the variable through your shell.
- **No list.** Environment variables are not enumerable via hasp.

## `file://` — Local filesystem

```bash
hasp get file:///etc/secrets/db-password
hasp put file:///tmp/secret "my-value"
hasp delete file:///tmp/secret
```

- **Creates parent directories** on `put`.
- **Trims trailing newlines** on `get`. A value written as
  `"secret\n"` is read back as `"secret"`.
- **Permissions** are whatever your umask produces; hasp does not
  force `0600`.

## `keyring://` — OS keyring

```bash
hasp get keyring://my-service/admin
hasp put keyring://my-service/admin "new-password"
hasp delete keyring://my-service/admin
```

- **Target** on Linux: `keyring://service/account`
- Uses the platform keyring (secret-service on Linux, Keychain on
  macOS, Credential Manager on Windows).

## `op://` — 1Password

```bash
hasp get op://Production/API/credential
hasp exists op://Production/API/credential
```

- Requires the 1Password CLI (`op`) to be installed and signed in.
- Read-only via hasp.

## `vault://` — HashiCorp Vault

```bash
hasp get vault://127.0.0.1/secret/data/prod/db-password
```

- Requires `VAULT_ADDR` and a Vault token (env var or
  `~/.vault-token`).
- Read-only via hasp.

## `bw://` — Bitwarden

```bash
hasp get bw://item/field
```

- Requires `bw` CLI installed and `BW_SESSION` set.
- Read-only via hasp.

## `aws-sm://` — AWS Secrets Manager

```bash
hasp get aws-sm://us-east-1/prod/db-password
```

- Uses the AWS SDK default credential chain.
- Read-only via hasp.

## `aws-ssm://` — AWS Systems Manager Parameter Store

```bash
hasp get aws-ssm://us-east-1/prod/db-password
```

- Uses the AWS SDK default credential chain.
- Read-only via hasp.

## `gcp-sm://` — GCP Secret Manager

```bash
hasp get gcp-sm://my-project/my-secret
```

- Uses Application Default Credentials (ADC) or `gcloud` auth.
- Read-only via hasp.

## `azure-kv://` — Azure Key Vault

```bash
hasp get azure-kv://my-vault/my-secret
```

- Uses the Azure SDK default credential chain.
- Read-only via hasp.

## What "read-only via hasp" means

Several backends do not support `put` or `delete` through hasp. This
is usually because the upstream CLI or API has additional constraints
(encryption at rest settings, versioning, soft-delete, etc.) that make
a generic "just write it" unsafe or impossible.

If you need write/delete on these backends, use their native CLIs or
APIs directly.
