# How Hasp Thinks

Understanding three core ideas makes everything else in hasp click:

1. **Every secret is a URL.**
2. **Ambient credentials only.**
3. **The CLI is a thin shell over the library.**

## Every secret is a URL

Hasp identifies every secret with a URL. The scheme selects the backend;
the rest is backend-specific addressing. This is the primary reason one
tool can speak to many stores without a sprawl of subcommands.

```text
env://MY_API_KEY
file:///etc/secrets/db-password
keyring://my-service/admin
aws-sm://us-east-1/prod/db-password
vault://127.0.0.1/secret/data/prod/db-password
op://vault/item/field
bw://item/field
gcp-sm://my-project/my-secret
azure-kv://my-vault/my-secret
```

The URL is the identifier. You pass it to `get`, `put`, `list`,
`delete`, or `exists`. The backend handles the rest.

### Why URLs?

- **They are self-describing.** You can tell it's AWS by the scheme.
- **They have a standard parser.** No custom grammar to learn.
- **They work in env vars and config files.** Drop a URL into any
  `.env` or TOML file and it's readable without further annotation.
- **They compose with aliases.** `@prod/db_password` expands to a full
  URL at runtime, so the human reads an alias and the machine gets a
  URL.

## Ambient credentials only

Hasp does not store credentials, rotate tokens, bootstrap auth, or
manage sessions. It reads what your environment already provides.

| Backend | What hasp reads |
|---|---|
| `env://` | The env var itself |
| `file://` | The file contents |
| `keyring://` | The OS keyring (keychain, secret-service, etc.) |
| `op://` | The 1Password CLI (`op read`) |
| `vault://` | `VAULT_ADDR` + `VAULT_TOKEN` (or `~/.vault-token`) |
| `bw://` | `BW_SESSION` + the `bw` CLI |
| `aws-sm://` | AWS SDK default chain (env, profile, IAM role) |
| `aws-ssm://` | AWS SDK default chain |
| `gcp-sm://` | `gcloud` auth or ADC |
| `azure-kv://` | Azure SDK default chain |

This is a deliberate boundary. Hasp is a secret **consumer**, not a
secret **lifecycle manager**. If you need to set up a Vault token,
configure AWS SSO, or unlock Bitwarden, do that before invoking hasp.

### What this means in practice

- **On a developer laptop:** 1Password is unlocked, Vault token is in
  `~/.vault-token`, AWS SSO session is current. Hasp just reads them.
- **In CI:** The runner has `AWS_ROLE_ARN`, `VAULT_TOKEN`, or
  `BW_SESSION` injected as env vars. Hasp just reads them.
- **On a server:** The EC2 instance has an IAM role. Hasp uses the
  IMDS endpoint transparently.

## The CLI is a thin shell over the library

`hasp-cli` is a thin wrapper. It parses arguments, resolves aliases,
reads stdin when needed, and calls `hasp::Store` methods. All the real
logic lives in `hasp` (the router) and `hasp-core` + backend crates.

This matters because:

- **Library consumers get the same behavior.** A Rust program using
  `hasp` as a crate gets identical URL parsing, alias resolution, and
  backend dispatch.
- **Errors are typed in the library.** The CLI translates them to
  human strings, but the underlying types are rich enough for code to
  match on `hasp::Error::NotFound`, `PermissionDenied`,
  `AuthenticationFailed`, etc.
- **No CLI-only behavior.** You won't find a feature that works on the
  command line but is inaccessible from Rust code.

## The five operations

Hasp exposes exactly five operations. Every backend implements the subset
it supports.

| Operation | Meaning | Example |
|---|---|---|
| `get` | Read a secret value | `store.get("env://HOME")` |
| `put` | Write a secret value | `store.put("file:///tmp/secret", &secret)` |
| `list` | List entries under a prefix or collection | `store.list("vault://127.0.0.1/secret/")` |
| `delete` | Remove a secret | `store.delete("file:///tmp/secret")` |
| `exists` | Check presence (exit 0 = present, 1 = absent) | `store.exists("env://HOME")` |

### Library entry points

The library provides three ways to obtain a `Store`:

```rust
use hasp::Store;

// All enabled backends (depends on Cargo features)
let store = Store::with_defaults();

// Custom subset, e.g. only env and file
let store = Store::with_backends(vec![
    hasp::env(),
    hasp::file(),
]);

// Empty store, then register backends manually
let mut store = Store::empty();
store.register(hasp::env());
```

For one-off usage, free functions construct a default store internally:

```rust
let secret = hasp::get("env://HOME")?;
hasp::put("file:///tmp/secret", &secret)?;
hasp::exists("env://HOME")?;
```

These match the sibling-crate `ferrule` convention and are thin wrappers
over `Store::with_defaults()`. Heavy callers should cache a `Store`
instance to avoid repeated backend construction.

`hasp` also exposes bulk operations:

```rust
let values = store.batch_get(
    &["env://A", "env://B", "env://A"]
)?;
// values.len() == 2 — deduplicated and resolved concurrently.

store.bulk_put(&[
    ("file:///tmp/a", &val_a),
    ("file:///tmp/b", &val_b),
])?;
```

Not every backend supports every operation. For example, `env://`
does not support `put` (environment variables are read-only after
process start) and does not support `list`. Hasp returns a clear
error when you try an unsupported operation.

## Error taxonomy

When something goes wrong, hasp tells you what category of problem it
is. This helps you decide whether to retry, re-authenticate, or fix a
URL.

| Kind | When it happens | What to check |
|---|---|---|
| `UrlParse` | The string isn't a valid URL | Scheme, slashes, encoding |
| `InvalidUrl` | The URL doesn't match backend grammar | Path segments, query params |
| `UnknownScheme` | The scheme has no registered backend | Feature flag, backend name |
| `UnsupportedOperation` | Backend doesn't do this | The backends table |
| `NotFound` | Secret doesn't exist | Name, permission, region |
| `PermissionDenied` | Credentials valid, but not authorized | IAM / RBAC / policies |
| `AuthenticationFailed` | Credentials missing or expired | Token, session, CLI login |
| `PreconditionFailed` | Resource in wrong state | Soft-deleted, wrong version |
| `Backend::{Transient,Throttled,Permanent}` | Upstream error | Retry, wait, or escalate |

See [Troubleshooting](troubleshooting.md) for the most common
scenarios.

## Retry decorator

For HTTP-backed stores (`aws-sm`, `aws-ssm`, `vault`, `gcp-sm`,
`azure-kv`) you can opt into automatic retry on transient failures:

```rust
use hasp::StoreBuilder;
use std::time::Duration;

let store = StoreBuilder::with_defaults()
    .with_retry(3, Duration::from_millis(100))
    .build();
```

The decorator wraps each HTTP backend with exponential backoff plus
jitter. Local backends (`env`, `file`, `keyring`, `op`, `bw`) are
never wrapped — their errors are not transient.

## Diagnostics

`Store::resolve` inspects a URL without performing I/O, returning the
scheme, the chosen backend name, and whether the entry is still in
the TTL cache. This powers the CLI `--explain` flag:

```text
$ hasp --explain get env://HOME
URL:      env://HOME
Backend:  env
Cache:    miss
```

Use it to debug alias expansion, proxy routing, or cache state before
running a destructive command.

## Where to next

- [Profile Aliases](profiles.md) — alias resolution rules, config
  file format, and environment overrides.
- [Supported Backends](backends.md) — URL grammar, supported
  operations, and auth per backend.
