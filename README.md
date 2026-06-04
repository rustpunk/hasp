# hasp

> The latch over the lock.

Unified secrets CLI for OS keyrings, AWS Secrets Manager & SSM Parameter
Store, HashiCorp Vault, GCP Secret Manager, Azure Key Vault, 1Password,
Bitwarden, and dotenv files. One binary, many backends, one URL-style
addressing scheme. Part of the rustpunk portfolio.

A *hasp* is the hinged latch a padlock passes through — the gateway
between the secured and the unsecured. `hasp` is that gateway for every
secret store you actually use, with feature-gated backends so the
default binary stays small and pure-Rust.

## Scope

`hasp` is a unified `get` / `put` / `list` / `delete` / `exists` for
**keyed secret stores**, shipping as both a **Rust library** (`hasp` crate)
and a **CLI binary** (`hasp-cli` crate). URL addressing parallels its
sibling [`ferrule`](https://github.com/rustpunk/ferrule):

```
keyring://service/account/key
aws-sm://us-west-2/prod/db-password?version-stage=AWSCURRENT
aws-ssm:///path/to/parameter?with-decryption=true
vault://kv/data/myapp/db-password
gcp-sm://projects/<project>/secrets/<name>/versions/latest
azure-kv://<vault>.vault.azure.net/secrets/<name>
op://Vault/Item/field
bw://item-uuid/login.password
file:///etc/secrets/db.txt
env://DATABASE_PASSWORD
```

Profile aliases collapse common cases:

```
hasp get @prod/db-password
hasp put @prod/db-password -          # value from stdin
hasp ls  @prod
```

### Installation

```bash
# CLI (all backends)
cargo install hasp-cli

# Library only
cargo add hasp
```

### Documentation

Full user documentation is an mdbook in `docs/`:

```bash
cargo install mdbook
mdbook serve docs --open
```

Or read it online at `https://rustpunk.github.io/hasp/`.

The library is the source of truth; the CLI is a thin shell over the
public library API. Both are first-class surfaces.

### Out of scope (handled elsewhere)

- Secret rotation — operational concern, separate tool.
- Password / key generation — distinct domain.
- Auth bootstrap — `hasp` assumes ambient credentials (env, IAM role,
  `~/.vault-token`) or delegates to a backend plugin.
- Bulk file encryption — see `age` / `sops` / `cocoon`.
- Certificate / TLS material lifecycle — separate problem space.

## Status

`0.2.0-alpha` — all five CRUD verbs (`get` / `put` / `list` / `delete` /
`exists`) are implemented across every backend. The CLI is functional.
Library API is stabilized before a `0.1.0` release.

## License

Licensed under either of [MIT](https://opensource.org/license/mit) or
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) at your option.
