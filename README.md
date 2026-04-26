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

This is a name reservation for the `hasp` crate. The implementation is in development.

## Scope

`hasp` is a unified `get` / `put` / `list` / `delete` / `exists` for
**keyed secret stores**. URL addressing parallels its sibling
[`ferrule`](https://github.com/rustpunk/ferrule):

```
keyring://service/account/key
aws-sm://name?region=us-west-2&version=AWSCURRENT
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

### Out of scope (handled elsewhere)

- Secret rotation — operational concern, separate tool.
- Password / key generation — distinct domain.
- Auth bootstrap — `hasp` assumes ambient credentials (env, IAM role,
  `~/.vault-token`) or delegates to a backend plugin.
- Bulk file encryption — see `age` / `sops` / `cocoon`.
- Certificate / TLS material lifecycle — separate problem space.

## Status

Pre-release placeholder at `0.1.0-alpha`.

## License

Licensed under either of [MIT](https://opensource.org/license/mit) or
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) at your option.
