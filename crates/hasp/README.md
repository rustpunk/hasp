# hasp

Unified secrets library for Rust — a single `Store` type that dispatches
`get` / `put` / `list` / `delete` / `exists` to multiple backends addressed
by URL scheme. Part of the rustpunk portfolio.

This crate is the **library**. The `hasp` CLI binary ships separately in
[`hasp-cli`](https://crates.io/crates/hasp-cli).

## Backends

Each backend is feature-gated, so consumers pay only for the stores they use.

| Scheme | Backend | Feature |
|--------|---------|---------|
| `env://VAR` | Environment variables | `env` (default) |
| `file:///path` | Local files | `file` |
| `keyring://service/account` | OS keyring | `keyring` |
| `aws-sm://region/name` | AWS Secrets Manager | `aws-sm` |
| `aws-ssm://region/name` | AWS SSM Parameter Store | `aws-ssm` |
| `gcp-sm://project/id` | Google Cloud Secret Manager | `gcp-sm` |
| `azure-kv://vault/name` | Azure Key Vault | `azure-kv` |
| `vault://mount/path` | HashiCorp Vault | `vault` |
| `op://vault/item/field` | 1Password CLI | `op` |
| `bw://item/field` | Bitwarden CLI | `bw` |

## Usage

```rust
use hasp::Store;

let store = Store::with_defaults();
let secret = store.get("env://HOME").unwrap();
```

Secret values cross the library boundary as `secrecy::SecretString`, so
`Debug` output never leaks plaintext. Enable the backends you need via Cargo
features:

```toml
[dependencies]
hasp = { version = "0.2.0-alpha", features = ["vault", "aws-sm"] }
```

## License

Licensed under either of [MIT](https://opensource.org/license/mit) or
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) at your option.
