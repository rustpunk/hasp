# Project Map

## Workspace

Verified: root `Cargo.toml` declares a Rust 2021 Cargo workspace with `members = ["crates/*"]`, shared package metadata, and workspace dependencies. Internal dependencies carry both `path` and `version`, with comments saying this is required for `cargo publish`.

## Root Files

| Path | Purpose | Evidence | Confidence |
| --- | --- | --- | --- |
| `Cargo.toml` | Workspace manifest, versions, internal dependency policy, shared dependencies. | `[workspace]`, `[workspace.package]`, `[workspace.dependencies]`. | High |
| `Cargo.lock` | Checked-in lockfile for binary-shipping workspace. | Present at root; `CLAUDE.md` notes it is checked in. | High |
| `rust-toolchain.toml` | Stable Rust toolchain with `rustfmt` and `clippy`. | `channel = "stable"`, components list. | High |
| `deny.toml` | cargo-deny policy. | License allow-list, yanked deny, advisory ignore. | High |
| `README.md` | Public project overview. | Describes unified secrets CLI/library and URL schemes. | Medium |
| `CHANGELOG.md` | Release history and behavior changes. | `0.2.0-alpha` entry. | Medium |
| `CLAUDE.md` | Existing agent guidance. | Workspace layout, build/test commands, architecture invariants. | High |

## Crates

| Package | Path | Purpose | Important Files | Tests | Confidence |
| --- | --- | --- | --- | --- | --- |
| `hasp-core` | `crates/hasp-core` | Core contracts and shared primitives. | `src/lib.rs`, `error.rs`, `audit.rs`, `cache.rs`, `hardening.rs`, `proxy.rs`, `retry.rs`, `field.rs`, `secret_mem.rs`, `test_utils.rs`. | `tests/audit_no_leak.rs`, `tests/memory_lock_tests.rs`, inline unit tests. | High |
| `hasp` | `crates/hasp` | Public library facade and `Store` dispatch. | `src/lib.rs`. | `tests/integration.rs`, `batch_tests.rs`, `copy_tests.rs`, `diff_tests.rs`, `url_parsing.rs`. | High |
| `hasp-cli` | `crates/hasp-cli` | `hasp` binary. | `src/main.rs`, `run.rs`, `profiles.rs`, `profile_allow.rs`, `audit_config.rs`, `completions.rs`, `config_init.rs`, `list_format.rs`. | `tests/cli*.rs`. | High |
| `hasp-backend-env` | `crates/hasp-backend-env` | `env://` backend. | `src/lib.rs`. | `tests/env_backend_tests.rs`, inline unit tests. | High |
| `hasp-backend-file` | `crates/hasp-backend-file` | `file://` backend. | `src/lib.rs`. | `tests/file_backend_tests.rs`, inline unit tests. | High |
| `hasp-backend-keyring` | `crates/hasp-backend-keyring` | `keyring://` OS keyring backend. | `src/lib.rs`. | Inline unit tests and `hasp` integration tests. | High |
| `hasp-backend-op` | `crates/hasp-backend-op` | `op://` 1Password CLI backend. | `src/lib.rs`. | Inline unit tests and fake-CLI integration tests. | High |
| `hasp-backend-bw` | `crates/hasp-backend-bw` | `bw://` Bitwarden CLI backend. | `src/lib.rs`. | Inline unit tests and fake-CLI integration tests. | High |
| `hasp-backend-vault` | `crates/hasp-backend-vault` | `vault://` HashiCorp Vault backend. | `src/lib.rs`. | Inline tests; some live behavior environment-gated. | Medium |
| `hasp-backend-aws-sm` | `crates/hasp-backend-aws-sm` | `aws-sm://` AWS Secrets Manager backend. | `src/lib.rs`. | Inline tests; live validation deferred. | Medium |
| `hasp-backend-aws-ssm` | `crates/hasp-backend-aws-ssm` | `aws-ssm://` AWS SSM Parameter Store backend. | `src/lib.rs`. | Inline tests; live validation deferred. | Medium |
| `hasp-backend-gcp-sm` | `crates/hasp-backend-gcp-sm` | `gcp-sm://` GCP Secret Manager backend. | `src/lib.rs`. | Inline tests; live validation deferred. | Medium |
| `hasp-backend-azure-kv` | `crates/hasp-backend-azure-kv` | `azure-kv://` Azure Key Vault backend. | `src/lib.rs`. | Inline tests; live validation deferred. | Medium |

## Internal Dependencies

Verified:

- Backend crates depend on `hasp-core`.
- `hasp` depends on `hasp-core`, `url`, and optional backend crates.
- `hasp-cli` depends on `hasp` and `hasp-core`.
- Tests use `hasp-core/test-utils`, `tempfile`, `proptest`, `url`, and fake CLI helpers.

## Architecturally Important External Dependencies

- `url`: URL parsing for store and backend grammar.
- `secrecy`: `SecretString` redaction boundary.
- `thiserror`: core error definitions.
- `moka`: in-process cache.
- `subtle`: constant-time equality for diff/copy verification.
- `reqwest`: blocking HTTP clients for REST backends.
- AWS SDK crates, Azure crates, `gcp-auth`: cloud backend auth/API access.
- `keyring-core` and platform keyring stores: OS keyring integration.
- `clap`, `clap_complete`, `clap_mangen`: CLI parsing, completions, man page.
- `serde`, `serde_json`, `toml`: config, JSON responses, list output, profiles.
- `sha2`: profile allow integrity.

## Documentation

| Path | Purpose | Confidence |
| --- | --- | --- |
| `docs/src` | mdbook source for user docs. | High |
| `docs/book` | built mdbook output. | High |
| `docs/internal/research` | design and threat-model research. | High |
| `notes` | planning, handoffs, deferred validation, prior-art notes. | High |
| crate `README.md` files | crate-specific public docs. | Medium because some appear stale. |

## CI, Build, And Release

- `.github/workflows/ci.yml`: format, build, clippy, test, docs, cargo-deny across feature matrix.
- `.github/workflows/release.yml`: tag-triggered multi-platform release builds with packaged artifacts and SLSA attestation.
- `deny.toml`: license/advisory policy.

## Examples And Benches

Verified: no `examples/` or `benches/` directories were found outside generated docs and target output during discovery. Tests are the main executable examples.
