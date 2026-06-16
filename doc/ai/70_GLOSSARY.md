# Glossary

| Term | Meaning | Where It Appears | Related Terms | Confidence |
| --- | --- | --- | --- | --- |
| Hasp | Unified secrets library and CLI for keyed secret stores. | `README.md`, crate names. | `hasp`, `hasp-cli`. | High |
| `hasp-core` | Core contract crate. | `crates/hasp-core`. | `Backend`, `Error`, `AuditEvent`. | High |
| `hasp` | Public library facade crate. | `crates/hasp`. | `Store`, `StoreBuilder`. | High |
| `hasp-cli` | Binary crate producing the `hasp` executable. | `crates/hasp-cli`. | `Command`, profiles, exit codes. | High |
| Backend | Trait implementation for one secret store scheme. | `hasp_core::Backend`. | `Entry`, `SecretString`. | High |
| Store | Library facade that dispatches operations to registered backends. | `hasp::Store`. | `StoreBuilder`, backend registry. | High |
| StoreBuilder | Fluent builder for `Store`. | `hasp::StoreBuilder`. | cache, proxy, retry, audit. | High |
| Scheme | URL scheme selecting a backend, such as `env` or `vault`. | `scheme()`, URL examples. | backend registration. | High |
| Entry | Named item returned by `list`, with gettable URL. | `hasp_core::Entry`. | `Backend::list`. | High |
| SecretString | Redacting secret value type from `secrecy`. | Core re-exports and backend `get`. | `ExposeSecret`, `wrap_secret`. | High |
| `wrap_secret` | Helper that wraps strings and optionally memory-locks. | `hasp-core/src/secret_mem.rs`. | memory-lock. | High |
| AuditEvent | Value-free structured audit record. | `hasp-core/src/audit.rs`. | `AuditSink`, `Verb`, `CacheEvent`. | High |
| AuditSink | Sink receiving audit events. | `hasp-core/src/audit.rs`. | `StderrSink`, `FileSink`, `SyslogSink`, `NoopSink`. | High |
| HardeningToken | Witness that process hardening was installed. | `hasp-core/src/hardening.rs`. | cache, `install_hardening`. | High |
| ProcessCache | Per-invocation in-memory cache. | `hasp-core/src/cache.rs`. | `CachePolicy`, `HardeningToken`. | High |
| Persistent cache | Feature-gated scaffold for future disk persistence. | `CachePolicy::Persistent`. | `cache-persistent`. | High |
| Profile alias | CLI alias form such as `@prod/db-password`. | `hasp-cli/src/profiles.rs`, docs. | `profiles.toml`. | High |
| Profile allow | Trust record for `profiles.toml`. | `profile_allow.rs`, CLI docs. | `HASP_REQUIRE_PROFILE_ALLOW`. | High |
| `HASP_REQUIRE_PROFILE_ALLOW` | Environment variable controlling profile allow enforcement. | CLI code/tests/docs. | `--no-profile-allow`. | High |
| `HASP_CACHE_TTL` | Environment variable overriding cache TTL or disabling cache with `0`. | CLI code/tests/docs. | `HASP_NO_CACHE`, `CI`. | High |
| `HASP_ALLOW_HTTP_PROXY` | Allows plain HTTP proxy for `cp`/`diff` when set to `1`. | CLI code/tests/docs. | proxy refusal. | High |
| `cp` | Cross-backend copy operation. | `hasp::Store::copy`, CLI. | `IfExists`, `CopyOptions`. | High |
| `diff` / compare | Constant-time binary comparison returning only match/differ. | `Store::compare`, CLI `diff`. | `DiffOutcome`, `subtle`. | High |
| Field extraction | Extracting JSON subfields via `?field=` or CLI `-F`. | `hasp-core/src/field.rs`, cloud/Vault/OP/BW paths. | dotted field path. | High |
| Ambient credentials | Auth expected from environment, local tools, cloud metadata, or tokens rather than hasp-managed login. | README, backend docs. | auth bootstrap out of scope. | High |
| Live cloud validation | Real-account validation of cloud error mappings. | `notes/TODO-live-error-mapping.md`. | AWS/GCP/Azure/Vault. | High |
| SLSA attestation | Release provenance artifact generated in release workflow. | `.github/workflows/release.yml`, installation docs. | release artifacts. | High |
| `cargo-deny` | Dependency policy checker. | `deny.toml`, CI. | license/advisory policy. | High |
