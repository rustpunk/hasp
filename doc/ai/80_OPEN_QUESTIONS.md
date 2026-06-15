# Open Questions

## Existing User Docs Conflict With Source On Backend Operations

- Priority: High
- Why it matters: agents may implement or document behavior incorrectly.
- Files/modules involved: `README.md`, `docs/src/backends.md`, backend crate READMEs, `crates/hasp-backend-*/src/lib.rs`, `crates/hasp/tests/integration.rs`.
- Suggested resolution: compare source and tests per backend, then update user docs and crate READMEs in a separate docs task.

## Profile Allow Default-On Docs Conflict

- Priority: High
- Why it matters: profile trust affects CLI security behavior and CI scripts.
- Files/modules involved: `docs/src/profiles.md`, `docs/src/cli-reference.md`, `CHANGELOG.md`, `crates/hasp-cli/src/main.rs`, `cli_profile_allow.rs`.
- Suggested resolution: update stale user docs after confirming intended release behavior.

## `README.md` Status Mentions `0.2.0-alpha` And Stabilizing Before `0.1.0`

- Priority: Medium
- Why it matters: release status may confuse contributors and users.
- Files/modules involved: `README.md`, `CHANGELOG.md`, root `Cargo.toml`.
- Suggested resolution: ask maintainer whether the intended next stable milestone is `0.1.0` or later.

## Live Cloud Error Mapping Is Not Fully Verified

- Priority: High
- Why it matters: auth, permission, throttling, not-found, and transient classification drive retries and exit codes.
- Files/modules involved: AWS, GCP, Azure, Vault backend crates; `notes/TODO-live-error-mapping.md`.
- Suggested resolution: run credential-backed tests or manual validation against controlled cloud resources.

## `RetryBackend::base_delay` May Not Affect Backoff

- Priority: Medium
- Why it matters: documented retry tuning may be misleading.
- Files/modules involved: `crates/hasp-core/src/retry.rs`.
- Suggested resolution: inspect and test `RetryBackend` behavior; if confirmed, file or fix as a code task.

## `ProxyConfig.url` Public Field May Contain Credentials

- Priority: Medium
- Why it matters: `Debug` redacts credentials, but callers can log the public field directly.
- Files/modules involved: `crates/hasp-core/src/proxy.rs`, docs using proxy config.
- Suggested resolution: ask whether API should deprecate or rename the raw field, or document a strict no-log rule.

## Dynamic Completions And Profile Trust

- Priority: Medium
- Why it matters: completions may read `profiles.toml` without profile-allow enforcement.
- Files/modules involved: `crates/hasp-cli/src/completions.rs`, `profiles.rs`, `profile_allow.rs`.
- Suggested resolution: decide whether completions should be allowed to read untrusted profiles or should degrade safely.

## Vault Field-Level Put Uses Last-Write-Wins

- Priority: Medium
- Why it matters: read-modify-write without CAS can lose concurrent updates.
- Files/modules involved: `crates/hasp-backend-vault/src/lib.rs`, Vault docs/tests.
- Suggested resolution: decide whether CAS support is required or document last-write-wins clearly.

## GCP Secret ID Grammar May Differ Between README And Source

- Priority: Low
- Why it matters: user-facing URL grammar may reject or allow different paths than docs imply.
- Files/modules involved: `crates/hasp-backend-gcp-sm/README.md`, `crates/hasp-backend-gcp-sm/src/lib.rs`.
- Suggested resolution: align README with parser behavior or tighten parser.

## Persistent Cache Is Scaffolded, Not Implemented

- Priority: Medium
- Why it matters: agents may treat `cache-persistent` as disk persistence.
- Files/modules involved: `crates/hasp-core/src/cache.rs`, CLI cache docs, `CHANGELOG.md`.
- Suggested resolution: keep docs explicit until implementation lands; ask before changing cache persistence behavior.
