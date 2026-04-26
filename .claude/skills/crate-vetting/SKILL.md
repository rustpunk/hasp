---
name: crate-vetting
description: "Verify a Rust crate is actively maintained before adding it to Cargo.toml. Opus has a documented tendency to reach for formerly-popular crates that are now archived (failure, error-chain, old actix, pre-async rocket, lazy_static). Auto-loads on any Cargo.toml edit. Triggers on: add dependency, add crate, bring in X crate, Cargo.toml edits."
paths: "**/Cargo.toml"
model: claude-sonnet-4-6
allowed-tools: Read, Bash, WebFetch
---

# Crate vetting

Before adding any new entry under `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, or `[workspace.dependencies]` — run the verification checklist below and write a 2-sentence justification alongside the edit. Apply to every new crate in a batch, not just the first one.

## Checklist (all six steps, every time)

1. **Release recency.** Run `cargo info <crate>` — record the current version and the date of the latest release. Flag anything whose last release is older than 12 months.

2. **Repo health.** If the crate lists a GitHub repository:
   ```
   gh api repos/<owner>/<name> --jq '{archived, pushed_at, open_issues_count, stargazers_count}'
   ```
   Flag if `archived: true`, `pushed_at` is older than 12 months, or the repo has been transferred to an "abandoned-projects" org.

3. **Advisory check.** Run `cargo audit` (if available) or check https://rustsec.org/advisories for any advisory affecting the crate — especially `RUSTSEC-*-unmaintained` flags. `cargo deny check` at pre-commit also catches these via `[advisories] unmaintained = "all"`.

4. **Yanked versions.** Check crates.io or `cargo info` output for yanked releases in the same major series. A major series with all versions yanked is a hard stop.

5. **Blessed alternative.** Identify what the 2026 Rust ecosystem prefers for this job. Known replacements:
   - `thiserror` / `anyhow` — NOT `failure`, `error-chain`, `err-derive`
   - `std::sync::LazyLock` / `std::sync::OnceLock` (Rust 1.80+) — NOT `lazy_static`, `once_cell`
   - `tokio` — NOT `async-std`, `smol`. The rustpunk portfolio standardizes on tokio.
   - `reqwest` (rustls) — NOT `hyper`-raw for most HTTP client needs; NOT legacy `isahc`. Rustls only — no `native-tls` / OpenSSL surface.
   - `clap` v4 (derive) — NOT `structopt`, `docopt`, `getopts`
   - `secrecy` + `zeroize` — wrap every credential, key, and token; NOT bare `String` / `Vec<u8>` for sensitive material
   - `serde-saphyr` — NOT `serde_yaml`, `serde_yml`, `serde_yaml_bw` (the YAML serde line is poisoned). Stay in TOML / JSON when possible.
   - `toml` — for `hasp` profiles (mirrors `.ferrule.toml`); NOT bespoke parsers
   - `insta` — NOT `trybuild` for snapshot tests
   - Rust 1.80+ stdlib — check before adding `itertools`, `nonempty`, `arrayvec`, `lazy_static`, `once_cell` for functionality now in stdlib
   Search the current ecosystem (crates.io trending, blessed.rs, lib.rs top-of-category) if the job isn't covered by the list above.

### Backend SDK choices for hasp

`hasp` pulls in vendor SDKs for cloud secret stores. Vetted defaults:

   - AWS Secrets Manager / SSM Parameter Store — `aws-sdk-secretsmanager`, `aws-sdk-ssm` (official, with `rustls` feature flag)
   - HashiCorp Vault — `vaultrs` (active, well-maintained); fall back to a hand-rolled `reqwest` client only when the surface needed is small
   - GCP Secret Manager — `google-cloud-secretmanager` (Google official) or `gcloud-sdk` (community)
   - Azure Key Vault — `azure_security_keyvault_secrets` (Azure official Rust SDK)
   - OS keyring — `keyring` crate (cross-platform: Secret Service / macOS Keychain / Windows Credential Manager)
   - 1Password CLI (`op`) / Bitwarden CLI (`bw`) — shell out via `tokio::process::Command`; no native Rust SDK
   - dotenv files — `dotenvy` (active fork of dead `dotenv`)
   - SOPS-encrypted files — `rops` (Rust SOPS) or shell out to `sops` binary; vet at use time

6. **Justification paragraph.** In the commit message or PR description write two sentences:
   ```
   Added `X` v`Y`. Active (release 2026-MM-DD, repo live, zero advisories).
   Considered `Z` but ruled out because [archived | has advisory | worse fit for <reason>].
   ```

## Positive rule

Prefer crates with: a release in the last 12 months, a non-archived GitHub repo, zero open RustSec advisories, clear ownership (org or named maintainer), and a blessed position in the ecosystem for this job.

## Hard stops

Refuse to add a crate if any of these are true:
- Repository is `archived: true` on GitHub
- Last release is older than 24 months and there is a blessed active alternative
- A RustSec `unmaintained` advisory matches
- All versions in the current major series are yanked
- The crate is on the YAML-serde forbidden list (`serde_yaml`, `serde_yml`, `serde_yaml_bw` — all unmaintained or broken; use `serde-saphyr` if YAML is unavoidable)
- The crate uses `native-tls` / OpenSSL by default and offers no `rustls` feature flag. The rustpunk portfolio is rustls-only — no host-side OpenSSL dependency.

If the user explicitly requests an archived/unmaintained crate anyway, flag each hard-stop and ask for explicit confirmation before proceeding. Do not infer consent from "just add X."

## What this skill is NOT

Not a license audit (that's `[licenses]` in `deny.toml`). Not a CVE scan (that's `cargo audit`). Not a semver-compat check (that's `cargo-semver-checks`). This skill vets the *maintenance posture* of a candidate crate before it enters the workspace.
