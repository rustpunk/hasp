# Testing And Commands

## Required Tools

- Verified from `rust-toolchain.toml`: stable Rust with `rustfmt` and `clippy`.
- Verified from CI: Linux CI installs `libdbus-1-dev` and `pkg-config` for keyring-related builds.
- Inferred from CI: `cargo-deny` is required for the deny check.
- Inferred from README: `mdbook` is required to serve user docs.

## Commands Run During Documentation Pass

Verified successful:

- `git status --short`
- `find . -maxdepth 3 -type f | sort | sed 's#^./##' | head -300`
- `cargo metadata --no-deps --format-version 1`
- `rg` and `sed` read-only discovery commands

No Cargo build/test/check command was run before creating docs because the user requested read-only discovery for Phase 1/2 and Cargo writes to `target/`.

## Fast Check Command

Inferred:

```bash
cargo check --workspace
```

Use for quick compile feedback. CI uses `cargo build`, not `cargo check`.

## Full Test Command

Inferred from CI and `CLAUDE.md`:

```bash
cargo test --workspace --all-features
```

CI command shape is `cargo test ${{ matrix.feature-set.flags }}` across all-features, default-only, minimal-backends, and memory-lock.

## CI-Equivalent Commands

Inferred from `.github/workflows/ci.yml`:

```bash
cargo fmt --check
cargo build --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
cargo deny check
```

Also test these feature sets when touching feature wiring:

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --no-default-features --features env,file,keyring
cargo clippy --all-targets --no-default-features --features env,file,keyring -- -D warnings
cargo test --no-default-features --features env,file,keyring
cargo build --no-default-features --features env,file,hasp-core/memory-lock
cargo clippy --all-targets --no-default-features --features env,file,hasp-core/memory-lock -- -D warnings
cargo test --no-default-features --features env,file,hasp-core/memory-lock
```

## Per-Package Commands

Inferred:

```bash
cargo test -p hasp-core
cargo test -p hasp-core --all-features
cargo test -p hasp
cargo test -p hasp --all-features
cargo test -p hasp-cli
cargo test -p hasp-backend-env
cargo test -p hasp-backend-file
cargo test -p hasp-backend-keyring
cargo test -p hasp-backend-op
cargo test -p hasp-backend-bw
cargo test -p hasp-backend-vault
cargo test -p hasp-backend-aws-sm
cargo test -p hasp-backend-aws-ssm
cargo test -p hasp-backend-gcp-sm
cargo test -p hasp-backend-azure-kv
```

## Focused Test Commands

Inferred:

```bash
cargo test -p hasp --test copy_tests --features env,file
cargo test -p hasp --test diff_tests --features env,file
cargo test -p hasp --test url_parsing
cargo test -p hasp-cli --test cli_run
cargo test -p hasp-cli --test cli_cp
cargo test -p hasp-cli --test cli_diff
cargo test -p hasp-cli --test cli_profile_allow
cargo test -p hasp-cli --test cli_audit
cargo test -p hasp-cli --test cli_exit_codes
cargo test -p hasp-cli --test cli_cache
cargo test -p hasp-cli --test cli_field
```

## Formatting

Verified from CI:

```bash
cargo fmt --check
```

For local formatting before review:

```bash
cargo fmt --all
```

## Linting

Verified from CI:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Docs

Verified from CI:

```bash
cargo doc --no-deps
```

Inferred from README:

```bash
mdbook serve docs --open
```

Do not use `--open` in headless agent environments unless the user explicitly asks to launch a browser.

## Example And Demo Commands

Inferred from README and docs:

```bash
cargo build --release --bin hasp
cargo install --path crates/hasp-cli
cargo build --release --bin hasp --no-default-features --features env,file
```

## Benchmark And Performance Commands

Verified: no benchmark targets were found during discovery.

Use tests and profiling only after identifying a concrete performance concern. Do not invent benchmarks during documentation-only work.

## CI And Deploy Commands

Verified from release workflow:

```bash
cargo build --release --bin hasp --target <target>
```

Release is tag-triggered on `v*` and uploads packaged binaries with SLSA attestation. Do not run release or upload commands from an agent session without explicit human approval.

## Commands Agents Should Run Before Claiming Success

For docs-only changes:

```bash
git diff --stat
git diff -- AGENTS.md doc/ai crates/AGENTS.md crates/hasp-core/AGENTS.md crates/hasp/AGENTS.md crates/hasp-cli/AGENTS.md crates/hasp-backend-env/AGENTS.md crates/hasp-backend-file/AGENTS.md crates/hasp-backend-keyring/AGENTS.md crates/hasp-backend-op/AGENTS.md crates/hasp-backend-bw/AGENTS.md crates/hasp-backend-vault/AGENTS.md crates/hasp-backend-aws-sm/AGENTS.md crates/hasp-backend-aws-ssm/AGENTS.md crates/hasp-backend-gcp-sm/AGENTS.md crates/hasp-backend-azure-kv/AGENTS.md
rg -n "TODO|TBD|FIXME|PLACEHOLDER|unchecked|stale path" AGENTS.md doc/ai crates/*/AGENTS.md crates/AGENTS.md
```

For code changes, run focused tests first, then the relevant CI-equivalent commands.

## Expensive, Flaky, Or Environment-Dependent Commands

- `cargo test --workspace --all-features`: compile-heavy because default CLI includes cloud backends.
- `cargo deny check`: may require installed `cargo-deny`.
- Live cloud/Vault tests: require credentials or environment variables and should not be assumed deterministic.
- `mdbook serve docs --open`: starts a server and opens a browser.
- Release workflow commands: packaging and upload behavior must remain human-controlled.

## Troubleshooting Notes

- Linux keyring builds may need `libdbus-1-dev` and `pkg-config`.
- `HASP_REQUIRE_PROFILE_ALLOW` is default-on in code/tests; use `HASP_REQUIRE_PROFILE_ALLOW=0` in tests that intentionally bypass profile trust.
- CLI cache is disabled by `CI`, `HASP_NO_CACHE`, or `HASP_CACHE_TTL=0`.
- Plain HTTP proxy use for `cp`/`diff` requires `HASP_ALLOW_HTTP_PROXY=1`.
