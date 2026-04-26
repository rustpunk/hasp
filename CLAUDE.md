# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status: name reservation only

`hasp` is published to crates.io as a `0.1.0-alpha` placeholder. `src/lib.rs` is six lines of doc comment with no implementation. Most "what does the code do" questions are premature — there is no code yet, only the design captured in `README.md`.

The crate ships in two shapes: a **library** (`hasp::…`) consumable from other Rust projects, and a **standalone CLI** (`hasp` binary) that is a thin shell over the library API. Both surfaces are first-class — design choices that help one at the expense of the other need a deliberate justification.

When asked to "add a feature" or "fix a bug", first check whether the request presupposes implementation that does not exist. If so, surface that to the user before scaffolding — the right answer is often a planning conversation, not a speculative skeleton.

## Build & test

Vanilla single-crate Cargo layout, edition 2021, MIT OR Apache-2.0:

```
cargo build                       # debug build of lib + bin
cargo build --release
cargo run -- get @prod/db-pass    # once the bin exists
cargo test --all-features
cargo test -p hasp --lib          # library-only tests
cargo doc --no-deps --open        # library API docs
cargo clippy --all-targets -- -D warnings
cargo fmt
```

`Cargo.lock` is currently git-ignored. Once the `[[bin]]` target lands, switch to committing it — the standard Cargo guidance for binary-shipping crates. `target/` and `lancedb/` stay local-only.

## Planned architecture (from README.md)

`hasp` is a unified `get` / `put` / `list` / `delete` / `exists` over multiple keyed secret stores, addressed by URL scheme. Any future code should preserve these design invariants:

- **Library is the source of truth; the CLI is a shell.** `clap`, `anyhow`, terminal colors, `process::exit`, and any other CLI-specific dependency must live behind a Cargo feature (e.g., `cli`) or in a separate `src/bin/hasp.rs` that depends only on the public library API. Library consumers must not pay for `clap`. Errors at the library surface are concrete, named types implementing `std::error::Error` — never `anyhow::Error`. The CLI may convert library errors into human strings; the library must not.
- **URL is the primary identifier.** Schemes: `keyring://`, `aws-sm://`, `aws-ssm://`, `vault://`, `gcp-sm://`, `azure-kv://`, `op://`, `bw://`, `file://`, `env://`. The CLI also accepts `@profile/key` aliases that expand to a URL via user config.
- **Feature-gated backends.** The default binary stays small and pure-Rust; cloud SDKs and OS-specific keyring code live behind Cargo features. Do not introduce a backend as an unconditional dependency.
- **Stateless wrt auth.** `hasp` assumes ambient credentials (env vars, IAM role, `~/.vault-token`) or delegates to a backend plugin. Do not add auth-bootstrap flows, token rotation, or credential storage.
- **Out of scope** (do not propose, do not stub): secret rotation, password/key generation, bulk file encryption (defer to `age`/`sops`/`cocoon`), TLS/cert lifecycle.

URL addressing intentionally parallels the sibling crate [`ferrule`](https://github.com/rustpunk/ferrule). When designing the parser, router, or scheme registry, look there first for the existing rustpunk convention before inventing a new one.

## Repo-local skills (auto-load)

`.claude/skills/` ships four skills that auto-invoke on the matching triggers:

- `comment-style` — Rust comment discipline for hasp. Prefer WHY over WHAT; short WHAT is fine when it adds precision the signature can't (units, redaction posture, secret lifetime, threat boundary). Bans ephemeral process refs (phase/wave/drill labels, internal-doc paths). Triggers on any `.rs` edit.
- `crate-vetting` — Verify a crate is actively maintained before adding to `Cargo.toml`. Triggers on any `Cargo.toml` dependency edit.
- `research-question` — Structured prior-art lookup for secret-store CLIs, Rust crates (keyring, vaultrs, aws-sdk-secretsmanager, secrecy, zeroize), cloud secret-store APIs, and threat-model references. Saves findings to `docs/internal/research/RESEARCH-<slug>.md`.
- `rustpunk-aesthetics` — Brand/visual style for any artifact (web UI, docs, diagrams) labeled as part of the rustpunk ecosystem.

These do not need to be invoked manually; they fire on the relevant triggers. Follow them.

## Secrets-handling posture (anticipatory)

Once code lands, treat every secret value as untrusted-output-grade:

- Never log secret values, even at `trace`. Log the URL/key, never the bytes.
- Wrap fetched secrets in a redacting type (`secrecy::SecretString` or equivalent) at the backend boundary. Redacted types are part of the public library API — downstream consumers must inherit the redaction posture, not reconstruct it.
- The CLI may print plaintext to stdout (that is its job — `hasp get … | …`), but it must do so only on the explicit code path that received the secret in a `Secret<…>` wrapper and unwrapped it deliberately. No general-purpose `Display` impl on secret types.
- Avoid panics on the secret path — a panic message can leak via `RUST_BACKTRACE`.
- Decisions about zeroization, memory locking, and process-image hygiene belong in a research note before implementation; do not pick a crate ad hoc.

## Working notes

Per the global convention, durable in-flight reasoning goes in `notes/` at the working tree root (human-writable scratchpad, distinct from auto-memory). Create `notes/` lazily when the first non-trivial design decision warrants it.
