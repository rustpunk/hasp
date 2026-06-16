# AGENTS.md

## Purpose

`hasp-cli` produces the user-facing `hasp` executable.

## Responsibilities

Owns CLI parsing, profile loading, profile allow trust, hardening startup, cache policy, audit sink selection, proxy policy, list formatting, `run`, completions, man generation, and exit-code mapping.

## Important Entry Points

`src/main.rs` `main` and command dispatch; `run::run`; `profiles::load_profiles`; `profile_allow::{profile_allow, profile_show, check_profile_allowed}`; `list_format::format_list`.

## Internal Module Map

- `main.rs`: commands, policy orchestration, store calls.
- `run.rs`: subprocess env injection.
- `profiles.rs`: aliases.
- `profile_allow.rs`: trust records.
- `audit_config.rs`: audit sink config.
- `completions.rs`: completions.
- `config_init.rs`: starter profile config.
- `list_format.rs`: list output.

## Dependency Rules

CLI-only dependencies stay here. Do not move `clap`, TOML profile loading, prompting, or process exit behavior into `hasp-core`.

## Invariants

Hardening runs before parsing. Profile allow is default-on in code/tests. Secrets print only on explicit stdout paths. Errors, audit, hints, and diagnostics must not include secret values. `run` resolves all secrets before spawn and refuses stdout TTY unless allowed.

## Common Mistakes

Do not bypass shared setup for new commands. Do not assume exit code 1 always means usage error: `exists` false and `diff` differ also use 1. Do not add a second `?field=` when `-F` is used.

## Local Commands

```bash
cargo test -p hasp-cli
cargo test -p hasp-cli --test cli_run
cargo test -p hasp-cli --test cli_cp
cargo test -p hasp-cli --test cli_diff
cargo test -p hasp-cli --test cli_profile_allow
cargo test -p hasp-cli --test cli_audit
cargo test -p hasp-cli --test cli_exit_codes
```

## Documentation Updates

Update `docs/src/cli-reference.md`, `doc/ai/50_TESTING_AND_COMMANDS.md`, and `doc/ai/30_DESIGN_RULES.md` for CLI behavior changes.

## Unclear / Ask Human

Ask before changing exit codes, profile trust defaults, proxy refusal, cache defaults, hardening behavior, or secret output policy.

## Evidence

`crates/hasp-cli/src/main.rs`, `crates/hasp-cli/tests/cli*.rs`, `docs/src/cli-reference.md`.
