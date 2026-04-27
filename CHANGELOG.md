# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CLI global flags `--quiet` / `--verbose` for controlling output noise.
- Hidden `man` subcommand generating ROFF man pages via `clap_mangen`.
- Dynamic tab-completion for `env://` URLs suggesting environment variable names.
- GitHub Actions CI pipeline testing fmt, clippy, tests, docs, and mdbook.
- GitHub Actions release pipeline building and publishing binaries for
  Linux x64, macOS x64, macOS ARM64, and Windows x64.

### Fixed

- `--quiet` now correctly suppresses `--verbose` diagnostic traces.

## [0.1.0-alpha] — 2026-04-27

### Added

- Unified `get` / `put` / `list` / `delete` / `exists` over ten secret backends.
- URL addressing: `env://`, `file://`, `keyring://`, `aws-sm://`, `aws-ssm://`,
  `vault://`, `gcp-sm://`, `azure-kv://`, `op://`, `bw://`.
- Profile aliases via `profiles.toml` (`@profile/key`) with self-key shorthand.
- Feature-gated backends so the default binary stays small and pure-Rust.
- Hidden `complete` subcommand generating AOT shell completions for bash, zsh,
  fish, and PowerShell.
- Dynamic shell completions via `clap_complete::CompleteEnv` completing URL
  schemes, profile aliases, and `file://` paths at tab-press time.
- Full mdbook user guide covering installation, quick start, concepts,
  profile aliases, backends, shell completions, CLI reference, and
  troubleshooting.
- Integration testing suite for CLI features using `env://` and `file://`
  backends only, requiring no ambient credentials.
