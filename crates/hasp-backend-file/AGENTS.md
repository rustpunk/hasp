# AGENTS.md

## Purpose

`hasp-backend-file` implements the `file://` backend.

## Responsibilities

Read, write, delete, exist-check, and list file-backed secrets with explicit newline and glob behavior.

## Important Public APIs

`FileBackend`, `FileUrl`, and `impl hasp_core::Backend for FileBackend`.

## Internal Module Map

Single-file crate: `src/lib.rs` contains URL parsing, file operations, glob/list behavior, IO error mapping, and unit tests.

## Dependency Rules

Keep filesystem behavior local to this backend. Do not add profile/config logic. Coordinate any new dependencies before editing `Cargo.toml`.

## Invariants

Default read strips exactly one trailing `\n` or `\r\n`, not arbitrary whitespace. List results should be regular files with URLs that are gettable. Symlink traversal behavior is security-sensitive.

## Common Mistakes

Do not use broad `trim()`. Do not follow symlinks by default. Do not emit list entries that `get` cannot read.

## Local Commands

```bash
cargo test -p hasp-backend-file
```

## Documentation Updates

Update backend README, `docs/src/backends.md`, `docs/src/quickstart.md`, and `doc/ai/40_COMMON_PATTERNS.md` if file grammar or newline behavior changes.

## Unclear / Ask Human

Ask before changing glob semantics, symlink policy, or newline trimming.

## Evidence

`crates/hasp-backend-file/src/lib.rs`, `crates/hasp-backend-file/tests/file_backend_tests.rs`.
