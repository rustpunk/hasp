# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cache-persistent` Cargo feature now ships a real on-disk encrypted
  cache (#22a). When the feature is built in and `HASP_CACHE_TTL` is
  set, the per-invocation cache snapshot is written to
  `$XDG_CACHE_HOME/hasp/cache.bin` on the success exit path, mode
  `0o600` on Unix, atomically replaced via tempfile + rename. The
  payload is XChaCha20-Poly1305 AEAD with a 24-byte random nonce per
  save; the 32-byte symmetric key lives in the OS keyring under
  service `hasp`, account `cache:<user>` (the first `Entry::get_secret`
  doubles as the headless-container probe). Loading on `ProcessCache::new`
  drops TTL-expired entries and treats AEAD-tamper as a cold cache.
  AWS Secrets Manager Agent's verbatim threat-model warning is
  reproduced on the type doc: *"After the secret value is pulled into
  the cache, any user with access to the compute environment can
  access the secret from the cache."* Fail-closed when the OS keyring
  is unreachable: `StoreBuilder::try_build` surfaces
  `Error::PermissionDenied`, which the CLI maps to exit code 3 — no
  silent file fallback. New audit-event labels `cache.load`,
  `cache.save`, `cache.tamper_rejected`; `audit_no_leak.rs` proptest
  extended. `Backend::canonical_cache_key` (UUID-tuple keying for
  `op://` rename stability) is filed as a separate follow-up issue;
  this release uses URL-string cache keys.
- `hasp cache clear --forget-key` removes the OS-keyring entry
  holding the cache symmetric key on top of the on-disk file
  deletion. Pre-archive cleanup hook for hardened deployments.
- `Store::save_cache()` and `StoreBuilder::try_build()` public API
  surface for library consumers that want the fail-closed keyring
  contract.

### Changed

- `op://` `put` no longer carries the secret value on `op`'s argv (#27).
  The implementation now fetches the existing item via
  `op item get --format=json`, splices the new value into the matching
  field's `value`, and pipes the JSON template through stdin to
  `op item edit <item> --vault <vault> -`. The `create` branch
  (NotFound fallback) builds a minimum-viable `PASSWORD`-category
  template in-process and pipes to `op item create … -`. On Linux this
  shrinks the exposure window from "full subprocess lifetime
  (`/proc/<pid>/cmdline` is same-uid readable)" to "pipe consumption
  interval (`/proc/<pid>/fd/0` is gated by `PTRACE_MODE_READ_FSCREDS`
  and `yama.ptrace_scope`)" — the path 1Password's own docs recommend.
  Stdin support was added to `bw://` `put` from the start in #23, so
  `op://` is the only backend that changed posture. The `FakeOpGuard`
  test scaffold rejects the legacy argv shape — regressions surface
  immediately. README's "Argv exposure on `put`" section rewritten.

### Added

- `bw://` backend `put` / `delete` / `list` (#23). `put` does a
  read-modify-write against `bw edit item <uuid>` because Bitwarden's
  CLI replaces the whole item document on every edit — hasp fetches
  the existing item, splices the field at the URL's `<field-path>`,
  base64-encodes the JSON, and feeds it through **stdin** rather than
  argv. On `NotFound` it falls through to `bw create item` with a
  minimum Login (or SecureNote for `notes`) — also stdin-fed.
  `delete` is soft (Trash, recoverable for 30 days); `--permanent` is
  not exposed. `list` honors `bw://<search>` (forwarded to
  `bw list items --search`) and the sentinel host `bw://_` for an
  unfiltered listing. Entry URLs prefer the JSON `id` (UUID,
  rename-stable) over the title, matching the `op://` shape. New
  workspace dep `base64 = "0.22"` (required because `bw edit/create
  item` accept payloads only as base64-encoded JSON).
- `Backend::get_into(&self, &Url, &mut SecretString)` trait method
  (#24): sized-read extension for backends whose transport reveals
  the value length up front (file metadata, HTTP `Content-Length`,
  keyring entries). The default impl falls back to `get` and copies;
  `FileBackend` overrides to reserve exactly the byte count returned
  by `metadata.len()` so the plaintext lives in a single
  non-reallocated buffer when `?raw=true` is in play. Soft breaking
  change for downstream `Backend` impls — they inherit the default
  automatically. Companion helper
  `hasp_core::secret_mem::read_to_secret_string` exposes the same
  exact-fit discipline to backends that own their own I/O loop.
- Per-invocation in-process secret cache (`hasp_core::cache`) replacing
  the previous hand-rolled `Store`-level HashMap cache (#8 Approach E).
  Built on `moka::sync` with an eviction listener that explicitly drops
  the `Arc<SecretString>` so the inner heap buffer zeroizes on eviction.
  Construction requires a `HardeningToken` returned by
  `hasp_core::install()` — caching cannot be installed without
  `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, and env-injection refusal
  having been applied first (a hasp-specific architectural lever no
  surveyed secrets CLI has). New audit-event classifiers:
  `cache.hit` / `cache.miss` / `cache.expire` / `cache.clear`, emitted
  through the existing `AuditSink` plumbing. Closed-shape enum
  (`CacheEvent`) keeps the no-leak proptest invariant.
- `--no-cache` CLI flag, `HASP_NO_CACHE=1` env var, and automatic
  cache-disable when `$CI` is set (Granted-CLI pattern; defends
  against the warm-cache exfil class demonstrated by the
  Bitwarden CLI 2026.4.0 compromise and the Mini Shai-Hulud /
  CanisterWorm worms in May 2026).
- `Store::clear_cache()` for surgical cache invalidation; emits a
  single `cache.clear` audit event.
- `StoreBuilder::with_cache_policy(CachePolicy, HardeningToken)` —
  the explicit, architecturally correct path for installing caching.
  `cache_ttl(Option<Duration>)` remains as an ergonomic shorthand
  that lazily installs hardening via `hasp_core::install()` (silently
  disables caching on hardening refusal).
- `hasp_core::install()` returning a `HardeningToken` witness type;
  re-exported via `hasp::install_hardening`.
- `hasp cache clear` CLI subcommand. Drops every in-process cache
  entry; with the `cache-persistent` feature also removes the
  encrypted on-disk file (see the #22a entry above for the full
  shape, including `--forget-key`).
- `CachePolicy::Persistent(PersistentPolicy)` variant on
  `hasp-core` (#8 Approach A). Originally landed as a scaffold;
  the real encrypted-file implementation ships in #22a (see top of
  this release).
- `HASP_CACHE_TTL=<seconds>` env var. Overrides the default cache
  TTL (1..=3600). Values above 3600 clamp to AWS Agent's published
  1-hour ceiling; `0` disables the cache entirely.
- `op://` backend `put` / `delete` / `list` (#7). `put` issues
  `op item edit <item> --vault <vault> <field>=<value>`; on NotFound
  it falls back to `op item create --category password`. `delete`
  issues `op item delete <item> --vault <vault>` (removes the entire
  item; the URL's `field` segment is ignored on delete). `list`
  operates on the vault-only URL shape `op://<vault>` and parses
  `op item list --vault <vault> --format=json`; emitted `Entry`
  URLs prefer the JSON `id` (UUID, rename-stable) over the title.
  All three honor the existing ambient-credential check and
  subprocess timeout. Argv exposure (`/proc/<pid>/cmdline` is
  same-uid readable on Linux) is the documented residual surface
  for `put` since `op` exposes no stdin variant for field values;
  the same constraint applies to every op-based tool. Symmetric
  `bw://` write path is filed as a follow-up.

### Changed

- Default CLI behavior now memoizes fetched secrets for the lifetime
  of one invocation (5-minute TTL, 1024-entry capacity ceiling).
  This eliminates the duplicate-URL footgun across batched fetches
  (`hasp get URL URL URL` triggers one backend call). Opt out per
  invocation with `--no-cache`, per environment with
  `HASP_NO_CACHE=1`, or run in CI (auto-disabled).
- `Verb::Run` removed from the library-side `hasp_core::audit::Verb`
  enum. `run` is a CLI-only concern (subprocess env injection) and
  does not belong on the library trait surface. CLI emission of
  `run.start` / `run.done` events now goes through the new
  `AuditEvent::with_event(event: &'static str, …)` constructor,
  which preserves the closed-set / no-leak invariant via the static
  string bound. **Soft breaking change** for any downstream that
  pattern-matched on `Verb::Run`.
- `HASP_REQUIRE_PROFILE_ALLOW` default is now **on**.
  Previously opt-in (`=1` enabled), now opt-out (`=0` / `false` /
  `no` / `off` disables; `--no-profile-allow` flag continues to
  bypass per-invocation). Refusal exit code is now 6 (precondition),
  matching the verb-error mapping conventions. **Soft breaking
  change**: existing users with a `profiles.toml` must run
  `hasp profile allow` once on upgrade, or set
  `HASP_REQUIRE_PROFILE_ALLOW=0` to opt out.
- `Verb` audit-event domain is unchanged otherwise. Cache events use
  a separate closed-shape `CacheEvent` classifier (`hit` / `miss` /
  `expire` / `clear`).

### Dependencies

- `moka = "0.12"` (sync feature only). Active (2.5k stars, 1525
  commits, release 2026-03-22, MIT/Apache-2.0, used by crates.io).
  Required for the synchronous eviction listener that lets the cache
  zeroize evicted `Arc<SecretString>` entries on Drop.
- `dirs = "6"` on `hasp-core` (optional, behind `cache-persistent`).
  Resolves the default persistent-cache file path. Already a
  workspace dep elsewhere.
- `serde_json` on `hasp-backend-op` (workspace dep). Used to parse
  `op item list --format=json`.

### Follow-up issues filed for next sprint

- #22 — op:// cross-invocation persistent cache (Approach A
  implementation: encrypted file + OS-keyring-bound key +
  UUID-tuple cache keys).
- #23 — bw:// write path (symmetric to #7).
- #24 — Heap-residue mitigation via sized-read backend API.
- #25 — PTY masking for `hasp run` (deferred from #2 MVP).

- `hasp diff <a> <b>` and `Store::compare(a, b) -> DiffOutcome` for
  cross-backend drift detection (#1). Read-only sibling of `cp`: fetches
  both secrets, compares in constant time via `subtle::ConstantTimeEq`,
  returns the binary `Match` / `Differ`. Mismatch reveals nothing
  beyond the boolean — no byte counts, common prefixes, or diff
  positions. Exit codes: `0` match, `1` differ (parallels `hasp exists`);
  backend errors flow through the standard 1–7 table. Honors the same
  cross-environment refusal (`--yes`) and plain-http proxy refusal
  (`HASP_ALLOW_HTTP_PROXY=1`) as `cp`. Emits `diff.start` / `diff.done`
  audit events with `"match"` / `"differ"` / `"error"` outcomes.
  Ecosystem-novel: only possible because `hasp` has unified URL
  addressing across backends.
- `memory-lock` Cargo feature in `hasp-core` (#9). Off by default;
  opt-in by binary builders for hardened deployments. When enabled,
  every secret fetched via the `env://` or `file://` backend is
  memory-locked via `lock_secret_pages(bytes)` immediately after the
  `SecretString` wrapping boundary:
  - Linux: `mlock` + `madvise(MADV_DONTDUMP)` + `madvise(MADV_WIPEONFORK)`.
  - macOS: `mlock`.
  - Windows: `VirtualLock`.
  All calls are best-effort and never abort: `EAGAIN` (RLIMIT_MEMLOCK
  exhausted, default 64 KiB on stock Linux) returns
  `applied: false` from `MitigationOutcome` and the secret is still
  usable. The `hasp_core::secret_mem::wrap_secret` helper centralizes
  the wrap-and-lock pattern for backend implementors; `lock_secret_pages`
  is also exported directly for callers that need to lock bytes already
  in a `SecretString`. CI matrix extended with a `memory-lock` job.
  No new crate dependency — implemented via the `libc` and `windows-sys`
  deps already in the workspace.
- `hasp profile allow` + `hasp profile show` — direnv-style trust model
  for `profiles.toml` (#17). Opt-in enforcement via
  `HASP_REQUIRE_PROFILE_ALLOW=1`: when set, every `hasp` invocation
  verifies that `profiles.toml` mtime and SHA-256 match the last
  `allow`. Any modification invalidates trust until re-allowed. The
  allow state is stored in `profiles.allowed` (same directory as
  `profiles.toml`, `0o600` on Unix). `--no-profile-allow` bypasses
  enforcement for scripted environments that cannot run `allow`.
  Default is opt-in for this release; intent is to default-on in a
  subsequent release cycle.
- `hasp run -e KEY=URL [...] -- <cmd>` subprocess env injection (#2).
  Resolves each `KEY=URL` pair through `Store::get`, exports the
  values as environment variables, and execs the command, preserving
  the child's exit code verbatim. All-or-nothing: a missing secret
  short-circuits before the child is spawned. Duplicate `-e` keys are
  refused at startup. Stdout-is-TTY refusal by default prevents
  accidental echo of injected secrets to scroll buffers; bypass with
  `--allow-tty`. Emits `run.start` / `run.done` audit events.
  Threat note: `/proc/<pid>/environ` is same-uid readable on Linux —
  the fundamental cost of env injection; documented in
  `docs/src/cli-reference.md#run`. PTY masking deferred.
- `hasp_core::audit`: `AuditSink` trait + `AuditEvent` struct (#12).
  Every `Store` verb now emits `*.start` / `*.done` structured
  one-line JSON events to the configured `AuditSink`. Built-in sinks:
  `StderrSink` (default, preserves existing `cp` behavior), `FileSink`
  (append, `0600` on Unix), `SyslogSink` (Unix-only, wraps `libc`'s
  `openlog`/`syslog`/`closelog`; no new crate dependency), and
  `NoopSink` (silent). CLI sink is configured via env vars
  (`HASP_AUDIT` / `HASP_AUDIT_PATH` / `HASP_AUDIT_IDENT`) or via
  `~/.config/hasp/audit.toml` (`HASP_AUDIT_CONFIG_PATH` to override
  the path); env vars take precedence over the TOML file. The sink
  is installed at CLI startup via `StoreBuilder::with_audit_sink`.
  Security invariant: `AuditEvent` is `#[non_exhaustive]` with only
  `'static` classifier strings and a timestamp — values, lengths, and
  value-derived material cannot appear in any serialized event (a
  proptest in `crates/hasp-core/tests/audit_no_leak.rs` enforces
  this). `Error::kind() -> &'static str` added for stable audit
  classification, replacing the former CLI-only `error_kind` function.
  Threat-model note (same-uid tamperability) documented in
  `docs/src/cli-reference.md#threat-model`.
- `file://` `list` with Unix shell glob semantics (#10). The path
  component of a `file://` URL may now contain `*`, `**`, `?`, and
  `[...]` patterns; `hasp list 'file:///etc/secrets/**/*.key'` lists
  all matching regular files. Symlink traversal and dotfile inclusion
  are both off by default; opt in with `?follow_symlinks=1` and
  `?hidden=1`. Only regular files are emitted; every returned entry
  URL is `get`-able. Depends on `glob = "0.3"` (rust-lang/glob, zero
  advisories, MIT OR Apache-2.0).

### Changed

- Audit events for `cp.start` / `cp.done` are now emitted by
  `Store::copy` (library side) rather than the CLI. The wire format
  and field set are identical; the only behavioral difference is that
  library consumers using `StoreBuilder::with_audit_sink` now receive
  `cp` events for free. **Soft behavioral change:** `cp.start` now
  appears after the `--explain` plan lines instead of before (previous
  order was undocumented). Scripts parsing `cp.start` events in order
  relative to the plan lines should be updated.
- All verbs (`get`, `put`, `list`, `delete`, `exists`, `cp`) emit
  `*.start` / `*.done` audit events to stderr by default. **Soft
  breaking change:** scripts that grep stderr will now see new JSON
  lines for verbs other than `cp`. Suppress with `HASP_AUDIT=off`.

### Dependencies

- `glob = "0.3"` — Unix shell glob matching for `file://` list.
  Vetted: rust-lang/glob, zero RustSec advisories, MIT OR Apache-2.0.

- SLSA v1.0 build provenance attestations for every release artifact,
  signed via GitHub OIDC and sigstore. The release workflow now runs
  `actions/attest-build-provenance@v1` per matrix target and publishes
  the `.intoto.jsonl` bundle alongside the binary. Verification
  documented in `docs/src/installation.md` (both `gh attestation
  verify` and `slsa-verifier verify-artifact`). Defends against the
  supply-chain class demonstrated by the Bitwarden CLI 2026.4.0 npm
  compromise.
- `?field=<path>` URL query parameter on `vault://`, `aws-sm://`,
  `gcp-sm://`, and `azure-kv://` extracts a single scalar from a
  JSON-encoded secret payload before the value crosses the
  `SecretString` boundary. Supports flat keys (`password`) and dotted
  nested paths (`.credentials.api_key`). CLI sugar: `hasp get -F
  <path>`. Backed by the new `hasp_core::extract_field` / `extract_field_from_str`
  helpers, which all four backends share so the contract stays uniform.
  Vault's existing flat-field extraction is now backed by the same
  helper and gains dotted-path support.
- `Store::copy(src, dst, CopyOptions)` and the `hasp cp <src> <dst>`
  CLI subcommand for cross-backend secret migration. Defaults
  `if_exists = Fail` (refuses to clobber, opt-in via `--force` /
  `--if-exists=overwrite`), refuses cross-environment copies between
  profiles carrying mismatched `environment` labels without `--yes`,
  refuses to run through a plain-http proxy without
  `HASP_ALLOW_HTTP_PROXY=1`, supports `--verify` (constant-time
  readback compare via `subtle::ConstantTimeEq`), and `--explain`
  acts as dry-run. Emits one-line JSON audit events
  (`cp.start` / `cp.done`) to stderr with no value or length data.
- `hasp-core::hardening` module called at CLI process start. Refuses
  on injection-style env vars (`LD_PRELOAD`, `LD_AUDIT`,
  `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`,
  `DYLD_FALLBACK_*`) and `geteuid() != getuid()`. Applies best-effort
  platform mitigations:
  - Linux: `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)`.
  - macOS: `setrlimit(RLIMIT_CORE, 0)`.
  - Windows: `SetErrorMode(NOGPFAULTERRORBOX | FAILCRITICALERRORS |
    NOOPENFILEERRORBOX)`, `WerAddExcludedApplication`,
    `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)`,
    `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)`,
    `SetDefaultDllDirectories(SEARCH_SYSTEM32)`.
- `environment = "..."` field for profile entries in `profiles.toml`,
  consumed by `hasp cp` for cross-environment refusal.
- `docs/internal/research/RESEARCH-cp-threat-model.md` documenting the
  threat model, mitigations, and deferred hardening work.
- `StoreBuilder::with_retry(max_retries, base_delay)` wrapping HTTP-backed
  default backends (`aws-sm`, `aws-ssm`, `vault`, `gcp-sm`, `azure-kv`) in a
  `RetryBackend` decorator with exponential backoff + jitter for transient
  failures. Local backends (`env`, `file`, `keyring`, `op`, `bw`) are never
  wrapped.
- `Store::batch_get(urls)` and `Store::bulk_put(items)` for multi-secret
  operations with per-item error collection and URL deduplication.
- `Store::resolve(url)` for dry-run diagnostics (scheme, backend name,
  cache hit status) powering the CLI `--explain` flag.
- `hasp init` CLI subcommand generating a commented `profiles.toml` template
  in the platform config directory, with `--force` to overwrite.
- SOCKS5 proxy support alongside HTTP CONNECT in `ProxyConfig`.
- `deny.toml` workspace policy (`cargo deny check`) and `rust-toolchain.toml`
  pinning stable with rustfmt + clippy.
- `[workspace.dependencies]` table consolidating shared crate versions.
- Per-backend `README.md` files documenting URL grammar and feature flags.
- CI matrix testing `--all-features`, `default-only`, and `minimal-backends`
  to prevent `#[cfg]` rot.
- Property-based URL parsing tests (`proptest`) for scheme validation.

### Dependencies

- `subtle = "2.6"` — constant-time comparison for `--verify`.
- `libc` (Unix targets) — `prctl`, `setrlimit`, `geteuid`/`getuid`
  for the hardening module.
- `windows-sys` (Windows targets, feature-gated) — `SetErrorMode`,
  `SetProcessMitigationPolicy`, `WerAddExcludedApplication`,
  `SetDefaultDllDirectories`.

### Changed

- CLI exit codes are now granular: 0 success, 1 usage/local, 2 not-found,
  3 permission-denied, 4 transport, 5 auth-failed, 6 precondition, 7
  backend (permanent / unexpected response). `hasp exists` preserves the
  0/1 boolean (present/absent), but backend errors during `exists` flow
  through the standard table. **Soft breaking change** for scripts that
  grep on a specific non-zero exit code — every prior failure was code 1;
  now failures fan out into 1–7.
- `Backend` newtype removed in favor of `pub type Backend = Arc<dyn hasp_core::Backend>`;
  factory functions (`hasp::env()`, `hasp::file()`, etc.) replace enum
  constructors. Breaking change for `0.1.0-alpha` consumers.
- `StoreBuilder::build()` backend registration extracted into
  `register_default_backends()` helper, reducing inline `#[cfg]` churn.
- `AwsSmBackend` and `AwsSsmBackend` no longer mutate process-wide
  `HTTP(S)_PROXY` env vars; proxy config is passed at construction time.

### Fixed

- `cargo deny check` now enforced in CI with explicit `cargo-deny` 0.19.1
  installation.
- `tempfile` added to `hasp-core` dev-dependencies so `test_utils.rs`
  compiles when `test-utils` feature is disabled.

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
- CLI global flags `--quiet` / `--verbose` for controlling output noise.
- Hidden `man` subcommand generating ROFF man pages via `clap_mangen`.
- GitHub Actions CI pipeline testing fmt, clippy, tests, docs, and mdbook.
- GitHub Actions release pipeline building and publishing binaries for
  Linux x64, macOS x64, macOS ARM64, and Windows x64.

### Fixed

- `--quiet` now correctly suppresses `--verbose` diagnostic traces.
