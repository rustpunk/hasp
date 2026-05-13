# Threat model and hardening for `hasp cp`

This note is the stable design artifact for the `hasp cp` feature.
It synthesizes (1) platform-hardening primitives across Linux/macOS/
Windows and (2) the prior-art / incident layer documented for
secret-handling CLIs.

`hasp cp <src-url> <dst-url>` copies a secret value from one backend
to another in a single invocation. It is the only verb that reads and
writes a secret in the same process, which widens the in-process
exposure window compared with a back-to-back `get` + `put`.

The dominant historical leak vector for secret CLIs is **logs and
crash reports, not memory inspection** (Azure LeakyCLI / CVE-2023-36052,
HashiCorp Vault HCSEC-2024-18, Travis CI 2022 public-log incident).
Memory hardening is necessary but not sufficient; redaction-by-type at
every emission site is the higher-leverage control. The mitigations
below cover both layers.

## Assets

- The plaintext secret value, in transit through `hasp`'s process
  memory between `get(src)` and `put(dst)`.
- The ambient credentials for both backends (env vars, IAM role,
  Vault token, …).
- The audit metadata about the copy (timestamps, source/destination
  schemes — not values).

## Adversaries

| Capability | Examples |
|---|---|
| Same-uid local process | Sibling user processes, malicious dev-tool extensions |
| Same-host root / admin | Compromised CI runner, malware with privilege escalation |
| Off-host MITM | Plain-http proxy, captive portal, compromised egress |
| Supply-chain attacker | Compromised dependency, typosquat, malicious release artifact |
| Operator footgun | `@prod` ↔ `@stage` swap, wrong-direction copy, default-overwrite |

## Trust boundaries

- The `hasp` binary trusts ambient credentials but does not bootstrap
  them.
- The library trusts URLs as references; it never accepts values on
  argv or env.
- The CLI trusts profile-alias resolution (per
  `RESEARCH-profile-resolver-scope.md` profile expansion is CLI-only).
- Each backend trusts its own auth source independently; `cp`
  aggregates two such trust boundaries in one process by design.

## Attack surface widened by `cp`

1. **Same process, two backends, one moment** — an attacker who
   compromises hasp mid-`cp` gets access to two backends and the
   plaintext value simultaneously. Intrinsic to the feature.
2. **Audit-trail fragmentation** — CloudTrail logs a `GetSecretValue`;
   Vault audit logs a `kv put`. To a SOC they look unrelated.
3. **Wrong-direction footgun** — argument swap → prod credentials
   written into a weaker-access store.
4. **`--verify` double-window** — opt-in second read of dst.
5. **No atomicity across backends** — mid-flight failure leaves dst
   indeterminate.

## Mitigations that landed with cp

### Process-level hardening (`hasp-core::hardening`)

Invoked once at CLI process start. Refuses to run on injection
signals; applies best-effort platform mitigations.

**Linux**
- `prctl(PR_SET_DUMPABLE, 0)` — disables ptrace-attach by same-uid
  peers, suppresses core dumps, makes `/proc/<pid>/{mem,maps,environ}`
  root-owned. Standing recommendation since the `ssh-agent` memory
  extraction PoC; HashiCorp Vault filed the same as `hashicorp/vault#4150`
  in 2018.
- `setrlimit(RLIMIT_CORE, 0)` — belt-and-braces backup.

**macOS**
- At runtime: `setrlimit(RLIMIT_CORE, 0)`.
- At build time (release pipeline, deferred backlog issue): Hardened
  Runtime + notarization with no `com.apple.security.cs.allow-dyld-
  environment-variables`, `disable-library-validation`, `allow-
  unsigned-executable-memory`, or `get-task-allow` entitlements.
  This is the cheapest big-bang macOS win — blocks
  `DYLD_INSERT_LIBRARIES`, blocks unsigned-library loading, and blocks
  `task_for_pid` from non-platform-binary peers in one entitlement
  posture.
- **Documented caveat:** ReportCrash writes `.ips` reports to
  `~/Library/Logs/DiagnosticReports/` independently of `RLIMIT_CORE`.
  No per-process kill switch exists. Mitigation = do not crash on the
  secret path; secret-side code uses `Result` propagation rather than
  `unwrap()` between `get` and `put`.

**Windows**
- `SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS |
  SEM_NOOPENFILEERRORBOX)` — suppresses the WER dialog and JIT-debugger
  invocation. Read-modify-write so inherited flags are preserved.
- `WerAddExcludedApplication(L"hasp.exe", FALSE)` — adds to the WER
  exclusion list. Writes user-registry; affects future invocations.
  The two APIs are complementary; neither alone suffices.
- `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` — blocks
  RWX and `VirtualProtect`-to-X. Safe for Rust (no JIT).
- `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)` —
  blocks AppInit_DLLs, Winsock LSPs, global hooks.
- `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` — closes
  DLL search-order hijack (MITRE T1574.001).

**Refusal modes (cross-platform)**
- `geteuid() != getuid()` → refuse. No setuid; sudo CVE-2021-3156 is
  the standing argument.
- Any of `LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`,
  `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`, `DYLD_FALLBACK_*`
  present → refuse. Hardened Runtime / `AT_SECURE` ignore most of
  these for trusted callers, but their presence in `environ`
  signals an attempt that the launching shell expected to take
  effect.

### Verb-level controls (`hasp cp`)

- **Constant-time `--verify`** via `subtle::ConstantTimeEq`. Errors
  are generic — "verify failed: source and destination differ" —
  with no length, hash, or position information.
- **Same-URL self-copy refusal** — prevents pointless version-counter
  inflation on backends that version writes (aws-sm, azure-kv,
  gcp-sm) and the degenerate case of accidentally writing a secret
  with itself.
- **`--if-exists=fail` default** — deliberately departs from Unix
  `cp`'s overwrite-by-default. Silent clobber of a production secret
  with a stage value is materially worse than a non-zero exit
  demanding `--force`.
- **`--dry-run` via `--explain`** — resolves both URLs and prints
  the plan; does not call `get` or `put`. Asserted in tests by
  checking dst non-existence after the invocation.
- **Cross-environment refusal** — when both src and dst profiles
  carry an `environment = "..."` label and they differ, refuse
  without `--yes`. Backwards compatible: absent labels disable the
  check.
- **Plain-http proxy refusal** — `cp` refuses to run when
  `HTTP_PROXY` / `HTTPS_PROXY` / `--proxy-url` resolves to an
  `http://` URL, unless `HASP_ALLOW_HTTP_PROXY=1` is set. The cp's
  doubled exposure window makes MITM cost higher than for other
  verbs.
- **Audit-event emission to stderr** — one JSON line on `cp.start`
  and one on `cp.done`. Fields: `event`, `ts`, `src_scheme`,
  `dst_scheme`, `outcome` (one of `copied` / `skipped` / `dry_run` /
  `error`), `error_kind` (stable classifier). Never includes
  values, lengths, or values-derived material.

### Logging and redaction

- `SecretString` end-to-end; no `Debug` formatting of secret values
  anywhere in the call path.
- The audit-event JSON is the only structured emission and is
  whitelist-based, not denylist-based — only the listed fields are
  ever emitted (lesson from Travis CI 2022 where naming-convention
  drift defeated a name-based denylist).
- Verbose mode (`--verbose`) prints `src` and `dst` URLs but never
  resolved values.

## Deferred work (filed as separate backlog issues)

| Item | Why deferred |
|---|---|
| `memory-lock` cargo feature with `mlock` / `MADV_DONTDUMP` / `MADV_WIPEONFORK` (Linux) / `VirtualLock` (Windows) | `RLIMIT_MEMLOCK` default is 64 KiB on stock Linux; needs careful per-platform error handling and graceful-degrade |
| macOS notarization + Hardened Runtime + Developer ID signing | Requires Apple Developer cert; ops dependency |
| Windows Authenticode signing for release binaries | Requires code-signing cert; ops dependency |
| SLSA v1.0 L2+ provenance via `actions/attest-build-provenance` | The Bitwarden CLI 2026.4.0 npm compromise is the standing argument |
| direnv-style `hasp profile allow` allow/deny + mtime tracking | Substantial UX surface; separate thread |
| Identity-drift detection (re-check `sts:GetCallerIdentity`-equivalent per `cp`) | Each backend has a different identity API; substantial implementation |
| Structured audit-log hook (writers, sinks, configurable fields) | Basic stderr JSON ships now; structured-sink crate is a separate concern |

## References

### Primitives layer

- prctl(2) — https://man7.org/linux/man-pages/man2/prctl.2.html
- PR_SET_DUMPABLE(2const) — https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html
- mlock(2) — https://man7.org/linux/man-pages/man2/mlock.2.html
- madvise(2) — https://man7.org/linux/man-pages/man2/madvise.2.html
- Apple — Hardened Runtime — https://developer.apple.com/documentation/security/hardened-runtime
- Apple — Disable library validation — https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.security.cs.disable-library-validation
- Apple — allow-dyld-environment-variables — https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables
- Eclectic Light — How macOS reports crashes — https://eclecticlight.co/2021/12/10/how-macos-reports-crashes/
- Microsoft Learn — SetProcessMitigationPolicy — https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy
- Microsoft Learn — SetErrorMode — https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode
- Microsoft Learn — VirtualLock — https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock
- rustc book — Exploit Mitigations — https://doc.rust-lang.org/rustc/exploit-mitigations.html
- ANSSI Rust secure-coding guide — https://anssi-fr.github.io/rust-guide/

### Incident layer

- CVE-2023-36052 (Azure CLI LeakyCLI) — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36052
- Orca — LeakyCLI AWS/Google follow-up — https://orca.security/resources/blog/leakycli-aws-google-cloud-command-line-tools-can-expose-sensitive-credentials-build-logs/
- HashiCorp HCSEC-2024-18 (Vault audit-device leak) — https://discuss.hashicorp.com/t/hcsec-2024-18-vault-leaks-client-token-and-token-accessor-in-audit-devices/69669
- Aqua — Travis CI public-log incident — https://blog.aquasec.com/travis-ci-security
- KeePass CVE-2023-32784 — https://nvd.nist.gov/vuln/detail/cve-2023-32784
- HashiCorp Vault #4150 — PR_SET_DUMPABLE request — https://github.com/hashicorp/vault/issues/4150
- Bitwarden CLI npm compromise — https://socket.dev/blog/bitwarden-cli-compromised
- sudo CVE-2021-3156 (Baron Samedit) — https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
- 1Password CVE-2024-42219 (IPC peer validation) — https://www.theregister.com/2024/08/08/using_1password_on_mac_patch/
- libsodium memory management — https://libsodium.gitbook.io/doc/memory_management
- OWASP Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- NIST SP 800-190 §3.4 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
- SLSA v1.0 FAQ — https://slsa.dev/spec/v1.0/faq
