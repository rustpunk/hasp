# RESEARCH-failure-modes — hasp credential pipeline negative results

Failure-mode / CVE research for decisions on zeroize discipline, keyring integration,
file-trim policy, and error taxonomy. All claims cite a fetched URL.

Date: 2026-04-26

---

## D1 — zeroize / secrecy failure modes

### RUSTSEC-2021-0115 / CVE-2021-45706 — `#[zeroize(drop)]` silently does nothing on enums

- **What failed:** The `zeroize_derive` proc-macro did not emit a `Drop` impl when
  `#[zeroize(drop)]` was applied to an `enum`. The annotation compiled without error but
  was a no-op, so memory was never cleared on drop.
- **Context:** All versions of `zeroize_derive` < 1.1.1.
- **Why:** The codegen path for enums was simply missing. Structs worked; enums did not.
- **Fix:** zeroize_derive 1.2 (also tracked as GHSA-c5hx-w945-j4pq).
- **hasp implication:** Any `enum` type that wraps a secret and derives `ZeroizeOnDrop`
  must be on zeroize >= 1.2. Audit transitive deps — it is easy to pull in an older
  pin through a crypto crate.
- URL: <https://rustsec.org/advisories/RUSTSEC-2021-0115.html>

---

### RUSTSEC-2024-0342 / CVE-2024-34063 — zeroization silently disabled by a feature-flag change in a transitive dep

- **What failed:** vodozemac 0.5.0–0.5.1 (a Matrix E2EE crypto library) stopped
  zeroizing secrets at all. Encryption keys lingered in heap after `drop`.
- **Why:** The Dalek crates (curve25519-dalek, etc.) moved their `zeroize` integration
  behind a non-default Cargo feature. vodozemac's dependency declaration disabled default
  features, so the zeroize hook was silently dropped — no compile error, no warning.
  The practical effect is more in-memory copies of session keys and longer residue windows.
- **Context:** This is the canonical real-world example of the "feature-flag stripping
  zeroize from a transitive dep" failure class.
- **Fix:** vodozemac 0.6.0 re-enables the feature.
- **hasp implication:** When adding any crypto dep with `default-features = false`,
  verify that the dep's `zeroize` feature (if any) is explicitly enabled. Cargo audit
  alone will not catch this — it requires reading the upstream CHANGELOG.
- URL: <https://rustsec.org/advisories/RUSTSEC-2024-0342.html>
- Advisory: <https://github.com/advisories/GHSA-c3hm-hxwf-g5c6>

---

### Stack-copy residue — zeroize zeroes only the *last* memory location of a moved value

- **What failed:** A struct containing a key implements `Drop` → `zeroize()`. The data
  is non-zero at three distinct stack addresses during its lifetime (function return,
  intermediate assignment, final drop site). Only the drop site is cleared; earlier
  addresses retain the secret indefinitely until stack frame reuse.
- **Why:** Rust move semantics compile to `memcpy` in the general case. Every move is a
  new copy at a new address. `Drop` fires once, at the final address. This is not a
  compiler bug — it is a property of the abstract machine.
- **Fix:** Heap-allocate secrets via `Box<T>`. `Box` move copies the pointer metadata
  only; the underlying allocation stays at one stable address.
- **hasp implication:** `SecretString` is already `Box<String>` internally. But any
  intermediate helper that temporarily holds a raw `String` or `Vec<u8>` before
  wrapping it undoes this protection. Watch deserialization helpers, hex-decode scratch
  buffers, and format strings.
- URL: <https://benma.github.io/2020/10/16/rust-zeroize-move.html>

---

### Stack-frame residue — no language-level way to zero the call stack of a "sensitive" function

- **What failed:** Even with correct `Box`-based heap allocation, any value passed by
  value through function arguments lands on the stack as a temporary. Compiler
  fence + volatile do not guarantee the stack frame is cleared after the function
  returns; the frame is merely "available for reuse," not zeroed.
- **Context:** Rust Internals discussion at the 2020 High Assurance Cryptography
  Workshop. The problem remains open; no `#[sensitive]` RFC has landed. LLVM's
  `__attribute__((annotate("sensitive")))` machinery exists but is not exposed to Rust.
- **Fix in the interim:** Keep secret values on the heap, minimize the number of
  function boundaries they cross by value, and accept that intermediate stack residue
  is an irreducible risk of the current Rust compilation model.
- URL: <https://internals.rust-lang.org/t/annotations-for-zeroing-the-stack-of-sensitive-functions-which-deal-in-transient-secrets/11588>

---

### Compiler fence does not prevent CPU-level memory reordering

- **Context:** `zeroize` uses `core::ptr::write_volatile` + `compiler_fence(SeqCst)`.
  This prevents the *compiler* from eliding the write. It does not prevent the CPU from
  reordering reads/writes in hardware, nor does it protect against speculative execution
  side-channels.
- **Documented by:** CipherStash's assembly-level verification post.
- **hasp implication:** For threat models that include physical memory access or
  side-channel attacks, zeroize is a mitigation, not a guarantee. The zeroize README
  says the same; the risk is that consumers read "zeroed" as a hard guarantee.
- URL: <https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd>

---

### `serde` deserialization creates an intermediate `String` before `SecretString` wraps it

- **What fails:** When deserializing a config file into a struct that contains a
  `SecretString`, the serde `String` deserializer allocates an ordinary `String` (no
  zeroize on drop) which the serde machinery hands off to `SecretString::from()`. The
  original allocation is freed by the normal `String` drop — which does not zeroize.
  The secret value therefore exists briefly in a non-zeroizing allocation.
- **Evidence:** The `secrecy` crate forum discussion acknowledges this; the crate does
  not claim to solve the intermediate-copy problem, only to prevent accidental
  `Display`/`Debug` exposure.
- **Context:** This applies to any format that goes through a `String` intermediate:
  JSON, TOML, YAML, env-var parsing via `std::env::var()` (which returns `String`).
- **hasp implication:** The intermediate copy is irreducible given the current serde
  API. The posture: document the limitation, wrap at the earliest possible boundary
  (immediately on `env::var()` return, immediately on config-file read), and do not
  attempt to layer additional zeroize calls on the already-freed intermediate.
- URL: <https://users.rust-lang.org/t/secrecy-crate-serialize-string/112263>

---

### `#[derive(Debug)]` on structs containing secrets leaks values into panic backtraces and logs

- **What fails:** A struct that wraps a secret and derives `Debug` will print the secret
  value in any panic message that formats the struct, in `RUST_LOG=debug` output, in
  `RUST_BACKTRACE=full` output, and in `anyhow`/`thiserror` error chains that include
  the struct.
- **Why:** `derive(Debug)` dumps all fields. There is no `#[debug(skip)]` in the derive
  macro stdlib (unlike `#[serde(skip)]`).
- **Fix:** `secrecy::Secret<T>` implements `Debug` as `Secret([REDACTED])`. Never apply
  `#[derive(Debug)]` to a custom type that holds a raw secret value; implement `Debug`
  manually and redact.
- **hasp implication:** The library surface should return `Secret<…>` types, not raw
  strings. All error types that carry any context about the *value* (not just the key
  path) are suspect. Backtrace redaction: avoid including the secret payload in any
  `Error::source()` chain.
- URL: <https://docs.rs/secrecy/latest/secrecy/>

---

## D2 — keyring crate failure modes

### Headless / container DBus: no session bus → cryptic or hung calls

- **What failed:** On headless Linux servers and in Docker containers without a desktop
  session, there is no DBus session bus and no gnome-keyring-daemon or KWallet daemon.
  The keyring crate (and the underlying dbus-secret-service crate) either returns an
  opaque error (`io::Error`, connection refused) or hangs indefinitely waiting for a
  DBus socket.
- **Context:** The dbus-secret-service crate requires a session DBus to be present.
  Multiple open issues in the Python `keyring` project document the identical problem;
  the Rust crate has the same root dependency structure.
- **hasp implication:** The `keyring://` backend must return a typed, user-readable
  error when the secret service daemon is absent — not an `io::Error` wrapping a raw
  OS error number. Consider `keyring::Error::NoStorageAccess` as the expected variant
  and document that CI environments need `DBUS_SESSION_BUS_ADDRESS` set and a
  daemon running (e.g., `gnome-keyring-daemon --daemonize --components=secrets`).
- URL: <https://github.com/jaraco/keyring/issues/477>
- URL: <https://docs.rs/keyring/latest/keyring/secret_service/index.html>

---

### gnome-keyring locks after idle → next call returns stale-lock error, not the credential

- **What failed:** gnome-keyring auto-locks after a configurable idle timeout. The next
  call to read a credential returns an error indicating the keyring is locked, not the
  credential itself. This surprises long-running daemons that cached a "works" result
  at startup.
- **Context:** Documented across multiple forum threads; the Arch Linux GNOME/Keyring
  wiki page covers the locking behavior.
- **hasp implication:** The `keyring://` backend must not cache "credential found" as
  an assumption. Treat each read as a fresh operation. Wrap locking errors in a distinct
  error variant so the caller can distinguish "not found" from "found but locked."
- URL: <https://wiki.archlinux.org/title/GNOME/Keyring>

---

### KWallet / SecretService backend inference leads to wrong backend being queried

- **What failed (Python keyring, same library architecture):** When both KWallet and
  gnome-keyring are available, the library's heuristic to pick one is incorrect in
  mixed-DE environments. It queries the wrong backend, gets a "not found," and returns
  an error even though the credential exists in the other store. This was fixed in
  Python keyring via explicit priority ordering (Secret Service > KWallet).
- **hasp implication:** The Rust keyring crate has the same multi-backend priority
  issue. Do not rely on ambient detection; let users explicitly specify the backend via
  the URL scheme (e.g., `keyring+secretservice://` vs `keyring+kwallet://`).
- URL: <https://github.com/jaraco/keyring/issues/496>

---

### macOS Keychain ACL: entry written by binary at path A is inaccessible after binary moves to path B

- **What failed:** The macOS Keychain ACL ties a keychain item to the code identity
  (signing identity + path) of the process that created it. When a binary is updated
  (new path, different code signature, or unsigned), the next read triggers a macOS
  authorization dialog or silently fails with `errSecAuthFailed`.
- **Why:** Keychain performs shallow code-signature verification. It trusts the main
  executable but does not comprehensively validate the full bundle. Dylib injection
  into an unprotected binary (no Hardened Runtime) can impersonate any app that wrote
  to the Keychain.
- **Real attack:** Security researcher Wojciech Regula demonstrated four techniques for
  stealing Keychain entries, including targeting apps without Hardened Runtime and
  exploiting `com.apple.security.cs.disable-library-validation`.
- **hasp implication:** The `keyring://` backend on macOS should document that:
  (a) unsigned or ad-hoc-signed builds may need ACL migration on update;
  (b) the "Data Protection Keychain" (new API path) is preferable to the legacy
  `SecKeychainItem` path for new entries; (c) ACL mismatch will surface as an error,
  not a silent empty result.
- URL: <https://wojciechregula.blog/post/stealing-macos-apps-keychain-entries/>
- URL: <https://developer.apple.com/forums/thread/110870>

---

### Windows Credential Manager: roaming profiles can sync credentials to other machines

- **What failed:** Windows "Credential Roaming" (a Group Policy feature) syncs Credential
  Manager entries across machines joined to the same AD domain. A credential written
  on a developer workstation may appear on other machines that share the roaming profile.
  APT29 was documented exploiting this feature (credential roaming as a lateral-movement
  vector — CVE-2022-30170).
- **Context:** Mandiant/Google Cloud documented APT29 abuse of credential roaming in 2022.
- **hasp implication:** On Windows enterprise environments, credentials written via
  `keyring://` may not be machine-scoped. This is not a bug in keyring-rs; it is an
  OS policy. Document it. For machine-scoped secrets on Windows, DPAPI with
  `CRYPTPROTECT_LOCAL_MACHINE` flag is the right primitive, not Credential Manager.
- URL: <https://cloud.google.com/blog/topics/threat-intelligence/apt29-windows-credential-roaming/>
- URL: <https://attack.mitre.org/techniques/T1555/004/>

---

### keyring-rs v3 → v4 migration: the crate itself recommends against use for new apps

- **What failed:** As of v4.0.0 (April 2026), the keyring-rs README explicitly
  states "do not depend on this crate for new applications" and points to
  `keyring-core` as the forward path. This is a maintainability signal: the crate's
  API surface is unstable enough that the author is deprecating it in favor of a new
  crate.
- **hasp implication:** Do not take a hard dependency on `keyring` (hwchen) directly.
  Implement the backend against the `keyring-core` interface (or an abstraction layer
  hasp owns) so the underlying store implementation can be swapped without breaking the
  library API.
- URL: <https://github.com/hwchen/keyring-rs>

---

## D6 — file:// trim footguns

### Trailing newline changes the encryption key (smallstep/cli)

- **What failed:** `pwgen -s 64 1 > my_pass` creates a password file with a trailing
  newline. step-cli used the raw file bytes (including `\n`) as the encryption key.
  Encrypting with the file succeeded; decrypting with the "same" file on a different
  invocation failed with `x509: decryption password incorrect` because one code path
  trimmed and another did not.
- **Context:** Reproducible with any tool that sometimes trims, sometimes does not.
  The password was not corrupted — it was inconsistently interpreted.
- **hasp implication:** The `file://` backend must have a documented, consistent policy.
  The safest choice: trim exactly one trailing `\n` or `\r\n` (POSIX "text file"
  convention) and document it. Never trim arbitrary whitespace — a user might
  legitimately append a space to a password.
- URL: <https://github.com/smallstep/cli/issues/428>

---

### No-trim regression breaks S3 auth (Argo Workflows)

- **What failed:** Argo Workflows < v2.2.0 trimmed whitespace from S3 access and secret
  keys read from Kubernetes Secrets. A refactor to use a shared `argoproj/pkg/s3` helper
  dropped the trim. K8s Secrets written by `kubectl create secret` include a trailing
  newline. The result: S3 operations began failing with malformed Authorization headers
  (`AWS <ACCESSKEY>\n:SECRET`).
- **Why:** A refactor silently removed existing normalization. The secret store (K8s)
  appended `\n`; the consumer (AWS SDK) rejected it.
- **hasp implication:** This is the mirror of the smallstep case — both "trim" and
  "don't trim" can break things depending on the consumer. The `file://` backend
  should trim one trailing newline by default and expose a `raw=true` query parameter
  for consumers that need exact bytes.
- URL: <https://github.com/argoproj/argo-workflows/issues/981>

---

### Drupal silently trims intentional trailing whitespace from passwords

- **What failed:** Drupal's password field trim strips leading and trailing whitespace
  silently. A user who intentionally sets a password with a trailing space (e.g., to
  defeat naive password-strength checkers) has the space stripped. Drupal then accepts
  login with the trimmed password, so the user never knows. The password is effectively
  weaker than set.
- **Security implication:** This is the documented case of trim being a security concern
  in the opposite direction — it can *weaken* a password by removing intentional entropy.
- **hasp implication:** For `file://` secrets, trimming trailing whitespace is usually
  correct for machine-generated secrets, but never correct for user-chosen passphrases.
  If hasp ever supports a "passphrase" semantic, trim must be opt-out.
- URL: <https://www.drupal.org/project/drupal/issues/1921576>

---

### openssl CLI: base64-decode fails without trailing newline

- **What failed:** `openssl enc -d -base64` requires the input to end with a newline.
  Scripts that pipe base64 without the trailing newline produce a truncation error or
  silently produce wrong output. This is the *opposite* footgun: a tool that requires
  the newline, breaking when trim removes it.
- **hasp implication:** The `file://` backend must not silently trim for `raw=true`
  callers. Pipe-based composition is the primary use case for hasp; always document
  what the output byte sequence is.
- URL: <https://github.com/openssl/openssl/issues/29595>

---

## D7 — error-taxonomy failure modes

### AWS SDK Rust: three levels of nesting required to match a service error variant

- **What failed:** To match on `NoSuchKey` from S3, a consumer must write:
  `SdkError::ServiceError { err: GetObjectError { kind: GetObjectErrorKind::NoSuchKey(_) } }`.
  Three levels of destructuring for what is conceptually a single discriminant.
- **Practical consequence:** Consumers write `match err.code() { Some("NoSuchKey") => … }`
  — a string comparison against an undocumented string constant. This is the
  "too coarse → string match" anti-pattern.
- **Status:** Open issue since July 2022; not resolved as of the research date.
- **hasp implication:** hasp's error type should be flat enough that a caller can write
  `hasp::Error::NotFound` without chaining into sub-variants. Wrap backend-specific
  errors at the backend boundary; do not expose SDK error hierarchies through the
  library surface.
- URL: <https://github.com/awslabs/aws-sdk-rust/issues/572>

---

### AWS SDK Rust: credential load failures surface as `DispatchFailure` or generic message, not a credential-specific variant

- **What failed:** When `AssumeRoleProvider` fails to load credentials, the error is
  `"An error occurred while loading credentials"` — a generic string with no variant
  to match on. The issue is intermittent (race-condition-adjacent), and there is no
  structured way to distinguish "credential expired," "network timeout," or "wrong
  role ARN."
- **Consequence:** Consumers must string-match on the error message or swallow all
  credential failures as a single bucket.
- **hasp implication:** Credential-load failures from any backend (AWS, Vault, keyring)
  must surface with enough structure to distinguish:
  - Not found (key doesn't exist)
  - Auth failure (credentials to the store itself are wrong)
  - Transient (network, timeout — safe to retry)
  - Permanent misconfiguration (wrong ARN, wrong region — do not retry)
- URL: <https://github.com/awslabs/aws-sdk-rust/issues/1381>

---

### AWS SDK Java v1 → v2: error class rename breaks catch blocks

- **What failed:** `AmazonClientException` became `SdkClientException` and
  `AmazonServiceException` became `AwsServiceException`. Method signatures also changed
  (`getErrorCode()` → `awsErrorDetails().errorCode()`). Any consumer that caught the
  v1 exception class or called the v1 method names stopped compiling.
- **hasp implication:** hasp's error type must be stable. Once `hasp::Error::NotFound`
  is published, renaming it or moving it behind a sub-enum is a semver-incompatible
  change. Design the taxonomy with enough headroom at 0.x to avoid forced renames at 1.0.
- URL: <https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/migration-exception-changes.html>

---

### AWS SDK: retrying `AccessDeniedException` burns quota; retrying `ThrottlingException` without backoff compounds throttling

- **What failed:** AWS SDK retry logic must distinguish:
  - `ThrottlingException` (429-class): safe to retry with exponential backoff
  - `AccessDeniedException` (403-class): retrying wastes requests and delays failure detection
  - `ProvisionedThroughputExceededException`: retry with backoff, separate from general throttle
- **Practical failure:** Projects that retry all non-5xx errors end up in a tight retry
  loop on `AccessDeniedException`, burning API quota and adding latency before the
  actual error surfaces.
- **hasp implication:** Error variants must encode retry semantics. A `RetryableError`
  wrapper or a `is_transient()` method on `hasp::Error` lets callers implement correct
  retry logic without checking error codes. Do not leave retry-vs-abort decisions to
  string matching.
- URL: <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.Errors.html>

---

### AWS SecretsManager on Lambda: extension returns `BadRequestException` with no body

- **What failed:** When using the Lambda Secrets Manager extension (port 2773), the
  extension returns HTTP 400 with `x-amzn-errortype: BadRequestException` and an empty
  body. No structured error explains *what* is malformed. Users spent significant time
  iterating on `secretId` formats (full ARN, short name) without diagnostic guidance.
- **hasp implication:** For backends that expose HTTP sub-errors, hasp must surface the
  raw sub-error code (not just "bad request") so CLI output and library callers can
  diagnose without a packet capture.
- URL: <https://github.com/awslabs/aws-sdk-rust/issues/905>

---

### Vault HCSEC-2024-18 / CVE-2024-8365: token and accessor logged in plaintext in audit device

- **What failed:** A code regression in Vault 1.17.3–1.17.4 (Community) and
  1.16.7–1.16.8 (Enterprise) removed the HMAC step that hashed client tokens and
  token accessors before writing them to audit logs. Tokens appeared in plaintext.
- **Context:** Audit device logs are frequently forwarded to SIEM systems with
  broader read access than the Vault API itself. Plaintext tokens in logs are
  immediately rotatable but the window between log creation and rotation is a
  credential exposure.
- **hasp implication:** For the `vault://` backend, token handling in debug/trace logs
  must be explicitly redacted. Never log the value of `X-Vault-Token`; log only
  whether it was present and its TTL class. This is an implementation invariant to
  enforce at the backend layer.
- URL: <https://discuss.hashicorp.com/t/hcsec-2024-18-vault-leaks-client-token-and-token-accessor-in-audit-devices/69669>

---

### Vault HCSEC-2026-07 / CVE-2026-4525: Vault forwards client token to auth plugins in header

- **What failed:** When an auth mount was configured to pass through the Authorization
  header, Vault failed to strip the client token from the forwarded header. Auth plugin
  backends received the caller's Vault token — a privilege escalation / information
  disclosure from the server routing layer.
- **Affected versions:** 0.11.2 through 1.21.4 (Community and Enterprise).
- **hasp implication:** When integrating with Vault as a backend, trust only the
  responses from Vault, not the ambient token environment inside an auth plugin.
  This advisory is server-side, but it reinforces the posture: treat Vault tokens
  as short-lived secrets with constrained scope.
- URL: <https://discuss.hashicorp.com/t/hcsec-2026-07-vault-may-expose-tokens-to-auth-plugins-due-to-incorrect-header-sanitization/77344>

---

## Cross-cutting failure modes

### argv leaks via `/proc/<pid>/cmdline` and `ps aux`

- **What failed:** Credentials passed as command-line arguments are globally readable
  via `/proc/<pid>/cmdline` on Linux for any process on the system. `ps aux` reads
  this file. The window of exposure is the process lifetime.
- **Specific tools:** `mysql --password amazingpw`, `curl -u carl:password …` both
  expose credentials this way. `mysql` and similar tools attempt to overwrite `argv`
  at startup but the overwrite is not atomic — there is a race.
- **1Password `op` CLI:** The `op run` command specifically avoids this by injecting
  secrets as environment variables to the subprocess, not as argv. The docs explicitly
  warn against passing secrets as arguments.
- **hasp implication:** The `hasp` CLI must never accept a secret value as a positional
  argument or `--value` flag. Input for `put` must come from stdin or a file path. For
  `get`, the output path (stdout) is deliberate and the caller's responsibility.
- URL: <https://smallstep.com/blog/command-line-secrets/>
- URL: <https://developer.1password.com/docs/cli/reference/commands/run/>

---

### `/proc/<pid>/environ` leaks all environment variables to any local user

- **What failed:** `/proc/<pid>/environ` is readable by any process with the same UID
  (and sometimes beyond, depending on kernel version and seccomp policy). Environment
  variables set by a parent shell and inherited by a child process are visible there.
  In containers, `docker inspect <container>` prints all env vars.
- **Practical consequence:** Any secret injected into the environment (e.g., by
  `op run`, `summon`, `direnv`) is visible to all co-tenant processes with the same UID.
- **Falco detection:** The Falco security project tracks `/proc/*/environ` reads as a
  detection rule, confirming this is an active attack vector.
- **hasp implication:** hasp's own process must not set env vars for its own sub-process
  invocations that contain secret values. The CLI `hasp get` outputs to stdout
  deliberately; the env-var injection pattern (if hasp ever supports `hasp exec …`)
  requires the same subprocess isolation as `op run`.
- URL: <https://github.com/falcosecurity/falco/issues/2192>
- URL: <https://www.nodejs-security.com/blog/do-not-use-secrets-in-environment-variables-and-here-is-how-to-do-it-better>

---

### Subprocess env var inheritance — child processes inherit all parent env vars

- **What failed:** When `op run`, `summon`, or `direnv` injects secrets into the shell
  environment, every subprocess spawned by the shell inherits all of them — including
  processes that do not need them. This violates least-privilege.
- **Summon's mitigation:** Summon injects secrets only into the target process's
  environment namespace and clears them when the process exits. It does not export to
  the calling shell.
- **direnv limitation:** direnv unloads env vars when you leave the directory, but
  while loaded, any subprocess receives them.
- **hasp implication:** If hasp gains an `exec` subcommand (out of scope per CLAUDE.md
  but worth noting), it must follow the summon pattern: inject only to the target
  process, not to the caller's shell.
- URL: <https://cyberark.github.io/summon/>
- URL: <https://developer.cyberark.com/blog/environment-variables-dont-keep-secrets-best-practices-for-plugging-application-credential-leaks/>

---

### Coredump / panic memory disclosure — secrets in heap end up on disk

- **What failed:** Two vulnerabilities in Linux core dump handlers (CVE-2025-5054 in
  Apport, CVE-2025-4598 in systemd-coredump) allowed local attackers to extract
  sensitive data from crashed processes, including password hashes from `unix_chkpwd`.
  The attack used a race condition in the dump handler's PID validation.
- **General posture:** A process that panics while holding a secret in heap (even a
  properly `Box`ed `SecretString`) will write that secret to the coredump file. POSIX
  `RLIMIT_CORE` can suppress coredumps, and `mlock` + `MADV_DONTDUMP` can exclude
  specific pages.
- **hasp implication:** For high-sensitivity deployments, document that:
  (a) `RLIMIT_CORE=0` should be set before invoking hasp in production;
  (b) future memory-locking work (if any) should use `mlock` on the secret allocation
  and `MADV_DONTDUMP` to exclude it from coredumps;
  (c) panics on the secret path should be avoided — prefer `Result` propagation.
- URL: <https://www.infosecurity-magazine.com/news/linux-vulnerabilities-expose/>
- URL: <https://linuxsecurity.com/news/security-vulnerabilities/linux-crash-dump-vulns>

---

### Cache-on-disk leaks — `~/.vault-token`, `~/.aws/cli/cache/`, `~/.config/op/`

- **What failed:** Vault CLI writes the active token to `~/.vault-token` after `vault
  login`. This file is world-readable by default in some configurations. AWS CLI caches
  assumed-role credentials to `~/.aws/cli/cache/*.json`. Both persist across sessions
  and are readable by any process with filesystem access.
- **hashicorp/vault issue #723:** Users requested control over whether the CLI writes
  to `~/.vault-token` vs. using only `VAULT_TOKEN`. The issue was opened in 2016 and
  took years to address properly via the `vault login -no-store` flag.
- **hasp implication:** hasp does not manage auth tokens (per CLAUDE.md: stateless wrt
  auth). But the `vault://` backend will read `~/.vault-token` as ambient credential.
  Document this explicitly so users know to restrict file permissions (0600) and that
  the file is where their Vault session lives.
- URL: <https://github.com/hashicorp/vault/issues/723>

---

### Log redaction miss — `RUST_LOG=trace` or error chain formatting exposes secret context

- **What failed:** Enabling `RUST_LOG=trace` in libraries that use `tracing` or `log`
  is a common debugging step. If any backend library logs request parameters at trace
  level, the secret value (or its URL + expected value) can appear in logs.
  `anyhow` error chains that include context strings (`context("fetching key: {value}")`)
  expose secrets in the formatted error.
- **hasp implication:** All hasp and backend code must follow the rule stated in
  CLAUDE.md: log the URL/key path, never the bytes. Apply this to every
  `tracing::debug!`, `log::trace!`, and `anyhow::Context` call. The error message
  for a failed fetch must say "failed to fetch keyring://prod/db-pass" not "failed to
  fetch keyring://prod/db-pass (expected: abc123)".
- URL: <https://gitguardian.com/remediation/hashicorp-vault-token>

---

*End of failure-mode research. No claims appear without a fetched URL.*
