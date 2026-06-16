# RESEARCH-cache-persistent-keyring

**Research date:** 2026-05-15
**Brief:** Implementation gate for hasp's persistent secret cache (issue #32): the on-disk encrypted-file load/save behind the `cache-persistent` Cargo feature, with the symmetric key stored in the OS keyring via `keyring-core` 1.0.
**Saved to:** `docs/internal/research/RESEARCH-cache-persistent-keyring.md`
**Cites and builds on:** `RESEARCH-op-caching.md` (esp. §Approach C "encrypted file cache" rejected as default, §6.5–§6.7 fail-closed posture); `RESEARCH-keyring-v3-vs-v4.md` (the May-2026 split; pin `keyring-core` 1.0 not `keyring` 4.x); `RESEARCH-keyring-url-grammar.md` (DBus probe references, headless container failure modes); `RESEARCH-secrets-zeroization.md` (`secrecy::SecretString` discipline, reallocation footgun); `CLAUDE.md` "library is source of truth" + "encrypted with a key sourced from an OS keystore."

---

## §1. The landscape

The decision encoded in `RESEARCH-op-caching.md` was *not* "ship no persistent cache." It was: **per-invocation in-process memoization is the default; persistent file cache is opt-in, feature-gated, and must inherit every protection the in-process cache already has.** Issue #32 implements that opt-in path. The scaffolding (`cache-persistent` Cargo feature, `PersistentPolicy` struct, `ProcessCache::new` downgrade behavior) is already in tree at `crates/hasp-core/src/cache.rs:104-147` and `crates/hasp-core/src/cache.rs:201-214`. What is missing is the actual on-disk codec and the OS-keyring key-fetching path.

The ecosystem position has been stable for two years and did not move between the April 2026 baseline and today:

- **OS-keyring-wrapped on-disk cache is the only defensible persistence pattern** (op-fast, aws-vault, envchain). The wrapping key lives in the OS keyring; the ciphertext lives at `$XDG_CACHE_HOME/hasp/cache.bin`. Co-locating the key on disk next to the ciphertext is the Doppler anti-pattern (`RESEARCH-op-caching.md` §Approach C).
- **`keyring-core` 1.0 is the only forward-supported library API.** `keyring` v4.0.0's own README says "Do not depend on this crate" ([crates.io/keyring](https://crates.io/crates/keyring)). The hasp-backend-keyring crate already uses the correct shape — `keyring-core = "1.0"` + per-platform `apple-native-keyring-store`, `windows-native-keyring-store`, `dbus-secret-service-keyring-store = { features = ["crypto-rust"] }` ([`crates/hasp-backend-keyring/Cargo.toml`](file:///home/user/hasp/crates/hasp-backend-keyring/Cargo.toml)). The cache crate must mirror this verbatim.
- **AEAD primitive: XChaCha20-Poly1305.** RustCrypto's `chacha20poly1305` crate, pure-Rust, 24-byte (192-bit) nonce, no nonce-counter durability problem. Random per-save nonce is the documented best practice for the 192-bit nonce extension ([`chacha20poly1305` on docs.rs](https://docs.rs/chacha20poly1305/), [lib.rs](https://lib.rs/crates/chacha20poly1305)).
- **MADV_WIPEONFORK has been available since Linux 4.14** (November 2017, [Linux Kernel patch](https://lore.kernel.org/linux-mm/20170811212829.29186-3-riel@redhat.com/)) — *not* 5.4 as the brief tentatively states. hasp's existing `crates/hasp-core/src/hardening.rs:278` already calls it via `libc::madvise`. The cache must call `hardening::lock_secret_pages(...)` on the decrypted plaintext buffer, not invent a parallel mechanism.

What is genuinely new for hasp: the cache module currently downgrades `Persistent` → `Process` (cache.rs:201-214), and the CLI integration (`resolve_cache_policy` at `crates/hasp-cli/src/main.rs:799`) never constructs a `Persistent` policy. Issue #32 lights up that code path end to end.

---

## §2. Approaches considered

### Approach A: `keyring-core` 1.0 single-key entry + `XChaCha20-Poly1305` + atomic-rename file (recommended)

**Used by:** op-fast (cometkim) for `op://` cache, aws-vault session-credential cache, envchain. None of these use `keyring-core` 1.0 directly (it's 4 weeks old), but the architectural shape is identical.

**How it works:**

1. **Key fetch.** At `ProcessCache::new` for `Persistent` policy: construct a `keyring_core::Entry::new(&policy.keyring_service, &policy.keyring_account)` ([keyring-rs wiki](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Core)). Try `entry.get_secret()` to read a 32-byte `Vec<u8>` symmetric key. On `Error::NoEntry`, generate 32 fresh bytes with `OsRng`, `entry.set_secret(&bytes)`, and proceed. The keyring service/account default to `"hasp"` and `"cache:{user}@{hostname}"` — already pinned in `PersistentPolicy::defaults()` ([`crates/hasp-core/src/cache.rs:127-136`](file:///home/user/hasp/crates/hasp-core/src/cache.rs)).
2. **Decrypt-on-load.** If `path` exists: read entire file (size-bounded, e.g., `policy.capacity * 16 KiB` ceiling), parse a `[version: u8 | nonce: 24 B | ciphertext+tag]` frame, call `XChaCha20Poly1305::new(&key).decrypt(&nonce, ciphertext)` ([`chacha20poly1305` docs.rs](https://docs.rs/chacha20poly1305/)). On AEAD failure (tamper, key rotation, version skew): treat as cold start, log a `cache.invalid` audit event, do **not** silently truncate the user's data unless told to.
3. **Encrypt-on-save.** Serialize the in-process Moka entries into a versioned record (CBOR via `ciborium` is the existing rustpunk default; `serde_json` with base64 is a simpler fallback). Generate a fresh 24-byte nonce with `XChaCha20Poly1305::generate_nonce(&mut OsRng)`, encrypt, write to a sibling tempfile, `fsync` the file, `persist()` to overwrite the cache, then `fsync` the directory. `tempfile::NamedTempFile::persist()` is "generally atomic on Windows and modern Linux filesystems" ([`tempfile` docs](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html)).
4. **Page residency.** Once decrypted bytes hit RAM, call `hasp_core::hardening::lock_secret_pages(&plaintext)` (only compiled with `memory-lock` feature; graceful no-op otherwise — [`crates/hasp-core/src/hardening.rs:181`](file:///home/user/hasp/crates/hasp-core/src/hardening.rs)). That helper already does `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` on Linux ([`hardening.rs:264,278`](file:///home/user/hasp/crates/hasp-core/src/hardening.rs)).

**Strengths:**
- **One platform-store crate dependency per OS, mirroring `hasp-backend-keyring`** — no new platform-detection logic needed. Reuses the proven `cfg(target_os = ...)` pattern at `crates/hasp-backend-keyring/Cargo.toml:10-17`.
- **Keyring-core's `set_secret`/`get_secret` exist precisely for non-UTF-8 binary payloads** like a 32-byte symmetric key ([keyring-core README](https://github.com/open-source-cooperative/keyring-core)) — no base64 detour, no "password is not valid UTF-8" failure mode.
- **AEAD with random nonce is collision-safe at 24 bytes.** XChaCha20-Poly1305's 192-bit nonce is purpose-built to make random nonces safe: birthday-bound collision after ~2^96 messages, which no hasp user will ever reach ([RFC 7539 / RFC 8439 baseline](https://datatracker.ietf.org/doc/html/rfc8439), [`chacha20poly1305` crate docs](https://docs.rs/chacha20poly1305/)).
- **No durable counter state.** Counter-based nonces require a fsync'd monotonically-increasing file that itself is corruption-prone; random-nonce sidesteps the entire class.
- **Pure Rust.** `chacha20poly1305` is `forbid(unsafe_code)` and integrates with `zeroize` for key material ([crate docs](https://docs.rs/chacha20poly1305/)). Aligns with rustpunk's pure-Rust default in `CLAUDE.md`.
- **Atomic-rename + fsync is the standard idiom.** No file lock needed for the common case: each writer creates its own tempfile, last-rename wins, the cache is regenerable so a clobbered concurrent write is recoverable on next save.

**Weaknesses / failure modes:**
- **Headless Linux container is the hard case.** No DBus session bus → `dbus-secret-service-keyring-store` cannot reach the Secret Service, returns `Error::NoStorageAccess(_)` or `Error::PlatformFailure(_)`. The keyring backend's existing mapper turns these into `Error::Backend { kind: Permanent, ... }` ([`crates/hasp-backend-keyring/src/lib.rs:167-176`](file:///home/user/hasp/crates/hasp-backend-keyring/src/lib.rs)). The cache code must **map these to `Error::PermissionDenied` instead**, so the existing exit-code-3 mapping at `crates/hasp-cli/src/main.rs:890` triggers (verified in §5 below).
- **macOS Keychain over SSH returns `errSecInteractionNotAllowed` (exit code 36).** Documented as a hard fail in [anthropics/claude-code#44028](https://github.com/anthropics/claude-code/issues/44028): "SSH sessions cannot access Keychain because the Security Framework requires a GUI desktop session." Same fail-closed treatment as Linux.
- **Windows non-interactive service sessions** return `ERROR_NO_SUCH_LOGON_SESSION` (0x80070520, "A specified logon session does not exist") from `CredRead` ([Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/2110103/how-to-create-windows-11-credential-with-local-com)). Same fail-closed treatment.
- **DBus single-thread requirement.** Per `dbus-secret-service-keyring-store` docs: "the underlying credential stores may not handle access from different threads reliably... be sure to have a separate thread that is used for all keyring calls." hasp's CLI is single-threaded on this path (each `hasp get` invocation is one process), so this is a non-issue for the v1 cache. **Document the constraint** for library consumers who do parallel reads.
- **Concurrent writers.** Two `hasp get` invocations racing on `save_cache()` each create a tempfile and `rename()`. The OS guarantees one wins, the other gets clobbered. **Acceptable** because the cache is regenerable from the upstream backend on next miss. Adding `fs2::FileExt::try_lock_exclusive` would serialize concurrent writes but adds a deadlock surface for marginal correctness gain.

**Rust crates:**
- `keyring-core = "1.0"` (per-workspace, already used) + per-platform stores ([`Cargo.toml:10-17`](file:///home/user/hasp/crates/hasp-backend-keyring/Cargo.toml)).
- `chacha20poly1305 = "0.10"` — pure-Rust, ~456 ns/KB symmetric encrypt class, `zeroize` integration, `AeadCore::generate_nonce` for random nonces ([`chacha20poly1305` lib.rs page](https://lib.rs/crates/chacha20poly1305)).
- `rand_core = "0.6"` (transitively via `chacha20poly1305`) for `OsRng`.
- `tempfile` (already in workspace deps as `tempfile = "3"`, [`Cargo.toml:21`](file:///home/user/hasp/Cargo.toml)) — `NamedTempFile::persist` for atomic replace.
- `ciborium` for the on-disk frame format. Not yet in workspace; alternative is `serde_json` + hex-encoded ciphertext, which adds 33% size overhead for no benefit on tiny secret payloads.

**Security implications:** Threat model matches `RESEARCH-op-caching.md` §5 worst case for OS-keyring-wrapped persistence: the entire incident class of CVE-2018-19358 (GNOME Keyring cross-app), KeySteal (macOS), Mimikatz DPAPI (Windows) applies. The defense the persistent cache adds *over* a plaintext file is the OS-keyring boundary + AEAD + page-residency hardening. The defense it does *not* add is sandboxing against same-user processes — `OS keyring is obfuscation, not sandboxing` (RESEARCH-op-caching.md §5.3). Document this verbatim alongside the feature.

**Source:** [keyring-core wiki](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Core), [`chacha20poly1305` docs.rs](https://docs.rs/chacha20poly1305/), [`tempfile::NamedTempFile`](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html), [`RESEARCH-keyring-v3-vs-v4.md`](file:///home/user/hasp/docs/internal/research/RESEARCH-keyring-v3-vs-v4.md), [`RESEARCH-op-caching.md`](file:///home/user/hasp/docs/internal/research/RESEARCH-op-caching.md) §Approach A.

---

### Approach B: Co-located keyfile (Doppler-style fallback file)

**Used by:** Doppler CLI (`--fallback`), older 1Password Connect designs.

**How it works:** Generate 32 bytes of key material at first use, write to `$XDG_CACHE_HOME/hasp/cache.key` (mode 0600), encrypt the cache with it, store both on disk side by side.

**Strengths:** Trivially works in headless containers (no DBus dependency). No platform-specific code.

**Weaknesses:**
- **The exact anti-pattern called out in `RESEARCH-op-caching.md` §Approach C:** *"Encryption key is co-located with the encrypted file in every persistent-cache design surveyed. Protection is 'operator with disk image but not running process,' not 'malicious local user.'"*
- **`OWASP Cryptographic Storage Cheat Sheet` requires the wrapping key to be sourced from an OS keystore**, not from a sibling file ([OWASP Crypto Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), already cited at RESEARCH-op-caching.md §4).
- **Inherits the `~/.aws/cli/cache/` exfil class** (RESEARCH-op-caching.md §5.1: "Every infostealer family (RedLine, Raccoon, Vidar) targets these by name").
- The `CLAUDE.md` "Secrets-handling posture" section is explicit: encryption-at-rest must inherit from an OS keystore, not a derived passphrase or sibling file.

**Reject.** Cite both `RESEARCH-op-caching.md` §Approach C and `OWASP Crypto Storage Cheat Sheet` if anyone proposes this.

---

### Approach C: `keyring` v4.0.0 meta-crate (silent fallback to file when keyring missing)

**Used by:** Nobody — the crate's README says "Do not depend on this crate" ([crates.io/keyring](https://crates.io/crates/keyring)).

**How it works:** Pull in `keyring = "4.0"`, get auto-selection of macOS Keychain / Windows / Linux Secret Service / **plus Turso encrypted-SQLite store**.

**Weaknesses:**
- Maintainer's explicit "do not depend" warning ([`RESEARCH-keyring-v3-vs-v4.md` §Approach C](file:///home/user/hasp/docs/internal/research/RESEARCH-keyring-v3-vs-v4.md)).
- Pulls Turso's `db-keystore` as an unwanted backend dependency. hasp does not want a SQLite-engine + libsql network transport sitting in the dep tree of `cache-persistent` (transitive blast radius for a 32-byte key store).
- Conflates store selection with feature gating, which is the design pathology that prompted the `keyring-rs` split in the first place.

**Reject.** Cited in `RESEARCH-keyring-v3-vs-v4.md` §Approach C.

---

### Approach D: Silent file fallback when keyring is unavailable

**Used by:** Doppler's `--fallback-only` mode, some early Vault Agent persistent-cache configurations.

**How it works:** If `entry.get_secret()` returns `Error::NoStorageAccess(_)`, generate a key file at `$XDG_CACHE_HOME/hasp/cache.fallback.key` mode 0600, proceed as Approach B.

**Weaknesses:**
- **Violates `RESEARCH-op-caching.md` §6.5–§6.7**: "*The fail-closed path must not regress to a silent file fallback... Headless-container detection that fails fast rather than silently falling back.*" The whole point of failing closed is that the user's threat-model expectation ("my secret cache is OS-keyring-encrypted") must not silently degrade to a weaker posture without a loud signal.
- **Doppler-class incident.** Cited by name in op-caching §Approach C.

**Reject.** Cite `RESEARCH-op-caching.md` §6.5–§6.7 + §Approach C. The right behavior on `Error::NoStorageAccess` is `Err(Error::PermissionDenied(...))`, surfaced to the CLI, which exits 3.

---

## §3. Benchmark data

| Operation | Cost | Source |
|---|---|---|
| `XChaCha20Poly1305::encrypt` 1 KB | ~500 ns–1 µs (ring AES-256-GCM 1 KB = 456 ns is the upper bound; ChaCha20 in pure-Rust mode is ~2× slower than hardware AES-NI but still sub-µs) | [Kerkour AEAD benchmark](https://kerkour.com/rust-symmetric-encryption-aead-benchmark), `chacha20poly1305` lib.rs page |
| `keyring_core::Entry::get_secret` (warm) Linux Secret Service | ~200 µs–2 ms | `RESEARCH-op-caching.md` §3 table |
| `keyring_core::Entry::get_secret` (warm) macOS Keychain | ~3.3 s pathological / no reliable warm-call median | `RESEARCH-keyring-v3-vs-v4.md` §benchmark; `RESEARCH-perf-data.md` |
| `keyring_core::Entry::get_secret` (warm) Windows Credential Manager | No published benchmark | — |
| `tempfile::NamedTempFile::persist` (rename + 1 fsync) | ~1 ms on local SSD; ~10 ms on a synced filesystem | [`tempfile` docs](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html), implementation observation |
| `MADV_WIPEONFORK` syscall | ~µs | `madvise(2)` man page |
| 32-byte `OsRng` draw | sub-µs | rand-core docs |

**Key facts:**
- **Per-invocation amortization:** the keyring fetch happens once per `hasp` process. For a single `hasp get`, the persistent cache pays one keyring round-trip (~1 ms on Linux, ~unknown ms on macOS warm) regardless of how many secrets are read. For batch operations the keyring cost is fully amortized.
- **Symmetric crypto is free relative to keyring access.** A 1024-entry cache at 256 bytes per entry encrypts in <1 ms total.
- **The dominating cost is the keyring fetch on macOS** when the keychain has not been recently unlocked. This is the "user-facing 3 s" failure mode the cache layer is *supposed* to amortize away — confirming caching's value proposition for `op://` and `keyring://` workloads.

**Honest gaps:** No published `keyring-core` 1.0 vs `keyring` 3.x latency comparison (v1.0 is 4 weeks old). No measured cost of `dbus-secret-service-keyring-store` first-call vs warm-call. The benchmarks assume the underlying OS keyring is unlocked; cold-boot first-unlock costs are not measured anywhere in the corpus.

---

## §4. Threat-model / standards anchors

| Source | Year | Body | Insight | URL |
|---|---|---|---|---|
| RFC 8439 (ChaCha20-Poly1305 IETF) | 2018 | IETF | Mandates 96-bit nonce per message; XChaCha20-Poly1305 extends to 192 bits via subkey derivation, making random nonces collision-safe at any realistic save volume | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) |
| OWASP Cryptographic Storage Cheat Sheet | current | OWASP | "Any on-disk cache must be encrypted with a key sourced from an OS keystore, not from a constant or a user-typed phrase" — the Approach B kill-switch | [OWASP Crypto Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) |
| NIST SP 800-88 Rev. 2 | 2024 | NIST | Sanitization scope includes cache; cryptographic-erase is valid when ciphertext is encrypted with a destroyed key. Deleting the keyring entry effectively cryptographically-erases the cache file. | [NIST SP 800-88](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) |
| FIPS 140-3 IG | 2019 (eff. 2020) | NIST | "Unprotected SSPs/CSPs" must be zeroized on eviction/shutdown. The decrypted cache buffer is an unprotected CSP; zeroize-on-drop via `SecretString` + `Arc` discipline (existing) satisfies this. | [FIPS 140-3 IG](https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf) |
| AWS Secrets Manager Agent | 2024 | AWS | 300 s default TTL / 3600 s max — the envelope `PersistentPolicy::DEFAULT_TTL` / `MAX_TTL` already encodes ([`cache.rs:119-122`](file:///home/user/hasp/crates/hasp-core/src/cache.rs)) | [AWS Secrets Manager Agent docs](https://docs.aws.amazon.com/secretsmanager/latest/userguide/secrets-manager-agent.html) |
| `madvise(2)` man page | current | kernel.org | `MADV_WIPEONFORK` available since Linux 4.14 (Nov 2017), zero-fills mapped range in child after `fork(2)`, cleared on `execve(2)`, applies only to private anonymous pages. Returns `EINVAL` on unsupported kernels (pre-4.14). | [madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html), [Ubuntu manpage](https://manpages.ubuntu.com/manpages/focal/en/man2/madvise.2.html) |
| MADV_WIPEONFORK patch | 2017 | LKML (Rik van Riel, Red Hat) | Introduced 2017-08-11, merged into 4.14. **RHEL 7 / CentOS 7 ship 3.10 → no MADV_WIPEONFORK**. RHEL 8 / 9 ship 4.18 / 5.14 → has it. | [LKML patch 2/2](https://lore.kernel.org/linux-mm/20170811212829.29186-3-riel@redhat.com/) |
| `keyring-core` wiki | 2026 | open-source-cooperative | `Entry::new(service, account)` + `set_secret(&[u8])` / `get_secret() -> Vec<u8>`. **DBus stores are not multithread-safe**: keyring access must serialize. | [keyring-rs wiki](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Core) |
| `dbus-secret-service-keyring-store` docs | 2026 | open-source-cooperative | Must enable `crypto-rust` or `crypto-openssl` feature; underlying credential stores may not handle multithread access reliably; headless container failure is documented | [crates.io/dbus-secret-service-keyring-store](https://crates.io/crates/dbus-secret-service-keyring-store) |
| `chacha20poly1305` docs | current | RustCrypto | Pure Rust `forbid(unsafe_code)`; XChaCha20-Poly1305 24-byte nonce extension; `AeadCore::generate_nonce(&mut OsRng)` is the documented random-nonce path; integrates with `zeroize` for key material | [`chacha20poly1305` lib.rs](https://lib.rs/crates/chacha20poly1305) |
| `tempfile::NamedTempFile` docs | current | Stebalien | `persist()` "atomically replaces" target on Windows and modern Linux; not durable without `sync_data()` + directory fsync; safer alternative `atomic-write-file` exists | [`tempfile` docs](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html) |
| Apple Developer Forums #44028 (claude-code) | 2026 | Apple/anthropics | macOS Keychain over SSH returns `errSecInteractionNotAllowed` exit code 36; "Security Framework requires a GUI desktop session" — confirms macOS headless detection must rely on first-call error rather than env-var probe | [claude-code#44028](https://github.com/anthropics/claude-code/issues/44028) |
| Microsoft Q&A: Credential Manager non-interactive | 2024 | Microsoft | Non-interactive Windows services receive `ERROR_NO_SUCH_LOGON_SESSION` (0x80070520) from `CredRead` | [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/2110103/how-to-create-windows-11-credential-with-local-com) |
| jaraco/keyring #477 | 2020 | Python keyring | Documents the headless Linux DBus failure pattern: `sh: 1: gnome-keyring-daemon: Operation not permitted` in containers. Reinforces "DBUS_SESSION_BUS_ADDRESS presence is necessary but not sufficient." | [jaraco/keyring#477](https://github.com/jaraco/keyring/issues/477) |

**Strongest applicable concrete guidance:**
- **OWASP Crypto Storage:** key from OS keystore, never co-located. Issue #32's design already encodes this.
- **AWS Secrets Manager Agent TTL envelope (300 s / 3600 s):** `PersistentPolicy::DEFAULT_TTL` / `MAX_TTL` already pin this at `cache.rs:119-122`.
- **RFC 8439 / XChaCha20 random-nonce safety at 192 bits:** the only correctness-critical primitive choice; random per-save nonce is the documented best practice.

**Genuine disagreements:**
1. **`MADV_WIPEONFORK` kernel-version detection.** The brief implies "Linux 5.4+." Actual availability is **Linux 4.14+** ([LKML 2017-08-11 patch](https://lore.kernel.org/linux-mm/20170811212829.29186-3-riel@redhat.com/), [`madvise(2)` man page](https://man7.org/linux/man-pages/man2/madvise.2.html)). The pre-4.14 case (RHEL 7 / CentOS 7 on 3.10) is the only real fallback case. The existing `hardening::lock_pages` at `crates/hasp-core/src/hardening.rs:278` already handles unsupported-advice by letting `madvise` return `-1`/`EINVAL` and recording `applied: false` in the `MitigationOutcome` — no special-casing needed. **The cache reuses this path; it does not invent kernel-version detection.**
2. **Atomic-rename vs explicit file-lock.** `tempfile::persist()` is documented "generally atomic on Windows and modern Linux." Adding `fs2::FileExt::try_lock_exclusive` would guarantee serialization but introduces a stale-lock recovery class. **Recommend tempfile + rename only**, accept that concurrent saves may clobber each other (cache is regenerable — that's the whole point of TTL).

---

## §5. Failure modes / CVEs to avoid

Ranked by likelihood of biting hasp specifically:

1. **Silent file fallback on keyring failure (Doppler anti-pattern).** Cited verbatim in `RESEARCH-op-caching.md` §6.5–§6.7: *"must fail closed with `PermissionDenied`."* If `keyring_core::Entry::get_secret()` returns `Error::NoStorageAccess(_)` or `Error::PlatformFailure(_)`, the cache constructor **must** return `Err(hasp::Error::PermissionDenied(...))`, which the existing CLI mapping at [`crates/hasp-cli/src/main.rs:890`](file:///home/user/hasp/crates/hasp-cli/src/main.rs) (`hasp::Error::PermissionDenied(_) => EXIT_PERMISSION_DENIED`) maps to exit code 3 ([`main.rs:290`](file:///home/user/hasp/crates/hasp-cli/src/main.rs): `pub(crate) const EXIT_PERMISSION_DENIED: i32 = 3;`). **Verified at the actual line numbers.**
2. **Headless detection by env-var alone is insufficient.** `DBUS_SESSION_BUS_ADDRESS` can be set by `dbus-launch --exit-with-session` for a transient bus that immediately tears down ([jaraco/keyring #477](https://github.com/jaraco/keyring/issues/477)). **The correct probe is the first `Entry::get_secret()` call itself** — catch the actual error rather than predict it from the environment.
3. **`keyring` v4.0.0 meta-crate.** Pulls Turso `db-keystore`, gives up runtime store selection, plus the upstream "do not depend" warning. Cited at `RESEARCH-keyring-v3-vs-v4.md` §Approach C.
4. **Co-located keyfile.** Cited at `RESEARCH-op-caching.md` §Approach C: *"Encryption key is co-located with the encrypted file in every persistent-cache design surveyed. Protection is 'operator with disk image but not running process,' not 'malicious local user.'"*
5. **Reallocation footgun on the decrypted plaintext.** `String`/`Vec` `push` past capacity copies bytes into a new allocation and frees the old one **un-zeroized** (`zeroize` crate docs). Mitigation: pre-size the decryption output buffer with `Vec::with_capacity(ciphertext.len())` ([`zeroize` docs.rs](https://docs.rs/zeroize/latest/zeroize/), cited in `RESEARCH-secrets-zeroization.md`).
6. **Counter-nonce footgun.** A nonce counter must be durably stored; if the file resets (snapshot, copy, container restart) the counter resets and nonce reuse breaks AEAD security catastrophically. **Random nonce sidesteps the entire class** — XChaCha20-Poly1305's 24 bytes were designed for exactly this trade-off (RFC 7539 / 8439).
7. **DBus single-thread requirement.** [`dbus-secret-service-keyring-store` docs](https://crates.io/crates/dbus-secret-service-keyring-store): *"if your application is using an async runtime... be sure to have a separate thread that is used for all keyring calls. Failure to use a separate thread is known to cause deadlocks."* hasp's CLI path is single-threaded; **document the constraint** for library consumers.
8. **Stale-lock from `flock`.** Adopting `fs2::FileExt::try_lock_exclusive` would mean a crashed `hasp` invocation leaves a sibling `.lock` file that the next invocation must time-out and recover from. Avoid by using tempfile + atomic rename (no lockfile, no recovery class). Cited at [`fs2` docs](https://docs.rs/fs2/latest/fs2/trait.FileExt.html).

---

## §6. Design insights for hasp

1. **The keyring fetch is the headless-detection probe.** Do not branch on `DBUS_SESSION_BUS_ADDRESS` or platform-specific env vars. The first call to `keyring_core::Entry::new(...)` + `entry.get_secret()` either succeeds (cache lights up) or fails with a typed error that the existing `crates/hasp-backend-keyring/src/lib.rs:163-222` mapper already classifies. **The cache's `PersistentPolicy` construction calls this mapper and translates its output to `Error::PermissionDenied` on `Error::Backend { kind: Permanent, ... }`.** One code path, three platforms, no env-var heuristics.

2. **Mirror `crates/hasp-backend-keyring/Cargo.toml:10-17` verbatim.** The persistent-cache module (provisional path: `crates/hasp-core/src/cache/persistent.rs` or a new `crates/hasp-cache-persistent` crate if it grows large) gets the same `cfg(target_os = ...)` block for `apple-native-keyring-store = "1.0"`, `windows-native-keyring-store = "1.0"`, `dbus-secret-service-keyring-store = { version = "1.0", features = ["crypto-rust"] }`. Add `keyring-core = "1.0"`, `chacha20poly1305 = "0.10"`, `rand_core = "0.6"`, `ciborium = "0.2"`. All under the `cache-persistent` feature.

3. **The `Persistent` → `Process` downgrade at `cache.rs:201-214` should not be removed; it should be reframed.** Today it downgrades unconditionally. After issue #32 lands, it should downgrade *only* when persistence load/save fails for non-security reasons (e.g., `$XDG_CACHE_HOME` is read-only). Security-relevant failures (keyring inaccessible) must fail closed with `PermissionDenied`, not downgrade silently. The behavioral difference is the difference between Approach D (rejected) and the recommended approach.

4. **Reuse `hardening::lock_secret_pages` for the decrypted plaintext buffer; do not invent a parallel MADV_WIPEONFORK call.** The existing helper at [`crates/hasp-core/src/hardening.rs:181-197`](file:///home/user/hasp/crates/hasp-core/src/hardening.rs) already wires `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` on Linux ([`hardening.rs:264-289`](file:///home/user/hasp/crates/hasp-core/src/hardening.rs)) and `VirtualLock` on Windows ([`hardening.rs:398-418`](file:///home/user/hasp/crates/hasp-core/src/hardening.rs)). It is gated on `feature = "memory-lock"`; the cache module should add `memory-lock` as a soft dependency (recommended-on, gracefully off). MADV_WIPEONFORK has been available since Linux 4.14 (not 5.4) so the only platform without it is RHEL 7 / CentOS 7 on kernel 3.10 — which the existing `lock_pages` already handles by recording `applied: false` and continuing.

5. **AEAD frame format: versioned, future-extensible.** A single-byte version prefix (`0x01`) + 24-byte nonce + ciphertext-with-tag. On mismatched version → cold start (regenerate, do not error). This lets us migrate to AES-GCM-SIV later if hardware-AES becomes important, without breaking compatibility for in-flight users. CBOR (`ciborium`) is the right inner-payload serializer — it's already used elsewhere in the rustpunk ecosystem (worth confirming; `serde_json` is the safe fallback).

6. **File lifecycle: tempfile + sync_data + persist + dir fsync.** No file lock. The standard idiom from [`tempfile` docs](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html): `let f = NamedTempFile::new_in(&dir)?; f.write_all(&framed)?; f.as_file_mut().sync_data()?; f.persist(&final_path)?; File::open(&dir)?.sync_all()?;`. Two concurrent writers each create their own tempfile; rename is atomic; whichever rename wins is the final state; the loser's tempfile is unlinked or replaced. Cache is regenerable, so no data is lost in the loser's case — the next miss refetches from the upstream backend.

7. **CLI integration is two lines.** `resolve_cache_policy` at [`crates/hasp-cli/src/main.rs:799-818`](file:///home/user/hasp/crates/hasp-cli/src/main.rs) currently returns `CachePolicy::Disabled` / `Process { ... }`. Add: when `HASP_CACHE_PERSIST=1` (or a `--cache-persistent` flag), return `CachePolicy::Persistent(PersistentPolicy::defaults()?.with_ttl(...))`. The `CachePolicy::Persistent` arm of `ProcessCache::new` at `cache.rs:201` then routes to the new module. The CI auto-disable at `main.rs:800` (`std::env::var_os("CI").is_some() → Disabled`) remains in force — persistent cache is **off** in CI by default for the same supply-chain reasons.

8. **Verification path before merging #32:** run the test matrix on (a) Linux desktop with Secret Service running → cache loads/saves, (b) Linux container with no DBus → `PermissionDenied`, exit 3, no fallback file written, (c) macOS GUI session → cache loads/saves, (d) macOS over SSH → `PermissionDenied`, exit 3, (e) Windows interactive user → cache loads/saves, (f) Windows non-interactive service → `PermissionDenied`, exit 3. These six cases map to the six §5 failure modes.

---

## §7. Recommendation

**Approach:** Approach A — `keyring-core` 1.0 binary-secret entry + `chacha20poly1305 = "0.10"` AEAD with per-save random 24-byte nonce + `tempfile`-atomic-rename + reuse of existing `hardening::lock_secret_pages`. Fail closed to `Error::PermissionDenied` on any keyring failure; **never** silent-fallback to a sibling keyfile.

**Confidence:** **High.** Every primitive (keyring-core API, chacha20poly1305 nonce policy, MADV_WIPEONFORK availability, atomic-rename pattern, exit-code mapping) is verified at a primary source. The one design lever with discretion — random vs counter nonce — has a clear RFC-anchored answer (random at 192 bits). The wiring into hasp's existing modules is mechanical: every required helper (`PermissionDenied`, `HardeningToken`, `lock_secret_pages`, `PersistentPolicy`) already exists in tree.

**Concrete file map for the implementer:**

| Concern | File | Existing line | New work |
|---|---|---|---|
| Persistent codec | new: `crates/hasp-core/src/cache/persistent.rs` (or break out into `crates/hasp-cache-persistent`) | — | encrypt/decrypt + load/save |
| Keyring access | inline in the new module, mirroring | `crates/hasp-backend-keyring/Cargo.toml:10-17` (per-platform deps), `crates/hasp-backend-keyring/src/lib.rs:107-161` (init pattern), `:163-222` (error mapper) | adapt error mapper to return `PermissionDenied` instead of `Backend { Permanent }` |
| Page locking | `crates/hasp-core/src/hardening.rs:181` `lock_secret_pages` | already wired | call from persistent module on the decrypted buffer |
| Cache policy enum | `crates/hasp-core/src/cache.rs:104-147` `PersistentPolicy` | scaffold present | un-downgrade the `Persistent` arm at `:201-214`, route to new module |
| CLI policy resolution | `crates/hasp-cli/src/main.rs:799-818` `resolve_cache_policy` | already returns `Disabled`/`Process` | add `HASP_CACHE_PERSIST=1` → `Persistent(...)` arm |
| Exit-code mapping | `crates/hasp-cli/src/main.rs:290` (`EXIT_PERMISSION_DENIED = 3`), `:890` (`PermissionDenied → EXIT_PERMISSION_DENIED`) | already maps | **no change** — verified |
| `hasp cache clear` | `crates/hasp-cli/src/main.rs:579-585` | clears in-process | extend to also delete `$XDG_CACHE_HOME/hasp/cache.bin` and the keyring entry |
| Workspace deps | `Cargo.toml:12-25` | `tempfile = "3"` already present | add `chacha20poly1305 = "0.10"`, `ciborium = "0.2"`, `keyring-core = "1.0"` (or per-crate) |

**Threat-model note:** This design preserves every guarantee `RESEARCH-op-caching.md` §7 made for the in-process cache, and explicitly inherits the new threat-model surface that §Approach A there flagged: cross-user-process keyring access (CVE-2018-19358, KeySteal, Mimikatz DPAPI) and disk-image / backup exfil of the ciphertext file. The user-facing documentation **must reproduce AWS Secrets Manager Agent's verbatim warning** that any same-user process can read the cache, plus a note that deleting the keyring entry cryptographically-erases the on-disk cache (NIST SP 800-88 Rev. 2 §4.5).

**Blocker that would force #32 to ship `Disabled` semantics:** none identified. The only soft risk is `keyring-core` 1.0's age — at six weeks old (released 2026-04-22) production exposure is essentially zero. Mitigation: keep the persistent module behind the `cache-persistent` Cargo feature for the 0.1.0 release; flip it on by default for 0.2.0 once `keyring-core` 1.0 has accumulated dependent crates.

**If wrong:** If `keyring-core` 1.0 exhibits a critical bug in the first six months, the swap-out is mechanical — wrap every keyring call in a single `cache::persistent::keyring` module so the underlying crate can be replaced with `keyring = "3.6.3"` (Approach A in `RESEARCH-keyring-v3-vs-v4.md`) without touching the AEAD or file layers. The boundary makes this a one-PR migration.

**Rejected alternatives:**
- **Approach B (co-located keyfile):** Doppler anti-pattern (RESEARCH-op-caching.md §Approach C); violates OWASP Crypto Storage; inherits `~/.aws/cli/cache/` exfil class.
- **Approach C (`keyring = "4"` meta-crate):** upstream "do not depend on this crate" (RESEARCH-keyring-v3-vs-v4.md §Approach C); pulls Turso into the dep tree.
- **Approach D (silent file fallback on keyring failure):** violates the fail-closed posture (RESEARCH-op-caching.md §6.5–§6.7); inherits the Doppler incident class.

---

## §8. Bibliography

| Source | Type | Relevance | URL |
|---|---|---|---|
| keyring-core wiki | Upstream doc | API shape for `Entry::new`, `set_secret`/`get_secret`, `set_default_store` | https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Core |
| keyring-core README | Upstream doc | v1.0.0 release notes, `set_secret` for binary payloads | https://github.com/open-source-cooperative/keyring-core |
| keyring-core 1.0.0 | Crate | Recommended dep (already in `hasp-backend-keyring/Cargo.toml`) | https://crates.io/crates/keyring-core |
| dbus-secret-service-keyring-store | Crate | Linux platform store; thread-safety + crypto-rust feature requirement | https://crates.io/crates/dbus-secret-service-keyring-store |
| apple-native-keyring-store | Crate | macOS platform store | https://crates.io/crates/apple-native-keyring-store |
| windows-native-keyring-store | Crate | Windows platform store | https://crates.io/crates/windows-native-keyring-store |
| keyring v4.0.0 README | Crate | "Do not depend on this crate" — confirms Approach C rejection | https://crates.io/crates/keyring |
| RFC 8439 (ChaCha20-Poly1305) | Standard | Nonce-policy baseline; 96-bit IETF nonce | https://datatracker.ietf.org/doc/html/rfc8439 |
| chacha20poly1305 (RustCrypto) | Crate | XChaCha20-Poly1305 192-bit-nonce extension, `AeadCore::generate_nonce`, pure Rust, zeroize integration | https://lib.rs/crates/chacha20poly1305 |
| chacha20poly1305 docs.rs | Docs | API surface, feature flags | https://docs.rs/chacha20poly1305/ |
| tempfile NamedTempFile docs | Crate docs | `persist()` atomicity, `sync_data` durability path | https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html |
| atomic-write-file | Crate | Alternative to tempfile::persist for stricter atomicity on Linux | https://docs.rs/atomic-write-file |
| fs2 FileExt | Crate docs | `try_lock_exclusive` — considered and rejected for the cache | https://docs.rs/fs2/latest/fs2/trait.FileExt.html |
| madvise(2) man page | Linux kernel | `MADV_WIPEONFORK` semantics + kernel-version (4.14) | https://man7.org/linux/man-pages/man2/madvise.2.html |
| MADV_WIPEONFORK LKML patch | Patch | Introduction 2017-08-11, Linux 4.14, Rik van Riel (Red Hat) | https://lore.kernel.org/linux-mm/20170811212829.29186-3-riel@redhat.com/ |
| jaraco/keyring #477 | GH issue | Headless Linux DBus failure pattern | https://github.com/jaraco/keyring/issues/477 |
| claude-code #44028 | GH issue | macOS Keychain over SSH `errSecInteractionNotAllowed` exit 36 | https://github.com/anthropics/claude-code/issues/44028 |
| Microsoft Q&A 2110103 | Vendor Q&A | Windows non-interactive service `CredRead` error 0x80070520 | https://learn.microsoft.com/en-us/answers/questions/2110103/how-to-create-windows-11-credential-with-local-com |
| OWASP Cryptographic Storage Cheat Sheet | Standard | Key-from-OS-keystore requirement; Approach B kill-switch | https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html |
| NIST SP 800-88 Rev. 2 | Standard | Cryptographic-erase via destroyed-key | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf |
| FIPS 140-3 IG | Standard | Unprotected-CSP zeroization | https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf |
| AWS Secrets Manager Agent | Vendor doc | TTL envelope (300 s / 3600 s) already encoded in `PersistentPolicy` | https://docs.aws.amazon.com/secretsmanager/latest/userguide/secrets-manager-agent.html |
| Kerkour AEAD benchmark | Benchmark | ring AES-256-GCM 1 KB = 456 ns (upper bound for ChaCha20-Poly1305 perf class) | https://kerkour.com/rust-symmetric-encryption-aead-benchmark |
| RESEARCH-op-caching.md | Internal note | §Approach A (recommended pattern), §Approach C (anti-pattern), §6.5–§6.7 (fail-closed) | `docs/internal/research/RESEARCH-op-caching.md` |
| RESEARCH-keyring-v3-vs-v4.md | Internal note | `keyring-core` 1.0 dep choice; rejects `keyring = "4"` | `docs/internal/research/RESEARCH-keyring-v3-vs-v4.md` |
| RESEARCH-keyring-url-grammar.md | Internal note | DBus probe + headless container failure | `docs/internal/research/RESEARCH-keyring-url-grammar.md` |
| RESEARCH-secrets-zeroization.md | Internal note | Reallocation footgun, secrecy::SecretString discipline | `docs/internal/research/RESEARCH-secrets-zeroization.md` |
| hasp-backend-keyring Cargo.toml | Source | Per-platform-deps pattern to mirror verbatim | `crates/hasp-backend-keyring/Cargo.toml` |
| hasp-backend-keyring src/lib.rs | Source | keyring-core wiring shape (lines 107-161), error mapper (163-222) | `crates/hasp-backend-keyring/src/lib.rs` |
| hasp-core src/cache.rs | Source | `PersistentPolicy` scaffold (104-147), `ProcessCache::new` (201-214) | `crates/hasp-core/src/cache.rs` |
| hasp-core src/hardening.rs | Source | `lock_secret_pages` (181), `MADV_WIPEONFORK` call site (278) | `crates/hasp-core/src/hardening.rs` |
| hasp-cli src/main.rs | Source | `EXIT_PERMISSION_DENIED = 3` (line 290), `PermissionDenied → EXIT_PERMISSION_DENIED` mapping (line 890), `resolve_cache_policy` (799-818), `hasp cache clear` (579-585) | `crates/hasp-cli/src/main.rs` |
