# RESEARCH-op-caching

**Research date:** 2026-04-26
**Brief:** Should hasp's `op://` backend (and potentially other backends) ship an in-process secret cache? If yes, what backend, TTL, key, scope, invalidation, threat-model boundary, and library-API exposure?
**Saved to:** `docs/internal/research/RESEARCH-op-caching.md`
**Cites and builds on:** `RESEARCH-op-cli.md` §1.8 (latency baseline) and §5.10 (deferral); `RESEARCH-error-taxonomy.md` (locked Error enum); `RESEARCH-secrets-zeroization.md`; `RESEARCH-keyring-v3-vs-v4.md`; `CLAUDE.md` Secrets-handling posture.

---

## §1. The landscape

The secrets-CLI ecosystem treats value caching as a **contested optimization**, not a default. The split is sharp. **Tools that cache values** (op-fast, op-cache, dcreemer/1pass, doppler, infisical, the AWS Secrets Manager Agent, Vault Agent, Vault Proxy, 1Password Connect, Bitwarden's full-vault sync) all carry a documented incident class — stale-on-rotation reports, cache-invalidation bugs, supply-chain malware that targets `~/.aws/cli/cache/`, daemon hangs (1Password macOS Tahoe), open-vault-across-subprocesses (manchicken's 1Password disclosure). **Tools that explicitly do not cache** (chamber, summon, pass, sops, gopass, vaultrs, teller, the official AWS SDKs for Azure/GCP/SSM) defer caching to either an external sidecar (vault-agent, 1Password Connect) or to the user's own application layer. Doppler's "fallback file with no TTL by default" is the documented anti-pattern; AWS's "Secrets Manager Agent (5-min default / 1-h max TTL)" is the most defensible numerical anchor.

Across all surveyed tools, **a force-refresh flag eventually ships in every tool that caches values**. dcreemer's `1pass -r`, op-fast's `store clear`, op-cache's `clear`, aws-vault's `clear`, AWS Secrets Manager Agent's `?refreshNow=true`, Doppler's `--no-cache` and `--fallback-only`, 1Password's `--cache=false` / `OP_CACHE=false`. None of them advertise "served from cache" in `--verbose` output — the tools that hide cache hits are the same tools that get stale-secret bug reports. The "stale-rotated-secret" UX problem is **unsolved across the entire ecosystem**; only Vault Proxy's static-secret cache (Enterprise) achieves true server-push invalidation by subscribing to KV event updates.

For `op://` *specifically*, two facts dominate. First, `op read` is anomalously slow at **700 ms–2 s per call** — and the bottleneck is **local IPC to the 1Password.app desktop process** ("NM requests"), not network round-trip ([1Password community thread](https://www.1password.community/discussions/developers/op-read-is-pretty-slow-700ms-per-invocation/25907)). The native `op` `--cache` flag does not measurably reduce wall time per the same hyperfine measurements. Second, **`op` already ships its own caching daemon**: encrypted-at-rest, IPC-authenticated (NSXPCConnection on macOS, GID-checked Unix socket on Linux, Authenticode named pipe on Windows), 10-min idle / 12-h hard timeout. The op-fast (90× speedup) and op-cache (1–2 ms hits) third-party caches both beat `op`'s own cache, which means the existing daemon does not actually amortize the IPC cost — confirmed in the hyperfine numbers.

---

## §2. Approaches considered

### Approach A: OS-keyring-backed cache (op-fast model)

**Used by:** op-fast (1Password CLI accelerator), aws-vault (session-credential cache), envchain (env-var cache).

**How it works:** values are written to the OS keyring (macOS Keychain, Linux Secret Service or keyutils, Windows Credential Manager) and survive across CLI invocations. Encryption-at-rest is the OS keyring's responsibility. Metadata (TTL, timestamps, glob patterns) lives in a parallel store (op-fast uses LMDB; aws-vault uses keyring backend's metadata channel).

**Strengths:**
- Cross-invocation persistence — solves the CI fanout case (5–20 sequential `hasp get` calls = 5–40 s without cache → ~110 ms with op-fast at 22 ms × 5).
- Encrypted at rest by OS contract (macOS Keychain SEP, DPAPI on Windows, Secret Service AES-decrypt on Linux desktops).
- Published 90× speedup on the canonical `op read` workload ([op-fast README](https://github.com/cometkim/op-fast)).
- Already a Rust idiom via `keyring` v4.0.0 / `keyring-core` v1.0.0 (April 2026).

**Weaknesses / failure modes:**
- **Linux Secret Service is broken in headless containers.** No DBus session bus → keyring backend fails. Fallback to keyutils requires `pam_keyinit` to have run. CI runners (the brief's stated motivating workload) hit this silently. ([aws-vault#304](https://github.com/99designs/aws-vault/issues/304), [Debian #910822](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=910822))
- **Cross-app access on all three OS keyrings.** CVE-2018-19358 (GNOME Keyring): any app on the user's bus reads any unlocked secret. macOS KeySteal / Wojciech Reguła's four-method dylib injection class. Mimikatz `sekurlsa::dpapi` for Windows DPAPI. **OS keyring is an obfuscation layer, not a sandbox** against code running as the same user.
- **DBus-based stores are not multithread-safe** ([keyring-core wiki](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Core)) — hasp's cache layer must serialize keyring access on Linux.
- **Cache-key stability:** op-fast uses the full URL string as key; renaming an item makes the cache return the wrong value (or a stale value indefinitely). No surveyed tool resolves to UUIDs first.
- **Persistence beyond parent process is the entire incident class** documented in §6 below — manchicken's 1Password disclosure, the Bitwarden `BW_SESSION` perpetual-unlock complaints, Shai-Hulud npm worm targeting on-disk credential caches.

**Rust crates:** `keyring` v4.0.0 (active, 2026-04-26 release; major redesign with pluggable credential stores via `keyring-core` trait); `op-fast` v0.1.1 as direct reference implementation.

**Security implications:** Cached value lives outside hasp's process for hours-to-days. Threat model expands from "hasp's process memory" to "every other process running as the same user, plus any backup tool that snapshots the keyring file, plus any post-fork supply-chain payload." Inherits the entire `~/.aws/cli/cache/`-class incident history.

**Source:** [op-fast README](https://github.com/cometkim/op-fast); [aws-vault USAGE](https://github.com/99designs/aws-vault/blob/master/USAGE.md); [keyring 4.0.0](https://crates.io/crates/keyring).

### Approach B: In-RAM-only daemon (op-cache model)

**Used by:** op-cache (third-party 1Password daemon), 1Password native `op daemon`, AWS Secrets Manager Agent, Vault Agent (in-memory mode), gpg-agent, ssh-agent.

**How it works:** A long-lived background process holds decrypted (or, in the 1Password native case, encrypted-but-unlockable) secrets in RAM. CLI clients connect via Unix socket / named pipe / NSXPCConnection. Cache survives across CLI invocations; dies when the daemon dies. Cache hit latency: **1–2 ms** (op-cache), **~12 ms warm** (AWS Secrets Manager Agent).

**Strengths:**
- Lowest hit latency in the corpus.
- No on-disk persistence — eliminates the `~/.aws/cli/cache/` exfil class.
- Daemon-process isolation gives a peer-credential-checkable boundary (vs. shared OS keyring).
- 1Password native daemon design preserves vault encryption: daemon "cannot decrypt vault items — it merely passes encrypted data to the CLI via socket" ([1Password CLI app integration security](https://developer.1password.com/docs/cli/app-integration-security/)).

**Weaknesses / failure modes:**
- **Daemon is a new operational surface.** macOS Tahoe TCC dialogs hang the 1Password daemon ([openclaw#55459](https://github.com/openclaw/openclaw/issues/55459)); Nixpkgs reports stuck-state recovery requires `op signout` ([NixOS/nixpkgs#373415](https://github.com/NixOS/nixpkgs/issues/373415)).
- **CVE-2023-38408 class:** any IPC daemon authenticated by "you can reach my socket" is one forwarding mistake away from RCE. Peer-credential check via `SO_PEERCRED` + binary-hash attestation is the bar, and few daemons clear it.
- **Open-vault-across-subprocesses** is the manchicken disclosure: a parent shell that unlocked the vault leaves it open for any descendant (npm postinstall, IDE extension, malicious dev-dep). The **persistence is the vulnerability**.
- **AWS's own warning, verbatim:** *"After the secret value is pulled into the Secrets Manager Agent, any user with access to the compute environment and SSRF token can access the secret"*; *"Secret values are not encrypted in the cache."* ([AWS docs](https://docs.aws.amazon.com/secretsmanager/latest/userguide/secrets-manager-agent.html))
- **Operational complexity for a 6-line crate.** hasp shipping its own daemon is architecturally expensive for marginal returns over Approach E.

**Rust crates:** None directly applicable — building a daemon is application-level work. `tokio` + `interprocess` for the IPC layer if pursued.

**Security implications:** Cached value lives outside hasp's process indefinitely (until daemon stop). Same threat model as Approach A for "code-as-user" attackers. Adds the daemon-RCE class on top.

**Source:** [op-cache README](https://github.com/SamSaffron/op-cache); [1Password CLI app integration security](https://developer.1password.com/docs/cli/app-integration-security/); [AWS Secrets Manager Agent docs](https://docs.aws.amazon.com/secretsmanager/latest/userguide/secrets-manager-agent.html).

### Approach C: Encrypted file cache (Doppler / Vault Agent persistent cache)

**Used by:** Doppler CLI (`--fallback`), Vault Agent persistent cache (Kubernetes-only), 1Password Connect (encrypted volume).

**How it works:** Cache lives on disk as an encrypted blob. Encryption key is bound to OS-keyring entry, TPM, or in Doppler's case derived from the service token (with passphrase override).

**Strengths:**
- Survives restart / cross-invocation / offline use.
- Encrypted-at-rest defends against trivial filesystem grep.
- Vault Agent's persistent cache is the only model in the corpus that ties cache lifetime to the *credential's actual cryptographic validity* (lease-driven, not wall-clock).

**Weaknesses / failure modes:**
- **Doppler ships fallback files with no TTL by default** — they document `doppler run clean --max-age` as a workaround. This is the documented anti-pattern; copying it inherits the incident class.
- **Vault Agent's persistent-cache `persist` block currently only supports the Kubernetes backend.** General-purpose persistent caching is not supported even by HashiCorp.
- **Encryption key is co-located with the encrypted file** in every persistent-cache design surveyed. Protection is "operator with disk image but not running process," not "malicious local user."
- **NIST SP 800-88 sanitization** explicitly includes cache areas. Plaintext-on-disk inherits to every host backup, snapshot, and forensic image.
- All Approach A weaknesses (cross-invocation persistence = expanded threat model).

**Rust crates:** `age` (file encryption, ~ms decrypt for small files), `ring` AES-256-GCM (~456 ns for 1 KB), `keyring` for the wrapping key. No ready-made "encrypted file cache" crate.

**Security implications:** Strictly worse than Approach B for hasp's threat model. The on-disk persistence buys *survival across daemon crash* but pays in disk-image / backup / supply-chain exposure. Justified only if hasp ships a persistent helper service, which is out of scope.

**Source:** [Doppler Secret Fallback Files](https://docs.doppler.com/docs/automatic-fallbacks); [Vault Agent persistent caches](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/caching/persistent-caches).

### Approach D: No cache (chamber, summon, pass model)

**Used by:** chamber (Segment), summon (CyberArk), pass, gopass, sops, vaultrs, teller, the official AWS SDKs for SSM/Azure/GCP.

**How it works:** Every invocation re-fetches. Latency mitigation comes from (a) batch APIs (`GetParameters`, `BatchGetSecretValue`), (b) restructuring data into fewer, larger entries (chamber's documented advice), (c) deferring to upstream session caches that already exist (gpg-agent for pass, vault-agent for vaultrs).

**Strengths:**
- **Eliminates the entire on-disk-cache CVE class** at one stroke.
- No stale-rotated-secret bugs.
- No cache-invalidation work.
- No new IPC failure modes.
- Aligns with rustpunk's "smallest defensible surface" identity.
- For `op://` specifically: the alternative latency mitigation is **batch fetching** (single `op inject` call for N secrets) rather than caching across calls, which sidesteps every CVE class.

**Weaknesses / failure modes:**
- **CI fanout pain.** Sequential `op read` × 10 = 7–20 s. AWS SSM rate-limits at 40 TPS by default ([Parameter Store throughput](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-throughput.html)).
- chamber's documented mitigation (restructure data into larger entries) is a punt onto the user.
- For backends where the *upstream* doesn't ship a cache (`op` daemon's cache demonstrably doesn't reduce wall time; AWS SSM SDK has no client cache), users feel the latency directly.

**Rust crates:** None needed.

**Security implications:** This is the upper bound on hasp's threat model. Every secret lives only for the duration of the request. No new redaction boundary, no new CVE class.

**Source:** [chamber README](https://github.com/segmentio/chamber/blob/master/README.md); [chamber#76 latency discussion](https://github.com/segmentio/chamber/issues/76); [summon README](https://github.com/cyberark/summon/blob/main/README.md).

### Approach E: Per-invocation in-process memoization (recommended baseline)

**Used by:** Implicitly by every CLI that processes multiple URLs in a single invocation; not formally named in the surveyed prior art because it's "not a cache."

**How it works:** A `Cache<Url, Arc<SecretString>>` (moka 0.12.15 sync) lives only for the lifetime of one `hasp::Backend` instance. CLI binary creates one per invocation. Library consumers can either (a) use one per request batch, (b) hold one for the application's lifetime if they want cross-call caching at *their* layer.

**Strengths:**
- **Hit cost is sub-microsecond** ([hitbox-class numbers](https://github.com/hit-box/hitbox)). Scales to any reasonable workload.
- Eliminates the duplicate-URL-in-one-batch footgun (`for h in hosts; do hasp get @prod/db; done` would otherwise hit `op read` once per iteration).
- Cache lifetime = process lifetime. **No persistence = no on-disk-cache CVE class, no daemon, no IPC RCE class.**
- moka eviction listener fires synchronously on `Drop`, so `Arc<SecretString>` zeroize-on-last-drop semantics work cleanly.
- **No standards-recognized "cached secret" boundary needed** — the cache's lifetime is shorter than the request that fetched it, by definition.
- Library API surface stays minimal: `Backend::with_cache(Arc<Cache<…>>)` or `Default::default()`. Composes with the rest of the design.

**Weaknesses / failure modes:**
- Does not help cross-invocation CI fanout (sequential `hasp get`). For that, the user must batch-fetch in one call, or wire a longer-lived cache at the library layer themselves.
- Process-memory leak class still applies: `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0` are mandatory before populating. Heap-locality of `SecretString` (it's `Box<String>`) dodges benma 2020's move/copy/drop pitfall.

**Rust crates:**
- **moka 0.12.15** (active, 2026-03-21): canonical concurrent TTL cache. `sync::Cache<K, V>` requires `V: Clone` → use `Arc<SecretString>`. `eviction_listener(|k, v, cause| { /* explicit drop / zeroize */ })` runs synchronously in v0.12 (background threads removed). MSRV 1.71.1.
- **secrecy 0.10.3**: `SecretString = SecretBox<str>`. Does **not** implement `Clone` (no `CloneableSecret` for `String`). Use `Arc<SecretString>` for cache values.
- **zeroize 1.8.2**: `Drop` zeroizes; `Vec`/`String`/`CString` reallocation footgun documented — pre-size with `String::with_capacity(exact_len)` at backend boundary.

**Security implications:** Same threat model as Approach D plus the in-process-leak class (coredump, swap, panic backtrace). All three mitigations are mandatory and cheap:
- `prctl(PR_SET_DUMPABLE, 0)` once a cached secret is held.
- `setrlimit(RLIMIT_CORE, 0)` at startup.
- No `Display`/`Debug` impl on cache types; never `format!` a value through `expose_secret()`.

**Source:** [moka 0.12.15](https://crates.io/crates/moka); [secrecy 0.10.3](https://crates.io/crates/secrecy); [moka eviction_listener docs](https://docs.rs/moka/latest/moka/sync/struct.CacheBuilder.html); [benma — Rust move/copy/drop pitfall](https://benma.github.io/2020/10/16/rust-zeroize-move.html).

---

## §3. Benchmark data

| Backend | Cold call | Warm call (no cache) | In-process cache hit | Speedup |
|---|---|---|---|---|
| `op://` (`op read`) | **2.0 s** (op-fast hyperfine) | **700 ms** (1Password community, M3 Max) | **22.6 ms** (op-fast OS keyring) or **1–2 ms** (op-cache RAM daemon) | **90×** for op-fast |
| `aws-sm://` `GetSecretValue` | ~580 ms incl. SDK init | 100–400 ms same-region | ~12 ms warm (AWS SM Agent) or sub-µs (in-proc) | 100–1000× |
| `aws-ssm://` `GetParameter` | n/a | ~20–30 ms same-region | sub-µs | ~10000× |
| `vault://` `kv get` | n/a | **4.4 ms** mean same-DC (HashiCorp benchmark) | sub-µs | ~1000× |
| `gcp-sm://` `AccessSecretVersion` | sometimes 10 s+ | **No clean p50 published** | sub-µs | huge but unverified |
| `azure-kv://` `GetSecret` | ~10 s (token acquisition) | **<1000 ms target** (Microsoft alert threshold) | sub-µs | huge but unverified |
| `keyring://` (Linux DBus) | ~200 µs–2 ms | same | sub-µs | **100–1000× — possibly not worth caching** |

**Key facts:**
- **`op` is anomalously slow for the cloud-secret-store class** because the cost is **local desktop IPC** (`NM requests` between CLI and 1Password.app), not network. Confirmed by user CPU breakdown: ~100–125 ms user / ~40–50 ms system / **550–600 ms desktop-app IPC** ([1Password community](https://www.1password.community/discussions/developers/op-read-is-pretty-slow-700ms-per-invocation/25907)).
- **`op --cache` flag does not measurably reduce wall time** — same hyperfine measurement. The native daemon does not amortize the IPC cost.
- **Symmetric crypto for any encrypted-file cache is essentially free** at this scale: ring AES-256-GCM 1 KB = 456 ns ([Kerkour benchmark](https://kerkour.com/rust-symmetric-encryption-aead-benchmark)). For ~50 cached secrets at 1 KB, a single keyring-key open (~ms) dominates.
- **TLS handshake dominates wire time for tiny GETs.** TLS 1.3 ~50 ms at 50 ms RTT. Connection-keepalive between fetches gets cache-like effect for cloud backends without the cache CVE class.

**Honest gaps:**
- No published `moka::Cache::get` ns/op benchmark — used hitbox's adjacent crate as proxy (sub-µs to low-µs).
- No published Linux Secret Service / macOS Keychain / Windows CredRead microbenchmarks — only architectural reasoning bounded by op-fast's bundled 22.6 ms.
- No clean GCP Secret Manager / Azure Key Vault same-region p50 numbers — only pathological-case user reports.
- No published moka-with-`SecretString` memory benchmark — arithmetic gives ~50–60 KiB for 50 × 1 KiB secrets, almost certainly negligible.

---

## §4. Threat-model / standards anchors

| Source | Year | Body | Insight | URL |
|---|---|---|---|---|
| NIST SP 800-57 Part 1 Rev. 5 §6 | 2020 | NIST | Treat any in-memory copy of key material as primary; same redaction, zeroization, TTL discipline as the original. **No standard distinguishes "cached secret" from "primary secret"** — that's a hasp-internal optimization, not a standards-recognized boundary. | [NIST.SP.800-57pt1r5.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) |
| NIST SP 800-63B-4 | 2024 | NIST | At AAL2: re-authenticate after **30 min of inactivity**; mandatory full re-auth at **12 h regardless of activity**. Governs *session tokens*, not value caches; value caches fall under 800-57's stricter regime. | [NIST 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| NIST SP 800-88 Rev. 2 | 2024 | NIST | Sanitization scope explicitly includes cache areas. Cryptographic erase is acceptable when records are encrypted with a destroyed key. **Plaintext-on-disk cache files are the worst case.** | [NIST.SP.800-88r2.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) |
| FIPS 140-3 | 2019 (eff. 2020) | NIST | Mandates zeroization of unprotected SSPs / CSPs at all levels. **An in-RAM plaintext cache is an unprotected CSP.** Zeroize on eviction, TTL expiry, process shutdown, and fault. | [FIPS 140-3 IG](https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf) |
| OWASP Secrets Management Cheat Sheet §2.5, §2.7.4 | current | OWASP | "Minimize the in-memory window; zero out after use; do not use immutable strings." TTL guidance is intentionally non-numeric: *as short as practical*. | [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| OWASP Cryptographic Storage Cheat Sheet | current | OWASP | Any on-disk cache must be encrypted with a key sourced from an OS keystore, **not from a constant or a user-typed phrase.** | [OWASP Crypto Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) |
| RFC 6749 §4.2.2, §5.1 | 2012 | IETF | OAuth `expires_in` is an upper bound on any cache TTL — never cache past the token's own expiry, even if the user-configured TTL is longer. | [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) |
| PCI DSS 4.0.1 Req 3.3.1 | 2024 | PCI SSC | "Delete on use" is a stronger posture than "delete after N seconds." Sensitive Authentication Data MUST NOT be stored after authorization. | [PCI DSS 4.0.1](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf) |
| AWS Secrets Manager Agent | 2024 | AWS | **Default TTL: 300 s (5 min). Max TTL: 3600 s (1 h). TTL=0 disables.** *"Secret values are not encrypted in the cache."* The only authoritative numerical TTL anchor in the corpus. | [AWS Secrets Manager Agent docs](https://docs.aws.amazon.com/secretsmanager/latest/userguide/secrets-manager-agent.html) |
| AWS Secrets Manager Java/.NET/Python client-side caching | current | AWS | Default cache item TTL = **1 hour** for `AWSCURRENT`; **48 hours** for explicit version pins. Returns *stale* secret if synchronous refresh fails (fail-open). | [AWS client-side caching](https://docs.aws.amazon.com/secretsmanager/latest/userguide/use-client-side-caching.html) |
| Vault Agent caching | current | HashiCorp | All cache ops in memory by default; nothing persisted unless explicitly configured. Eviction on max-TTL or renewal error. **Lease-driven invalidation = the only correctness-preserving model in the corpus.** | [Vault Agent caching](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/caching) |
| 1Password CLI App Integration Security | 2025-2026 | AgileBits | `op` daemon caches encrypted entries in memory by default (UNIX-like). Authorization TTL: **10 min idle, 12 h hard.** Encrypted using same scheme as 1Password.com — daemon cannot decrypt without user-confirmed session key. **hasp adding another cache layer above this duplicates an existing protection.** | [op CLI app integration security](https://developer.1password.com/docs/cli/app-integration-security/) |
| systemd Credentials | current | systemd | Credentials mounted into tmpfs, **`mlock`-ed in RAM**, readable only by the service, auto-cleaned on stop. Inspirational reference for "cache ergonomics done right." | [systemd CREDENTIALS](https://systemd.io/CREDENTIALS/) |
| `mlock(2)` man | current | kernel.org | Locks pages in RAM, prevents swap-out. Caveat: **suspend-to-disk dumps locked pages anyway**. `RLIMIT_MEMLOCK` small by default in containers. Defense-in-depth, not a primitive. | [mlock(2)](https://www.man7.org/linux/man-pages/man2/mlock.2.html) |
| `prctl(PR_SET_DUMPABLE, 0)` | current | kernel.org | Disables core dumps and `ptrace(PTRACE_ATTACH)`. **One-line defense against `RUST_BACKTRACE=1` panic dumps and signal-driven core dumps leaking secrets.** | [PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html) |
| Halderman et al., *Lest We Remember* | 2008 | USENIX/CACM | DRAM retains contents seconds-to-minutes after power loss; cooling extends to hours. Justifies short TTL + zeroize-on-Drop on ostensibly trusted hosts. | [coldboot-cacm09.pdf](https://jhalderm.com/pub/papers/coldboot-cacm09.pdf) |

**Strongest applicable concrete guidance:** AWS Secrets Manager Agent's **5-minute default / 1-hour maximum** TTL — published, official, aimed at exactly the same threat model. Reproduce AWS's warning verbatim alongside any hasp cache: *"any user with access to the compute environment can access the secret from the cache."*

**Strongest applicable principle-level guidance:** OWASP Secrets Management Cheat Sheet §2.5 ("minimize the time window where a secret is in memory") + NIST SP 800-57 §6 ("Protection Mechanisms for Key Information in Storage"). Both are deliberately non-numeric: *as short as practical for the workload* is the floor.

**Genuine disagreements in the corpus:**
1. **Stale-on-failure vs fail-closed.** AWS client-side caching libs return the *stale* secret if refresh fails (convenience). PCI DSS 3.3.1 and a strict reading of NIST 800-57 favor fail-closed (correctness). hasp should fail closed by default; `--allow-stale` is a reasonable convenience flag but not the default.
2. **mlock recommendation.** No NIST/FIPS document mandates `mlock` for cached secret material. systemd-creds uses it; Vault Agent does not document it. **Conclusion:** best-effort with graceful degradation; do not promise it as a security primitive in user-facing docs.
3. **On-disk plaintext cache.** No standard explicitly *prohibits* it, but every standard makes it harder to defend (NIST 800-88 sanitization, OWASP Crypto Storage encryption-at-rest, FIPS 140-3 unprotected CSP). **In-RAM only by default; persistent cache is opt-in.**

---

## §5. Failure modes / CVEs to avoid

Ranked by demonstrated incident frequency:

1. **On-disk plaintext caches.** `~/.aws/cli/cache/`, `~/.aws/sso/cache/`, `~/.vault-token`, `~/.config/op/`, `BW_SESSION` env var. Every infostealer family (RedLine, Raccoon, Vidar) targets these by name. TeamTNT cryptojacking worm explicitly steals AWS credentials from disk. Open AWS bug [aws/aws-cli#6724](https://github.com/aws/aws-cli/issues/6724) — expired SSO sessions remain usable via cross-profile lookup; AWS labelled it "guidance," no fix.
2. **CI / build-pipeline secret leaks.** [CVE-2025-30066 (tj-actions/changed-files)](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction): compromised Action read `Runner.Worker` process memory and printed every secret to public logs across **23,000+ repos**. [Cacheract](https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache/): GitHub Actions cache poisoning via overwritten `action.yml` in cached tarballs.
3. **OS-keyring same-user access.** [CVE-2018-19358 (GNOME Keyring)](https://nvd.nist.gov/vuln/detail/CVE-2018-19358): any app on the user's bus reads any unlocked secret. [macOS KeySteal / dylib injection](https://wojciechregula.blog/post/stealing-macos-apps-keychain-entries/). Mimikatz `sekurlsa::dpapi` for Windows DPAPI. **OS keyring is obfuscation, not sandboxing**, against code running as the user.
4. **Long-lived IPC daemons.** [CVE-2023-38408 (ssh-agent PKCS#11 RCE via forwarding)](https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent): ~700k OpenSSH instances exposed. [manchicken's 1Password disclosure](https://codeberg.org/manchicken/1password-cli-vuln-disclosure): unlocked vault leaves itself open for any descendant subprocess. [1Password macOS CVE-2024-42218 / -42219](https://www.helpnetsecurity.com/2024/08/09/cve-2024-42219-cve-2024-42218/): IPC validation flaws.
5. **Supply-chain attacks targeting credential CLIs.** [Bitwarden CLI compromised April 2026](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html) — `@bitwarden/cli@2026.4.0` distributed via malicious npm payload (Shai-Hulud "Third Coming"). [Shai-Hulud / Shai-Hulud 2.0](https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages): npm worm that searches for `~/.aws/credentials`, GitHub PATs, npm tokens, GCP creds; >700 packages, 27,000 attacker-created repos, 14,000 secrets exposed.
6. **In-process leaks (coredump, swap, panic).** [CVE-2025-5054 (apport) and CVE-2025-4598 (systemd-coredump)](https://blog.qualys.com/vulnerabilities-threat-research/2025/05/29/qualys-tru-discovers-two-local-information-disclosure-vulnerabilities-in-apport-and-systemd-coredump-cve-2025-5054-and-cve-2025-4598): race condition lets a local attacker substitute a privileged process and capture its core. **Mitigation: `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0` before unwrapping a `SecretString`.**
7. **Rust-specific in-process traps:**
   - [zeroize crate docs](https://docs.rs/zeroize/latest/zeroize/): `Vec`/`String`/`CString` zeroize the *current* backing buffer, but **previously-reallocated buffers are not tracked.** Any `push`/`resize` past capacity has already copied bytes to a new allocation; the old one is freed but un-zeroized. Mitigation: `String::with_capacity(exact_len)` at the backend boundary.
   - [benma 2020 — Rust move/copy/drop pitfall](https://benma.github.io/2020/10/16/rust-zeroize-move.html): `Zeroize` only clears the *destination* of a move; source bytes linger until overwritten by chance. Mitigation: heap-box (`Box<SecretString>`, which `secrecy::SecretBox` already does) so the secret has a single fixed address.
   - **Tokio task cancellation:** holding an `&str` from `expose_secret()` across `.await` retains a stack reference into a buffer that may move on resume. Engineering rule: never hold an exposed-secret reference across an await.
   - [secrecy declines mlock](https://github.com/iqlusioninc/crates/issues/480): `secrecy` is `forbid(unsafe_code)`; swap-out leaks are out of scope.
8. **Stale-on-rotation bugs.** Universal across the ecosystem. [hashicorp/vault#19684](https://github.com/hashicorp/vault/issues/19684): Agent lease cache interferes with template refresh for dynamic secrets. dcreemer/1pass `-r` flag exists explicitly because users hit "I rotated and the CLI kept giving me the old value." 1Password community has multiple such threads. **Every value-caching tool that ships eventually adds a force-refresh flag.**

**Mitigations that have actually worked in practice:**
- Short token lifetime + ambient re-auth > durable cache.
- OS-keyring + per-app private collection / access groups > shared default keyring (Granted CLI's keychain integration is the cited "got it right" example for AWS SSO).
- `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0` + no env-var-passing for in-process protection.
- Peer-credential verification + binary attestation for any IPC daemon.
- **Cache scope = single process, single invocation.** Nothing that survives the parent CLI exit unless the user explicitly opted in.

---

## §6. Design insights for hasp

1. **For `op://` specifically, hasp adding a cache layer above the `op` daemon adds attack surface without adding security.** `op` already caches encrypted-at-rest in its own daemon (10-min idle / 12-h hard, IPC-authenticated, encryption preserved across the IPC boundary). The 700 ms–2 s latency is *local desktop IPC*, not network — the native cache demonstrably doesn't reduce it. Two options that *do* reduce it (op-fast OS-keyring, op-cache RAM daemon) both inherit the entire on-disk-cache or daemon-RCE CVE class. The architecturally honest answer is: **don't ship a cross-invocation cache for `op://` in v1.** Document the latency, document `op inject` for batch fetch, defer cross-invocation caching to a follow-on with explicit user demand and a defensible threat model.
2. **Per-invocation in-process memoization is essentially free correctness, and should be the baseline.** A `Cache<Url, Arc<SecretString>>` (moka 0.12.15 sync, fixed capacity, eviction listener that explicitly drops) lives only for the lifetime of one `Backend` instance. Cost: sub-µs hit. Benefit: eliminates the duplicate-URL-in-one-batch footgun. No on-disk persistence, no daemon, no IPC, no new CVE class. **This is not "a cache" in the standards sense** — its lifetime is shorter than the request that fetched it, by definition.
3. **Per-backend, not dispatch-level.** No surveyed tool ships a generic cache layer above heterogeneous backends, and every backend brings different invariants (Vault leases, AWS Secrets Manager `VersionStage` re-resolution, KV v2 non-leased nature, op rotation events). A `Cached<B: Backend>` decorator pattern — `Cached<OnePasswordBackend>` registered for `op://`, `Cached<AwsSmBackend>` for `aws-sm://` if/when added, bare `KeyringBackend` for `keyring://` (already fast enough not to need caching) — is the structurally correct fit. Aligns with the URL-scheme-keyed router design and lets each backend declare its own caching posture.
4. **Cache key resolution: URL is wrong; (vault_uuid, item_uuid, field) is correct.** op-fast uses the URL string and ignores rename. The ferrule-style URL parallel hasp wants is cache-key-friendly only if the URL is canonical and stable. For `op://`, the field path is **not stable across renames**. If hasp ever does cache values for `op://`, the cache key normalization step must resolve to UUIDs at fetch time. Zero documented prior-art adoption of this — hasp would be establishing the reference implementation.
5. **Mandatory in-process protections (cheap, must ship from day one):**
   - `prctl(PR_SET_DUMPABLE, 0)` once a `SecretString` enters process memory.
   - `setrlimit(RLIMIT_CORE, 0)` at startup.
   - `Cache<K, Arc<SecretString>>` (because `SecretString: !Clone`); eviction listener that explicitly `drop`s the `Arc`, allowing zeroize to fire when the last holder drops.
   - `String::with_capacity(exact_len)` at the backend boundary to defeat the reallocation-buffer-leak class.
   - No `Display`/`Debug` impl on cache types; no `format!` of any value through `expose_secret()`.
   - `mlock` best-effort with graceful degradation; document the caveat (RLIMIT_MEMLOCK in containers, suspend-to-disk on laptops).
6. **Library API surface stays minimal.** `Backend::with_cache(Arc<Cache<Url, Arc<SecretString>>>)` or `Default::default()`. Library consumers who want longer-lived caching at *their* layer can pass an `Arc<Cache>` they own, threaded through multiple `Backend` calls. Default is None / per-call. This composes with the "library is source of truth, CLI is shell" principle and aligns with caller-owned-`Arc<Cache>` as the modern Rust idiom (over lazy_static singletons).
7. **Cross-invocation cache (if it ever ships) is feature-gated, opt-in, and per-backend.** Mirror Vault's posture: in-RAM only by default; any persistent option encrypted with a key bound to OS keystore/TPM, file mode 0600, behind a Cargo feature with a security note that quotes AWS Agent's verbatim warning. **Default TTL 300 s, max 3600 s, TTL=0 disables, fail-closed on refresh failure.** Force-refresh flag (`hasp get --no-cache <URL>` and a `hasp cache clear` subcommand) ship from day one — every tool eventually adds one, get ahead of it.
8. **The architecturally honest answer to all eight design questions in the brief:**

   | Q | Answer |
   |---|---|
   | 1. Cache backend | **Per-invocation in-RAM (moka)** for v1. OS keyring / encrypted file are deferred until explicit user demand, and even then only feature-gated and per-backend. |
   | 2. TTL policy | **Process-lifetime** for the per-invocation cache (no TTL needed). For any future cross-invocation cache: **300 s default, 3600 s max, 0 = disabled.** Per-backend, not global. |
   | 3. Cache key | **Backend-resolved UUID tuple** wherever possible. For `op://`: `(vault_uuid, item_uuid, field)`, not the URL string. For URL-stable backends, the canonical URL is fine. |
   | 4. Cache scope | **Per-process** for v1. Per-user daemon and per-session are deferred. |
   | 5. Invalidation | **TTL + manual `hasp cache clear`**. Backend-signaled rotation eviction (e.g., Vault lease expiry) when the backend exposes it. **No rotation-detection at the dispatch layer** — that's a per-backend concern. |
   | 6. Threat model | Cached value lives only within hasp's process memory for v1. `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE = 0`, `mlock` best-effort, zeroize-on-Drop via `Arc<SecretString>` + moka eviction listener. |
   | 7. Layer | **Per-backend `Cached<B>` decorator**, not dispatch-level. Each backend decides whether caching is appropriate and what key shape to use. |
   | 8. Library exposure | **Internal-only by default.** Library API takes `Option<Arc<Cache>>` for callers who want to thread one through; CLI binary creates one per invocation. No public `Cache` trait in v1. |

---

## §7. Decision criteria (enforced)

This is a greenfield project with zero users and zero deployments. Implementation complexity, file count, breaking-change risk, and "pragmatic alternatives" are NOT valid factors. The only valid criteria are:
- Architectural correctness (unified-CLI abstraction, no backend leak into user surface)
- Threat-model soundness (secret lifetime, redaction, zeroize, no log/error/debug leaks)
- Long-term maintainability of the correct design
- Alignment with rustpunk identity (pure-Rust default, rustls-only, feature-gated backends, parallel to ferrule)

If an approach is architecturally correct but requires significant work (e.g., UUID-resolved cache keys for `op://`), that's a point in its favor, not against it. Security-sensitive code is hostile to "fix it later."

---

## §8. Recommendation

**Approach:** **E (per-invocation in-process memoization) for v1, deferred cross-invocation caching as a future opt-in.**

**Confidence:** **High.**

**Rationale:**
- For `op://` specifically, the underlying `op` daemon already caches encrypted-at-rest with a defensible TTL envelope (10-min idle / 12-h hard) and IPC peer-auth ([1Password CLI app integration security](https://developer.1password.com/docs/cli/app-integration-security/)). Adding a hasp-layer cache **above** this duplicates the encryption-at-rest property without adding it, and inherits one of the ranked-1 (`~/.aws/cli/cache/`-class) or ranked-4 (daemon-RCE) CVE classes.
- The actual `op read` latency bottleneck is **local desktop IPC**, not network — confirmed by the 1Password community hyperfine breakdown and reproduced by op-fast/op-cache speedups. The latency-mitigation lever that does NOT inherit a CVE class is **batch fetch in a single hasp invocation** (`hasp get URL1 URL2 URL3`), not cross-invocation caching.
- Per-invocation in-process memoization (moka 0.12.15 sync + `Arc<SecretString>` + `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0`) eliminates the duplicate-URL footgun with no new threat-model boundary, no on-disk persistence, no daemon, no IPC.
- The ecosystem's universal "force-refresh flag" tax confirms that every value-caching tool eventually ships one — i.e., every value-caching tool has had user-facing stale-secret bugs. Punting cross-invocation caching to a future feature-gated opt-in lets us avoid that incident class entirely in v1.

**Key risk:** CI fanout pain. Sequential `hasp get` × 10 = 7–20 s for `op://`. Mitigation: `hasp get` accepts multiple URLs and fetches them via `op inject` in a single subprocess call. Document this prominently. If real users in real CI workflows still feel pain after that, revisit cross-invocation caching as a feature-gated opt-in with the AWS Agent threat-model warning quoted verbatim.

**Threat-model note:** Per-invocation in-process memoization preserves every existing security invariant. `secrecy::SecretString` end-to-end (already planned). Zeroize-on-Drop via `Arc<SecretString>` with moka's synchronous eviction listener. Coredump suppression via `prctl(PR_SET_DUMPABLE, 0)`. No on-disk persistence. No new IPC. No new daemon. **The cache is shorter-lived than the request that fetched it.**

**If wrong:** If user demand pushes for cross-invocation caching despite the batch-fetch alternative, the next-best approach is per-backend feature-gated cache with:
- AWS Agent's TTL envelope (300 s default, 3600 s max, 0 = disabled).
- OS keyring backend, never plaintext file.
- UUID-tuple cache key for `op://` (not the URL string).
- `--no-cache` flag and `hasp cache clear` subcommand from day one.
- Verbatim threat-model warning in docs: *"any process running as the same user can read every cached secret in the keyring."*
- Headless-container detection that fails fast rather than silently falling back.

**Rejected alternatives:**
- **Approach A (OS keyring) as default:** rejected. Inherits cross-app-keyring CVE class (CVE-2018-19358, KeySteal, Mimikatz DPAPI), headless-container brittleness (aws-vault#304 history), single-threaded RPC on Linux. Still on the table as an opt-in for v2; not for v1 default.
- **Approach B (in-RAM daemon) for v1:** rejected. Daemon = new operational surface (1Password macOS Tahoe TCC hangs, Nixpkgs stuck-state reports), plus the CVE-2023-38408 class for any IPC daemon. Architecturally expensive for marginal returns over Approach E for hasp's CLI-shaped workload.
- **Approach C (encrypted file cache):** rejected. Strictly worse than B in hasp's threat model. Doppler's TTL-less fallback file is the documented anti-pattern.
- **Approach D (no cache at all, even per-invocation):** rejected. Misses the trivially-cheap correctness win of memoizing within a single invocation. Also the architecturally honest path if Approach E proves operationally fragile, but that's a fallback, not a target.

---

## §9. Bibliography

| Source | Type | Relevance | URL |
|---|---|---|---|
| op-fast (cometkim) | Rust crate | Direct prior art for OS-keyring `op://` cache; 90× speedup benchmark | https://github.com/cometkim/op-fast |
| op-cache (SamSaffron) | Daemon | Direct prior art for in-RAM `op://` cache; 1–2 ms hits | https://github.com/SamSaffron/op-cache |
| dcreemer/1pass | Python wrapper | Encrypted-file cache prior art; force-refresh flag rationale | https://github.com/dcreemer/1pass |
| 1Password CLI app integration security | Vendor doc | `op` daemon caching architecture, 10-min/12-h TTL envelope | https://developer.1password.com/docs/cli/app-integration-security/ |
| 1Password community: op read is slow | Community | Latency baseline + IPC bottleneck breakdown | https://www.1password.community/discussions/developers/op-read-is-pretty-slow-700ms-per-invocation/25907 |
| 99designs/aws-vault USAGE | Tool docs | Session-credential cache backend selection (keyring + file fallback) | https://github.com/99designs/aws-vault/blob/master/USAGE.md |
| Vault Agent caching | HashiCorp doc | Lease-driven cache invalidation reference design | https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/caching |
| Vault Proxy static-secret caching | HashiCorp doc | Only server-push invalidation example in corpus | https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy/caching/static-secret-caching |
| AWS Secrets Manager Agent | AWS doc | 5-min default / 1-h max TTL — strongest numerical anchor | https://docs.aws.amazon.com/secretsmanager/latest/userguide/secrets-manager-agent.html |
| AWS Secrets Manager client-side caching | AWS doc | Java/.NET/Python lib defaults, fail-open-with-stale | https://docs.aws.amazon.com/secretsmanager/latest/userguide/use-client-side-caching.html |
| aws_secretsmanager_caching (Rust) | Crate | Official AWS Rust caching crate (does not use SecretBox — anti-example) | https://docs.rs/aws-secretsmanager-caching/latest/aws_secretsmanager_caching/ |
| Doppler Secret Fallback Files | Vendor doc | Documented anti-pattern: TTL-less fallback file | https://docs.doppler.com/docs/automatic-fallbacks |
| chamber (segmentio) | Tool | "No cache, restructure data instead" prior art | https://github.com/segmentio/chamber |
| Bitwarden vault sync | Vendor doc | Full-vault encrypted blob sync model | https://bitwarden.com/help/vault-sync/ |
| 1Password Connect | Vendor doc | Server-side cache architecture | https://developer.1password.com/docs/connect/ |
| moka 0.12.15 | Rust crate | Canonical 2026 in-memory TTL cache; sync + future, eviction listener | https://crates.io/crates/moka |
| moka eviction_listener docs | Rust doc | Synchronous listener semantics, panic-stops-listener warning | https://docs.rs/moka/latest/moka/sync/struct.CacheBuilder.html |
| secrecy 0.10.3 | Rust crate | SecretBox<S>; SecretString = SecretBox<str>; CloneableSecret unsealed marker | https://crates.io/crates/secrecy |
| zeroize 1.8.2 | Rust crate | Vec/String/CString reallocation footgun docs | https://docs.rs/zeroize/latest/zeroize/ |
| benma — Rust move/copy/drop pitfall | Blog | Stack-move bypasses zeroize; mitigation is heap-box | https://benma.github.io/2020/10/16/rust-zeroize-move.html |
| keyring 4.0.0 + keyring-core | Rust crate | New pluggable credential-store API; April 2026 release | https://crates.io/crates/keyring |
| NIST SP 800-57 Part 1 Rev. 5 | Standard | Treat cached secret as primary; no "cache" carve-out | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf |
| NIST SP 800-63B-4 | Standard | Session token TTL: 30 min idle / 12 h hard | https://pages.nist.gov/800-63-3/sp800-63b.html |
| NIST SP 800-88 Rev. 2 | Standard | Sanitization scope includes cache; cryptographic-erase guidance | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf |
| FIPS 140-3 IG | Standard | Unprotected CSP zeroization | https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf |
| OWASP Secrets Management Cheat Sheet | Standard | §2.5 minimize in-memory window; §2.7.4 expiration | https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html |
| OWASP Cryptographic Storage Cheat Sheet | Standard | OS-keystore-bound key for any on-disk cache | https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html |
| RFC 6749 §4.2.2, §5.1 | Standard | OAuth `expires_in` as TTL upper bound | https://datatracker.ietf.org/doc/html/rfc6749 |
| systemd Credentials | systemd doc | tmpfs + mlock + service-scoped — "done right" reference | https://systemd.io/CREDENTIALS/ |
| `prctl(PR_SET_DUMPABLE, 0)` | Linux man | Coredump / `RUST_BACKTRACE` mitigation | https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html |
| `mlock(2)` | Linux man | Swap-out mitigation; suspend-to-disk caveat | https://www.man7.org/linux/man-pages/man2/mlock.2.html |
| Halderman et al. — *Lest We Remember* | Paper | DRAM retention; justifies short TTL + zeroize | https://jhalderm.com/pub/papers/coldboot-cacm09.pdf |
| Common Fate / Granted on AWS plaintext SSO | Blog | `~/.aws/cli/cache/` exfil class | https://medium.com/@commonfatetech/making-aws-cli-use-encrypted-credentials-instead-of-plain-text-sso-tokens-2f2794499145 |
| aws/aws-cli#6724 | GH issue | Expired SSO cache reuse — open, no fix | https://github.com/aws/aws-cli/issues/6724 |
| TeamTNT cryptojacking worm | Incident | AWS credential theft from disk | https://www.bleepingcomputer.com/news/security/cryptojacking-worm-steals-aws-credentials-from-docker-systems/ |
| Red Canary — SSO double trouble | Incident | SSO token theft analysis | https://redcanary.com/blog/threat-detection/aws-sso-access-tokens/ |
| manchicken 1Password CLI disclosure | Incident | Open-vault-across-subprocesses | https://codeberg.org/manchicken/1password-cli-vuln-disclosure |
| Help Net Security CVE-2024-42218/42219 | Incident | macOS 1Password IPC validation flaws | https://www.helpnetsecurity.com/2024/08/09/cve-2024-42219-cve-2024-42218/ |
| Bitwarden CLI Compromised April 2026 | Incident | Supply-chain attack on credential CLI itself | https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html |
| Sysdig — Shai-Hulud worm | Incident | Self-replicating npm worm targeting credential caches | https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages |
| NVD CVE-2018-19358 GNOME Keyring | CVE | Cross-app Linux Secret Service access | https://nvd.nist.gov/vuln/detail/CVE-2018-19358 |
| Wojciech Reguła — KeySteal | Research | macOS Keychain four extraction methods | https://wojciechregula.blog/post/stealing-macos-apps-keychain-entries/ |
| SpecterOps — DPAPI offensive | Research | Mimikatz DPAPI extraction | https://specterops.io/blog/2018/08/22/operational-guidance-for-offensive-user-dpapi-abuse/ |
| aws-vault#304 | GH issue | Linux Secret Service headless-container failure | https://github.com/99designs/aws-vault/issues/304 |
| Qualys CVE-2025-5054 / CVE-2025-4598 | CVE | apport/systemd-coredump credential extraction | https://blog.qualys.com/vulnerabilities-threat-research/2025/05/29/qualys-tru-discovers-two-local-information-disclosure-vulnerabilities-in-apport-and-systemd-coredump-cve-2025-5054-and-cve-2025-4598 |
| Qualys CVE-2023-38408 | CVE | ssh-agent PKCS#11 RCE via forwarding | https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent |
| CISA tj-actions/changed-files | Incident | 23k repos, secret leak via compromised Action | https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction |
| Adnan Khan — Cacheract | Research | GitHub Actions cache poisoning | https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache/ |
| HashiCorp HCSEC-2024-18 | Advisory | Vault token leak via audit-device HMAC bug | https://discuss.hashicorp.com/t/hcsec-2024-18-vault-leaks-client-token-and-token-accessor-in-audit-devices/69669 |
| hashicorp/vault#19684 | GH issue | Agent lease cache vs template-refresh stale-value bug | https://github.com/hashicorp/vault/issues/19684 |
| Stenio Ferreira — Vault performance | Benchmark | KV read 4.40 ms mean same-DC | https://medium.com/hashicorp-engineering/hashicorp-vault-performance-benchmark-13d0ea7b703f |
| Aquia — Secrets Manager Lambda Extension | Benchmark | 12 ms warm vs 580 ms SDK direct | https://blog.aquia.us/blog/2023-01-01-secrets-manager-lambda-extension/ |
| Kerkour — AEAD benchmark | Benchmark | ring AES-256-GCM 1 KB = 456 ns | https://kerkour.com/rust-symmetric-encryption-aead-benchmark |
| AWS Parameter Store throughput | AWS doc | 40 TPS default; throttling pressure on caching | https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-throughput.html |
