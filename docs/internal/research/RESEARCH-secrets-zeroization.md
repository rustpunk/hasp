# RESEARCH-secrets-zeroization

> Decision: which crate(s) and posture govern in-memory secret material in `hasp`?
>
> Date: 2026-04-26
> Audience: hasp-core authors, downstream library consumers
> Status: recommendation, awaiting design lock

---

## Core question

Should `hasp-core` depend on `secrecy` directly, define its own zeroizing wrapper, or compose `zeroize` and friends manually? What memory-locking and process-image-hygiene posture is correct for a default unprivileged CLI that is also embedded in long-lived daemons?

---

## The landscape

**Cross-platform baseline:** `secrecy` and `zeroize` are pure-Rust, `forbid(unsafe_code)`-friendly, `no_std`-compatible crates that compile and run identically on Linux, macOS, and Windows. The boundary recommendation (`SecretString` from every backend) imposes zero platform-conditional code on hasp consumers. The platform-conditional discussion below applies *only* to the optional `memory-lock` Cargo feature — the OS-locked-pages primitive degrades in capability across OSes (Linux strongest, macOS / Windows weaker). Without that feature enabled, the library is OS-agnostic by construction.

The Rust ecosystem has converged on a layered stack: `zeroize` (volatile-write primitive, RustCrypto), `secrecy` (typed wrapper that adds redacted `Debug`, `ExposeSecret` discipline, gated `Clone`/`Serialize`), and a small set of opt-in crates (`secrets`, `memsec`, `secure-types`, `shush-rs`) that layer `mlock`/`mprotect`/`VirtualLock`/guard pages on top. `secrecy`'s own documentation explicitly says it does not provide `mlock(2)`/`mprotect(2)` and points users to the `secrets` crate when OS-level memory protection is required ([docs.rs/secrecy](https://docs.rs/secrecy/0.10.3/secrecy/)).

`secrecy` 0.10.3 (2024-10-09, ~103M downloads, owned by Tony Arcieri / iqlusioninc — the same author as `zeroize`) is the de facto baseline. The 0.8 → 0.10 migration renamed `Secret<T: Sized>` to `SecretBox<S: ?Sized>` and introduced `SecretString = SecretBox<str>`, removing a heap indirection for the common string case. `zeroize` 1.8.2 (~430M downloads) implements `core::ptr::write_volatile` plus `compiler_fence(SeqCst)` — the two-instruction pattern is verified empirically by ARM64 disassembly to survive LLVM dead-store elimination ([CipherStash](https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd)).

The standards literature has a load-bearing nuance: NIST SP 800-57 Pt 1 Rev. 5 §8.3.4 mandates "unrecoverable" key destruction; FIPS 140-2 §4.7 mandates plaintext-key zeroization; OWASP Secrets Management Cheat Sheet §2.5 recommends post-use zeroing — but explicitly notes this may be "overkill" for low-capability threat actors. CWE-591 documents that POSIX `mlock` does **not** guarantee no-swap on most Unix implementations; Linux is the explicit exception. The actionable conclusion: zeroize-on-drop is the floor; `mlock` is conditional theatre depending on platform and process lifetime ([NIST SP 800-57](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf), [FIPS 140-2](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.140-2.pdf), [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [CWE-591](https://cwe.mitre.org/data/definitions/591.html)).

Peer Rust libraries are inconsistent: `aws-credential-types` v1.2.14 holds `secret_access_key` as a plain `String` with no zeroize and an unredacted `Debug` impl. `vaultrs` v0.8.0 deserializes KV values into raw structs without `secrecy`. `age`/`rage` use `zeroize` directly without `secrecy`. `rustls` has a longstanding open issue about not zeroizing private-key bytes by default. `hasp` is filling a real gap by being principled about this at the library boundary.

---

## Approach A: depend on `secrecy` directly, re-export it

**Used by:** Ferrule (`secrecy = "0.10"` workspace dep), `vodozemac` (with the post-RUSTSEC-2024-0342 fix), `hyperfine`, `tower-cookies`.

**How it works:** `hasp-core` adds `secrecy = "0.10"` as a non-optional dependency, re-exports `secrecy::SecretString` and `secrecy::ExposeSecret`, returns `SecretString` from every `Backend::get` call. Downstream consumers either pull `secrecy` themselves (one extra resolve, but no version conflict because of re-export discipline) or use `hasp::SecretString` directly.

**Strengths:**
- Zero net-new public types — every Rust crate already touching secrets in the ecosystem either uses `secrecy` or could swap to it without ergonomic loss. Ferrule and Spall both already depend on `secrecy`; an `Into`/`From` conversion is unnecessary.
- `secrecy` provides redacted `Debug`, `ExposeSecret` access discipline, opt-in `Clone` (`CloneableSecret` marker), opt-in `Serialize` (`SerializableSecret` marker). All four security properties land for free.
- Same maintainer for `secrecy` and `zeroize` (Tony Arcieri / iqlusioninc) — no version-skew risk between the two.
- 103M+ downloads, MIT OR Apache-2.0, `forbid(unsafe_code)`, `no_std`-friendly.

**Weaknesses / failure modes:**
- `SecretString` does **not** zeroize the intermediate `String` produced by `serde` deserialization or `std::env::var()` before the wrap. The original `String` allocation is freed by normal `Drop`, not zeroized. Documented limitation; no way to fix at the `secrecy` layer ([users.rust-lang.org thread](https://users.rust-lang.org/t/secrecy-crate-serialize-string/112263)).
- Stack-copy residue: a `SecretString` returned by value transits multiple stack frames; only the final `Drop` site is zeroed. The intermediate stack slots retain bytes ([benma's Rust zeroize/move analysis](https://benma.github.io/2020/10/16/rust-zeroize-move.html)). Heap-allocate (`SecretString` is `Box<str>` already) and avoid by-value passes through helper layers.
- No `mlock`/`mprotect`. Secrets sit in normal heap and may swap to disk on memory pressure. On Linux this is mitigated by `mlock` (when used); on macOS / Windows / BSDs the guarantee is weaker. CWE-591 documents this.
- RUSTSEC-2024-0342 / CVE-2024-34063 demonstrates the real-world failure mode: a transitive crate pulled in with `default-features = false` silently disabled `zeroize` integration. Vodozemac 0.5.0–0.5.1 stopped zeroizing session keys without a warning. Same trap applies to anyone consuming `hasp` who accidentally turns off the `secrecy` feature on a transitive dep ([RUSTSEC-2024-0342](https://rustsec.org/advisories/RUSTSEC-2024-0342.html)).

**Security implications:** Floor (zeroize-on-drop, redacted `Debug`, no accidental serialization) is met. Ceiling (anti-swap, anti-coredump) is not — addressed in Approach B if needed.

**Source:** [docs.rs/secrecy/0.10.3](https://docs.rs/secrecy/0.10.3/secrecy/), [crates.io/secrecy](https://crates.io/crates/secrecy), [docs.rs/zeroize](https://docs.rs/zeroize/latest/zeroize/).

---

## Approach B: `secrecy` for the library boundary + opt-in `memory-lock` Cargo feature

**Used by:** No published Rust secret-store crate currently composes the layers this way (the closest is `secrets`, which is a leaf type, not a boundary type). `hasp` would be first.

**How it works:** Same as Approach A for the default surface. Add a `memory-lock` Cargo feature on `hasp-core` (off by default) that, when enabled, wraps every backend-returned secret in a `secrets::SecretBox`-style mlocked container. The public type is still `SecretString`; the underlying allocation is mlocked. Daemon callers (Ferrule REPL, Spall server-mode, future long-lived consumers) opt in; CLI and short-lived callers do not pay the cost.

**Strengths:**
- Threat-model honest: `mlock` adds genuine value for **long-lived processes on Linux** (CWE-591 acknowledges Linux as the exception that does guarantee no-swap for mlocked pages). For short-lived `hasp get …` invocations, the process exits before swap pressure materializes — `mlock` would be theatre.
- Opt-in: 64 KB `RLIMIT_MEMLOCK` default on Linux is not exhausted by typical CLI workloads; daemons that need it explicitly raise the limit and accept the cost.
- Future-compatible with `memfd_secret(2)` (Linux 5.14+) — pages removed even from kernel direct map; also inhibits hibernation. Strongest available primitive on Linux. Could become the Linux backend for the `memory-lock` feature.

**Weaknesses / failure modes:**
- Doubles the crate's surface area at compile time (extra `cfg`-guarded code paths) and adds a runtime cost to `Drop` (unmap pages).
- Cross-platform parity is poor: Windows `VirtualLock` does not provide persistent no-swap guarantees, and macOS has no equivalent to `memfd_secret`. Effectively a Linux-mostly feature.
- `memfd_secret` requires `secretmem.enable=y` boot parameter on kernels < 6.5 — not always available.
- Hibernation defeats `mlock` on every platform.

**Security implications:** Provides meaningful additional protection only on Linux daemons. On macOS / Windows / containers the threat model is essentially unchanged from Approach A.

**Source:** [LWN on RLIMIT_MEMLOCK](https://lwn.net/Articles/876288/), [`memfd_secret(2)` man page](https://man7.org/linux/man-pages/man2/memfd_secret.2.html), [`secrets` crate](https://github.com/stouset/secrets), [CWE-591](https://cwe.mitre.org/data/definitions/591.html).

---

## Approach C: hand-rolled zeroizing wrapper in `hasp-core`

**Used by:** No mature Rust secrets project found that has done this and remained maintained. `rustls` partially does so for `PrivateKey` but the gap (no zeroize) is widely criticized.

**How it works:** Define `pub struct HaspSecret(Box<[u8]>)` (or a parallel `SecretString`) in `hasp-core`, manually impl `Drop` calling `zeroize::Zeroize::zeroize`, manually impl `Debug` redacting, manually gate `Clone`/`Serialize`.

**Strengths:**
- One fewer crate dep (`secrecy` removed; `zeroize` retained because hand-rolled `Drop` still calls into it for the volatile-write primitive — anything else would silently regress).
- No risk of `default-features = false` skew for `secrecy`.

**Weaknesses / failure modes:**
- Re-implements work that `secrecy` already does correctly. No marginal value.
- Forces every downstream consumer (Ferrule, Spall, future projects) to convert between `hasp::HaspSecret` and `secrecy::SecretString`. Both Ferrule and Spall already use `secrecy::SecretString` natively — a hasp-owned wrapper makes integration *worse*, not better.
- Carries the maintenance burden of re-validating the zeroize discipline in source. CipherStash's verification work would have to be reproduced. RUSTSEC-2024-0342 demonstrates how easy it is to silently break.
- **Reject this approach** unless `secrecy` becomes unmaintained.

**Security implications:** Equal floor to Approach A in theory; lower in practice because of higher defect surface.

---

## Benchmark data

- **`zeroize` per-byte cost:** No published Rust-specific microbenchmark. Derived from CipherStash assembly verification + Travis Downs Intel zero-fill data: a 32-byte `write_volatile` loop is approximately 5–50 ns on warm L1 cache. Negligible against any backend I/O ([CipherStash blog](https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd), [Travis Downs](https://travisdowns.github.io/blog/2020/05/13/intel-zero-opt.html)).
- **`SecretString` allocation overhead vs raw `String`:** Zero. `SecretBox<T>` is `#[repr(transparent)]` over `Box<T>`; identical heap layout. Only `Drop` differs: ~5–50 ns added for the zeroize call ([docs.rs/secrecy](https://docs.rs/secrecy/latest/secrecy/struct.SecretBox.html)).
- **`mlock()` per-page cost:** No direct Rust-specific benchmark. Linux syscall cost is typically ~100–500 ns. Per-call, not per-byte. The relevant constraint is `RLIMIT_MEMLOCK` (default 64 KB); proposed increase to 8 MB ([LWN](https://lwn.net/Articles/876288/)). Practical impact: ~250 secrets of 256 bytes each before exhausting the default limit.
- No published benchmark for `secrecy::SecretString` allocation overhead (zero by construction).

---

## Threat-model / standards anchors

| Source | Year | Body | Relevant insight | URL |
|--------|------|------|-----------------|-----|
| NIST SP 800-57 Pt 1 Rev. 5 §8.3.4 | 2020 | NIST | Key destruction must render material "unrecoverable"; zeroization of volatile memory is the listed mechanism for transient secrets. | [link](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf) |
| FIPS 140-2 §4.7 | 2002 | NIST | Mandates zeroization of all plaintext SSPs (Sensitive Security Parameters) in volatile memory. | [link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.140-2.pdf) |
| FIPS 140-3 / CMVP | 2019 | NIST/ISO | References ISO/IEC 19790; Level 3+ adds hardware-enforced tamper-triggered zeroization (out of scope for hasp). | [link](https://csrc.nist.gov/pubs/fips/140-3/final) |
| OWASP Secrets Mgmt Cheat Sheet §2.5 | 2023 | OWASP | "Memory occupied by a secret should be zeroed out after use"; explicitly notes this may be "overkill" against low-capability threats. | [link](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| OWASP ASVS 4.0 §V6.4 | 2019 | OWASP | L2/L3 require that key material is not exposed to the application but uses an isolated security module. Aspirational; defines the ceiling. | [link](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x14-V6-Cryptography.md) |
| CWE-591 | current | MITRE | POSIX `mlock` does not guarantee no-swap on most Unixes; Linux is the documented exception. | [link](https://cwe.mitre.org/data/definitions/591.html) |
| Linux `memfd_secret(2)` | 2021 (5.14) | kernel.org | Anonymous pages removed from kernel direct map; implies `mlock` semantics; inhibits hibernation. Strongest Linux primitive. | [link](https://man7.org/linux/man-pages/man2/memfd_secret.2.html) |

---

## Failure modes / CVEs to avoid

- **RUSTSEC-2021-0115 / CVE-2021-45706 — `#[zeroize(drop)]` no-op on enums in `zeroize_derive` < 1.1.1.** Audit transitive pins. Fix: `zeroize_derive >= 1.2`. ([advisory](https://rustsec.org/advisories/RUSTSEC-2021-0115.html))
- **RUSTSEC-2024-0342 / CVE-2024-34063 — Vodozemac 0.5.0–0.5.1 silently disabled session-key zeroization.** Cause: a transitive dep was pulled in with `default-features = false`; the `zeroize` integration feature was off. No compile error, no warning. **Direct implication for hasp:** if any backend crate enables a transitive crypto dep with `default-features = false`, verify the `zeroize` feature is explicitly re-enabled. `cargo audit` does not catch this. ([advisory](https://rustsec.org/advisories/RUSTSEC-2024-0342.html))
- **`#[derive(Debug)]` on a struct holding a raw secret leaks via panic backtrace, `RUST_BACKTRACE=full`, `RUST_LOG=debug`, and `anyhow` error chains.** Always use `SecretString` or hand-implement `Debug` to redact. ([docs.rs/secrecy](https://docs.rs/secrecy/latest/secrecy/))
- **serde intermediate `String`** is allocated from a non-zeroizing allocator and freed normally before being wrapped in `SecretString`. Document the limitation; cannot be solved at the `secrecy` layer. ([users.rust-lang.org](https://users.rust-lang.org/t/secrecy-crate-serialize-string/112263))
- **Stack residue from move semantics.** Heap-allocate (which `SecretString` does internally via `Box<str>`); avoid passing secrets by value through helper functions where possible. ([benma](https://benma.github.io/2020/10/16/rust-zeroize-move.html))
- **Coredump leak.** CVE-2025-5054 (Apport) and CVE-2025-4598 (systemd-coredump) extracted password hashes from crashed processes. Production deployments of any hasp-using daemon should set `RLIMIT_CORE=0` and prefer `Result` propagation over panics on the secret path. mlock pages should also be `madvise(MADV_DONTDUMP)`-marked.
- **No language mechanism to zero the call stack** of a secret-handling function. LLVM has the attribute; Rust does not expose it. Volatile + `compiler_fence(SeqCst)` only address compiler elision, not CPU-level reordering on weakly-ordered ISAs. ([internals.rust-lang.org](https://internals.rust-lang.org/t/annotations-for-zeroing-the-stack-of-sensitive-functions-which-deal-in-transient-secrets/11588))

---

## Design insights for hasp

1. **`hasp-core` depends on `secrecy = "0.10"` directly and re-exports `SecretString` and `ExposeSecret`.** Do not define a hasp-owned wrapper. Both Ferrule and Spall already use `secrecy::SecretString` natively — a wrapper makes integration worse, not better. The maintenance burden of correctly re-implementing `secrecy`'s discipline outweighs any conceivable gain.
2. **Pin `secrecy` exactly at the `0.10.x` line and `zeroize` to the version `secrecy` selects.** Do not pull `zeroize` into `Cargo.toml` as a separate top-level dep at a different version — version skew between `secrecy` and `zeroize` is the documented RUSTSEC-2024-0342 failure mode.
3. **Memory-locking is a Cargo feature, off by default.** Daemon embedders opt in. Short-lived CLI invocations and most library consumers do not pay the cost. Document the gap honestly: `mlock` is a meaningful protection only on Linux long-lived processes; on macOS / Windows / hibernate-capable laptops it is largely theatre.
4. **Wrap at the earliest possible boundary.** Backend implementations should construct `SecretString` from raw bytes immediately upon receiving them from the OS / network — never hold a raw `String` or `Vec<u8>` longer than necessary. Document that the serde deserialization intermediate string is unavoidable but minimized.
5. **No `Debug` impl on any internal hasp type that contains a `SecretString`.** Either delegate to `SecretString`'s redacted `Debug`, or hand-implement to print only the redaction-safe URL/key path. Forbid `#[derive(Debug)]` on `Entry`/`Backend` internal types holding secret material.
6. **Document the threat model boundary.** Process-image hygiene (`/proc` redaction, `prctl(PR_SET_DUMPABLE, 0)`, argv clearing) is the embedding application's responsibility. hasp can only enforce: never accept secret values on argv (CLI uses `--secret-file` / stdin / env), never build strings from argv internally, never `Debug`-print a secret. Embedders are pointed at the OWASP Secrets Management Cheat Sheet.
7. **Wave-3+ backend crates inherit the discipline.** Every cloud backend (`aws-sm`, `vault`, `gcp-sm`, etc.) returns `SecretString` from its `Backend::get` impl. The wrapping happens inside the backend crate, immediately after the SDK call returns plaintext bytes. No backend exposes a raw `String` even internally beyond the boundary.

---

## Decision criteria (enforced)

Greenfield, zero deployments. NOT valid factors:
- Implementation effort, files touched, breaking-change risk
- "Pragmatic" alternatives that compromise architecture or weaken security

ONLY valid criteria:
- Architectural correctness (no backend leak; uniform redaction posture)
- Threat-model soundness (zeroize lifetime, no debug/log/error leaks)
- Long-term maintainability of the correct design
- Rustpunk identity alignment (pure-Rust default; opt-in OS specifics)

If `mlock` on Linux daemons is worth a Cargo feature even though it adds compile-time complexity, that is a point in its favor — the threat model is real for that use case.

---

## Recommendation

**Approach A + opt-in slice of B.** `hasp-core` depends on `secrecy = "0.10"` directly, re-exports the two boundary types (`SecretString`, `ExposeSecret`), and ships an off-by-default `memory-lock` Cargo feature that swaps the underlying allocation to `secrets::SecretBox`-style mlocked pages on Linux (best-effort on macOS/Windows; documented gap).

**Confidence:** High.

**Rationale:**
- `secrecy` is the de facto standard; both immediate consumers (Ferrule, Spall) already depend on it. A hand-rolled wrapper makes integration worse with no gain ([Ferrule deps](file:///home/glitch/code/rustpunk/ferrule/ferrule-config/Cargo.toml)).
- Same maintainer for `secrecy` and `zeroize` removes version-skew risk.
- The `memory-lock` feature provides a real upgrade path for daemon callers who need it without forcing the cost on CLI users.
- Standards (NIST SP 800-57, FIPS 140-2, OWASP §2.5) all require zeroize-on-drop as a floor; `secrecy` provides this. mlock is an enhancement, not a baseline requirement.

**Key risk:** Vodozemac-style `default-features = false` accident on a transitive crypto dep silently disabling zeroize. **Mitigation:** the crate-vetting skill must verify, for every backend crate, that the `zeroize` feature on transitive crypto deps is explicitly enabled. Add a CI check that fails if `cargo tree --no-default-features` shows any of those deps as a `zeroize`-disabled.

**Threat-model note:** Approach A meets NIST SP 800-57 §8.3.4 zeroization, FIPS 140-2 §4.7 SSP zeroization, and OWASP §2.5 post-use clearing. It does not meet `mlock`-style anti-swap on platforms other than Linux, and does not meet `memfd_secret`-style anti-coredump or anti-hibernate even on Linux unless the `memory-lock` feature is enabled. These gaps are inherent to user-space libraries; the only complete fix is HSM delegation (ASVS 6.4.2).

**If wrong:** If `secrecy` becomes unmaintained or has a security advisory we cannot work around, fall back to a minimal hasp-owned wrapper composed directly on `zeroize`. The boundary type stays `hasp::SecretString`; the implementation swaps. Public API surface is unchanged.

**Rejected alternatives:**
- **Approach C (hand-rolled wrapper):** rejected because it forces every consumer to convert between `hasp::HaspSecret` and `secrecy::SecretString`, adds maintenance burden with no marginal security gain, and reinvents work that the ecosystem has already validated. "Architecturally inferior" — it weakens integration ergonomics for a self-inflicted dependency-trimming exercise.
- **`memory-lock` as default (Approach B always-on):** rejected because the Linux 64 KB `RLIMIT_MEMLOCK` default would be exhausted by ~250 cached secrets, the per-platform parity is poor, and the cost is wasted on short-lived CLI invocations. Off-by-default is the right posture; long-lived embedders opt in.
- **Pulling `zeroize` as a top-level dep at a pinned version different from `secrecy`'s selection:** rejected per RUSTSEC-2024-0342 — version skew between the two has caused silent zeroize disabling in production.

## Implementation notes (added 2026-05-14)

The `memory-lock` feature shipped as part of sprint #9. Key decisions:

**No new crate.** `region`, `memsec`, and `os-memlock` were evaluated.
`region` was last pushed June 2024 (borderline 12-month window); `os-memlock`'s
GitHub repo did not resolve. Implemented directly via `libc` (mlock, madvise)
and `windows-sys` (VirtualLock) — both already in the workspace, zero crate
audit surface added.

**Crate decision: none.** Direct libc/windows-sys calls, same pattern as
existing `hardening.rs` platform modules.

**Backends migrated.** `env://` and `file://` backends now call `wrap_secret()`
from `hasp_core::secret_mem`, which invokes `lock_secret_pages` when the feature
is active. Other backends retain `SecretString::new(...)` for now and can
migrate incrementally.

**Graceful degrade.** mlock failure returns `MitigationOutcome { applied: false }`
and the secret is usable. CI matrix tests with `--features hasp-core/memory-lock`
on Linux where RLIMIT_MEMLOCK may be 64 KiB.

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| `secrecy` crate (0.10.3) | crate | Boundary type for hasp library API | [docs.rs](https://docs.rs/secrecy/0.10.3/secrecy/) |
| `zeroize` crate (1.8.2) | crate | Volatile-write primitive used by `secrecy` | [docs.rs](https://docs.rs/zeroize/latest/zeroize/) |
| `secrets` crate (stouset) | crate | Reference for `mlock`+guard-page approach | [github](https://github.com/stouset/secrets) |
| `memsec` crate | crate | Alternative `mlock`/`VirtualLock` wrapper | [docs.rs](https://docs.rs/memsec/latest/memsec/) |
| `secure-types` crate | crate | Adds `memfd_secret` Linux backend | [crates.io](https://crates.io/crates/secure-types) |
| RUSTSEC-2021-0115 | advisory | `zeroize_derive` no-op on enums | [link](https://rustsec.org/advisories/RUSTSEC-2021-0115.html) |
| RUSTSEC-2024-0342 | advisory | Transitive `default-features=false` disabled zeroize | [link](https://rustsec.org/advisories/RUSTSEC-2024-0342.html) |
| CipherStash assembly verification | post | Empirical proof of `write_volatile`+`compiler_fence` correctness | [link](https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd) |
| benma — Rust zeroize and move | post | Stack-residue analysis | [link](https://benma.github.io/2020/10/16/rust-zeroize-move.html) |
| serde intermediate-String thread | issue | Documented limitation of wrap-at-boundary | [link](https://users.rust-lang.org/t/secrecy-crate-serialize-string/112263) |
| NIST SP 800-57 Pt 1 Rev. 5 | standard | Mandates "unrecoverable" key destruction | [link](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf) |
| FIPS 140-2 §4.7 | standard | Plaintext-key zeroization in volatile memory | [link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.140-2.pdf) |
| FIPS 140-3 / CMVP | standard | ISO 19790 reference | [link](https://csrc.nist.gov/pubs/fips/140-3/final) |
| OWASP Secrets Management Cheat Sheet | guide | Post-use zeroing as risk reduction | [link](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| OWASP ASVS 4.0 §V6.4 | standard | HSM delegation as ceiling | [link](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x14-V6-Cryptography.md) |
| CWE-591 | weakness | `mlock` non-portability | [link](https://cwe.mitre.org/data/definitions/591.html) |
| `memfd_secret(2)` | man page | Strongest Linux memory protection | [link](https://man7.org/linux/man-pages/man2/memfd_secret.2.html) |
| LWN — `RLIMIT_MEMLOCK` raise | post | Default 64 KB, proposed 8 MB | [link](https://lwn.net/Articles/876288/) |
| Smallstep — secrets on the command line | post | argv leak via `/proc/<pid>/cmdline` | [link](https://smallstep.com/blog/command-line-secrets/) |
| Ferrule `credentials.rs` | source | Existing rustpunk consumer using `secrecy` 0.10 | `~/code/rustpunk/ferrule/ferrule-config/src/credentials.rs` |
