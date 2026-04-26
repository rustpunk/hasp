# RESEARCH-keyring-v3-vs-v4

> Decision: which keyring crate (and version) does `hasp-backend-keyring` depend on?
>
> Date: 2026-04-26
> Audience: hasp-backend-keyring author, Wave 1 implementers
> Status: recommendation, awaiting design lock — **note: ecosystem changed today; D2 question reframed**

---

## Core question

The original question: "pin `keyring` v3 (current stable, Ferrule already uses it) or `keyring` v4 (RC)." That framing is now obsolete. The actual decision is between:

1. **`keyring` v3.6.3** — the previous combined library, last release 2025-07-27, marked "likely final v3 release."
2. **`keyring-core` v1.0.0** — the new library dependency, released 2026-04-22 (~4 days ago).
3. **`keyring` v4.0.0** — released 2026-04-26 (today). The crate's own README states **"Do not depend on this crate!"** It is now sample / CLI / inventory code only.

This shift happened in the past four days. Ferrule's `keyring = "3"` pin (`ferrule-config/Cargo.toml:17`) is now on the deprecated combined-library path.

---

## The landscape

The `keyring-rs` project (maintained by Daniel Brotsky under the `open-source-cooperative` GitHub org) executed a major architectural split. The monolithic `keyring` crate that combined the `Entry` API and per-platform credential stores has been broken into:

- `keyring-core` — the trait and `Entry` API only ([crates.io](https://crates.io/crates/keyring-core), [docs.rs](https://docs.rs/keyring-core/latest/keyring_core/))
- a constellation of independent store crates: `dbus-secret-service-keyring-store`, `zbus-secret-service-keyring-store`, `linux-keyutils-keyring-store`, `apple-native-keyring-store`, `windows-native-keyring-store`, `android-native-keyring-store`, `db-keystore` (encrypted SQLite via Turso) ([docs.rs](https://docs.rs/keyring/latest/keyring/))
- `keyring` v4.0.0, retained as a sample-code / inventory crate **explicitly not for library use**

The motivation: the old design forced a Cargo-feature compile-time choice of credential store. Applications that needed runtime store selection, or wanted to ship multiple stores in one binary and pick at runtime, could not do so cleanly. The new design makes default-store selection an explicit runtime call (`keyring_core::set_default_store(...)`), which is required before any `Entry::new` succeeds.

Ferrule pins `keyring = "3"` and uses `Entry::new("ferrule", name)` (`ferrule-config/src/credentials.rs:21`). Today's release does not invalidate that code; v3.6.3 still works. But Ferrule will eventually need to migrate. hasp's choice cascades to whether Ferrule migrates *to hasp* (and inherits hasp's keyring choice) or migrates *with hasp* (both moving to `keyring-core` 1.0.0 simultaneously).

---

## Approach A: pin `keyring` v3.6.3

**Used by:** Ferrule (existing), every other published Rust crate that depends on `keyring` as of this morning.

**How it works:** `hasp-backend-keyring/Cargo.toml` declares `keyring = "3"`. The `Entry::new(service, account)` and `Entry::new_with_target(target, service, account)` API maps directly to `keyring://service/account` and (with extra grammar) `keyring://target/service/account`.

**Strengths:**
- Stable. v3 series is six minor versions deep; well-trodden code path. Three-plus years of bug-fixes embedded.
- API directly matches the keyring backend's needs; no wrapping required.
- Ferrule integration is a no-op — both crates pin the same version.

**Weaknesses / failure modes:**
- **Officially the last v3 release.** No new features and presumably only critical security backports. hasp would be adopting a code path the upstream maintainers consider end-of-life.
- Default-store selection is a Cargo feature (compile-time). hasp's batteries-included root crate would have to decide at compile time whether the binary supports Secret Service, KWallet, KeePassXC, etc. Runtime fallback is not possible. This is the exact constraint that drove the v3→v4 split.
- Cross-platform regression risk: any v3 → v3.x.y bug fix that requires API changes is now stalled because the maintainers are focused on v4/keyring-core.
- Locks downstream consumers (Ferrule, future) to migrating *away* from hasp's choice within a year or two.

**Source:** [keyring-rs releases](https://github.com/open-source-cooperative/keyring-rs/releases), [crates.io/keyring](https://crates.io/crates/keyring), [Ferrule Cargo.toml](file:///home/glitch/code/rustpunk/ferrule/ferrule-config/Cargo.toml).

---

## Approach B: pin `keyring-core` v1.0.0 + select store crates per-platform

**Used by:** Newest Rust projects starting fresh today; no production consumers yet (released 4 days ago, 72K downloads).

**How it works:** `hasp-backend-keyring/Cargo.toml` declares `keyring-core = "1"` plus per-platform `cfg`-gated dependencies: `apple-native-keyring-store` for macOS, `windows-native-keyring-store` for Windows, one of the Secret Service crates (`dbus-secret-service-keyring-store` or `zbus-secret-service-keyring-store`) for Linux. The backend's initialization code calls `keyring_core::set_default_store(...)` once at startup before any `Entry::new` happens.

**Strengths:**
- API is on the actively-developed path. v1.0.0 is the maintainers' chosen forward direction.
- Runtime store selection means hasp can ship a single binary that detects the correct store at runtime (e.g., try Secret Service via DBus first, fall back to a file-backed encrypted store for headless containers). This addresses the documented Linux pain point (Secret Service requires DBus, breaks in headless containers).
- The per-store crate split lets hasp depend only on what it needs — smaller binary, fewer transitive deps. No `dbus` linkage on macOS-only builds.
- Mock store (`keyring_core::mock`) ships in-tree for tests, always built. Doesn't require a feature flag.
- Aligns with the locked architectural decision in `notes/scaffold.md`: per-backend feature gating maps cleanly onto per-platform store crate selection.

**Weaknesses / failure modes:**
- **4 days old.** Production exposure is essentially zero. No published Rust crate has yet shipped against `keyring-core` 1.0. hasp would be early-adopter.
- Migration cost for Ferrule is now hasp-driven: if hasp pins `keyring-core` 1.0, Ferrule cannot integrate without migrating off `keyring = "3"` simultaneously.
- The store-selection contract is new. `set_default_store` must be called exactly once before any `Entry::new`; calling it twice or after the first `Entry` is a runtime error. hasp must enforce this in its `Backend::register` path.
- `Entry::new_with_target` is **removed**. Replaced by `Entry::new_with_modifiers(HashMap)` where `target` is one key in the map. Any URL grammar that had been planning to map cleanly onto `Entry::new_with_target` now goes through the modifiers HashMap (see RESEARCH-keyring-url-grammar.md).
- Per-store crates may have independent release cadences; version skew between, e.g., `keyring-core` 1.0.x and `apple-native-keyring-store` 1.y.z is a new failure mode.

**Source:** [keyring-core docs.rs](https://docs.rs/keyring-core/latest/keyring_core/), [keyring v4 README on crates.io](https://crates.io/crates/keyring), [Error enum](https://docs.rs/keyring-core/latest/keyring_core/error/enum.Error.html).

---

## Approach C: depend on `keyring` v4.0.0

**Used by:** Nobody. The crate's own README says do not.

**How it works:** Same as v3, with the Cargo manifest line `keyring = "4"`.

**Strengths:** none specific.

**Weaknesses / failure modes:**
- Maintainers explicitly tell consumers not to do this.
- The crate is now sample / CLI / inventory code; no library API contract.
- **Reject this approach.**

---

## Benchmark data

No published latency benchmarks for `keyring` v3 vs `keyring-core` v1 specifically. Underlying OS calls dominate (see `RESEARCH-perf-data.md` notes on macOS Keychain ~3.3 s pathological case, no reliable warm-call data, no Windows Credential Manager / Linux DBus benchmark). Crate-layer overhead is negligible relative to the OS call.

`keyring-core::mock` store is in-process in-memory; sub-microsecond. Useful for tests; not representative of production.

---

## Threat-model / standards anchors

| Source | Year | Body | Relevant insight | URL |
|--------|------|------|-----------------|-----|
| FIPS 140-2 §4.7 | 2002 | NIST | Plaintext SSP zeroization in volatile memory; satisfied at hasp-core layer regardless of keyring choice | [link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.140-2.pdf) |
| OWASP ASVS 4.0 §V6.4 | 2019 | OWASP | L2/L3: key material in isolated security module. macOS Keychain and Windows Credential Manager partially satisfy this; Linux Secret Service does not (process-memory key store with ambient access). | [link](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x14-V6-Cryptography.md) |
| Apple TN3137 | 2024 | Apple | macOS legacy `SecKeychain*` is a compat shim over the iOS-style Data Protection Keychain; modern API path is `SecItemCopyMatching`. `keyring-core` 1.0 + `apple-native-keyring-store` uses the modern path. | [link](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) |

---

## Failure modes / CVEs to avoid

- **Headless / container DBus failure.** No DBus session bus → `dbus-secret-service-keyring-store` returns opaque OS errors or hangs. Documented across multiple jaraco/keyring issues; the upstream guidance is to start `gnome-keyring-daemon --daemonize --components=secrets` with a fake password before tests. **hasp implication:** the keyring backend must surface a typed `Error::Backend { kind: Permanent, message: "secret service daemon unavailable" }` rather than propagating the OS errno. ([github.com/jaraco/keyring/issues/477](https://github.com/jaraco/keyring/issues/477))
- **gnome-keyring auto-locks after idle.** A long-running daemon that confirmed a credential at startup may fail on a later read because the keyring locked. `keyring-core` 1.0 surfaces this as `Error::NoStorageAccess(PlatformError)`. **hasp implication:** map this to `Error::Backend { kind: Permanent, ... }` with a message that hints at the lock state — it is not `NotFound` (the entry exists but is sealed). ([Arch wiki](https://wiki.archlinux.org/title/GNOME/Keyring))
- **KWallet vs SecretService backend confusion.** v3's auto-detection picks the wrong store on mixed-DE Linux. v4 / `keyring-core` solves this by making selection explicit — `set_default_store(...)` forces hasp to pick. Document the failure mode and the override URL grammar. ([github.com/jaraco/keyring/issues/496](https://github.com/jaraco/keyring/issues/496))
- **macOS Keychain ACL after binary move / re-sign.** Keychain items are tied to creating-process code identity. Binary update or move triggers `errSecAuthFailed` or a UI prompt. Document the constraint; recommend ad-hoc-signed builds use the same identity across releases. ([wojciechregula.blog](https://wojciechregula.blog/post/stealing-macos-apps-keychain-entries/))
- **Windows Credential Roaming syncs across AD-joined machines.** APT29 used this as a lateral-movement vector (CVE-2022-30170). Document that `keyring://` on Windows enterprise is not machine-scoped by default; for machine-scope, recommend DPAPI with `CRYPTPROTECT_LOCAL_MACHINE` (out of `keyring-core` scope; future hasp `dpapi://` backend). ([Mandiant / Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence/apt29-windows-credential-roaming/))
- **Cross-store ambiguity** (`Error::Ambiguous(Vec<Entry>)`). New variant in `keyring-core` 1.0. Multiple matches at the lookup tuple. hasp must surface this explicitly; the wave-1 backend may return `Error::Backend { kind: Permanent, message: "multiple keyring entries match" }` or the URL grammar must support enough specificity to avoid ambiguity. (See RESEARCH-keyring-url-grammar.md.)

---

## Design insights for hasp

1. **Pin `keyring-core` 1.0 (Approach B), not `keyring` 3.x or 4.x.** The 4-days-old release recency is real; the alternative is taking a dep that the upstream maintainers have publicly walked away from. For a greenfield library that intends to be the secrets-handling foundation for the rustpunk portfolio over the next several years, "ride the actively developed path" wins.
2. **Make per-platform store crates `cfg(target_os = "...")`-gated within `hasp-backend-keyring`.** Linux gets `dbus-secret-service-keyring-store` by default with `linux-keyutils-keyring-store` as a Cargo-feature alternative. macOS gets `apple-native-keyring-store`. Windows gets `windows-native-keyring-store`. The user does not see this — it's all behind `Backend::Keyring` in the root crate.
3. **Initialize the default store in `Backend::register` (or equivalent), exactly once.** The `keyring-core` API requires this call before `Entry::new` succeeds. If hasp's `Store` is constructed twice (e.g., by an embedder and a test), the second `set_default_store` fails. Wrap the call in a `OnceCell`-style guard so re-construction is harmless.
4. **Document the keyring `Error` mapping explicitly.** `keyring_core::Error::NoEntry` → `hasp::Error::NotFound`. `Error::NoStorageAccess(_)` → `hasp::Error::Backend { kind: Permanent, message: "keyring locked or unavailable" }`. `Error::PlatformFailure(_)` → `hasp::Error::Backend { kind: Transient, ... }` (most likely transient — DBus disconnect, recoverable). `Error::Ambiguous(_)` → `hasp::Error::Backend { kind: Permanent, message: "multiple matches" }`. `Error::NotSupportedByStore(_)` → `hasp::Error::UnsupportedOperation`. `Error::TooLong(_, _)` and `Error::BadDataFormat(_, _)` → `hasp::Error::Backend { kind: Permanent, ... }`.
5. **Expose the mock store in a `testing` Cargo feature** for downstream consumers (Ferrule integration tests, Spall integration tests, etc.). `keyring-core` ships `mock::Store` always-built; hasp re-exports it under `hasp_backend_keyring::testing::mock_store()` so callers don't need to add `keyring-core` directly to dev-deps.
6. **Surface the v3 → keyring-core migration as a Ferrule blocker.** Ferrule currently pins `keyring = "3"`. It cannot integrate with hasp's keyring backend without simultaneously migrating its own direct usage to `keyring-core` 1.0 — *or* hasp must wrap both versions, which doubles the code. The cleaner path is a coordinated cutover: Ferrule's hasp integration replaces `ferrule-config/src/credentials.rs` calls with `hasp::get("keyring://ferrule/...")`, removing Ferrule's direct `keyring` dep entirely.

---

## Decision criteria (enforced)

NOT valid: implementation effort, migration cost for Ferrule, "v3 is more proven."

ONLY valid:
- Architectural correctness (runtime store selection is a real architectural improvement, not just ergonomics)
- Threat-model soundness (explicit store selection eliminates the KWallet vs Secret Service ambient-detection failure mode)
- Long-term maintainability (active development is on v4 / keyring-core; v3 is in maintenance mode)
- Rustpunk identity (per-backend Cargo features map cleanly onto per-platform store crate selection)

The greenfield greenfield-status of the library makes this an easy call: there is no installed base to migrate. Adopt the new path now, while there is no debt.

---

## Recommendation

**Approach B — pin `keyring-core = "1"` plus per-platform store crates.**

**Confidence:** Medium-high. The "medium" comes from the 4-day recency; the "high" comes from the explicit upstream guidance to use `keyring-core` over `keyring` and the architectural improvements (runtime store selection, explicit error variants, per-platform crate split) being clearly aligned with hasp's design.

**Rationale:**
- `keyring` v4 README: "Do not depend on this crate" ([crates.io/keyring](https://crates.io/crates/keyring)). v3 is end-of-life ([releases page](https://github.com/open-source-cooperative/keyring-rs/releases)). `keyring-core` 1.0 is the only forward-supported library option.
- The runtime store selection in `keyring-core` 1.0 directly addresses the documented `KWallet`-vs-`SecretService` ambient-detection failure mode that v3 has — this is an architectural, not ergonomic, improvement.
- The per-platform store crate split aligns with the locked decision in `notes/scaffold.md` to keep cloud SDKs and OS-specific crates feature-gated and out of the default binary.
- The `Error` enum (`NoEntry`, `NoStorageAccess`, `PlatformFailure`, `Ambiguous`, `NotSupportedByStore`) maps cleanly onto hasp's planned `Error` taxonomy.

**Key risk:** `keyring-core` 1.0 has minimal production exposure. If a critical bug surfaces in the first 6 months, hasp will be one of the first projects to encounter it. **Mitigation:** wrap every `keyring-core` call in `hasp-backend-keyring` so the underlying crate can be swapped without changing hasp's public API. Ship integration tests that exercise the real OS keyring on each supported platform in CI. Subscribe to the `keyring-rs` GitHub releases.

**Threat-model note:** Approach B is strictly better than Approach A on the KWallet-vs-Secret-Service axis (explicit selection, no ambient-detection failure). It is equivalent on macOS Keychain ACL behavior (same OS API) and Windows Credential Manager roaming (same OS API). Documented threat-model gaps inherent to OS keyring use (ambient access by other processes in the same user session, headless container failure, gnome-keyring auto-lock) apply equally to all approaches.

**If wrong:** If `keyring-core` 1.0 turns out to have a critical defect we cannot work around in the first 6 months, fall back to `keyring = "3.6.3"` and accept the EOL status. The boundary inside `hasp-backend-keyring` makes this swap mechanical.

**Rejected alternatives:**
- **Approach A (`keyring = "3"`):** rejected because the maintainers have explicitly moved on. Adopting an EOL crate for a greenfield foundational library calcifies a worse architecture (compile-time store selection, ambient-detection bugs) into hasp's public surface for years. "Ferrule already uses it" is not a valid reason — Ferrule will migrate when hasp lands.
- **Approach C (`keyring = "4"`):** rejected per the upstream's explicit "do not depend on this crate" warning.
- **Wait for `keyring-core` to mature for 6 months:** rejected because it would block Ferrule and Spall (Wave 1 backend is the unblocker). The right move is to adopt now with a thin wrapper that lets us swap if we have to.

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| `keyring-core` v1.0.0 | crate | Recommended dependency | [crates.io](https://crates.io/crates/keyring-core) |
| `keyring-core` rustdoc | docs | API surface | [docs.rs](https://docs.rs/keyring-core/latest/keyring_core/) |
| `keyring` v4.0.0 (deprecated for lib use) | crate | Confirms v4 is sample-only | [crates.io](https://crates.io/crates/keyring) |
| `keyring-rs` releases page | repo | v3.6.3 marked end-of-life | [github](https://github.com/open-source-cooperative/keyring-rs/releases) |
| `keyring-core::Error` enum | docs | Error mapping for hasp | [docs.rs](https://docs.rs/keyring-core/latest/keyring_core/error/enum.Error.html) |
| Apple TN3137 | doc | macOS Keychain modern API path | [link](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) |
| jaraco/keyring #477 | issue | Headless container DBus failure | [link](https://github.com/jaraco/keyring/issues/477) |
| jaraco/keyring #496 | issue | KWallet vs Secret Service confusion | [link](https://github.com/jaraco/keyring/issues/496) |
| Wojciech Regula — macOS Keychain ACL | post | Code-identity ACL gotchas | [link](https://wojciechregula.blog/post/stealing-macos-apps-keychain-entries/) |
| Mandiant — APT29 Windows Credential Roaming | post | Roaming sync as lateral-movement | [link](https://cloud.google.com/blog/topics/threat-intelligence/apt29-windows-credential-roaming/) |
| Ferrule `Cargo.toml` (current) | source | Existing `keyring = "3"` pin | `~/code/rustpunk/ferrule/ferrule-config/Cargo.toml` |
| Arch Linux GNOME/Keyring wiki | doc | Auto-lock semantics | [link](https://wiki.archlinux.org/title/GNOME/Keyring) |
