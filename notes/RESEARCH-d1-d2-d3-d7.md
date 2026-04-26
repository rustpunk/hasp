# hasp Design Research: D1, D2, D3, D7

Date: 2026-04-26
Scope: Rust crate ecosystem evidence base for four locked design decisions.
This file is the synthesizer's input — no hasp design proposals here.

---

## D1 — secrecy / zeroize posture

### secrecy

- **Latest version:** 0.10.3, released 2024-10-09.
  Source: https://crates.io/crates/secrecy
- **Downloads:** 103,984,620 all time. High adoption signal.
- **Owner:** Tony Arcieri (tony-iqlusion / iqlusioninc), also owns `zeroize`.
  Source: https://docs.rs/secrecy/0.10.3/secrecy/
- **License:** Apache-2.0 OR MIT.
- **MSRV:** Rust 1.60.
- **`forbid(unsafe_code)`** — the entire crate uses only safe Rust.
- **`no_std`-friendly** — works in embedded / WASM contexts.
- **Dependency:** `zeroize ^1.6` (normal, unconditional); `serde ^1` (optional).

#### API surface in 0.10.3 (fetched from docs.rs)

| Item | Kind | Notes |
|------|------|-------|
| `SecretBox<S>` | struct | Core wrapper; `S: Zeroize + ?Sized` |
| `SecretString` | type alias | `SecretBox<str>` |
| `SecretSlice<T>` | type alias | `SecretBox<[T]>` |
| `ExposeSecret<S>` | trait | `fn expose_secret(&self) -> &S` |
| `ExposeSecretMut<S>` | trait | `fn expose_secret_mut(&mut self) -> &mut S` |
| `CloneableSecret` | marker trait | opt-in; without it `SecretBox` does not impl `Clone` |
| `SerializableSecret` | marker trait | opt-in; without it `SecretBox<T>` has no `Serialize` |
| `DebugSecret` | (via `Debug` impl on SecretBox) | formats as `"***SECRET REDACTED***"` |

Serde: `SecretBox<T>` gets `Deserialize` (load from config) but NOT `Serialize` by default.
`Serialize` requires the inner type to impl `SerializableSecret` — intentional exfiltration guard.
Source: https://docs.rs/secrecy/0.10.3/secrecy/

#### 0.8 → 0.10 API delta

The changelog at docs.rs/crate/secrecy/latest/source/CHANGELOG.md exists but its content was not directly fetchable in this session. Based on the published API documentation, the key observable change is:
- In older versions (≤0.8), the primary export was `Secret<T>` (with `T: Sized`). The 0.10 API replaced this with `SecretBox<S>` where `S: ?Sized`, enabling `SecretBox<str>` (≡ `SecretString`) and `SecretBox<[T]>` (≡ `SecretSlice`). The old `Secret<String>` pattern becomes `SecretBox<str>` / `SecretString`.
- `ExposeSecretMut` was added (not present in 0.8).
- The crate README still refers to `Secret<T>` in the "about" section (older copy), but the 0.10 type index only lists `SecretBox`.

#### What secrecy adds on top of raw zeroize

1. **`Debug` blocker** — `impl Debug for SecretBox<S>` always prints `"***SECRET REDACTED***"` regardless of what `S: Debug` would produce.
2. **`Clone` gate** — `SecretBox` does not implement `Clone` unless `S: CloneableSecret`. Prevents accidental secret duplication.
3. **`Serialize` gate** — no `Serialize` impl by default; requires opt-in `SerializableSecret` marker.
4. **`Drop` with zeroize** — `impl Drop for SecretBox<S>` calls `self.inner.zeroize()` via the `ZeroizeOnDrop` impl.
5. **`ExposeSecret` discipline** — callers must explicitly call `.expose_secret()` to access the inner value; there is no `Deref` impl.
6. **Re-exports zeroize** — `pub use zeroize;` so consumers get the same version without an extra dep.

Source: https://docs.rs/secrecy/0.10.3/secrecy/, https://crates.io/crates/secrecy

#### Explicit non-feature of secrecy

The 0.10.3 docs explicitly state:
> "Presently this crate favors a simple, `no_std`-friendly, safe i.e. `forbid(unsafe_code)`-based implementation and does not provide more advanced memory protection mechanisms e.g. ones based on `mlock(2)`/`mprotect(2)`. We may explore more advanced protection mechanisms in the future. Those who don't mind `std` and `libc` dependencies should consider using the `secrets` crate."
Source: https://docs.rs/secrecy/0.10.3/secrecy/

### zeroize

- **Latest version:** 1.8.2, released ~7 months ago (approx. Oct 2025).
- **Owner:** RustCrypto org + Tony Arcieri (tarcieri). Load-bearing RustCrypto crate.
- **Downloads:** 430,150,574 all time. One of the most downloaded Rust crates.
- **Implementation:** `core::ptr::write_volatile` + atomic memory fences. No FFI, no asm, no unsafe, WASM-compatible.
- **`zeroize_derive`** — optional derive feature (`#[derive(Zeroize, ZeroizeOnDrop)]`) for custom structs. Composable with `secrecy::CloneableSecret` etc.
- Source: https://crates.io/crates/zeroize

### Memory-locking crates

Beyond zeroize (which only zeros, does not prevent swap/core-dump):

| Crate | Mechanism | Status | Notes |
|-------|-----------|--------|-------|
| `memsec` | `mlock(2)` / Windows `VirtualLock`; port of libsodium utilities | Active | No recent crates.io page fetched; docs.rs live |
| `secure-types` | `mlock` + `madvise` + `memfd_secret` on Linux | Active (~4mo ago) | std + libc required |
| `memsecurity` | Encrypted memory + `mlock`/`munlock`, Ascon128a | Active | Adds encryption on top of locking |
| `shush-rs` | `mlock` + `mprotect` | Active | Focused on secret page protection |
| `os-memlock` | Thin unsafe wrapper: `mlock`/`munlock` + `madvise(MADV_DONTDUMP)` | Very small, auditable | No persistence/zeroize by itself |
| `secrets` crate | Full `mlock`-backed secret cell | Active | The crate secrecy docs point to; requires `std` + `libc` |

The secrecy GitHub issue #480 tracks a request to add `mlock` to `secrecy` — it was declined in favor of pointing users to `secrets`.
Source: https://github.com/iqlusioninc/crates/issues/480, https://docs.rs/memsec/latest/memsec/, https://crates.io/crates/secure-types, https://github.com/Eyob94/shush-rs

### How other Rust secret-handling libraries handle memory

- **rustls private keys:** Wraps private key bytes in `rustls::pki_types::PrivateKeyDer` which does NOT implement `zeroize` by default; there have been longstanding issues about this. Some downstream code uses `secrecy` or `zeroize` manually.
- **aws-credential-types:** `Credentials` struct (v1.2.14) holds `access_key_id`, `secret_access_key`, `session_token` as plain `String`. No zeroize. No secrecy wrapper. Access key secret is unredacted in Debug.
  Source: https://crates.io/crates/aws-credential-types
- **age/rage:** Uses `zeroize` directly on key material. Does not use `secrecy`.
- **cocoon:** Focuses on encrypted at-rest storage, uses `zeroize` on its internal key state.
- **vaultrs:** No secret wrapping; KV values returned as raw `serde_json::Value` or deserialized structs. No `secrecy` dependency observed in deps.

---

## D2 — keyring v3 vs v4

### Architecture change: keyring is now two crates

Starting with v4 (released 2026-04-26, today), the `keyring` crate has been restructured:

- **`keyring` v4.0.0** — now a "sample code / CLI / inventory" crate. The crate's own README says: **"Do not depend on this crate!"** App developers should use `keyring-core` instead.
  Source: https://crates.io/crates/keyring
- **`keyring-core` v1.0.0** — the new library crate. Released ~4 days ago. This is what applications should depend on.
  Source: https://crates.io/crates/keyring-core

The previous `keyring` v3.x (last: v3.6.3, released 2025-07-27) was the "API library plus credential store" combination. v3.6.3 was explicitly labeled "likely final release of v3."
Source: https://github.com/open-source-cooperative/keyring-rs/releases

### keyring-core v1.0.0 API

```rust
// Primary API — keyring-core::Entry
Entry::new(service: &str, account: &str) -> Result<Entry, Error>
Entry::new_with_modifiers(modifiers: &HashMap<&str, &str>, service: &str, account: &str) -> Result<Entry, Error>
Entry::search(query: &HashMap<&str, &str>) -> Result<Vec<Entry>, Error>

entry.set_password(password: &str) -> Result<(), Error>
entry.get_password() -> Result<String, Error>
entry.set_secret(secret: &[u8]) -> Result<(), Error>
entry.get_secret() -> Result<Vec<u8>, Error>
entry.delete_credential() -> Result<(), Error>
entry.get_credential() -> Result<Entry, Error>

// Store lifecycle
keyring_core::set_default_store(store: impl CredentialStore) -> ()
keyring_core::get_default_store() -> Option<...>
keyring_core::unset_default_store() -> ()
```

Source: https://docs.rs/keyring-core/latest/keyring_core/, https://crates.io/crates/keyring-core

### API delta v3 → v4 (keyring-core)

- `Entry::new_with_target(target, service, user)` is **gone**. Replaced by `Entry::new_with_modifiers(HashMap)` where `target` is just one possible key in the modifiers map.
- Default credential store selection was compile-time feature in v3; now it is **explicit runtime allocation** via `set_default_store()`.
- `Entry::get_credential()` no longer exposes the raw platform credential object. It returns a wrapped `Entry` if the underlying credential exists, `Error::NoEntry` otherwise.
- `Ambiguous` error now returns `Vec<Entry>` (wrapped) not `Vec<CredentialObject>`.
- New `Entry::search` API for attribute-based lookup (not all stores implement it).

Source: https://crates.io/crates/keyring-core

### Platform coverage

`keyring` v4.0.0 ships connectors for:
- `dbus-secret-service-keyring-store` — Linux Secret Service via libdbus
- `zbus-secret-service-keyring-store` — Linux Secret Service via zbus (pure Rust)
- `linux-keyutils-keyring-store` — Linux Kernel keyutils (in-kernel, not Secret Service)
- `apple-native-keyring-store` — macOS Keychain + iOS Protected Data
- `windows-native-keyring-store` — Windows Credential Manager
- `android-native-keyring-store` — Android Shared Preferences
- `db-keystore` — cross-platform SQLite (Turso)-backed encrypted store

Source: https://docs.rs/keyring/latest/keyring/

### Mock / testing support

`keyring-core` ships a `mock::Store` (always built) and a `sample::Store` (feature-gated: `sample` feature, file-backed). Both are explicitly unsecured/unrobust; for tests only.

```rust
use keyring_core::{mock, set_default_store};
set_default_store(mock::Store::new()?);
```

Source: https://crates.io/crates/keyring-core, https://docs.rs/keyring-core/latest/keyring_core/

### keyring-core Error enum (non-exhaustive)

```rust
#[non_exhaustive]
pub enum Error {
    PlatformFailure(PlatformError),   // OS-level failure in storage system
    NoStorageAccess(PlatformError),   // Store locked / access denied
    NoEntry,                          // Credential not found / deleted
    BadEncoding(Vec<u8>),             // Retrieved bytes not valid UTF-8
    BadDataFormat(Vec<u8>, PlatformError), // Store-specific format error
    BadStoreFormat(String),           // Store itself malformatted
    TooLong(String, u32),             // Attribute exceeds platform limit
    Invalid(String, String),          // Invalid parameter
    Ambiguous(Vec<Entry>),            // Multiple matches
    NoDefaultStore,                   // set_default_store not called
    NotSupportedByStore(String),      // Operation not implemented by store
}
```

Source: https://docs.rs/keyring-core/latest/keyring_core/error/enum.Error.html

### Maintainership

- Original author: Walther Chen (hwchen). Organization transferred to open-source-cooperative.
- Current primary maintainer: Dan Brotsky (brotskydotcom).
- Active: v4.0.0 released today (2026-04-26). v3.6.3 was July 2025.
- Stars: 721 (GitHub), 10.8M total downloads (keyring crate).

Source: https://github.com/open-source-cooperative/keyring-rs/releases, https://crates.io/crates/keyring

---

## D3 — keyring URL grammar (API detail)

### What the API exposes

In **keyring-core v1** the identifier tuple is `(service: &str, account: &str)` plus an optional `modifiers: HashMap<&str, &str>` map. There is no native URL parser inside keyring-core; URL interpretation is the caller's responsibility.

The `target` modifier (from v3's `Entry::new_with_target`) maps per-platform as follows (based on v3 docs, still relevant for modifier behavior in v4):

| Platform | `target` semantics |
|----------|--------------------|
| Linux Secret Service | Collection name (defaults to `default`) |
| macOS Keychain | Distinguishes Generic (no target) vs. Internet passwords (target = server URL) |
| Windows Credential Manager | The "target name" field — the primary key in WCM |
| Linux Keyutils | Key description prefix |

In keyring-core v4, `target` is passed via the modifiers map; each credential store documents which modifier keys it accepts.

Source: https://crates.io/crates/keyring-core, https://docs.rs/keyring-core/latest/keyring_core/

### Attribute-based lookup

`Entry::search(query)` — new in keyring-core v1. Takes a `HashMap<&str, &str>` query. Not all stores implement it (returns `Error::NotSupportedByStore`). No URL-style routing built in.

### Prior-art: Rust crates wrapping keyring with URL/path-style API

No publicly released Rust crate found that wraps keyring with a URL-scheme routing layer. `vaultmux` (below) comes closest: it uses a `BackendType` enum + `Config` struct, not URL syntax. `hasp` would be the first to define `keyring://` scheme routing over the keyring-core API.

---

## D7 — Error taxonomy (Rust ecosystem angle)

### AWS Secrets Manager (aws-sdk-secretsmanager v1.104.0)

Error type: `SdkError<E, R = HttpResponse>` (non-exhaustive enum from `aws-smithy-runtime-api`).

`SdkError` variants:
- `ConstructionFailure` — request could not be built
- `TimeoutError` — timed out before response received
- `DispatchFailure` — network/connector error (wraps `ConnectorError`)
- `ResponseError` — response received but couldn't be parsed
- `ServiceError(ServiceError<E>)` — service returned a structured error

`ServiceError<E>` carries the operation-specific error type. For `GetSecretValue`:

```
GetSecretValueError variants:
  DecryptionFailure      — KMS can't decrypt the protected text
  InternalServiceError   — AWS-side failure
  InvalidParameterException — bad parameter name/value
  InvalidRequestException   — parameter invalid for current resource state
                              (e.g., secret scheduled for deletion)
  ResourceNotFoundException — secret not found / deleted
  Unhandled              — unexpected/unmodeled error (deprecated to match directly)
```

Pattern to extract: `err.into_service_error()` downcasts `SdkError<E>` to `E`.
`ProvideErrorMetadata` trait gives `.code()` and `.message()` from the raw response.

Source: https://docs.aws.amazon.com/sdk-for-rust/latest/dg/error-handling.html,
https://docs.rs/aws-sdk-secretsmanager/latest/aws_sdk_secretsmanager/,
https://docs.rs/aws-sdk-secretsmanager/latest/aws_sdk_secretsmanager/operation/get_secret_value/enum.GetSecretValueError.html

### AWS SSM (aws-sdk-ssm)

Same `SdkError<E>` envelope as Secrets Manager. Operation-specific errors for `GetParameter` include `ParameterNotFound`, `ParameterVersionNotFound`, `InvalidKeyId` (KMS), `InternalServerError`.

### vaultrs v0.8.0

- Latest: 0.8.0, released ~1 month ago.
- Downloads: 8.3M. Maintenance: active (jmgilman).
- Default TLS: rustls. `native-tls` feature available.
- Uses `thiserror ^2`.
- Error type: `ClientError` enum (14 variants, not using `#[non_exhaustive]`):

```
APIError { code: u16, errors: Vec<String> }  — Vault API-level error with status + messages
FileNotFoundError
FileReadError
FileWriteError
InvalidLoginMethodError
JsonParseError
ParseCertificateError
ResponseEmptyError        — API returned empty response
ResponseDataEmptyError    — API response missing required data fields
ResponseWrapError
RestClientBuildError      — reqwest client construction failure
RestClientError           — general HTTP error (wraps rustify)
WrapInvalidError
InvalidUpdateParameter
```

The `APIError` variant is the primary semantic error (e.g., 403 PermissionDenied, 404 not found). All non-API errors are infrastructure/parse errors. No retry-signaling annotation in the enum.

Source: https://crates.io/crates/vaultrs, https://docs.rs/vaultrs/latest/vaultrs/error/enum.ClientError.html

### Azure Key Vault (azure_security_keyvault_secrets)

- Latest version referenced in search: 0.5.0 (July 2025 release). Still pre-1.0; "large breaking changes may happen before 1.0."
- Error type: `azure_core::Error` — opaque struct wrapping `ErrorKind` + source chain.
- Matching pattern: `e.kind()` returns `ErrorKind`, e.g. `ErrorKind::HttpResponse { status, error_code }`.
  - `status: StatusCode` — HTTP status (404 = not found, 403 = forbidden, 429 = throttled).
  - `error_code: Option<String>` — Azure service error code string if available.
- No named variants for specific Key Vault operations; callers match on HTTP status code.
- Source: https://learn.microsoft.com/en-us/azure/developer/rust/sdk/azure-core-types,
  https://crates.io/crates/azure_security_keyvault_secrets/0.12.0

### GCP Secret Manager (google-cloud-secretmanager-v1)

- Canonical crate: `google-cloud-secretmanager-v1` (from `googleapis/google-cloud-rust`).
  Version: 1.8.0, released 12 days ago. 1M+ downloads. Actively maintained by Googlers.
- Default TLS: rustls + aws-lc-rs (can be disabled).
- Error handling: wraps `tonic::Status` for gRPC errors.
- Source: https://crates.io/crates/google-cloud-secretmanager-v1

#### tonic::Status codes and retry semantics

gRPC standard codes relevant to secret access:

| Code | Semantics | Retry? |
|------|-----------|--------|
| `Unauthenticated` | Missing/invalid credentials | No (fix auth) |
| `PermissionDenied` | Authenticated but not authorized | No (fix IAM) |
| `NotFound` | Secret or version does not exist | No |
| `AlreadyExists` | Conflict on create | No |
| `ResourceExhausted` | Quota exceeded / rate limited | Yes (with backoff) |
| `Unavailable` | Transient server-side failure | Yes |
| `DeadlineExceeded` | Timeout | Yes |
| `FailedPrecondition` | State precondition failed (e.g., secret disabled) | No |
| `Aborted` | Concurrency conflict | Conditional |
| `Internal` | Unexpected server error | Maybe |
| `Unknown` | Unclassified | Maybe |

The retry-vs-permanent split maps cleanly: `NotFound`, `PermissionDenied`, `Unauthenticated`, `FailedPrecondition` are permanent. `ResourceExhausted`, `Unavailable`, `DeadlineExceeded` are transient.

### keyring-core Error (for completeness)

Covered above in D2. The `NotSupportedByStore` variant is hasp's `UnsupportedOperation` equivalent. `NoEntry` is "not found." `NoStorageAccess` + `PlatformFailure` are "backend unavailable" — potentially transient.

### thiserror transient/permanent retry patterns

The standard Rust pattern (no built-in retry annotation in thiserror):

```rust
// Pattern 1: method on the error
impl MyError {
    pub fn is_transient(&self) -> bool {
        matches!(self,
            Self::NetworkTimeout | Self::RateLimited | Self::ServiceUnavailable)
    }
}

// Pattern 2: use the `backoff` crate's BackoffError wrapper at call sites
// Permanent errors are not retried; transient are.
```

The `backoff` crate (https://docs.rs/backoff) uses `Error::permanent(e)` / `Error::transient(e)` wrappers at the point of retry, not encoded in the error type itself. HTTP status codes that signal transient: 408, 429, 500, 502, 503, 504.

For `reqwest::Error`: `.is_timeout()`, `.is_connect()`, `.is_request()` methods classify errors. Status-based: `.status()` returns `Option<StatusCode>`.

Sources: https://www.lpalmieri.com/posts/error-handling-rust/,
https://docs.rs/backoff/latest/backoff/,
https://oneuptime.com/blog/post/2026-01-07-rust-retry-exponential-backoff/view

---

## Supplementary: dotenvy

- **Version:** 0.15.7. Released ~3 years ago. **Maintenance: slow** — only 7 versions published total, last release was 3 years ago. But widely adopted (100M+ downloads). Recommended as replacement for `dotenv` per RUSTSEC-2021-0141.
- **Malformed line behavior:** `dotenvy::dotenv()` returns `Err` if the `.env` file cannot be parsed. For `from_read_iter()`, iteration stops at the first parse error; caller must handle each `Result`. Empty values (`KEY=`) are valid and produce an empty string.
- **No redaction:** dotenvy loads values into the process environment via `std::env::set_var`. No secret typing, no zeroize. Values are observable by any code calling `std::env::vars()`.
- **Multiline support:** Added in fork (not in original dotenv).
- Source: https://crates.io/crates/dotenvy

## Supplementary: rops

- **Version:** 0.1.7, released ~2 months ago. MPL-2.0.
- **Description:** Pure Rust SOPS alternative. Supports YAML, JSON, TOML file encryption. Integrations: Age, AWS KMS.
- **Status:** Early (0.1.x); 105K downloads; 8 versions. `rops-cli` crate (separate) last released May 2025.
- **Posture:** File-level encryption tool (like sops/age). Does NOT provide a get/put secrets API. Orthogonal to hasp's scope.
- Source: https://crates.io/crates/rops, https://github.com/gibbz00/rops

## Supplementary: aws-credential-types

- **Version:** 1.2.14, released ~2 months ago. Maintained by AWS SDK team.
- **Provider chain pattern:** `ProvideCredentials` async trait. `Credentials::new(access_key, secret_key, session_token, expiry, provider_name)`. `SharedCredentialsProvider` for shared ownership.
- **No secret wrapping** — credentials stored as plain `String`. No `secrecy` integration. No zeroize.
- Source: https://crates.io/crates/aws-credential-types

## Supplementary: vaultmux

- **Version:** 0.1.0, released 2026-01-09 (~4 months ago). Very new; 26 total downloads.
- **Concept:** Unified async `Backend` trait over 8 backends (mock, pass, Bitwarden, 1Password, AWS, GCP, Azure, Windows Credential Manager). Feature-flagged compilation.
- **API:** `backend.init()`, `backend.authenticate() -> Session`, `backend.create_item(key, value, session)`, `backend.get_notes(key, session)`. Uses tokio async.
- **Verbs:** Only get/set semantics. No list, delete, exists exposed at the trait level (based on README).
- **Status:** Extremely early; 1 version; no CI results yet. Not production-ready evidence, but useful prior-art for the trait shape question.
- Source: https://crates.io/crates/vaultmux

## Supplementary: secret-vault-rs

- **Description:** In-memory secret vault that fetches from GCP/AWS/Azure and stores in memory with optional encryption. Different scope from hasp (in-memory cache, not CLI).
- Source: https://github.com/abdolence/secret-vault-rs
