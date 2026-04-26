# RESEARCH-error-taxonomy

> Decision: shape of `hasp::Error` and `BackendFailureKind` that survives every cloud and on-prem backend hasp will ever ship.
>
> Date: 2026-04-26
> Audience: hasp-core authors, every backend implementer
> Status: recommendation, awaiting design lock

---

## Core question

The locked draft is `Error::{ NotFound, PermissionDenied, Backend { scheme, kind: BackendFailureKind, message } }` with `BackendFailureKind { Transient, Permanent, Unknown }`. Is this sufficient, too coarse, or too rich? What do AWS / Vault / Azure / GCP error hierarchies actually require? What classification depth do downstream callers (retry policies, fallback chains) really act on?

This shape is a public-API contract. Get it wrong at v1 and every consumer either string-matches `message` or can't implement correct retry behavior. Get it right and consumers write `match` arms that mean what they say.

---

## The landscape

The five backends hasp will eventually ship surface different error vocabularies. Mapping them to a unified taxonomy requires deciding which variants are first-class and which collapse into `Backend { kind, message }`.

| Backend | Auth missing | Auth invalid | No permission | Not found | Throttled | Transient | Sealed/disabled state |
|---------|--------------|--------------|---------------|-----------|-----------|-----------|------------------------|
| AWS Secrets Manager | `UnrecognizedClientException`, `ExpiredTokenException` | same (collapsed) | `AccessDeniedException` | `ResourceNotFoundException` | `ThrottlingException`, `LimitExceededException` | `InternalServiceError`, dispatch/timeout | `InvalidRequestException` (state mismatch — secret scheduled for deletion) |
| AWS SSM | same | same | `AccessDeniedException` | `ParameterNotFound`, `ParameterVersionNotFound` | `ThrottlingException`, `RequestTimeoutException` | `InternalServerError`, dispatch/timeout | n/a |
| Vault | n/a (token in body) | 403 — **ambiguous with no-permission** | 403 — **ambiguous with bad-token** | 404 — **ambiguous with no-permission (intentional leak prevention)** | 429 | 500/502/503 (sealed; standby) | 503 (sealed); 412 (eventual-consistency lag, "should retry") |
| GCP Secret Manager (gRPC) | `UNAUTHENTICATED` | same | `PERMISSION_DENIED` | `NOT_FOUND` | `RESOURCE_EXHAUSTED` | `UNAVAILABLE`, `DEADLINE_EXCEEDED` | `FAILED_PRECONDITION` (version DISABLED) |
| Azure Key Vault | 401 | 401 | 403 | 404 | 429 (~4,000 req/10s general) | 500 | 403 + `error.code: SecretDisabled` (NOT a permission error); 409 + `ObjectIsBeingDeleted` |

Two important subtleties surface immediately:

1. **Vault's 403/404 ambiguity is intentional.** Vault deliberately collapses "not found" and "no permission" on 404 to prevent state leakage. A caller cannot tell whether the secret exists. hasp must choose: surface as `NotFound` (matches Vault's exposed semantics; loses the "you have no permission" signal) or surface as `PermissionDenied` (false-positive; the secret may genuinely not exist). The honest choice is `NotFound` — Vault has already decided to hide the distinction; hasp should not re-introduce it ([HashiCorp Vault API docs](https://developer.hashicorp.com/vault/api-docs#error-response)).

2. **Azure's `SecretDisabled` returns 403 but is NOT a permission error** — it's a state error (the secret exists, the caller has permission, the version is disabled). Mapping it to `PermissionDenied` is semantically wrong; callers attempting to "fix the permission" never succeed. The natural mapping is to a state-error variant — analogous to GCP's `FAILED_PRECONDITION`.

The retry-policy literature is clear: mature SDKs use **2-class classification** (Transient + Throttle, with Permanent as the implicit residual), not 3-class. AWS smithy-rs, GCP AIP-194, Azure SDK, the `backoff` crate, Tower's `Policy` trait — none of them encode "Unknown" as a distinct retry class. "Unknown" gets collapsed: AWS treats unclassified as "no action" (don't retry); `backoff::Error` has only `Permanent` and `Transient { retry_after }`.

The single variant that consistently warrants its own class is **Throttled / RateLimited**. Every backend signals this distinctly (AWS `x-amz-retry-after` header, GCP `RetryInfo` detail proto, Azure `Retry-After` header, Vault `Retry-After`); ignoring the signal causes the documented "burns quota" failure mode where retrying without backoff compounds throttling.

The auth-vs-permission split is meaningful on GCP and Azure (they distinguish at the protocol level: 401 vs 403; UNAUTHENTICATED vs PERMISSION_DENIED). AWS and Vault collapse them (one HTTP status / one error variant covers both). For hasp to expose the distinction reliably, it would need to elevate `AuthenticationFailed` to a top-level variant alongside `PermissionDenied`. The cost is one extra variant; the benefit is correct retry decisions on the backends that distinguish (and graceful degradation to `PermissionDenied` on the backends that don't, which is the only honest mapping anyway).

The Rust SDK literature shows that **flat enums beat nested `SdkError<E>::ServiceError { err: GetObjectError { kind: GetObjectErrorKind::NoSuchKey } }`** patterns. The AWS SDK's three-level nesting forces consumers into string-matching `err.code() == Some("NoSuchKey")` because typed matches are unwieldy ([github.com/awslabs/aws-sdk-rust/issues/572](https://github.com/awslabs/aws-sdk-rust/issues/572)). hasp's flat `thiserror` enum at `hasp-core` is the right shape; the question is only what variants populate it.

---

## Approach A: minimal flat enum (current locked draft)

```rust
pub enum Error {
    UrlParse(#[from] url::ParseError),
    UnknownScheme(String),
    UnsupportedOperation { scheme: &'static str, operation: &'static str },
    NotFound(String),
    PermissionDenied(String),
    Backend {
        scheme: &'static str,
        kind: BackendFailureKind,
        message: String,
    },
    ProfileNotFound(String),
    ProfileKeyNotFound { profile: String, key: String },
}

pub enum BackendFailureKind {
    Transient,
    Permanent,
    Unknown,
}
```

**Strengths:**
- Small, easy to remember.
- Maps Vault 403/404 ambiguity reasonably (both → `NotFound` or `PermissionDenied` per backend choice).
- Captures the two most important user-action distinctions: not-found (prompt user) and permission-denied (warn).

**Weaknesses / failure modes:**
- **`Unknown` is dead weight.** No SDK in the survey treats Unknown distinctly from Permanent. Consumers will write `match _ => retry`-style catch-alls that swallow it. ([Survey: AWS smithy-rs, GCP AIP-194, Azure SDK, Rust `backoff` crate.](https://docs.aws.amazon.com/sdkref/latest/guide/feature-retry-behavior.html))
- **No `Throttled` variant.** Consumers cannot honor `Retry-After` without parsing `Backend.message` strings. The documented failure mode (retry without backoff compounds throttling, burns quota) becomes a hasp-API-induced bug.
- **No auth-vs-permission distinction.** GCP and Azure expose this; hasp collapses it. Operators who page on `AuthenticationFailed` (creds expired, rotate them) versus `PermissionDenied` (creds valid, fix the IAM policy) cannot route alerts correctly.
- **No state-error variant.** Azure `SecretDisabled` and GCP `FAILED_PRECONDITION` map awkwardly to `PermissionDenied` (wrong semantically) or `Backend { Permanent }` (loses signal).

---

## Approach B: refined flat enum — drop `Unknown`, add `Throttled` and `AuthenticationFailed`

```rust
pub enum Error {
    UrlParse(#[from] url::ParseError),
    InvalidUrl(String),                      // scheme-specific URL violation
    UnknownScheme(String),
    UnsupportedOperation { scheme: &'static str, operation: &'static str },

    NotFound(String),
    PermissionDenied(String),
    AuthenticationFailed(String),            // creds invalid/missing/expired (vs PermissionDenied = creds valid)
    PreconditionFailed(String),              // disabled, deleted-but-recoverable, sealed-with-manual-unseal

    Backend {
        scheme: &'static str,
        kind: BackendFailureKind,
        message: String,
    },

    // CLI-only types live in hasp-cli, NOT here:
    // ProfileNotFound / ProfileKeyNotFound move out per RESEARCH-profile-resolver-scope.md
}

pub enum BackendFailureKind {
    /// Temporary failure; safe to retry with exponential backoff.
    /// Covers: timeouts, connection refused, 5xx server errors, gRPC UNAVAILABLE.
    Transient,

    /// Backend rate-limited the caller. Honor any Retry-After signal in `Backend.message`
    /// or in a future `retry_after: Option<Duration>` field.
    /// Covers: AWS ThrottlingException, HTTP 429, gRPC RESOURCE_EXHAUSTED.
    Throttled,

    /// Permanent failure unless external action is taken (config change, operator intervention).
    /// Covers: validation errors, malformed requests, unrecognized resources at the backend layer
    /// that don't fit a more specific top-level variant.
    Permanent,
}

impl Error {
    /// Returns true if a retry has any chance of succeeding without external action.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Backend { kind: BackendFailureKind::Transient | BackendFailureKind::Throttled, .. }
        )
    }
}
```

**Strengths:**
- **Drops `Unknown`** — every SDK in the survey collapses unclassified errors into Permanent. Doing the same in hasp matches consumer expectations.
- **Adds `Throttled` as a first-class kind** — every cloud backend emits a distinct rate-limit signal with `Retry-After`. Without this variant, consumers cannot implement correct rate-limit honoring without string-matching `message`. With it, `if matches!(err, Error::Backend { kind: Throttled, .. }) { sleep(retry_after); retry(); }` is correct.
- **Adds `AuthenticationFailed`** alongside `PermissionDenied` — GCP and Azure protocols distinguish; hasp surfaces it. AWS and Vault map both to `PermissionDenied` (the protocol forces it; we don't invent signal).
- **Adds `PreconditionFailed`** for state errors that are neither auth nor permission nor transient — covers Azure `SecretDisabled`, GCP `FAILED_PRECONDITION`, Vault sealed-with-manual-unseal.
- **`InvalidUrl(String)`** explicitly carries scheme-specific URL violations distinct from `UrlParse(url::ParseError)`. The latter is for malformed URLs at the parser layer; the former is for syntactically valid URLs that don't satisfy a backend's grammar (e.g., `keyring://foo/bar/baz` where `keyring://` only allows two path segments — see `RESEARCH-keyring-url-grammar.md`).
- **`is_transient(&self) -> bool` predicate** — gives consumers a one-liner for "should I retry?" without forcing them to enumerate variants. Mirrors the `reqwest::Error::is_timeout()` / `reqwest::Error::is_connect()` pattern that Rust users expect.
- **`ProfileNotFound` / `ProfileKeyNotFound` moved out** — per `RESEARCH-profile-resolver-scope.md`, profile resolution is CLI-only; the variants belong in `hasp-cli`, not in `hasp-core`.

**Weaknesses / failure modes:**
- Wider variant set; consumers writing exhaustive `match` arms have more cases to cover. Mitigation: variants are added with explicit user-action semantics (what does the caller do differently?), so each one earns its place.
- `AuthenticationFailed` will only be distinct on GCP and Azure backends; AWS and Vault backends will map both to `PermissionDenied` because the protocol doesn't distinguish. Document this; it's not hasp's bug.
- A future Throttled variant may need to carry a `retry_after: Option<Duration>` field. Rather than encode it now (premature), retain the option to migrate by being explicit that Throttled's `Backend.message` field is the place hasp will surface backend-provided Retry-After hints in v0.x; promote to a typed field at v1.0 if a clear pattern emerges.

---

## Approach C: typed retry-policy SDK-style nesting

```rust
pub enum Error {
    SdkError(SdkErrorKind),
    Backend(BackendError<BackendKind>),
    ...
}
pub struct BackendError<K> { kind: K, source: Box<dyn StdError> }
pub enum BackendKind { S3 { details: ... }, Vault { code: u16, ... } }
```

**Reject this approach.** This is the AWS SDK pattern that consumers consistently work around with string-matching ([github.com/awslabs/aws-sdk-rust/issues/572](https://github.com/awslabs/aws-sdk-rust/issues/572)). hasp's flat enum is intentionally not this shape; the locked architecture is correct on this axis.

---

## Benchmark data

Not applicable. Error construction and matching are sub-microsecond operations dominated by string allocation. No benchmark would change the architectural choice.

---

## Threat-model / standards anchors

| Source | Year | Body | Relevant insight | URL |
|--------|------|------|-----------------|-----|
| GCP AIP-194 | 2024 | Google | Formal retry guidance: only UNAVAILABLE auto-retryable for GET; DEADLINE_EXCEEDED conditional; RESOURCE_EXHAUSTED explicitly NOT auto-retryable (use application-level logic) | [link](https://google.aip.dev/194) |
| AWS smithy-rs RFC discussion #3050 | 2024 | AWS | Two retry classes only (Transient, Throttle); auth/permanent fall through to "no action" | [link](https://github.com/smithy-lang/smithy-rs/discussions/3050) |
| Vault HTTP API error response | current | HashiCorp | 403/404 ambiguity is intentional state-leakage prevention; sealed/standby are distinct status codes | [link](https://developer.hashicorp.com/vault/api-docs#error-response) |
| Azure Key Vault common error codes | current | Microsoft | 401 vs 403 split (Unauthenticated vs Forbidden); `SecretDisabled` returns 403 but is a state error | [link](https://learn.microsoft.com/en-us/azure/key-vault/general/common-error-codes) |

---

## Failure modes / CVEs to avoid

- **AWS Rust SDK 3-level nesting → string-matching escape hatch.** `S3::NoSuchKey` requires `match SdkError::ServiceError { err: GetObjectError { kind: GetObjectErrorKind::NoSuchKey(_) } }` — consumers fall back to `match err.code() { Some("NoSuchKey") }`. Open since July 2022 ([github.com/awslabs/aws-sdk-rust/issues/572](https://github.com/awslabs/aws-sdk-rust/issues/572)). hasp's flat enum avoids this by construction.
- **AWS SDK Java v1 → v2 error class rename broke every catch block.** `AmazonClientException` → `SdkClientException`. Consumers with typed catch blocks stopped compiling ([AWS Java migration doc](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/migration-exception-changes.html)). **Lesson:** the error type is a stable public API surface. Design with enough headroom at 0.x to avoid forced renames at 1.0. Approach B's variant set is judged against this: each variant exists because at least one major backend produces it; we are not over-fitting to one backend.
- **AWS DynamoDB programming guide:** retrying on `AccessDeniedException` burns quota; retrying on `ThrottlingException` without backoff compounds throttling ([AWS docs](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.Errors.html)). **hasp implication:** distinct variants for `PermissionDenied` (caller stops, surfaces to operator) and `Throttled` (caller waits, retries) are required. Approach B has both; Approach A's `BackendFailureKind { Permanent }` collapses the throttle case.
- **AWS credential-load failures surface as a generic string in the Rust SDK** — `"An error occurred while loading credentials"` — unmatable, non-discriminating ([github.com/awslabs/aws-sdk-rust/issues/1381](https://github.com/awslabs/aws-sdk-rust/issues/1381)). hasp's `AuthenticationFailed(String)` carries the message but at least the variant is matchable, allowing consumers to distinguish "rotate creds" from "fix IAM" workflows.
- **AWS Lambda Secrets Manager extension returns HTTP 400 with empty body, no diagnostic** ([github.com/awslabs/aws-sdk-rust/issues/905](https://github.com/awslabs/aws-sdk-rust/issues/905)). hasp implication: surface the raw sub-error code from every backend in `Backend.message`, not just the HTTP status class. Backend impls should populate `message` with as much information as possible.

---

## Design insights for hasp

1. **Adopt Approach B.** Drop `Unknown`. Add `Throttled` to `BackendFailureKind`. Promote `AuthenticationFailed` to a top-level variant alongside `PermissionDenied`. Add `PreconditionFailed` for state errors (Azure `SecretDisabled`, GCP `FAILED_PRECONDITION`, Vault sealed-with-manual-unseal). These additions are not speculative; each is required by at least one named backend in Wave 3+.
2. **Provide an `is_transient(&self) -> bool` method on `Error`.** Mirrors `reqwest::Error::is_timeout()`. Lets consumers write `if err.is_transient() { retry(); }` without enumerating variants — the most common predicate consumers want.
3. **Document Vault's 403/404 ambiguity in the `vault://` backend rustdoc.** Vault deliberately conflates "not found" and "no permission" on 404. hasp's `vault://` backend will surface 404 as `Error::NotFound`. Document that this is Vault's design decision, not hasp's loss of signal.
4. **Document the auth-vs-permission split per backend.** GCP and Azure produce distinct `AuthenticationFailed` and `PermissionDenied`; AWS and Vault collapse both into `PermissionDenied` (their protocols don't distinguish). Each backend's rustdoc lists which variants it can produce.
5. **Backend impls populate `Backend.message` aggressively.** Include the underlying error code, HTTP status, gRPC status, and any sub-code the backend exposes. The variant gives consumers structural matching; the message gives operators diagnostic detail. Do not redact secret URLs from messages — the URL/key path is loggable; only secret values are not.
6. **Error variants are `non_exhaustive` at the enum level.** `#[non_exhaustive] pub enum Error { ... }`. Consumers must include a `_ => ...` arm in match. This lets hasp add a new variant in a minor version without breaking consumers — required headroom against the AWS Java v1→v2 lesson.
7. **`BackendFailureKind` is `non_exhaustive` too.** Same reason. We may discover (e.g., when implementing `azure-kv://`) that `Conflict` deserves its own variant for write paths; `non_exhaustive` lets us add it without semver bump on consumers using the wildcard arm.
8. **Move `ProfileNotFound` / `ProfileKeyNotFound` out of `hasp-core`.** Per `RESEARCH-profile-resolver-scope.md`, profile expansion is `hasp-cli`-only. The variants live in `hasp-cli`'s own error type. `hasp-core` has no profile concept.
9. **Future expansion path: optional structured fields on Backend variant.** If `Throttled` consistently carries `Retry-After`, promote to `Backend { ..., retry_after: Option<Duration> }` at v1.0. Avoid introducing this at v0.x where the field would be `None` for backends that don't surface the hint.

---

## Decision criteria (enforced)

NOT valid: implementation effort, the small additional surface area of B over A.

ONLY valid:
- Architectural correctness (variants exist if and only if a real backend produces a distinct signal that consumers act on)
- Threat-model soundness (`Throttled` enables correct rate-limit honoring; misclassifying as `Transient` burns quota)
- Long-term maintainability (`non_exhaustive` and `is_transient()` predicate give headroom against AWS-Java-style v1→v2 breaks)
- Alignment with rustpunk identity (flat thiserror enum; no `anyhow` at the library boundary)

---

## Recommendation

**Approach B — refined flat enum: drop `Unknown`, add `Throttled` to `BackendFailureKind`, add `AuthenticationFailed` and `PreconditionFailed` to top-level `Error`, mark both enums `non_exhaustive`, provide `is_transient()` predicate, move CLI-only variants out.**

**Confidence:** High.

**Rationale:**
- Every variant in the proposed shape is produced by at least one of {AWS SM, AWS SSM, Vault, GCP SM, Azure KV} as a distinct error class that maps to a distinct caller action ([AWS docs](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html), [Vault](https://developer.hashicorp.com/vault/api-docs#error-response), [GCP AIP-194](https://google.aip.dev/194), [Azure KV common errors](https://learn.microsoft.com/en-us/azure/key-vault/general/common-error-codes)).
- `Throttled` matches AWS smithy-rs's two-class retry classifier (Transient + Throttle), which is the most-deployed Rust retry classifier in production today ([smithy-rs #3050](https://github.com/smithy-lang/smithy-rs/discussions/3050)).
- Dropping `Unknown` matches every retry-policy library in the survey (`backoff`, smithy-rs, GCP AIP-194); none distinguish Unknown from Permanent in practice.
- `non_exhaustive` + `is_transient()` predicate together give the long-term-stability headroom that the AWS Java v1→v2 lesson demands.
- The flat enum (no nesting) directly avoids the AWS Rust SDK string-matching antipattern that issue #572 documents.

**Key risk:** A future backend (HSM, KMIP, blockchain-based) introduces an error class that doesn't map cleanly to any existing variant. **Mitigation:** `non_exhaustive` on both enums means hasp can add the variant in a 0.x.y release without breaking consumers using the wildcard arm. Specific concern: if `Conflict` becomes important for write paths (Azure `ObjectIsBeingDeleted`, AWS `ResourceExistsException`), add it as `BackendFailureKind::Conflict` in a minor release.

**Threat-model note:** Approach B preserves redaction (no variant carries secret values; messages contain URL/key paths only — backend impls must enforce this in `Display`). The `AuthenticationFailed` distinction matters operationally: an alerting pipeline that pages on `AuthenticationFailed` (rotate creds — caller responsibility) versus `PermissionDenied` (fix IAM — operator responsibility) routes correctly. Without the split, both alerts go to one queue and the operator wastes time triaging.

**If wrong:** If post-Wave-3 experience shows that `Throttled` is consistently equivalent to `Transient` in caller behavior (no consumer actually honors `Retry-After`), demote it. Demotion is harder than promotion (consumers may have written specific `match` arms), but `non_exhaustive` gives us the option to deprecate without breaking. More likely, we discover a need for `Conflict` and add it.

**Rejected alternatives:**
- **Approach A (locked draft):** rejected because `Unknown` is dead weight (no SDK in the survey distinguishes it; consumers will collapse it to Permanent), and the absence of `Throttled` forces consumers to string-match `message` for `Retry-After` handling — re-creating the AWS string-matching antipattern that the flat enum was designed to avoid.
- **Approach C (nested SDK-style):** rejected because it is the AWS Rust SDK pattern that consumers route around with string-matching ([issue #572](https://github.com/awslabs/aws-sdk-rust/issues/572)). Architecturally inferior to flat thiserror.

---

## Final type shape (recommended, ready to lift into `hasp-core/src/error.rs`)

```rust
/// hasp library-surface errors. Stable across all backends; backend impls
/// map their native error vocabulary into these variants.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// URL parse failure at the `url` crate layer (malformed URI).
    #[error("invalid URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// URL parsed but does not satisfy a backend-specific grammar rule
    /// (e.g. wrong path-segment count, missing required component).
    #[error("invalid URL for backend: {0}")]
    InvalidUrl(String),

    /// URL scheme is not registered in this Store.
    #[error("unsupported scheme: {0}")]
    UnknownScheme(String),

    /// Backend recognized the URL but does not implement the requested verb
    /// (e.g. `env://` does not support `put`).
    #[error("{scheme} does not support {operation}")]
    UnsupportedOperation { scheme: &'static str, operation: &'static str },

    /// The addressed secret does not exist.
    /// On Vault this is also returned for paths the caller has no permission
    /// to read — Vault collapses 403/404 intentionally.
    #[error("not found: {0}")]
    NotFound(String),

    /// Caller's credentials are valid; caller is not authorized for this resource.
    /// (vs `AuthenticationFailed` = credentials invalid)
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Caller's credentials are missing, invalid, or expired.
    /// Distinct from `PermissionDenied` on GCP (UNAUTHENTICATED vs PERMISSION_DENIED)
    /// and Azure (401 vs 403). On AWS and Vault, this collapses into PermissionDenied
    /// because the protocol does not distinguish.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Resource is in a state that blocks the operation, even though the caller
    /// has permission and the resource exists. Covers: Azure `SecretDisabled`,
    /// GCP `FAILED_PRECONDITION` (version DISABLED), Vault sealed-with-manual-unseal,
    /// soft-deleted-but-recoverable secrets.
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    /// Backend-specific failure that does not fit a more-specific variant.
    /// `kind` provides retry guidance; `message` carries diagnostic detail
    /// (backend error code, HTTP status, sub-error). Never includes secret values.
    #[error("backend '{scheme}' failed: {message}")]
    Backend {
        scheme: &'static str,
        kind: BackendFailureKind,
        message: String,
    },
}

/// Retry-policy classification for `Error::Backend`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailureKind {
    /// Temporary failure; retry with exponential backoff.
    /// Covers: timeouts, connection refused, HTTP 5xx, gRPC UNAVAILABLE,
    /// gRPC DEADLINE_EXCEEDED.
    Transient,

    /// Backend is rate-limiting the caller. Retry honoring any Retry-After
    /// signal in `Backend.message`. Covers: AWS ThrottlingException, HTTP 429,
    /// gRPC RESOURCE_EXHAUSTED.
    Throttled,

    /// Permanent failure; retry will not help without external action.
    /// Covers: validation errors, malformed requests, unrecognized fields,
    /// any backend-specific permanent condition not captured by a more-specific
    /// top-level variant.
    Permanent,
}

impl Error {
    /// True if a retry has any chance of succeeding without external action.
    /// Returns true for `Backend { kind: Transient | Throttled, .. }`.
    /// Returns false for everything else, including `NotFound`,
    /// `PermissionDenied`, `AuthenticationFailed`, `PreconditionFailed`.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Backend { kind: BackendFailureKind::Transient | BackendFailureKind::Throttled, .. }
        )
    }
}
```

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| AWS Secrets Manager `GetSecretValue` API | doc | Variant inventory | [link](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html) |
| AWS Secrets Manager Common Errors | doc | Throttling/auth variant | [link](https://docs.aws.amazon.com/secretsmanager/latest/apireference/CommonErrors.html) |
| AWS SSM `GetParameter` API | doc | Variant inventory | [link](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html) |
| HashiCorp Vault HTTP API | doc | Status code mapping; 403/404 ambiguity | [link](https://developer.hashicorp.com/vault/api-docs#error-response) |
| GCP AIP-194 | standard | Retry-policy formal guidance | [link](https://google.aip.dev/194) |
| Azure Key Vault common error codes | doc | 401 vs 403 split; SecretDisabled state | [link](https://learn.microsoft.com/en-us/azure/key-vault/general/common-error-codes) |
| AWS smithy-rs RFC discussion #3050 | discussion | 2-class retry classifier | [link](https://github.com/smithy-lang/smithy-rs/discussions/3050) |
| AWS SDK Rust issue #572 | issue | Nested error string-matching antipattern | [link](https://github.com/awslabs/aws-sdk-rust/issues/572) |
| AWS SDK Rust issue #1381 | issue | Credential-load failure as opaque string | [link](https://github.com/awslabs/aws-sdk-rust/issues/1381) |
| AWS SDK Rust issue #905 | issue | Lambda extension HTTP 400 with empty body | [link](https://github.com/awslabs/aws-sdk-rust/issues/905) |
| AWS SDK Java v1→v2 migration | doc | Forced rename pain | [link](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/migration-exception-changes.html) |
| AWS DynamoDB programming guide | doc | Retry-on-wrong-class burns quota | [link](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.Errors.html) |
| `backoff` crate | crate | Permanent / Transient { retry_after } pattern | [docs.rs](https://docs.rs/backoff/latest/backoff/) |
| `vaultrs` 0.8.0 ClientError | docs | Existing Rust Vault error shape | [docs.rs](https://docs.rs/vaultrs/latest/vaultrs/error/enum.ClientError.html) |
| Spall WISHLIST §5 | doc | NotFound→prompt, unavailable→retry, permission→warn | `docs/internal/spall/WISHLIST.md` |
| Ferrule WISHLIST §7.2 | doc | Same granularity as Spall | `docs/internal/ferrule/WISHLIST.md` |
