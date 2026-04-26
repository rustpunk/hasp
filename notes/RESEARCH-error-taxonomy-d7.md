# D7 Error Taxonomy Research — Backend Protocol-Level Errors

Date: 2026-04-26
Researcher: supplementary protocol-level agent (claude-sonnet-4-6)
Deliverable: D7 — Error taxonomy completeness for hasp-core BackendFailureKind

---

## 1. AWS Secrets Manager

**Source:** https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html  
**Common errors source:** https://docs.aws.amazon.com/secretsmanager/latest/apireference/CommonErrors.html

### Operation-specific errors (GetSecretValue)

| Error name | HTTP | Meaning |
|---|---|---|
| `ResourceNotFoundException` | 400 | Secret not found |
| `DecryptionFailure` | 400 | KMS key cannot decrypt; also fires if CMK is disabled/deleted |
| `InternalServiceError` | 500 | AWS-side internal error |
| `InvalidParameterException` | 400 | Bad parameter name/value |
| `InvalidRequestException` | 400 | Valid param, wrong state (secret scheduled for deletion; managed by another service) |

### Common/global errors (apply to all SM operations)

| Error name | HTTP | Category |
|---|---|---|
| `AccessDeniedException` | 400 | Permanent — no IAM permission |
| `NotAuthorized` | 400 | Permanent — no permission |
| `InvalidClientTokenId` | 403 | Auth — X.509/key ID not recognized |
| `UnrecognizedClientException` | 403 | Auth — key ID invalid |
| `ExpiredTokenException` | (see STS) | Auth — token expired (surfaces via STS layer) |
| `ThrottlingException` | 400 | Throttle — request rate too high |
| `LimitExceededException` | 400 | Quota — would exceed SM quota |
| `RequestThrottledException` | 400 | Throttle (SM-specific alias) |
| `InternalFailure` | 500 | Transient — unknown internal error |
| `ServiceUnavailable` | 503 | Transient — temporary server failure |
| `EncryptionFailure` | 400 | Permanent-ish — KMS key state problem |
| `ResourceExistsException` | 400 | Conflict — resource already exists |
| `PreconditionNotMetException` | 400 | PreconditionFailed |
| `MalformedPolicyDocumentException` | 400 | Validation |
| `ValidationError` / `ValidationException` | 400 | Validation |
| `RequestExpired` | 400 | Clock skew >15 min — permanent (fix clock) |

### SdkError outer envelope (aws-smithy-runtime)

The AWS SDK for Rust wraps all errors in `SdkError<E>` with these variants:
- `Construction` — request could not be built (client bug)
- `Timeout` — timeout before response received (transient)
- `Dispatch` — transport/connector error (transient)
- `Response` — HTTP response received but could not be parsed
- `Service(E)` — service returned an error response; `E` is the typed service error

Auth failures (`UnrecognizedClientException`, `ExpiredTokenException`,
`InvalidClientTokenId`) arrive as `SdkError::Service(...)` variants, not at
the outer envelope. The Smithy-RS retry classifier (smithy-lang/smithy-rs
discussion #3050) uses four sub-classifiers:
- `ModeledAsRetryableClassifier` — explicit model flags
- `TransientErrorClassifier` — `SdkError::Timeout` and `SdkError::Dispatch`
- `HttpStatusCodeClassifier` — HTTP 500, 502, 503, 504
- `AwsErrorCodeClassifier` — checks `x-amz-retry-after` header; marks
  `ThrottlingException`, `RequestThrottledException` as throttle-class

**Key observation:** The AWS SDK retry system uses exactly two retry classes:
`Transient` and `Throttle`. Auth errors and permanent business errors produce
`NoActionIndicated` and are not retried.

### Wire shape & auth
- REST/JSON over HTTPS (not gRPC)
- Auth: SigV4 via ambient credentials chain (env vars, instance profile,
  assume-role); no library-level auth bootstrap

### Rate limits
- ~5,000 transactions/second per region per account for GetSecretValue
  (with bursting); documented at service limits page

---

## 2. AWS SSM Parameter Store

**Source:** https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html  
**Common errors source:** https://docs.aws.amazon.com/systems-manager/latest/APIReference/CommonErrors.html

### GetParameter-specific errors

| Error name | HTTP | Meaning |
|---|---|---|
| `ParameterNotFound` | 400 | Parameter does not exist (NOT logged in CloudTrail) |
| `ParameterVersionNotFound` | 400 | Specific version requested does not exist |
| `InvalidKeyId` | 400 | KMS key ID for SecureString is invalid |
| `InternalServerError` | 500 | Server-side error |

### Common/global errors (apply to all SSM operations)

| Error name | HTTP | Category |
|---|---|---|
| `AccessDeniedException` | 403 | Permanent — no IAM permission |
| `ExpiredTokenException` | 403 | Auth — STS token expired |
| `UnrecognizedClientException` | 403 | Auth — key not recognized |
| `ThrottlingException` | 400 | Throttle |
| `ServiceUnavailable` | 503 | Transient |
| `InternalFailure` | 500 | Transient |
| `RequestTimeoutException` | 408 | Transient |

### SSM vs SM differences

- SSM does NOT have `DecryptionFailure` at the parameter level; KMS key
  errors surface as `InvalidKeyId` (400) or `AccessDeniedException` (403)
- SSM has `ParameterVersionNotFound` (version-specific not-found) which SM
  expresses through `InvalidRequestException` instead
- SSM throttle behavior: documented per-API TPS limits are lower than SM
  (40 TPS standard tier, 1000 TPS advanced tier for GetParameter)
- Both services share the same SdkError/Smithy retry infrastructure

### Wire shape & auth
- REST/JSON over HTTPS; SigV4 auth; same ambient credential chain as SM

---

## 3. HashiCorp Vault (HTTP API + vaultrs)

**Source:** https://developer.hashicorp.com/vault/api-docs#error-response  
**KV v2 source:** https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2

### HTTP status code mapping (canonical, from official docs)

| Status | Meaning | Retry class |
|---|---|---|
| 200 | Success with data | — |
| 204 | Success, no data | — |
| 400 | Invalid request / missing data | Permanent (validation) |
| 403 | Forbidden — bad credentials, no ACL permission, or CORS | Permanent (auth/authz) |
| 404 | Invalid path OR no permission (leak-prevention) OR LIST with no results | Permanent (not-found or authz) |
| 405 | Method not allowed | Permanent |
| 412 | Precondition failed — Enterprise eventual consistency lag; explicitly should retry with backoff | Transient |
| 429 | Standby node (default health status) OR rate limit | Transient |
| 472 | DR mode replication secondary active | Permanent (routing issue) |
| 473 | Performance standby health | Transient |
| 500 | Internal server error — retry later | Transient |
| 501 | Vault not initialized | Permanent |
| 503 | Vault sealed OR maintenance | Transient (with caveats, see below) |
| 502 | Third-party backend returned error | Transient |

**Critical notes:**
- 403 covers BOTH bad token AND valid token without ACL permission; they
  are indistinguishable from the HTTP status alone. The error body message
  differs but there is no structured code.
- 404 intentionally collapses "path not found" and "no permission" to
  prevent state leakage — a caller cannot distinguish "secret does not
  exist" from "you are not allowed to read this path."
- 412 is Enterprise-only and explicitly documented as "should retry with
  backoff" — this is a true transient classification the API surface
  explicitly declares.
- 503 (sealed) is technically transient IF the vault will unseal (e.g.,
  after a restart when auto-unseal is configured). If manual intervention
  is required, it behaves permanently. From hasp's perspective this is
  `ServiceUnavailable` with `kind: Transient`.
- 429 in practice is used for health checks on standby nodes more than
  actual rate-limiting; Vault Enterprise adds a separate rate-limit
  response on this code.

### KV v1 vs KV v2 errors
- The URL path structure differs (`/v1/secret/foo` vs
  `/v1/secret/data/foo`) but HTTP status codes are identical.
- KV v2 introduces soft-delete and destroy; a destroyed version returns
  404 (same code as not-found). A soft-deleted (but not destroyed) version
  returns 404 as well with an empty response body.
- KV v2 CAS (check-and-set) failures return 400 with a descriptive error
  string — this maps to `PreconditionFailed` in hasp terms.

### vaultrs crate (Rust)
- Official community Rust client: https://github.com/jmgilman/vaultrs
- Error type is `ClientError`; the raw GitHub source was not directly
  retrievable, but documentation confirms it wraps HTTP errors as a single
  opaque variant plus an API-error variant.
- The crate does NOT map HTTP status codes to distinct named variants;
  callers receive the raw HTTP status and body string inside a generic
  error. This means hasp's backend module must do the status-code
  classification itself.

### Sealed vault classification
Sealed vault (503) is produced by `/v1/sys/health` returning 503 and by
any normal API call when the vault is sealed. A sealed condition requires
human operator action unless auto-unseal (AWS KMS, GCP KMS, Azure Key
Vault, HSM) is configured. It is NOT the same as a transient network
failure. Recommendation: surface as `Backend { scheme: "vault", kind:
Transient, message: "vault sealed" }` with the understanding that the
caller or retry layer should apply a longer back-off than for generic
transient errors.

### Wire shape & auth
- REST/JSON over HTTPS
- Auth: static token (X-Vault-Token header), AppRole, Kubernetes, OIDC,
  AWS IAM, GCP IAM, Azure MSI — all ambient; hasp must not manage token
  renewal

---

## 4. GCP Secret Manager (gRPC + REST)

**Sources:**  
- https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access  
- https://google.aip.dev/193 (Google error design)  
- https://google.aip.dev/194 (GCP retry policy — official)

### gRPC status codes and AccessSecretVersion

The REST API uses HTTP status codes that map 1:1 to gRPC codes. The
following codes are confirmed to fire for AccessSecretVersion:

| gRPC code | HTTP | Condition | Retry? |
|---|---|---|---|
| `OK` | 200 | Success | — |
| `NOT_FOUND` | 404 | Secret or version does not exist; also fires if version is destroyed | No |
| `PERMISSION_DENIED` | 403 | Valid auth, missing `secretmanager.versions.access` IAM permission | No |
| `UNAUTHENTICATED` | 401 | Missing or invalid credentials | No |
| `RESOURCE_EXHAUSTED` | 429 | Quota exceeded (per-project RPS limits) | Conditional — long back-off |
| `UNAVAILABLE` | 503 | Network/infrastructure transient | Yes |
| `DEADLINE_EXCEEDED` | 504 | Request timeout | Yes |
| `INTERNAL` | 500 | GCP-internal bug | No (surface to user) |
| `FAILED_PRECONDITION` | 400 | Secret version is disabled (state != ENABLED) | No (fix state first) |
| `INVALID_ARGUMENT` | 400 | Malformed resource name | No |

**Key observations:**
- `FAILED_PRECONDITION` fires specifically when the secret version state is
  `DISABLED` — this is distinct from `NOT_FOUND` and is the closest GCP
  analogue to Azure's `SecretDisabled`.
- `PERMISSION_DENIED` and `UNAUTHENTICATED` are distinct at the API level.
  In practice, malformed or missing credentials produce `UNAUTHENTICATED`;
  present-but-insufficient credentials produce `PERMISSION_DENIED`.
  However, some credential providers (e.g., defaulting to wrong service
  account) can produce `PERMISSION_DENIED` when the root cause is auth
  misconfiguration.
- `RESOURCE_EXHAUSTED` is listed in AIP-194 as "generally non-retryable"
  because it may reflect quota exhaustion needing hours to recover; but for
  per-second rate limits it is functionally a `Transient`/`RateLimited`
  condition.
- `ABORTED` does not appear for read operations; it is used for
  transactional writes.

### GCP official retry policy (AIP-194)

Retryable: `UNAVAILABLE` only (for non-idempotent). For GET operations,
clients may also retry `DEADLINE_EXCEEDED`.

Non-retryable: `NOT_FOUND`, `PERMISSION_DENIED`, `UNAUTHENTICATED`,
`FAILED_PRECONDITION`, `INVALID_ARGUMENT`, `UNIMPLEMENTED`, `CANCELLED`,
`DATA_LOSS`.

`RESOURCE_EXHAUSTED`: "generally should not be automatically retried"
because it may mean quota; if used for rate-limiting with short expected
wait, may be retried. GCP recommends application-level logic here.

`INTERNAL`: Generally not retried (bug should be filed). This contradicts
the naive "5xx = transient" heuristic.

### Wire shape & auth
- gRPC (with HTTP/JSON transcoding available)
- Auth: Service Account JSON, ADC (Workload Identity, Metadata Server),
  OIDC; hasp uses ambient ADC

---

## 5. Azure Key Vault

**Sources:**  
- https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret  
- https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes  
- https://learn.microsoft.com/en-us/azure/key-vault/general/common-error-codes

### HTTP status codes for GetSecret

| HTTP | Meaning | Notes |
|---|---|---|
| 200 | Success | |
| 401 | Unauthenticated | Token missing, expired, wrong audience, wrong tenant |
| 403 | Insufficient permissions | No access policy; OR IP firewall block |
| 404 | Secret not found | Also returned for soft-deleted secrets when accessed via normal path |
| 409 | Conflict | `ObjectIsBeingDeleted` — secret is currently in async deletion |
| 429 | Too Many Requests | Rate limit: ~4,000 req/10s general; lower for HSM operations |

### Error.code strings (JSON body)

The REST error response has the shape `{"error": {"code": "...", "message":
"...", "innererror": ...}}`. Confirmed `error.code` values:

| code | HTTP | Condition |
|---|---|---|
| `SecretDisabled` | 403 | Secret exists but is disabled (`attributes.enabled = false`) |
| `AccessDenied` | 403 | Missing access policy |
| `ForbiddenByFirewall` | 403 | Caller IP not allowed |
| `ObjectIsBeingDeleted` | 409 | Async delete in progress |
| `ObjectIsDeletedButRecoverable` | 409 or 404 | Soft-deleted, can be recovered |
| `VaultAlreadyExists` | 409 | (Create-only; soft-delete namespace collision) |
| `ConflictError` | 409 | Generic concurrent operation conflict |
| `ResourceNotFound` | 404 | Secret not found |
| `CertificateExpired` | 400 | (Certificates only) |

**Key observations:**
- `SecretDisabled` returns HTTP 403 with `error.code = "SecretDisabled"`;
  it is NOT a permission error — the caller has permission, but the secret
  lifecycle state blocks access. Mapping this to `PermissionDenied` in
  hasp would be wrong.
- `ObjectIsDeletedButRecoverable`: the secret is in soft-delete state (90
  day retention window). A GET to the normal secrets endpoint returns an
  error; only the recovery endpoint (`/deletedsecrets/{name}`) sees it.
  This is semantically `NotFound` with the additional context that recovery
  is possible — not a transient error.
- `ObjectIsBeingDeleted` (409): async deletion is in progress; a brief
  retry after the deletion completes would succeed if the secret is
  recovered, fail if it completes. Functionally `Conflict/Transient`.
- 401 (Unauthenticated) is distinct from 403 (Forbidden). The 401 doc
  explicitly lists: no token, expired token, wrong audience, wrong tenant.
  The 403 doc explicitly lists: no access policy, firewall block.

### Soft-delete and purge-protection implications
- With soft-delete enabled (now default), deleting a secret moves it to
  a `DeletedSecret` state. Normal GET returns a 404 or the
  `ObjectIsDeletedButRecoverable` code depending on API version.
- With purge-protection enabled, a deleted secret CANNOT be purged
  (permanently removed) until the retention period expires. Write
  operations to the same name return 409 (`ObjectIsDeletedButRecoverable`)
  until the retention window expires or the secret is recovered.
- These two conditions are distinct from `NotFound` at the semantic level
  but do share the not-found HTTP code.

### Wire shape & auth
- REST/JSON over HTTPS
- Auth: OAuth2/Bearer token against Azure AD (Entra ID); hasp uses ambient
  Managed Identity or DefaultAzureCredential chain

---

## Cross-cutting Analysis

### A. AWS SDK Rust Retry Classification

**Sources:**  
- https://docs.aws.amazon.com/sdk-for-rust/latest/dg/retries.html  
- https://docs.aws.amazon.com/sdkref/latest/guide/feature-retry-behavior.html  
- https://github.com/smithy-lang/smithy-rs/discussions/3050

The AWS SDK for Rust (via smithy-rs) uses **two retry classes** at the
classification layer:

1. **Transient** — socket timeout, IO error, HTTP 500/502/503/504
2. **Throttle** — `ThrottlingException`, `RequestThrottledException`,
   HTTP 429, HTTP 509, plus `x-amz-retry-after` header presence

All other errors (auth failures, not-found, validation) produce
`NoActionIndicated` and are not retried automatically. The SDK does NOT
have a named "Permanent" class — it is the absence of retry classification.

HTTP status codes for transient: 400, 408, 500, 502, 503, 504  
HTTP status codes for throttling: 400, 403, 429, 502, 503, 509

Note: 400 appears in BOTH transient and throttling lists; differentiation
is done via error code, not HTTP status alone.

### B. GCP Official Retry Policy (AIP-194)

**Source:** https://google.aip.dev/194

Single retryable code for GET operations: `UNAVAILABLE`.  
`DEADLINE_EXCEEDED` may also be retried for GET.  
`RESOURCE_EXHAUSTED` is explicitly flagged as "generally non-retryable"
with guidance to use application-level logic (long backoff).  
`INTERNAL` is non-retryable (bug should be filed).

This means GCP's official guidance is closer to a **binary**
(retryable/non-retryable) for most codes, with `RESOURCE_EXHAUSTED`
as a special conditional case.

### C. backoff crate — Rust retry error classification

**Source:** https://docs.rs/backoff/latest/backoff/enum.Error.html

```rust
pub enum Error<E> {
    Permanent(E),
    Transient { err: E, retry_after: Option<Duration> },
}
```

Two variants only. Throttle/rate-limit is a `Transient` with an explicit
`retry_after` duration. There is no separate throttle category; callers
encode throttle intent via `retry_after`.

### D. 3-tier vs flat — What mature SDKs actually use

| Layer | Classification |
|---|---|
| AWS SDK for Rust (smithy-rs) | 2-class: Transient \| Throttle |
| GCP AIP-194 | Binary (retry vs not), with `RESOURCE_EXHAUSTED` as conditional |
| backoff (Rust crate) | 2-class: Permanent \| Transient (with optional retry_after) |
| `backoff::Error` for throttle | Transient + retry_after (no separate variant) |
| Azure SDK for Rust (azure_core) | Follows HTTP: 429 = retry with Retry-After header |
| vaultrs | No native retry; passes through HTTP status |

No mainstream Rust retry library uses a 3-tier (Transient/Permanent/Unknown)
classification. The AWS SDK uses 2+1 (Transient + Throttle + implicit
Unknown/Permanent). GCP uses ~binary.

**The "Unknown" category is not practically useful for generated code:**
- A caller who does not know if an error is transient or permanent should
  err on the side of not retrying (to avoid cascading failures / idempotency
  violations).
- The AWS approach — classify known-transient/throttle, leave everything
  else as "do not retry" — is more correct than surfacing `Unknown` as a
  separate enum arm that callers would need to handle.

---

## Concrete Variant Analysis (Cross-Backend)

### Does each proposed variant fire on at least one backend?

| Variant | AWS SM | AWS SSM | Vault | GCP SM | Azure KV | Notes |
|---|---|---|---|---|---|---|
| `NotFound` | `ResourceNotFoundException` | `ParameterNotFound` | 404 | `NOT_FOUND` | 404/`ResourceNotFound` | All backends |
| `PermissionDenied` | `AccessDeniedException` | `AccessDeniedException` | 403 (authz) | `PERMISSION_DENIED` | 403/`AccessDenied` | All backends |
| `AuthenticationFailed` | `UnrecognizedClientException`/`ExpiredTokenException` | same | 403 (bad token) | `UNAUTHENTICATED` | 401 | All backends; distinct from PermissionDenied on GCP+Azure |
| `Throttled`/`RateLimited` | `ThrottlingException` | `ThrottlingException` | 429 | `RESOURCE_EXHAUSTED` | 429 | All backends |
| `Timeout` | `SdkError::Timeout` | same | — | `DEADLINE_EXCEEDED` | — | AWS+GCP |
| `NetworkUnavailable` | `SdkError::Dispatch` | same | 502 | `UNAVAILABLE` | — | AWS+Vault+GCP |
| `ServiceUnavailable` | `ServiceUnavailable`(503) | same | 503 (sealed/maint) | `UNAVAILABLE`(503) | — | All |
| `Conflict`/`AlreadyExists` | `ResourceExistsException` | — | — | `ALREADY_EXISTS` | 409/`ObjectIsBeingDeleted` | AWS SM, Azure, GCP |
| `PreconditionFailed` | `PreconditionNotMetException` | — | 412 (Enterprise) | `FAILED_PRECONDITION` | — | AWS SM, Vault Ent, GCP |
| `InvalidArgument`/`Validation` | `InvalidParameterException` | `ValidationError` | 400 | `INVALID_ARGUMENT` | 400 | All |
| `Unimplemented` | `InvalidAction` | `UnknownOperationException` | 405 | `UNIMPLEMENTED` | — | All |

### What callers actually need to distinguish (vs collapse)

**Consumer code typically needs to branch on:**
1. `NotFound` — decide whether to create, propagate the absence, or error
2. `PermissionDenied` + `AuthenticationFailed` — alert operator; no retry
3. `Throttled` — retry with exponential backoff + jitter
4. `Transient` (timeout, network, 5xx) — retry with backoff
5. Backend-specific state errors (sealed vault, disabled secret, soft-delete)
   — these collapse to `NotFound` or `PermissionDenied` depending on semantics

**Consumer code typically collapses:**
- `Timeout` + `NetworkUnavailable` + `ServiceUnavailable` into a single
  "retry with backoff" branch — they differ in root cause but not in
  action
- `InvalidArgument` + `Validation` — both are "fix the caller"
- `Conflict` + `AlreadyExists` — both are "check state before writing"
- `AuthenticationFailed` and `PermissionDenied` — often collapsed into
  a single "auth problem, alert operator" branch

**The one variant that consumers consistently need separately:**
`Throttled` must be separated from generic `Transient` because throttle
handling requires honoring the `Retry-After` header (or an equivalent
exponential back-off signal), while transient errors use a different
(usually shorter) retry schedule. AWS, Azure, and GCP all emit explicit
`Retry-After` headers on throttle responses.

---

## Recommended BackendFailureKind Shape

The current draft is:
```rust
enum BackendFailureKind {
    Transient,
    Permanent,
    Unknown,
}
```

### Recommended revision

```rust
enum BackendFailureKind {
    /// Caller should retry with exponential backoff. No Retry-After hint.
    Transient,
    /// Caller should retry after the specified duration; honor explicit
    /// back-off signal from the backend (Retry-After header, etc.).
    Throttled,
    /// Caller should not retry; the error will not resolve without
    /// external action (operator, config change, state change).
    Permanent,
}
```

**Rationale:**
- Drop `Unknown` — it is not used by any mature SDK in a way that produces
  distinct consumer behavior. A hasp backend that cannot classify an error
  should default to `Permanent` (safer than retrying something with unknown
  idempotency).
- Add `Throttled` — every backend emits this as a distinct signal with
  explicit retry timing. Collapsing it into `Transient` forces callers to
  implement their own rate-limit detection on top of hasp, defeating the
  abstraction.
- Keep `Transient` and `Permanent` — they cleanly cover the rest of the
  space as confirmed by every major SDK surveyed.

**What to encode in `Backend { scheme, kind, message }`:**
- `scheme`: URL scheme string (e.g., `"aws-sm"`, `"vault"`, `"gcp-sm"`)
- `kind`: `BackendFailureKind` as above
- `message`: human-readable, key-safe (no secret material), no structured
  parsing contract — for logs and operator messages only

**Sealed vault edge case:**
Map Vault 503 to `Backend { kind: Transient }` but surface in `message`
that the vault appears sealed. The caller cannot distinguish a sealed vault
from a transient outage without additional API calls — that ambiguity is
acceptable at the hasp abstraction level.

**`SecretDisabled` (Azure) and `FAILED_PRECONDITION` (GCP):**
These are states where the secret exists but is not accessible due to
lifecycle management. Map to `PermissionDenied` at the hasp surface (the
canonical error), with the `Backend` variant as the downstream escape
hatch if the caller needs fine-grained Azure/GCP behavior.

---

## Lower-Priority Touch-Points

### Wire shape summary

| Backend | Protocol | Auth |
|---|---|---|
| AWS SM | REST/JSON + SigV4 | Ambient credentials (IAM, env, instance profile) |
| AWS SSM | REST/JSON + SigV4 | Ambient credentials (IAM) |
| Vault | REST/JSON | Token, AppRole, k8s, AWS IAM, etc. — ambient |
| GCP SM | gRPC (+ HTTP/JSON transcoding) | ADC (service account, Workload Identity) |
| Azure KV | REST/JSON + OAuth2 Bearer | Managed Identity, DefaultAzureCredential |

### Rate limits baseline

| Backend | Typical limit |
|---|---|
| AWS SM | ~5,000 TPS GetSecretValue per region |
| AWS SSM | 40 TPS (standard), 1,000 TPS (advanced tier) |
| Vault | Operator-configured; Vault Enterprise adds ACL rate limits |
| GCP SM | 6,000 AccessSecretVersion/min per project (as of 2025) |
| Azure KV | 4,000 req/10s general; lower for HSM key operations |

### Consistency

| Backend | Consistency |
|---|---|
| AWS SM | Strongly consistent within a region |
| AWS SSM | Strongly consistent; version-pinned reads available |
| Vault | Eventually consistent (HA), strongly consistent on active node |
| GCP SM | Globally replicated, strongly consistent per version |
| Azure KV | Strongly consistent within a region; geo-replication is eventual |

---

## URLs Cited

1. https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
2. https://docs.aws.amazon.com/secretsmanager/latest/apireference/CommonErrors.html
3. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html
4. https://docs.aws.amazon.com/systems-manager/latest/APIReference/CommonErrors.html
5. https://docs.aws.amazon.com/sdk-for-rust/latest/dg/retries.html
6. https://docs.aws.amazon.com/sdkref/latest/guide/feature-retry-behavior.html
7. https://github.com/smithy-lang/smithy-rs/discussions/3050
8. https://developer.hashicorp.com/vault/api-docs#error-response
9. https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
10. https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access
11. https://google.aip.dev/193
12. https://google.aip.dev/194
13. https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret
14. https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes
15. https://learn.microsoft.com/en-us/azure/key-vault/general/common-error-codes
16. https://docs.rs/backoff/latest/backoff/enum.Error.html
17. https://docs.rs/vaultrs/latest/vaultrs/
18. https://github.com/jmgilman/vaultrs
