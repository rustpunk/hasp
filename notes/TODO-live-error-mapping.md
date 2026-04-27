# TODO: Live cloud error-mapping validation

Status: **deferred** — no sandbox credentials available. Revisit before `0.1.0` release.

## Why this matters

All error mappings in AWS SM, AWS SSM, GCP SM, and Azure KV are unit-tested against documented error codes but have never been exercised against real cloud APIs. SDKs sometimes return codes undocumented in the REST spec, and AWS in particular adds new error codes without announcement. Running `hasp list` against a real account with valid-but-unprivileged credentials is the fastest way to discover gaps.

## Acceptance criteria

1. At least one of AWS SM / AWS SSM / GCP SM / Azure KV is tested live.
2. Each test verifies that the SDK-provided error code maps to the correct `hasp_core::Error` variant.
3. Any unmapped codes are added to the relevant `from_service_error` / `map_http_status` match arm.
4. Findings are written to `docs/internal/research/RESEARCH-<backend>-live-errors.md`.

## Test matrix

| Scenario | Expected hasp error |
|---|---|
| Valid creds, no secrets in scope | `NotFound` or empty `Vec<Entry>` |
| Invalid / missing creds | `AuthenticationFailed` |
| Valid creds, insufficient IAM / RBAC | `PermissionDenied` |
| Malformed URL (bad query param) | `InvalidUrl` |
| Resource locked / soft-deleted | `PreconditionFailed` |
| Throttled | `Backend { kind: Throttled, .. }` |

## Cloud sandbox options

- **AWS SSM Standard tier**: free, no expiry. Recommended for cost zero.
- **GCP Secret Manager**: 6 active versions free tier, 10,000 ops/month.
- **Azure Key Vault**: no free tier; consumes general credit.

See the previous assistant response for full IAM policy and setup instructions.

## Files that will need updating

- `crates/hasp-backend-aws-sm/src/lib.rs` — `from_service_error`
- `crates/hasp-backend-aws-ssm/src/lib.rs` — `from_service_error`
- `crates/hasp-backend-gcp-sm/src/lib.rs` — `map_http_status`
- `crates/hasp-backend-azure-kv/src/lib.rs` — `map_http_status`

## Code location markers

Search for `TODO(#4)` in any of the four backend crates to find the exact error-mapping functions.
