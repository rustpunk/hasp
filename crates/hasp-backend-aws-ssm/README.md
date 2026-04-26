# `hasp-backend-aws-ssm`

`aws-ssm://` backend for hasp — AWS Systems Manager Parameter Store.

## URL grammar

```
aws-ssm://<region>/<parameter-name>?with-decryption=<bool>
```

- `<region>` — AWS region (e.g. `us-east-1`). Required; placed in the URL host so the address is self-contained.
- `<parameter-name>` — Parameter Store name. All leading `/` characters are stripped from the path; hierarchical parameters that require a leading `/` must be encoded with a double slash after the host (e.g. `aws-ssm://us-east-1//my/app/param`).
- `?with-decryption` — Optional boolean, default `true`. Pass `false` to avoid invoking KMS when reading a `SecureString`.

## Supported operations

| Operation | Status | Notes |
|-----------|--------|-------|
| `get`     | ✅     | Returns the parameter value as `SecretString`. Works for `String`, `StringList`, and `SecureString` types. |
| `put`     | ❌     | `UnsupportedOperation` |
| `list`    | ❌     | `UnsupportedOperation` |
| `delete`  | ❌     | `UnsupportedOperation` |
| `exists`  | ✅     | Uses `GetParameter` with `with_decryption=false` so no KMS call is made. |

## Authentication

Ambient credentials only. The backend uses the AWS SDK default credential chain:

- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- Shared credentials file (`~/.aws/credentials`)
- IAM role via IMDS/ECS/EKS

No auth-bootstrap flows, token refresh, or credential caching lives in this crate.

## Failure modes

| Native error | Mapped `hasp_core::Error` |
|--------------|---------------------------|
| `ParameterNotFound` | `NotFound` |
| `ParameterVersionNotFound` | `NotFound` |
| `InvalidParameterException` | `InvalidUrl` |
| `InvalidParameterValue` | `InvalidUrl` |
| `InvalidRequestException` | `PreconditionFailed` |
| `AccessDeniedException` | `PermissionDenied` |
| `UnauthorizedException` | `AuthenticationFailed` |
| `ThrottlingException` | `Backend { kind: Throttled }` |
| `TooManyUpdates` | `Backend { kind: Throttled }` |
| `InternalServerError` | `Backend { kind: Transient }` |
| `HierarchyDepthLimitExceeded` | `PreconditionFailed` |
| `ParameterAlreadyExists` | `PreconditionFailed` |
| `ParameterLimitExceeded` | `PreconditionFailed` |
| `InvalidKeyId` | `Backend { kind: Permanent }` |
| `UnsupportedParameterType` | `Backend { kind: Permanent }` |
| All other service errors | `Backend { kind: Permanent }` |
| Timeout / dispatch failure | `Backend { kind: Transient }` |

## Cargo features

This crate has no optional features of its own. It is pulled in by the `hasp` crate when the `aws-ssm` feature is enabled.
