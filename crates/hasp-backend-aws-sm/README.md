# hasp-backend-aws-sm

`aws-sm://` backend for hasp — AWS Secrets Manager via the official AWS SDK for Rust.

## URL grammar

```
aws-sm://<region>/<secret-name>?version-stage=<stage>&version-id=<id>&field=<path>
```

- `<region>` — AWS region (e.g. `us-east-1`, `eu-west-1`). Required, host component.
- `<secret-name>` — Secret name or full ARN. Path component; leading `/` stripped.
- `?version-stage=<stage>` — Optional version stage (`AWSCURRENT`, `AWSPREVIOUS`, …).
- `?version-id=<id>` — Optional version UUID. Mutually exclusive with `version-stage`.
- `?field=<path>` — Optional dotted JSON path (`password`, `.creds.api_key`).
  When set, the stored secret value is parsed as JSON and the named scalar is
  returned. Non-JSON payloads fail with `InvalidUrl`. CLI sugar: `-F <path>`.

Examples:

```
aws-sm://us-east-1/prod/db-password
aws-sm://us-west-2/prod/db-password?version-stage=AWSPREVIOUS
aws-sm://eu-west-1/arn:aws:secretsmanager:eu-west-1:123456789012:secret:my-secret-AbCdEf
```

## Supported operations

| verb | support | notes |
|------|---------|-------|
| `get` | ✅ | Returns `SecretString`. Binary secrets are rejected with a permanent backend error. |
| `put` | ❌ | `UnsupportedOperation` |
| `list` | ❌ | `UnsupportedOperation` |
| `delete` | ❌ | `UnsupportedOperation` |
| `exists` | ✅ | Uses `DescribeSecret` (metadata-only, no secret value crosses the wire). |

## Auth model

Ambient credentials only. The backend uses the AWS SDK default credential chain:

- `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
- `AWS_PROFILE` → `~/.aws/credentials`
- IAM role via IMDS (EC2), ECS task role, EKS IRSA, etc.

No auth-bootstrap, token refresh, or credential storage logic lives in this crate.

## Failure modes

| AWS error | hasp `Error` variant |
|-----------|----------------------|
| `ResourceNotFoundException` | `NotFound` |
| `InvalidParameterException` | `InvalidUrl` |
| `InvalidRequestException` | `PreconditionFailed` |
| `AccessDeniedException` | `PermissionDenied` |
| `ThrottlingException` | `Backend { Throttled }` |
| `DecryptionFailure` / `InternalServiceError` | `Backend { Transient }` |
| SDK timeout / dispatch failure | `Backend { Transient }` |
| Other service error | `Backend { Permanent }` |

The Tokio runtime is `current_thread` and created once per `AwsSmBackend` instance. If runtime creation fails (extremely rare), the backend is silently omitted from `Store::with_defaults()`.
