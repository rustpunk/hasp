# hasp-backend-gcp-sm

`gcp-sm://` backend for hasp — GCP Secret Manager via the REST API.

## URL Grammar

```
gcp-sm://<project-id>/<secret-id>?version=<version>
```

- `<project-id>` — GCP project identifier (host). Must be non-empty.
- `<secret-id>`  — Secret ID (path). Must match `^[a-zA-Z0-9-_]{1,255}$` per GCP. Leading `/` is stripped.
- `?version=<version>` — Optional version label. Defaults to `latest`.

Examples:

```
gcp-sm://my-project/prod/db-password
gcp-sm://my-project/prod/db-password?version=3
```

## Supported Operations

| Operation | Support | Notes |
|-----------|---------|-------|
| `get` | ✅ | Returns base64-decoded `SecretString`. |
| `put` | ✅ | Creates or updates secret value. |
| `list` | ✅ | Lists secret names (not values). |
| `delete` | ✅ | Destroys secret versions permanently. |
| `exists` | ✅ | Uses metadata endpoint (no secret value crosses the wire). |

## Auth Model

Ambient credentials only. The backend uses the GCP auth default credential chain:

- `GOOGLE_APPLICATION_CREDENTIALS` → service account JSON file
- `GOOGLE_APPLICATION_CREDENTIALS_JSON` → inline JSON
- GCE / GKE / Cloud Run metadata service

No auth-bootstrap, token refresh, or credential storage logic lives in this crate.

## Failure Modes

| HTTP Status | hasp `Error` variant |
|------------|----------------------|
| `404` | `NotFound` |
| `401` / `403` | `PermissionDenied` |
| `429` | `Backend { Throttled }` |
| `5xx` | `Backend { Transient }` |
| Other | `Backend { Permanent }` |
