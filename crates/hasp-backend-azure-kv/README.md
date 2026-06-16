# hasp-backend-azure-kv

`azure-kv://` backend for hasp — Azure Key Vault secrets via the REST API.

## URL Grammar

```
azure-kv://<vault-name>/<secret-name>?version=<version>&field=<path>
```

- `<vault-name>`  — Azure Key Vault name (host). Must be non-empty.
- `<secret-name>` — Path segment after the host. Must be non-empty.
- `?version=<version>` — Optional version string. Defaults to latest (empty).
- `?field=<path>` — Optional dotted JSON path (`password`, `.creds.api_key`).
  When set, the stored secret value is parsed as JSON and the named scalar is
  returned. Non-JSON payloads fail with `InvalidUrl`. CLI sugar: `-F <path>`.

Examples:

```
azure-kv://my-vault/prod/db-password
azure-kv://my-vault/prod/db-password?version=2024-01-15
```

## Supported Operations

| Operation | Support | Notes |
|-----------|---------|-------|
| `get` | ✅ | Returns `SecretString`. |
| `put` | ✅ | Sets secret value; requires `secrets/set` permission. |
| `list` | ✅ | Lists secret names (not values). |
| `delete` | ✅ | Soft-delete; purge requires `purge` permission. |
| `exists` | ✅ | Uses `GET` metadata endpoint (no secret value crosses the wire). |

## Auth Model

Ambient credentials only. `azure_identity::create_credential` resolves the standard
Azure credential chain:

- Service principal env vars (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
- Managed identity (VM, App Service, AKS, etc.)
- Azure CLI cached token

No auth-bootstrap, token refresh, or credential storage logic lives in this crate.

## Failure Modes

| HTTP Status | hasp `Error` variant |
|------------|----------------------|
| `404` | `NotFound` |
| `401` / `403` | `PermissionDenied` |
| `429` | `Backend { Throttled }` |
| `5xx` | `Backend { Transient }` |
| Other | `Backend { Permanent }` |
