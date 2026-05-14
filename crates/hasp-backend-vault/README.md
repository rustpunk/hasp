# hasp-backend-vault

`vault://` backend for hasp — HashiCorp Vault KV HTTP client.

## URL Grammar

`vault://<mount>/<path>?field=<key>`

- `<mount>` — Vault secrets engine mount point (e.g., `secret`, `kv`).
- `<path>` — secret path within the mount. For KV v2, include the `data/`
  prefix (e.g., `data/myapp/config`). For KV v1, use the path directly
  (e.g., `myapp/config`).
- `?field=<key>` — optional dotted JSON path into `data.data`. Supports both
  flat keys (`password`) and dotted nested paths (`.credentials.api_key`).
  Leading `.` is optional. If omitted, the entire `data.data` object is
  serialized to JSON and returned. CLI sugar: `-F <path>`.

Examples:
- `vault://secret/data/myapp/config?field=password`
- `vault://kv/data/prod/db?field=.connection.string`

## Supported Operations

- `get` — HTTP GET to `{VAULT_ADDR}/v1/<mount>/<path>`. Returns the secret
  value wrapped in `SecretString`.
- `exists` — HTTP GET to the same endpoint. Returns `true` if 200; `false` if
  403 or 404. Vault intentionally collapses permission-denied and not-found;
  this backend follows that semantics.
- `put`, `list`, `delete` — `UnsupportedOperation` (deferred).

## Authentication Model

Stateless ambient auth only. No auth-bootstrap, token renewal, or credential
storage.

Required environment variables:
- `VAULT_ADDR` — base URL of the Vault server (e.g., `https://vault.example.com:8200`)
- `VAULT_TOKEN` — Vault token sent as `X-Vault-Token` header

If either variable is missing, every operation fails fast with
`AuthenticationFailed` before any network request.

## Failure Modes

| HTTP Status | `get` Mapping | `exists` Mapping |
|-------------|---------------|------------------|
| 200         | Return secret | `true` |
| 403         | `NotFound`    | `false` |
| 404         | `NotFound`    | `false` |
| 429         | `Backend { Throttled }` | `Backend { Throttled }` |
| 5xx         | `Backend { Transient }` | `Backend { Transient }` |
| Network timeout / refused | `Backend { Transient }` | `Backend { Transient }` |
| Invalid JSON | `Backend { Permanent }` | `Backend { Permanent }` |
| Missing `data.data` | `Backend { Permanent }` | `Backend { Permanent }` |

**403/404 collapse:** Vault's API intentionally returns the same status codes
for "secret does not exist" and "caller lacks permission" to prevent
existence oracles. This backend maps both 403 and 404 to `NotFound` on `get`
and to `false` on `exists`, following Vault's own semantic design.
