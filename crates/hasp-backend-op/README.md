# hasp-backend-op

`op://` backend for hasp. Wraps the 1Password CLI (`op`) via
`std::process::Command` subprocess.

## URL grammar

`op://vault/item/field`

- Exactly three non-empty path segments.
- No query parameters.

Vault, item, and field identifiers are not secret values; they may
appear in error messages (redacted per URL discipline).

## Supported operations

| Operation | Status |
|-----------|--------|
| `get`     | Supported |
| `exists`  | Supported |
| `put`     | `UnsupportedOperation` |
| `list`    | `UnsupportedOperation` |
| `delete`  | `UnsupportedOperation` |

`put`, `list`, and `delete` are deferred, not stubbed. The `op item
edit` JSON interface changes across CLI major versions; fragile
implementations would break on version upgrades.

## Authentication

Ambient credentials only — hasp does not implement auth flows:

- `OP_SERVICE_ACCOUNT_TOKEN`
- `OP_SESSION_*` (any prefix)
- `OP_CONNECT_TOKEN` + `OP_CONNECT_HOST`

If no ambient credentials are detected, `get` and `exists` return
`AuthenticationFailed` without spawning the `op` binary. This prevents
indefinite hangs in headless contexts where the desktop-app biometric
prompt would otherwise block forever.

## Error mapping

| stderr anchor | hasp Error |
|---------------|------------|
| `could not find item` / `isn't a vault` / `isn't an item` / `more than one item matches` | `NotFound` |
| `not currently signed in` / `authorization timeout` / `connecting to desktop app` / `connection reset` / `signin credentials are not compatible` | `AuthenticationFailed` |
| `connection reset` / `dial` / `getaddrinfo` / `i/o timeout` / `EOF` / `no such host` | `Backend { Transient }` |
| unmatched | `Backend { Permanent }` |

`PermissionDenied` is unreachable from `op read` because 1Password's
server returns 404 for both missing and no-permission cases (deliberate
authorization-aware design preventing existence oracles). These map to
`NotFound`.

## Deferred

- **Connect HTTP backend**: Would recover 401/403/404 distinction;
  deferred to a future wave with a separate feature flag and a
  name-to-UUID resolution dance.
- **Cross-invocation caching**: `op` already caches encrypted-at-rest in
  its own daemon (10-min idle / 12-h hard TTL). Adding a hasp-layer
  cache duplicates protection without adding it.
- **`put` / `delete`**: `op item edit` JSON interface changes across CLI
  major versions; deferred until the interface stabilizes.
