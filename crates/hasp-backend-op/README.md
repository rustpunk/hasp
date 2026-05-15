# hasp-backend-op

`op://` backend for hasp. Wraps the 1Password CLI (`op`) via
`std::process::Command` subprocess.

## URL grammar

`op://vault/item/field` — 3-segment form, used by `get` / `put` /
`delete` / `exists`. All three segments non-empty, no query
parameters.

`op://vault` — vault-only form, used by `list` (host only, no path).

Vault, item, and field identifiers are not secret values; they may
appear in error messages (redacted per URL discipline).

## Supported operations

| Operation | Status |
|-----------|--------|
| `get`     | Supported (`op read`) |
| `exists`  | Supported |
| `put`     | Supported (`op item edit`; falls back to `op item create` on NotFound) |
| `list`    | Supported (`op item list --vault <vault> --format=json`) |
| `delete`  | Supported (`op item delete` — removes the entire item; the URL's `field` segment is ignored) |

### Argv exposure on `put`

`op item edit` and `op item create` accept the secret value only as
a positional `<field>=<value>` argument. The value lives on `op`'s
argv for the life of the subprocess. On Linux, `/proc/<pid>/cmdline`
is same-uid readable — a same-uid attacker can observe the value
during the brief subprocess lifetime. This is the documented cost of
the `op` CLI surface and applies to every op-based tool. The
mitigation when `op` exposes a stdin variant (or when the Connect
HTTP backend lands) is a follow-up.

### Rename caveat on `list`

`Entry` URLs emitted by `list` prefer the item's `id` field (UUID,
rename-stable) when present in `op item list --format=json` output.
When `id` is absent (e.g., very old `op` versions, certain
fake-bin paths), the URL falls back to the title — which is
rename-fragile. The forthcoming UUID-tuple cache-key resolution
closes this fully.

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
- **UUID-tuple cache resolution**: `list` already emits UUIDs when
  `op item list --format=json` carries `id`. The follow-up extends
  this to a `Backend::canonical_cache_key` method that resolves
  vault/item names to UUIDs at fetch time, closing the rename
  caveat for the cache layer.
- **stdin / Connect-HTTP value path for `put`**: Removes the
  `/proc/<pid>/cmdline` argv exposure.
