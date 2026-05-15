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

hasp's `put` feeds the JSON template through stdin (`op item edit
<item> --vault <vault> -` and the symmetric `op item create … -`) so
the secret value never lives on `op`'s argv. On Linux this collapses
the exposure window from "full subprocess lifetime —
`/proc/<pid>/cmdline` is same-uid readable" to "pipe consumption
interval — `/proc/<pid>/fd/0` is gated by `PTRACE_MODE_READ_FSCREDS`
and `yama.ptrace_scope`". 1Password explicitly recommends this path
in the [item-edit docs](https://developer.1password.com/docs/cli/item-edit/):
*"Command arguments get logged in your command history, and can be
visible to other processes on your machine. If you're assigning
sensitive values, use a JSON template instead."*

The `edit` branch is read-modify-write: hasp first issues
`op item get --format=json`, splices the new value into the matching
field's `value`, and pipes the modified template to `op item edit`.
The `create` branch (NotFound fallback) builds a minimum-viable
`PASSWORD`-category template in-process. Neither branch carries
secret bytes on argv.

Connect HTTP would eliminate the subprocess entirely and recover the
401/403/404 distinction; tracked as a separate feature.

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

- **Connect HTTP backend**: Would recover 401/403/404 distinction
  and eliminate the subprocess. Separate feature flag with a
  name-to-UUID resolution dance.
- **UUID-tuple cache resolution**: `list` already emits UUIDs when
  `op item list --format=json` carries `id`. The follow-up extends
  this to a `Backend::canonical_cache_key` method that resolves
  vault/item names to UUIDs at fetch time, closing the rename
  caveat for the cache layer.
- **Passkey-preserving edit**: `op item edit` via the JSON-template
  path overwrites passkeys (per the 1Password docs). hasp inherits
  this footgun; a defensive check (refuse to edit items whose
  template contains a passkey field) is tracked separately.
