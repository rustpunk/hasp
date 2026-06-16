# hasp-backend-bw

`bw://` backend for hasp. Wraps the Bitwarden CLI (`bw`) via
`std::process::Command` subprocess.

## URL grammar

`bw://<item>/<field-path>` — get / put / delete / exists.

- `<item>` is the Bitwarden item name **or** UUID. Write paths
  resolve names to UUIDs internally before invoking `bw edit|delete`,
  which only accept UUIDs.
- `<field-path>` is a dot-separated path into the item JSON. Examples:
  `login.password`, `notes`, `fields.0.value`.
- No query parameters.

`bw://<search>` (host only, no path) — list. The sentinel host `_`
lists every item in the unlocked vault; any other host is forwarded to
`bw list items --search`.

**Sentinel collision caveat.** `_` is reserved for `list`; an item
literally named `_` cannot be enumerated via `hasp list bw://_`
(that URL is intercepted as the "list all" sentinel). `hasp get
bw://_/login.password` still resolves the literal name on get/put/
delete because the get-grammar URL has a path segment, distinguishing
it from the list-grammar URL. Bitwarden discourages one-character
names and this collision has not been observed in practice; an
escape syntax can be added if a user runs into it.

Item name and field path are identifiers, not secret values. They may
appear in error messages (redacted per URL discipline).

## Supported operations

| Operation | Status |
|-----------|--------|
| `get`     | Supported |
| `exists`  | Supported |
| `put`     | Supported (read-modify-write) |
| `list`    | Supported |
| `delete`  | Supported (soft delete — Trash) |

`put` performs a read-modify-write because Bitwarden's `bw edit item`
is whole-item replace. The backend fetches the existing item, splices
the field at `<field-path>` with the new value, base64-encodes the
JSON, and feeds it through stdin. On `NotFound` it builds a minimum
Login (or SecureNote for `notes`) and falls through to `bw create
item` via stdin.

`delete` is **soft** — the item moves to Trash and is recoverable for
30 days. The `bw delete item --permanent` option is deliberately not
exposed; this mirrors `op item delete`'s posture and keeps a single
misclick from being unrecoverable.

## Authentication

Ambient credentials only — hasp does not implement auth flows:

- `BW_SESSION` — session decryption key from `bw unlock --raw`

If no `BW_SESSION` is present, every operation returns
`AuthenticationFailed` without spawning the `bw` binary. This prevents
biometric unlock prompts in headless contexts.

## Argv exposure on `put`

`bw edit item` and `bw create item` accept the base64-encoded JSON
payload via stdin *or* as a positional argv. hasp uses the **stdin
path**: the secret transits stdin, never argv. On Linux this shrinks
the exposure window from "full subprocess lifetime
(`/proc/<pid>/cmdline` is same-uid readable)" to "pipe consumption
interval (`/proc/<pid>/fd/0` is gated by `PTRACE_MODE_READ_FSCREDS`
and `yama.ptrace_scope`)". Same posture as `op item edit/create` via
`op item edit -`.

The `FakeBwGuard` test scaffold asserts the stdin path: the fake
binary fails if hasp regresses to passing the payload on argv.

## Error mapping

Bitwarden uses `--response` for machine-readable JSON envelopes.
The backend parses `message` and maps it as follows:

| Response message anchor | hasp Error |
|-------------------------|------------|
| `Not found.` / `More than one result was found` | `NotFound` |
| `Vault is locked.` / `You are not logged in.` / `Your authentication request appears to be coming from a bot.` | `AuthenticationFailed` |
| `fetch failed` / `timeout` / `connection` / `dial` / `getaddrinfo` / `no such host` | `Backend { Transient }` |
| `Access to this item type is restricted by organizational policy.` | `PermissionDenied` |
| unmatched | `Backend { Permanent }` |

## Caveats

- **Whole-item replace.** `bw edit item` replaces the entire item
  document. A partial payload would clobber sibling fields. hasp's
  `put` reads the existing item first and splices in place; this
  doubles `put` latency from ~1 s to ~2 s relative to a fictional
  per-field edit, but Bitwarden offers no such per-field shorthand.
- **`bw list items` performance.** Bitwarden decrypts the entire
  vault client-side then filters in JavaScript. Large vaults
  (700+ items) can take 2+ minutes; the 30-second timeout reflects
  the typical case, not the worst case.
- **Personal vault only on create.** `BwBackend::put`'s create
  fallback builds items with `organizationId: null`, `folderId:
  null`, `collectionIds: null`. Org-scoped writes (with
  collection / folder assignment) are out of scope until a URL
  shape for them lands.

## Cross-invocation caching

`bw` caches encrypted vault data locally in `data.json`. A hasp-layer
cache duplicates protection without adding freshness guarantees, so
none is shipped.
