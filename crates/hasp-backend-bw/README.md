# hasp-backend-bw

`bw://` backend for hasp. Wraps the Bitwarden CLI (`bw`) via
`std::process::Command` subprocess.

## URL grammar

`bw://<item>/<field-path>`

- `<item>` is the Bitwarden item name (host component). Must be non-empty.
- `<field-path>` is a dot-separated path into the item JSON (first path
  segment). Examples: `login.password`, `notes`, `fields.0.value`.
- No query parameters.

Item name and field path are identifiers, not secret values. They may
appear in error messages (redacted per URL discipline).

## Supported operations

| Operation | Status |
|-----------|--------|
| `get`     | Supported |
| `exists`  | Supported |
| `put`     | `UnsupportedOperation` |
| `list`    | `UnsupportedOperation` |
| `delete`  | `UnsupportedOperation` |

`put`, `list`, and `delete` are deferred, not stubbed. The Bitwarden CLI
`bw edit` interface requires a full JSON round-trip and is brittle across
versions.

## Authentication

Ambient credentials only — hasp does not implement auth flows:

- `BW_SESSION` — session decryption key from `bw unlock -\-raw`

If no `BW_SESSION` is present, `get` and `exists` return
`AuthenticationFailed` without spawning the `bw` binary. This prevents
biometric unlock prompts in headless contexts.

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

## Deferred

- **`put` / `delete`**: `bw edit` requires a full JSON round-trip and
  is brittle across CLI versions; deferred until the interface stabilizes.
- **Cross-invocation caching**: `bw` caches encrypted vault data locally
  in `data.json`. A hasp-layer cache duplicates protection without adding
  freshness guarantees.
- **Direct field access via `bw get password`**: Only works for passwords.
  The current JSON extraction approach is general and consistent.
