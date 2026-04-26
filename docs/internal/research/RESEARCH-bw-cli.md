# Research: Bitwarden CLI (`bw`) interface for hasp backend

**Research date:** 2026-04-26
**Sources:** Bitwarden official docs (bitwarden.com/help/cli), GitHub source (bitwarden/clients), release notes
**Saved to:** docs/internal/research/RESEARCH-bw-cli.md

---

## Version requirements

The Bitwarden CLI (`bw`) is distributed as an independent binary from the main `clients` monorepo.
Releases are tagged `cli-vYYYY.MM.N` (e.g. `cli-v2026.4.1`).

- **Minimum viable version:** The CLI has supported `bw get item <name>` and `bw list items` with stable JSON output since at least the 2021-era releases (the canonical CLI documentation has not materially changed the output shape since ~2021.08). The August 2021 release introduced Captcha/auth challenges.
- **Current latest:** `2026.4.1` (as of 2026-04-23).
- **Recommendation for hasp:** Target `bw >= 2024.x` to avoid legacy behavior. The JSON output format has been stable for years; no breaking shape changes are expected.

**Official CLI docs URL:** https://bitwarden.com/help/cli/

---

## Command reference

### Global options (relevant to automation)

| Option | Effect |
|--------|--------|
| `--pretty` | Format JSON output with 2-space indentation |
| `--raw` | Return raw output instead of a descriptive message |
| `--response` | Return a JSON envelope `{success, message, data}` instead of plain data |
| `--quiet` | Suppress stdout entirely |
| `--nointeraction` | Do not prompt for interactive user input (fails instead) |
| `--session <session>` | Pass session key instead of reading `BW_SESSION` env |
| `-v, --version` | Print the CLI version |

**Note on version output:** `bw --version` (or `bw -v`) prints the version string obtained from the application's platform utils. Sample expected format (inferred from `program.ts`):
```
2026.4.1
```
(Exact string is the application version; no additional prefix/suffix is added.)

### `bw get` — retrieve a single object

Syntax:
```
bw get (item|username|password|uri|totp|notes|exposed|attachment|folder|collection|organization|org-collection|template|fingerprint) <id> [options]
```

For hasp's purposes, the relevant forms are:

| Form | Example | Notes |
|------|---------|-------|
| `bw get item <id>` | `bw get item 99ee88d2-6046-4ea7-92c2-acac464b1412` | Returns full JSON item. `<id>` can be an exact GUID or a search string. |
| `bw get password <name>` | `bw get password "github.com"` | Returns **only** the password string (raw). If >1 match, errors. |
| `bw get username <name>` | `bw get username "github.com"` | Returns only the username string. |
| `bw get notes <name>` | `bw get notes "My Note"` | Returns only the notes text. |
| `bw get uri <name>` | `bw get uri "github.com"` | Returns only the first URI. |

**Important:** The `get` command can only return **one result**. If multiple results match the search string, it returns an error (`Multiple results found`).

To extract a specific field from a full item JSON, use `jq` or parse the JSON:
```bash
bw get item "github.com" | jq -r '.login.password'
bw get item "github.com" | jq -r '.login.username'
bw get item "github.com" | jq -r '.notes'
```

### `bw list` — retrieve arrays

Syntax:
```
bw list (items|folders|collections|organizations|org-collections|org-members) [options]
```

Filters:
```
--url <url>
--folderid <folderid>
--collectionid <collectionid>
--organizationid <organizationid>
--trash
```

Search:
```
--search <search-term>
```

Example for existence check:
```bash
bw list items --search "github.com"
```

Combining filter + search performs an **AND** operation. Multiple filters perform an **OR** operation.

### `bw status`

Returns JSON with server URL, last sync, user email, and auth status (`unauthenticated` | `locked` | `unlocked`).

Useful for pre-flight auth validation:
```bash
bw status --response
```

---

## JSON output shape

### `bw get item` (successful, without `--response`)

The CLI returns a `CipherResponse` which extends `CipherWithIdExport`. Representative shape (synthesized from `cipher.response.ts` and `CipherWithIdExport`):

```json
{
  "object": "item",
  "id": "99ee88d2-6046-4ea7-92c2-acac464b1412",
  "type": 1,
  "name": "github.com",
  "notes": "My secure note",
  "favorite": false,
  "login": {
    "username": "jdoe",
    "password": "myp@ssw0rd123",
    "totp": null,
    "uris": [
      {
        "match": null,
        "uri": "https://github.com"
      }
    ]
  },
  "collectionIds": ["5c926f4f-de9c-449b-8d5f-aec1011c48f6"],
  "folderId": "9742101e-68b8-4a07-b5b1-9578b5f88e6f",
  "organizationId": null,
  "attachments": [],
  "revisionDate": "2024-01-15T10:30:00.000Z",
  "creationDate": "2023-06-01T08:00:00.000Z",
  "deletedDate": null,
  "passwordHistory": [],
  "fields": [],
  "reprompt": 0,
  "secureNote": null,
  "card": null,
  "identity": null
}
```

**Field extraction for `hasp get bw://<name>/<field>`:**

| Field path in JSON | Meaning |
|--------------------|---------|
| `.login.password` | Password |
| `.login.username` | Username |
| `.notes` | Secure note text |
| `.login.totp` | TOTP seed |
| `.login.uris[].uri` | URI list |
| `.fields[]` | Custom fields (array of `{name, value, type}`) |

Custom fields example:
```json
{
  "fields": [
    { "name": "API Key", "value": "sk-xxx", "type": 0 },
    { "name": "Environment", "value": "prod", "type": 1 }
  ]
}
```

### `bw list items` (successful)

Returns an array of the same item objects (with the same `CipherResponse` shape), wrapped in a `list` object when using `--response`:

Without `--response`:
```json
[
  { /* item 1 */ },
  { /* item 2 */ }
]
```

With `--response`:
```json
{
  "object": "list",
  "data": [
    { /* item 1 */ },
    { /* item 2 */ }
  ]
}
```

### `bw status` output

```json
{
  "object": "template",
  "template": {
    "serverUrl": "https://vault.bitwarden.com",
    "lastSync": "2024-01-15T10:30:00.000Z",
    "userEmail": "jdoe@example.com",
    "userId": "abc123...",
    "status": "unlocked"
  }
}
```

---

## Error text and exit codes

### Exit code behavior

From `base-program.ts` (`processResponse`):

| Condition | Exit code | Behavior |
|-----------|-----------|----------|
| Success | `0` | Prints JSON/data to stdout |
| Error (default) | `1` | Prints `response.message` to stderr in red |
| Error + `--cleanexit` | `0` | Prints error but exits 0 |

**Note:** `--cleanexit` means the CLI exits 0 even on errors. hasp must NOT rely on exit code 0 as success when `--cleanexit` is used. Default behavior (no `--cleanexit`) exits 1 on all errors.

### Common error messages

| Scenario | Error text (stderr) | Exit code |
|----------|---------------------|-----------|
| Not logged in | `You are not logged in.` | 1 |
| Vault locked | `Vault is locked.` | 1 |
| Item not found | `Not found.` | 1 |
| Multiple matches | `More than one result was found. Try getting a specific object by \`id\` instead. The following objects were found: ...` | 1 |
| Auth challenge / bot detection | `Your authentication request appears to be coming from a bot.` | 1 |
| API key auth challenge fail | (varies, see `cli-auth-challenges` docs) | 1 |
| No password available | `No username available for this login.` | 1 |
| Not a login type | `Not a login.` | 1 |
| Restricted by org policy | `Access to this item type is restricted by organizational policy.` | 1 |
| Network errors | Thrown as exceptions, message varies (e.g. `fetch failed`, timeout) | 1 |
| Invalid command | `Invalid command: ...` | 1 |

**The `Response` object source (`response.ts`):**
```typescript
static notFound(): Response { return Response.error("Not found."); }
static badRequest(message: string): Response { return Response.error(message); }
static multipleResults(ids: string[]): Response {
  let msg = "More than one result was found. Try getting a specific object by `id` instead. " +
            "The following objects were found:";
  ids.forEach((id) => { msg += "\n" + id; });
  return Response.error(msg, ids);
}
```

**When using `--response` flag:**
Errors are returned as JSON on stdout (not stderr), with shape:
```json
{
  "success": false,
  "message": "Not found.",
  "data": null
}
```

This is the recommended mode for subprocess parsing because it is machine-readable and separates control output from data.

---

## Auth model

### Two-step model: login + unlock

The Bitwarden CLI uses a two-step model:

1. **Login** (`bw login`) — authenticates identity with the server.
2. **Unlock** (`bw unlock`) — decrypts the vault locally using the master password, producing a **session key**.

Only after unlock can data commands (`get`, `list`, `edit`, `delete`) be used.

### Session key (`BW_SESSION`)

- Generated by `bw unlock` (or `bw login` with email+password).
- Must be passed via the `BW_SESSION` environment variable **or** via `--session <key>` on every command.
- **Does not persist across terminal sessions.** Opening a new terminal requires a new `bw unlock`.
- Invalidated by `bw lock` or `bw logout`.

Example:
```bash
export BW_SESSION="5PBYGU+5yt3RHcCjoeJKx/wByU34vokGRZjXpSH7Ylo8w=="
bw list items
# or
bw list items --session "5PBYGU+5yt3RHcCjoeJKx/wByU34vokGRZjXpSH7Ylo8w=="
```

### Environment variables for ambient auth

| Variable | Required for | Value |
|----------|--------------|-------|
| `BW_SESSION` | **All data commands** | Session key from `bw unlock` |
| `BW_CLIENTID` | API-key login | `user.<uuid>` (from web vault) |
| `BW_CLIENTSECRET` | API-key login | Personal API key `client_secret` |
| `BW_PASSWORD` | `bw unlock --passwordenv` | Master password |
| `BW_PRETTY` | Global option flag | Set by `--pretty` |
| `BW_RAW` | Global option flag | Set by `--raw` |
| `BW_RESPONSE` | Global option flag | Set by `--response` |
| `BW_QUIET` | Global option flag | Set by `--quiet` |
| `BW_NOINTERACTION` | Global option flag | Set by `--nointeraction` |
| `BW_CLEANEXIT` | Global option flag | Set by `--cleanexit` |
| `BITWARDENCLI_APPDATA_DIR` | Multi-account | Path to a separate `data.json` config directory |

### Login methods

| Method | Command | Notes |
|--------|---------|-------|
| Email + password | `bw login [email] [password]` | Interactive prompt if args omitted. Not recommended for automation. |
| API key | `bw login --apikey` | Reads `BW_CLIENTID` / `BW_CLIENTSECRET`. Recommended for CI/automation. Still requires `bw unlock` after. |
| SSO | `bw login --sso` | Launches browser flow. Not suitable for automation. |

### Unlock automation

For CI/automated workflows, after `bw login --apikey`:
```bash
bw unlock --passwordenv BW_PASSWORD --raw
```
The `--raw` flag returns **only** the session key, which can be captured:
```bash
export BW_SESSION=$(bw unlock --passwordenv BW_PASSWORD --raw)
```

---

## Design implications for hasp

### Subprocess backend strategy

A Rust `bw` backend for `hasp` should:

1. **Require `BW_SESSION` as the ambient credential.** The backend must check that `BW_SESSION` is set (or provided via the URL query parameter `?session=...`, though passing secrets in URLs is a threat-model concern).
2. **Always use `--response` and `--nointeraction`.** `--response` gives machine-readable JSON; `--nointeraction` prevents the CLI from hanging on prompts.
3. **Parse the `Response` envelope.** With `--response`, success is determined by `"success": true`, not by exit code alone.
4. **Handle `multipleResults` as an error.** The backend cannot disambiguate; return a clear error to the user.
5. **Use `jq`-like JSON path extraction.** The `hasp` URL scheme for `bw` could be:
   ```
   bw://<item-name>/<field-path>
   ```
   e.g.:
   ```
   bw://github.com/login.password
   bw://github.com/notes
   bw://API%20Key/fields.API%20Key
   ```
6. **Do NOT expose `--cleanexit`.** It makes exit code unreliable.
7. **Use `bw status` for pre-flight auth check.** Call `bw status --response` and verify `"status": "unlocked"` before expensive operations.
8. **Redaction discipline:** The `bw` CLI may print secret values to stdout (that is its job). `hasp` must capture stdout, extract the value, and immediately wrap it in `secrecy::SecretString`. Never log raw `bw` output.
9. **Never pass `BW_SESSION` on argv.** Use the environment variable. The `--session` flag is available but appears in `ps`.

### Threat-model notes

- `BW_SESSION` is a high-sensitivity bearer token. If compromised, an attacker has read access to the entire vault.
- `bw` stores local state (including encrypted vault data) in a `data.json` file. The session key decrypts this local cache, not the server directly.
- Process-boundary leak: `BW_SESSION` may be visible in `/proc/<pid>/environ`. There is no `bw` equivalent to `op`'s file-descriptor session passing.
- The CLI does not provide built-in output redaction for secret values; it prints them as raw JSON strings. The redaction burden falls entirely on the `hasp` wrapper.

### Rejected alternatives

- **Avoid parsing human-readable `bw` output without `--response`.** The plain output format changes slightly between commands (sometimes just a string, sometimes JSON, sometimes a message). `--response` is the only stable contract.
- **Avoid `bw get password <name>` for general `hasp get`.** It only works for passwords and returns raw text. Using `bw get item` + JSON extraction is more general and consistent.

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| Bitwarden CLI Docs | Official docs | Command reference, auth model | https://bitwarden.com/help/cli/ |
| CLI Authentication Challenges | Official docs | `BW_CLIENTSECRET` usage | https://bitwarden.com/help/cli-auth-challenges/ |
| Bitwarden CLI Releases | GitHub releases | Version history, minimum viable version | https://github.com/bitwarden/clients/releases?q=cli |
| `program.ts` | Source code | Global flags (`--response`, `--raw`, `--version`) | https://github.com/bitwarden/clients/blob/main/apps/cli/src/program.ts |
| `base-program.ts` | Source code | Exit code logic, `processResponse` | https://github.com/bitwarden/clients/blob/main/apps/cli/src/base-program.ts |
| `get.command.ts` | Source code | `bw get` implementation, error messages | https://github.com/bitwarden/clients/blob/main/apps/cli/src/commands/get.command.ts |
| `list.command.ts` | Source code | `bw list` implementation, filters | https://github.com/bitwarden/clients/blob/main/apps/cli/src/commands/list.command.ts |
| `response.ts` | Source code | `Response.error()`, `notFound()`, `multipleResults()` | https://github.com/bitwarden/clients/blob/main/apps/cli/src/models/response.ts |
| `cipher.response.ts` | Source code | JSON output shape for items | https://github.com/bitwarden/clients/blob/main/apps/cli/src/vault/models/cipher.response.ts |
| `utils.ts` | Source code | `writeLn` (stdout/stderr handling) | https://github.com/bitwarden/clients/blob/main/apps/cli/src/utils.ts |

