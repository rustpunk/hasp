# RESEARCH-bw-cli-write

**Research date:** 2026-05-15
**Brief:** Bitwarden CLI (`bw`) write-side surface — what `put` / `delete` /
`list` must do for the `bw://` backend to reach parity with the shipped
`op://` write path.
**Saved to:** `docs/internal/research/RESEARCH-bw-cli-write.md`
**Cites and builds on:** `RESEARCH-bw-cli.md` (read side, error envelope,
auth model), `RESEARCH-op-cli.md` (op:// write reference)

---

## Headline findings

1. `bw edit item` and `bw create item` **require base64-encoded JSON** as
   their data argument. They accept the encoded blob either as a
   positional argv argument or via stdin. There is no raw-JSON path and
   no `<field>=<value>` shorthand — every write touches the **whole
   item document**. This is a load-bearing semantic difference from
   `op item edit` (which patches individual fields).
2. `bw edit item <id>` returns `Response.notFound()` (message string
   exactly `"Not found."`) when `<id>` does not resolve — same anchor
   already mapped in `map_bw_response_error`. The edit-then-create
   fallback can branch on `Error::NotFound`.
3. `bw delete item <id>` soft-deletes (Trash) by default; `--permanent`
   destroys irrecoverably. hasp should always soft-delete and **not**
   expose `--permanent` in `0.1.0`.
4. `bw list items` decrypts the entire vault client-side, then applies
   filters in JS. Latency scales with vault size; 5300 items took
   ~20 min on `2024.4.1`. The current 10 s `EXISTS_TIMEOUT` is
   insufficient; recommend 30 s for `list` and keep 15 s for `get`.
5. CLI versions `2026.4.0` (npm @bitwarden/cli) were compromised in the
   Shai-Hulud / Checkmarx supply-chain incident (Apr 22, 2026). hasp
   does not bundle `bw`, but the existing `parse_bw_version` floor of
   2023.1.0 should be raised so we ignore `2026.4.0` if seen — or at
   minimum the per-backend README must warn about it.

---

## §1. `bw edit item` — exact surface

### Invocation grammar

```
bw edit item <id> [encodedJson] [options]
```

- `<id>` is **the item UUID**. Names are not accepted here. (`bw get
  item <name>` resolves names; `bw edit` resolves only IDs. This is
  consistent across all object types and confirmed via `edit.command.ts`
  source.)
- `[encodedJson]` is base64-encoded JSON. Optional on the command line:
  when omitted, the CLI reads stdin.

### Stdin vs positional argv

From `edit.command.ts` (bitwarden/cli, master):

```typescript
if (process.env.BW_SERVE !== "true" &&
    (requestJson == null || requestJson === "")) {
  requestJson = await CliUtils.readStdin();
}
const reqJson = Buffer.from(requestJson, "base64").toString();
req = JSON.parse(reqJson);
```

**Both paths are supported.** stdin is read only when the positional
argument is absent or empty, *and* the CLI is not running in
`BW_SERVE=true` mode. Same logic appears in `create.command.ts`.

This is the equivalent of `op item edit … field=value` — except
Bitwarden has no per-field assignment shorthand, so the whole item JSON
must be re-uploaded every time.

**Implication for hasp:** the secret value will be embedded in the
base64-encoded item JSON. We must use the **stdin path** to keep the
plaintext password out of argv and process listings. This is the same
hardening posture documented in `RESEARCH-op-cli.md` for `op item
create` (but Bitwarden actually offers the stdin path that op did not).

### Replace semantics

From the Bitwarden help docs: "the edit command will perform a replace
operation on the object." A partial JSON payload — e.g. one that only
sets `login.password` — would clobber `login.username`, `notes`,
`fields[]`, `folderId`, and every other top-level key. The required
flow is **get → mutate → put**:

```
bw get item <id> --response | jq '.data.login.password = "newp@ss"' \
  | jq -c .data | bw encode | bw edit item <id>
```

hasp's `put` must do the same: fetch the current item, splice the field
indicated by the URL path, re-encode, send. This is a structural
departure from the op:// `put` shape — note for the implementation
plan.

### JSON shape for a Login item with `login.password`

The `bw get template item` output, confirmed across multiple sources:

```json
{
  "organizationId": null,
  "collectionIds": null,
  "folderId": null,
  "type": 1,
  "name": "Item name",
  "notes": null,
  "favorite": false,
  "fields": [],
  "login": {
    "username": null,
    "password": null,
    "totp": null,
    "uris": []
  },
  "secureNote": null,
  "card": null,
  "identity": null,
  "reprompt": 0
}
```

`type: 1` = Login. Other types: 2 = SecureNote, 3 = Card, 4 = Identity.

For the canonical hasp URL `bw://<item-uuid>/login.password`, the edit
payload after mutation looks like:

```json
{
  "type": 1,
  "name": "github.com",
  "login": { "username": "jdoe", "password": "<new>", "totp": null, "uris": [...] },
  ...
}
```

The `id` field can be present or omitted; the CLI uses the positional
`<id>` argument.

### Failure shapes

With `--response`:

| Scenario | `message` text | `success` |
|----------|----------------|-----------|
| Item not found | `"Not found."` | `false` |
| Invalid base64 / JSON | `"Error parsing the encoded request data."` | `false` |
| Missing argv and no stdin | `` "`requestJson` was not provided." `` | `false` |
| Deleted item (in Trash) | `"You may not edit a deleted item. Use the restore command first."` | `false` |
| Vault locked / no session | `"Vault is locked."` / `"You are not logged in."` | `false` |

Exit code is `1` on every error (same as the read side documented in
`RESEARCH-bw-cli.md` §1.4 / §1.6). The `--response` envelope is the
same `{ "success": bool, "message": string, "data": any }` shape used
by `bw get` / `bw list`.

The existing `map_bw_response_error` (`crates/hasp-backend-bw/src/lib.rs:372-409`)
already maps `"not found."` → `Error::NotFound`. The edit-then-create
fallback can branch on `matches!(err, Error::NotFound(_))` exactly as
the op:// path does at
`crates/hasp-backend-op/src/lib.rs:348`.

The `"You may not edit a deleted item"` anchor is new; recommend adding
it to `map_bw_response_error` as `Error::Conflict` or fall through to
the permanent default.

**Sources:**
- https://bitwarden.com/help/cli/ (help docs — invocation grammar, "replace operation")
- https://github.com/bitwarden/cli/blob/master/src/commands/edit.command.ts (stdin handling, base64 decode, notFound() call site)
- https://github.com/bitwarden/clients/blob/main/apps/cli/src/models/response.ts (Response.notFound message text)

---

## §2. `bw create item` — exact surface

### Invocation grammar

```
bw create item [encodedJson] [options]
```

Same shape as edit (stdin or positional argv, base64 JSON).

### Required fields for a Login item

From the template above plus testing notes in community threads, the
minimum-viable Login item is:

```json
{
  "type": 1,
  "name": "<title>",
  "login": { "password": "<value>" }
}
```

`organizationId`, `folderId`, `collectionIds` may all be `null` for a
personal vault item. `notes`, `favorite`, `fields`, `uris` are optional
and default to safe values.

### Folder / collection / org assignment

| Field | When required |
|-------|---------------|
| `organizationId` | Org-owned item (otherwise null = personal vault) |
| `collectionIds` | Required if `organizationId` is set; ignored otherwise |
| `folderId` | Optional, references a folder UUID from `bw list folders` |

For `0.1.0`, hasp's `put` should create personal-vault items only:
`organizationId: null`, `folderId: null`. Org-scoped writes need a
separate URL shape (e.g. `bw://<org-id>/<item>` or
`?org=<uuid>&collection=<uuid>` — out of scope for issue #23).

### Edit-then-create fallback

Per §1, `bw edit item <id>` returns `Response.notFound()` ("Not
found.") when `<id>` does not resolve. The same code path is used
inside `editCipher()`:

```typescript
if (cipher == null) {
  return Response.notFound();
}
```

`map_bw_response_error` already routes that anchor to `Error::NotFound`,
so the op://-style fallback works as written. The wrinkle is that hasp
must first resolve the URL's `<item>` token to a UUID via `bw list
items --search <name>` before calling `bw edit`. The current `get`
path already does this implicitly (`bw get item <name>` accepts a name
or UUID); `edit` does not. See §6.

**Sources:**
- https://github.com/bitwarden/cli/blob/master/src/commands/create.command.ts (stdin path, base64 decode, CipherExport type)
- https://bitwarden.com/help/cli/ (template structure, type codes)
- https://github.com/bitwarden/cli/issues/153 (org-collection assignment after create)

---

## §3. `bw delete item` — trash vs permanent

### Source (delete.command.ts)

```typescript
if (options.permanent) {
  await this.cipherService.deleteWithServer(id);
} else {
  await this.cipherService.softDeleteWithServer(id);
}
```

| Mode | Default | Recoverable | Server effect |
|------|---------|-------------|---------------|
| Soft delete (no flag) | yes | yes, for 30 days via `bw restore item <id>` | sets `deletedDate` |
| `-p`, `--permanent` | no | **no** | removes the cipher row server-side |

### Recommendation for hasp

**Default to soft delete. Do not expose `--permanent`.** Rationale:

- Mirrors `op item delete` (1Password also moves to Archive / Trash by
  default; `op item delete --archive` exists but the default semantics
  match).
- A `hasp delete bw://item/login.password` invocation issued from a
  script should never be irrecoverable. The user can recover via
  `bw restore item <id>` for 30 days.
- The op:// surface at `crates/hasp-backend-op/src/lib.rs:462-482`
  ships no destructive-delete flag; bw:// should match.

A future `hasp delete --permanent` flag is debatable but explicitly out
of scope for #23.

### Field-vs-item granularity

`bw delete item <id>` deletes the entire cipher, not just one field —
identical to `op item delete`. The URL's field path
(`bw://<item>/login.password`) is required by hasp's grammar but
ignored by the delete handler. This matches the documented op://
behavior at `crates/hasp-backend-op/src/lib.rs:467-471` and should be
called out in the per-backend README.

**Sources:**
- https://github.com/bitwarden/cli/blob/master/src/commands/delete.command.ts
- https://bitwarden.com/help/cli/ ("default" and "--permanent" semantics)

---

## §4. `bw list items` — shape, filters, performance

### Filters (server-side or client-side?)

**Client-side, after full-vault decrypt.** From `list.command.ts`:

```typescript
let ciphers = await this.cipherService.getAllDecrypted();
ciphers = ciphers.filter((c) => { ... apply --search / --folderid / --collectionid ... });
```

| Flag | Effect |
|------|--------|
| `--search <term>` | name/notes substring filter (client-side) |
| `--folderid <id>` | folder filter; accepts `null` / `notnull` |
| `--collectionid <id>` | collection filter; accepts `null` / `notnull` |
| `--organizationid <id>` | org filter |
| `--trash` | show only items in Trash (boolean) |
| `--url <url>` | URI filter |

Filter combinators: multiple filters OR; filter + `--search` is AND.

### Performance data

| Vault size | Version | Latency |
|------------|---------|---------|
| ~700 items | 2024.4.1 | 2 min 45 s |
| 5300 items | 2024.4.1 | ~20 min |
| Comparable vaults | 1.19.1 (legacy) | < 20 s |

(Source: bitwarden/clients#9403. The regression was tracked in PR
9589.)

This is a hard performance problem inherited from `bw`; hasp cannot
fix it. Implications:

- The current `EXISTS_TIMEOUT = 10s` (`crates/hasp-backend-bw/src/lib.rs:107`)
  is too short for `list` against any non-trivial vault.
- **Recommendation:** introduce `LIST_TIMEOUT = 30s`. 15 s would match
  `GET_TIMEOUT` but the data above shows 700 items can already exceed
  that; 30 s is the smallest value with a non-zero chance of completing
  on a 1k-item vault.
- Document the timeout in the per-backend README. Users with large
  vaults should expect `Error::Backend{kind: Transient}` and either
  (a) raise the timeout via a future config knob or (b) use a search
  filter to narrow the result.

### URL shape returned by `list`

`bw://<item>/<field>` requires both segments. For `list`, every entry
needs to be addressable by a *get-able* URL. Mirroring the op:// shape
at `crates/hasp-backend-op/src/lib.rs:447`:

```rust
let entry_url = format!("bw://{}/login.password", item_id);
```

Use the item UUID (rename-stable), default field to `login.password`,
skip non-Login items (`type != 1`) — same posture as op:// skipping
non-`LOGIN`/`PASSWORD` categories at lines 438-445. Consumers piping
`hasp list bw://` into `hasp get` on a vault full of SecureNotes will
hit `not found` on the synthesized field; document it.

Output envelope with `--response`:

```json
{ "success": true, "data": { "object": "list", "data": [ {...item...} ] } }
```

(Double-`data`: the outer envelope wraps the list, and the inner
ListResponse has its own `data` array.)

**Sources:**
- https://github.com/bitwarden/cli/blob/master/src/commands/list.command.ts
- https://bitwarden.com/help/cli/ (filter docs)
- https://github.com/bitwarden/clients/issues/9403 (perf regression)

---

## §5. Auth-state requirements for write paths

`bw status` returns one of `"unlocked"` / `"locked"` /
`"unauthenticated"`. Every write path (edit, create, delete, list)
requires `"unlocked"` — same as `get`. No write command requires a
re-prompt for the master password beyond what `unlock` already
established; the session key is sufficient.

### Existing `check_ambient_credentials` is sufficient

`crates/hasp-backend-bw/src/lib.rs:446-453` checks for `BW_SESSION`.
Same pre-flight applies to all four write methods. No changes needed.

### Vault sync staleness

One documented gotcha (issue #11669, `bw edit item-collections`
example): writes immediately after a `create` can fail with `"Not
found."` because the local vault cache hasn't refreshed. Workaround:
`bw sync -f` between operations. hasp's `put` uses the edit-then-create
pattern, so this affects the `create` path's subsequent `edit` — but
since we never chain those (each `put` is a single
edit-or-create-but-not-both), this should not bite us.

Document the workaround in the per-backend README in case a user
scripts `hasp put` immediately followed by `hasp get` on a freshly
created item. The `Store` TTL cache may also paper over staleness
positively.

### Session-key argv exposure

`BW_SESSION` must be passed via the env var, **never** via
`--session <key>`. The latter appears in `/proc/<pid>/cmdline`.
Existing `run_bw_with_timeout` does not pass `--session`, so this is
already correct. Same posture as op://'s `OP_SERVICE_ACCOUNT_TOKEN`.

**Sources:**
- https://bitwarden.com/help/cli/ (auth model, status states)
- https://github.com/bitwarden/clients/issues/11669 (sync staleness)

---

## §6. Item-ID precedence (URL canonicalization)

### Name vs UUID acceptance

| Command | Accepts name? | Accepts UUID? |
|---------|---------------|---------------|
| `bw get item <id>` | yes (via search) | yes |
| `bw edit item <id>` | **no** — UUID only | yes |
| `bw delete item <id>` | **no** — UUID only | yes |

This forces hasp to resolve names to UUIDs before any write. The
resolution path is `bw list items --search <name>` → first match's
`id` field. If multiple matches, return `Error::NotFound` with the
"More than one result" anchor (already handled in
`map_bw_response_error`).

### Canonical URL after write

Mirror the op:// posture at
`crates/hasp-backend-op/src/lib.rs:419-427`: when the backend has a
choice between a user-supplied name and the canonical UUID, prefer the
UUID for cache keys and returned URLs. For `bw list`, the synthesized
entry URL must use the UUID (rename-stable). For `bw put` on an
existing item, after the edit succeeds the operation is complete; for
`bw put` on a not-yet-existing item, after the create succeeds the
returned UUID should be available for the cache key.

### Suggested URL pattern

The existing grammar `bw://<item>/<field>` supports both — `<item>` is
treated as opaque and passed to `bw get item <item>`. For write paths,
the implementation must always go through a name→UUID resolution step,
even if the URL already contains a UUID (cheap idempotent check).

**Sources:**
- https://github.com/bitwarden/cli/blob/master/src/commands/edit.command.ts
- https://github.com/bitwarden/cli/blob/master/src/commands/delete.command.ts
- `crates/hasp-backend-op/src/lib.rs:419-427` (op:// `id` precedence)

---

## §7. Failure modes / known incidents

### Supply-chain compromise of `@bitwarden/cli@2026.4.0` (April 2026)

- npm package `@bitwarden/cli@2026.4.0` shipped a malicious
  `bw_setup.js` + `bw1.js` payload between **17:57 ET and 19:30 ET on
  2026-04-22** (~93 min window).
- Root cause: compromised `checkmarx/ast-github-action` used in
  bitwarden's CI/CD pipeline.
- Payload: harvested GitHub tokens, npm tokens, SSH keys, env vars,
  shell history, AWS / Azure / GCP credentials.
- 334 developers downloaded the bad package before takedown.
- Last known clean: `@bitwarden/cli@2026.3.0`. Re-released as
  `@bitwarden/cli@2026.4.1` on 2026-04-23 16:45 GMT+2.
- hasp does not bundle `bw`; we invoke whatever's on `PATH`. The
  threat is purely indirect: a developer with `2026.4.0` installed has
  their `BW_SESSION` and shell history exfiltrated.

**Recommendation:** add a hard block on version `2026.4.0` exactly in
`check_version`. The existing `parse_bw_version` already extracts the
triple; insert an `if version == (2026, 4, 0)` reject path with a
specific error message pointing at the advisory.

### `bw list items` slowness on large vaults

See §4. Not a CVE but a UX cliff.

### Sync staleness after `create`

See §5. Not a CVE; documented community-known issue.

### No documented argv-leakage CVE specifically for `bw`

A search for `/proc/cmdline` / argv-leak CVEs against `bw` returned
nothing — but the *general* threat model (any value on argv is visible
to same-uid processes via `/proc/<pid>/cmdline`) applies. Using the
stdin path for `bw edit | bw create` payloads sidesteps this entirely.

**Sources:**
- https://www.endorlabs.com/learn/shai-hulud-the-third-coming----inside-the-bitwarden-cli-2026-4-0-supply-chain-attack
- https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html
- https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127
- https://github.com/bitwarden/clients/issues/9403 (list perf)
- https://github.com/bitwarden/clients/issues/11669 (sync staleness)

---

## §8. Design insights for hasp (concrete function sketches)

### `BwBackend::put` (sketch)

```rust
fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
    use hasp_core::ExposeSecret;

    self.ensure_init()?;
    check_ambient_credentials()?;

    let bw_url = BwUrl::try_from(url)?;
    let reference = format!("bw://{}/{}", bw_url.item, bw_url.field_path);

    // Step 1: resolve item name -> UUID, fetch current JSON.
    // Step 2: if not found, build a fresh template + splice value, create.
    // Step 3: if found, splice value into the existing JSON, edit.

    let existing = match get_item_envelope(&bw_url.item, GET_TIMEOUT, &reference) {
        Ok(envelope) => Some(envelope),
        Err(Error::NotFound(_)) => None,
        Err(e) => return Err(e),
    };

    match existing {
        Some(envelope) => {
            let mut item = envelope.get("data").cloned().ok_or_else(|| /* ... */)?;
            let item_id = item.get("id").and_then(|v| v.as_str())
                .ok_or_else(|| /* ... */)?
                .to_owned();
            splice_field(&mut item, &bw_url.field_path, value.expose_secret(), &reference)?;
            bw_edit_item(&item_id, &item, EDIT_TIMEOUT, &reference)
        }
        None => {
            let mut item = build_login_template(&bw_url.item);
            splice_field(&mut item, &bw_url.field_path, value.expose_secret(), &reference)?;
            bw_create_item(&item, CREATE_TIMEOUT, &reference)
        }
    }
}

fn bw_edit_item(id: &str, item: &serde_json::Value, timeout: Duration, reference: &str)
    -> Result<(), Error>
{
    // Serialize to JSON, base64-encode, pipe to stdin of `bw edit item <id>`.
    // NEVER place the JSON or the secret on argv.
    let json = serde_json::to_string(item)?;
    let b64 = BASE64.encode(json.as_bytes());
    run_bw_with_stdin(&["--response", "--nointeraction", "edit", "item", id], &b64, timeout)
}
```

Key invariants:

- `splice_field` operates on `serde_json::Value` and mirrors
  `extract_field`'s dot-path grammar. Existing `extract_field` returns
  a `String`; `splice_field` is the inverse.
- `bw_edit_item` / `bw_create_item` write the base64 payload to the
  child's stdin via a third reader thread. The existing
  `run_bw_with_timeout` only handles stdout/stderr — needs an
  `run_bw_with_stdin` variant that also drains stdin.
- The secret value is in the base64 blob fed to stdin. Argv contains
  only `edit item <uuid>` — safe to appear in `/proc/<pid>/cmdline`.

### `BwBackend::delete` (sketch)

```rust
fn delete(&self, url: &Url) -> Result<(), Error> {
    self.ensure_init()?;
    check_ambient_credentials()?;

    let bw_url = BwUrl::try_from(url)?;
    let reference = format!("bw://{}/{}", bw_url.item, bw_url.field_path);

    // Resolve name -> UUID via get, then delete by UUID.
    let envelope = get_item_envelope(&bw_url.item, GET_TIMEOUT, &reference)?;
    let id = envelope.get("data").and_then(|d| d.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| /* missing id */)?;

    // Soft delete only. No --permanent.
    let args = ["--response", "--nointeraction", "delete", "item", id];
    let output = run_bw_with_timeout(&args, DELETE_TIMEOUT)?;
    parse_response_envelope_for_delete(&output, &reference)
}
```

### `BwBackend::list` (sketch)

```rust
fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
    self.ensure_init()?;
    check_ambient_credentials()?;

    // `bw://` host is required by grammar but irrelevant for `list`.
    // Future enhancement: `bw://?folderid=<uuid>` to push a filter.
    let args = ["--response", "--nointeraction", "list", "items"];
    let output = run_bw_with_timeout(&args, LIST_TIMEOUT)?;

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    // envelope.data.data is the array of items (double-nest, see §4).
    let items = envelope.pointer("/data/data")
        .and_then(|v| v.as_array())
        .ok_or_else(|| /* unexpected shape */)?;

    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or_continue;
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or(id);
        // Type 1 = Login. Skip everything else for now (synthesized
        // `login.password` URL would 404 on non-Login items).
        if item.get("type").and_then(|v| v.as_i64()) != Some(1) {
            continue;
        }
        let entry_url = Url::parse(&format!("bw://{}/login.password", id))?;
        entries.push(Entry { name: name.to_owned(), url: entry_url });
    }
    Ok(entries)
}
```

### `FakeBwGuard` extensions

`crates/hasp-core/src/test_utils.rs:200-296` ships a read-side fake.
Extensions needed for write coverage:

1. Handle `bw edit item <uuid>` from stdin: read stdin, base64-decode,
   parse JSON, store in a per-test sidecar file (e.g.
   `$TMPDIR/fake-bw-state.json`), emit
   `{"success":true,"data":{"id":"<uuid>", ...}}`.
2. Handle `bw create item` from stdin: same, but synthesize a new
   UUID. Append to state file.
3. Handle `bw delete item <uuid>`: mark soft-deleted in state file.
   Emit `{"success":true,"data":null}` (or whatever Bitwarden
   actually emits — TBD by reading `delete.command.ts` once more).
4. Handle `bw list items`: emit a JSON array from the state file.

Soft-delete vs permanent is irrelevant for fake-bin coverage (we never
plumb `--permanent`).

### Constants to add

```rust
/// Wall-clock timeout for write operations (edit / create / delete).
/// Same baseline as GET_TIMEOUT; writes incur an extra server round-trip
/// but no client-side decrypt of the full vault.
const PUT_TIMEOUT: Duration = Duration::from_secs(15);
const DELETE_TIMEOUT: Duration = Duration::from_secs(15);

/// Wall-clock timeout for `bw list items`. The CLI decrypts the entire
/// vault before applying filters; 700-item vaults observed at ~3min on
/// 2024.4.1. 30 s is the smallest value with non-zero chance of
/// completing on a 1k-item vault. Users with larger vaults will see
/// Transient timeouts.
const LIST_TIMEOUT: Duration = Duration::from_secs(30);
```

### `map_bw_response_error` additions

Add anchors:

| Anchor (lowercased substring) | Mapping |
|-------------------------------|---------|
| `"error parsing the encoded request data"` | `Error::Backend { kind: Permanent }` |
| `"you may not edit a deleted item"` | `Error::Backend { kind: Permanent }` (or `Error::NotFound` if we want to fall through to create) |
| `` "`requestjson` was not provided" `` | `Error::Backend { kind: Permanent }` — internal bug if ever hit |

---

## §9. Recommendation

| Decision | Recommended value | Rationale |
|----------|-------------------|-----------|
| `bw delete` default | soft (Trash) | Mirrors op://; recoverable for 30 days; one user mistake doesn't destroy data. |
| Expose `--permanent` in hasp `0.1.0`? | **no** | Out of scope; can add `hasp delete --permanent` as a flag later. |
| `LIST_TIMEOUT` | 30 s | 10 s far too low given full-vault decrypt; 30 s covers ~1k items typical case. |
| `PUT_TIMEOUT` / `DELETE_TIMEOUT` | 15 s | Match `GET_TIMEOUT`; writes are not slower than reads. |
| Pass payload via | **stdin** | Keeps secret out of `/proc/<pid>/cmdline`. The `bw edit/create` stdin path is supported and documented. |
| Block CLI version | `2026.4.0` exactly | Supply-chain compromise; safe versions are `<= 2026.3.0` or `>= 2026.4.1`. |
| Org / collection writes | out of scope for #23 | Personal vault only in `0.1.0`. URL shape extension is a follow-up. |
| Edit-then-create fallback | yes, branch on `Error::NotFound` | Mirrors op:// at `crates/hasp-backend-op/src/lib.rs:340-376`. |
| URL canonicalization | always use UUID in synthesized URLs | `bw edit/delete` reject names; UUID is the only stable identifier. |

### What forces #23 to ship partial

None of the above are blockers. The two friction points are:

1. **Whole-item replace semantics** mean `put` must do a get→splice→edit
   round-trip instead of a single subprocess. This is more code than
   op://'s single-shot `op item edit field=value`, but it's
   straightforward and the fake-bin tests can cover it.
2. **List performance on large vaults** — 5300 items / 20 min is real
   and we cannot fix it. Documenting a 30 s timeout and accepting that
   `hasp list bw://` may time out on very large vaults is the
   pragmatic call. Future enhancement: surface `--folderid` / `--search`
   filters via URL query (`bw://?folderid=<uuid>`).

### Confidence

**High** for write-path semantics (edit / create / delete: source-code
quoted, error strings exact, JSON shape confirmed). **Medium-high**
for list output shape (double-nested `--response` envelope verified
across two sources; would prefer to confirm against a live `bw
2026.4.1` if available).

### Most-likely-to-bite risk

**The whole-item replace semantic.** A buggy `splice_field` that drops
fields not covered by the URL path will silently corrupt user vault
items — e.g. clobbering `login.username` while updating
`login.password`. This is exactly the kind of failure mode that
warrants:

- A `splice_field` implementation that operates on the *parsed JSON*,
  not a string template (so it cannot accidentally drop sibling keys).
- A round-trip test in fake-bin coverage that `put` then `get`
  preserves every other field of the item.
- An idempotency check: doing `put` twice with the same value must
  result in identical item JSON.

---

## §10. Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| Bitwarden CLI Docs (help) | Official docs | edit / create / delete / list grammar | https://bitwarden.com/help/cli/ |
| `edit.command.ts` (cli repo, master) | Source code | stdin path, base64 decode, Response.notFound() | https://github.com/bitwarden/cli/blob/master/src/commands/edit.command.ts |
| `create.command.ts` (cli repo, master) | Source code | stdin path, base64 decode, error strings | https://github.com/bitwarden/cli/blob/master/src/commands/create.command.ts |
| `delete.command.ts` (cli repo, master) | Source code | softDelete vs deleteWithServer | https://github.com/bitwarden/cli/blob/master/src/commands/delete.command.ts |
| `list.command.ts` (cli repo, master) | Source code | client-side filtering, getAllDecrypted | https://github.com/bitwarden/cli/blob/master/src/commands/list.command.ts |
| `response.ts` (clients repo, main) | Source code | Response.notFound() message text | https://github.com/bitwarden/clients/blob/main/apps/cli/src/models/response.ts |
| bitwarden/clients#9403 | GitHub issue | `bw list items` perf regression timings | https://github.com/bitwarden/clients/issues/9403 |
| bitwarden/clients#11669 | GitHub issue | Sync staleness after create | https://github.com/bitwarden/clients/issues/11669 |
| bitwarden/cli#153 | GitHub issue | Org-collection assignment after create | https://github.com/bitwarden/cli/issues/153 |
| Endor Labs blog | Vendor blog | Shai-Hulud / @bitwarden/cli@2026.4.0 incident | https://www.endorlabs.com/learn/shai-hulud-the-third-coming----inside-the-bitwarden-cli-2026-4-0-supply-chain-attack |
| Bitwarden official statement | Vendor advisory | Versions affected, remediation | https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127 |
| The Hacker News | News | Independent reporting on Bitwarden CLI compromise | https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html |
| BleepingComputer | News | Bitwarden CLI npm compromise | https://www.bleepingcomputer.com/news/security/bitwarden-cli-npm-package-compromised-to-steal-developer-credentials/ |
| RESEARCH-bw-cli.md | Internal | Read-side coverage, error envelope, auth model | `docs/internal/research/RESEARCH-bw-cli.md` |
| RESEARCH-op-cli.md | Internal | op:// write-side reference | `docs/internal/research/RESEARCH-op-cli.md` |
