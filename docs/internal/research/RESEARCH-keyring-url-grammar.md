# RESEARCH-keyring-url-grammar

> Decision: definitive `keyring://` URL grammar that survives Wave 1 and any future consumer.
>
> Date: 2026-04-26
> Audience: hasp-backend-keyring author, downstream consumers (Ferrule, Spall, future)
> Status: recommendation, awaiting design lock

---

## Core question

Is the canonical URL `keyring://service/account` (2-component, maps to `Entry::new`) or `keyring://target/service/account` (3-component, maps to the `Entry::new_with_modifiers` HashMap with a `target` key)? How should consumers like Spall (whose WISHLIST mentions `keyring://spall/github/token` — three components) be addressed when the underlying primitive is genuinely 2-tuple?

This is the design decision most likely to bite later. Once the URL grammar ships in any consumer, changing it is a breaking change that ripples through every config file, every script, every doc.

---

## The landscape

The underlying `keyring-core` 1.0 API exposes two constructors and an attribute-based search:

```rust
Entry::new(service: &str, account: &str) -> Result<Entry, Error>
Entry::new_with_modifiers(modifiers: &HashMap<&str, &str>, service, account) -> Result<Entry, Error>
Entry::search(query: &HashMap<&str, &str>) -> Result<Vec<Entry>, Error>  // not all stores impl
```

The native identifier is fundamentally a **2-tuple of `(service, account)`** plus an optional bag of modifiers ([keyring-core docs.rs](https://docs.rs/keyring-core/latest/keyring_core/)). The `target` modifier is the most common; its semantics are platform-specific:

| Platform | `target` modifier semantics |
|----------|-----------------------------|
| Linux Secret Service | Collection name (default: `"default"`) |
| Linux Keyutils | Key description prefix |
| macOS Keychain | Distinguishes Generic (no target) from Internet (target = server URL) |
| Windows Credential Manager | The "target name" primary key — not a namespace, the actual lookup key |

This per-platform divergence is significant. On Windows, `target` *is* the lookup key; service+account are secondary. On Linux Secret Service, `target` is a *namespace* (collection); service+account narrow within it. Pretending one URL component maps cleanly to all four platforms would be a leaky abstraction.

The wider ecosystem provides three reference points:

1. **1Password (`op://vault/item/field`)** — the only mainstream tool with a genuine 3-level URL scheme, where each level has *distinct semantic meaning* (vault is the access boundary, item is the named container, field is the named slot within the item). 1Password's underlying data model natively supports named-field storage on a single item, so this is not a workaround ([1Password CLI secret reference syntax](https://developer.1password.com/docs/cli/secret-reference-syntax/)).
2. **envchain (`(namespace, varname)`)** — the canonical workaround when the underlying keyring is 2-tuple but the user wants 3-component addressing. envchain folds the namespace into the service string: `service = "envchain-NAMESPACE"`, `account = VARNAME`. This works but prevents looking up a single secret without knowing the namespace prefix ([envchain README](https://github.com/sorah/envchain/blob/master/README.md)).
3. **`pass`** — filesystem hierarchy under `~/.password-store`, no constraint on depth. But `pass` is GPG-encrypted files on disk, not a 2-tuple OS keyring — so the comparison breaks down; `pass`'s "depth" is filesystem-native, not a workaround.

**No published Rust crate routes URL-style addresses over the `keyring-core` API.** hasp would be defining the grammar fresh.

---

## What Spall actually needs

Spall's WISHLIST (`docs/internal/spall/WISHLIST.md`) names `keyring://spall/github/token` and notes Wave 3 OAuth2 PKCE flow needs to persist both an access token and a refresh token. That is genuinely two named fields under one logical "GitHub" record. Three options:

1. **Two URLs:** `keyring://spall/github-access-token` and `keyring://spall/github-refresh-token`. Two flat keyring entries. Spall does the field naming itself in the URL string.
2. **Single URL with a 3-component grammar:** `keyring://spall/github/access` and `keyring://spall/github/refresh`. Requires hasp to invent a 3-component scheme that maps onto the 2-tuple (folding two of the components into one keyring field).
3. **Use a different backend for Spall:** `op://Vaults/spall-github/access_token` and `op://Vaults/spall-github/refresh_token`. 1Password natively has named-field-on-item; uses 3-level addressing without contortions.

Spall's WISHLIST does not require option 2. It's a stylistic preference. Option 1 is dead-simple and matches how `envchain` has run for a decade. Option 3 is technically the cleanest but adds a 1Password dependency on Spall's critical path — heavy.

---

## Approach A: Canonical 2-component (`keyring://service/account`), no shorthands, no modifiers

**How it works:**

```
keyring://service/account
       └ host  └ first path segment
```

`url::Url::parse` gives `host_str() = "service"` and `path_segments().next() = "account"`. `EntryUrl::try_from(&url::Url)` returns `Err(...)` if the URL has more than one path segment, a query string, a fragment, or any other deviation. `Entry::new(service, account)` is the only platform call.

Spall maps `keyring://spall/github-access-token` and `keyring://spall/github-refresh-token`. Both are 2-component. Spall picks the field-naming convention (hyphen-joined). Other consumers can pick differently (`spall_github_access`, `spall.github.access`) — hasp does not impose.

**Strengths:**
- **One-to-one with the platform primitive.** Every URL maps trivially to `Entry::new(service, account)`. No platform-conditional grammar interpretation. No leaky abstraction across macOS / Windows / Linux.
- Future-proof on the addressability axis: if the keyring backend ever needs to express the `target` modifier explicitly, it can do so via a query parameter (`?target=...`) without changing the canonical address grammar — query params are *modifiers*, not part of the canonical address.
- Cleanly aligns with the keyring-core API. No need to reverse-engineer "what would 3-component mean on Windows vs Linux."
- Honest: 1Password and Vault have genuine 3-level data models; OS keyrings do not. Pretending otherwise is a footgun.
- Forces consumers to make explicit naming choices (`github-access`, `github-refresh`) instead of hiding the field structure behind URL syntax.

**Weaknesses / failure modes:**
- Spall's WISHLIST text mentions `keyring://spall/github/token` (3-component). Adopting this grammar means Spall renames at integration time. Acceptable per "Ferrule and Spall are not the design constraint."
- Cannot express the `target` modifier in the canonical URL. If a Linux user has multiple Secret Service collections and wants secrets in a specific one, they cannot say so without extending the grammar with query params.
- Slightly inflexible — power users on Linux Secret Service may find collection-aware addressing useful.

**Source:** [keyring-core docs](https://docs.rs/keyring-core/latest/keyring_core/), [envchain README](https://github.com/sorah/envchain/blob/master/README.md), [Spall WISHLIST](file:///home/glitch/code/rustpunk/hasp/docs/internal/spall/WISHLIST.md).

---

## Approach B: Canonical 2-component + optional `?target=...` query for the modifier

**How it works:**

```
keyring://service/account                       # bare; Entry::new(service, account)
keyring://service/account?target=collection     # Entry::new_with_modifiers({"target": "collection"}, service, account)
```

Same as Approach A for the address part; query params are reserved for the keyring-core modifier bag. Future modifiers (e.g., a hypothetical `?store=keyutils` to override which Linux store to query) plug into the same slot.

**Strengths:**
- Approach A's strengths plus: power users can address specific Secret Service collections, distinguish macOS Keychain Generic vs Internet items, or override Windows target-name semantics.
- Backward-compatible with Approach A: any URL valid in A is valid in B.
- The modifier semantics are platform-specific and opt-in; documented in hasp's `keyring://` URL grammar reference, not implicitly inferred.

**Weaknesses / failure modes:**
- Slightly more surface to document and test. Each platform's `target` modifier behavior must be spelled out.
- If a future modifier is added to `keyring-core` that wasn't anticipated, hasp must decide whether to expose it as a query param. (Manageable — modifiers are a HashMap by design.)

**Source:** as Approach A.

---

## Approach C: 3-component canonical (`keyring://target/service/account`), 2-component as shorthand

**How it works:**

```
keyring://service/account              # 2-component shorthand: target defaults to None or to service
keyring://target/service/account       # 3-component canonical
```

Three path segments interpreted as `(target, service, account)`. Two path segments interpreted as a shorthand where `target` is omitted (or implicitly defaults to `service`).

**Strengths:**
- Matches Spall's WISHLIST text without renaming.
- Looks superficially "more capable."

**Weaknesses / failure modes:**
- **Leaky abstraction at the platform layer.** A 3-component URL means different things on Linux Secret Service (target = collection) vs Windows Credential Manager (target = primary key) vs macOS Keychain (target = generic-vs-internet flag). The same URL on three platforms refers to three different things. This is an architectural defect.
- The "shorthand" is ambiguous: `keyring://spall/github` — is `spall` the target (Linux: collection) and `github` the service, or is `spall` the service and `github` the account? Position-dependent semantics is exactly what URLs are supposed to remove.
- `target = service` defaulting on the shorthand path is a magical behavior that consumers must remember. Footgun.
- Lock-in: once a consumer has `keyring://prod-collection/app/db-password` (3-component) URLs in their config files, hasp cannot later admit "actually we shouldn't have done that" without a breaking change.
- Does not solve Spall's named-field need. Spall's three components in the WISHLIST were `(service, item, field)`; `target/service/account` is `(collection, service, account)`. The scheme structure does not match the actual data model Spall is reaching for.

**Reject this approach.**

---

## Approach D: Refer Spall to `op://` or `vault://` for genuine 3-level addressing

**How it works:** `keyring://` stays at 2-component (Approach A or B). hasp documents that consumers needing 3-level named-field storage (access + refresh tokens, multi-field secrets) should use a backend that natively supports it: `op://Vault/Item/field` or `vault://kv/data/path/field`.

**Strengths:**
- Honest about the OS keyring's 2-tuple nature.
- Pushes consumers toward backends that match their data model.

**Weaknesses / failure modes:**
- Spall has explicitly named OS keyring as the storage target in its WISHLIST (`Why P0: Wave 3's spall needs to persist long-lived tokens after interactive setup → store token in OS keyring`). Telling Spall to use 1Password instead is forcing a heavy dependency.
- Two flat keyring entries (`spall/github-access`, `spall/github-refresh`) is fine — Spall does not need 1Password.

This is not really an alternative; it's a doc note for the rare case. Use it as supplementary guidance, not as the primary recommendation.

---

## Benchmark data

No benchmarks relevant to URL grammar. URL parsing cost is sub-microsecond; the OS keyring call dominates by 4–6 orders of magnitude (see `RESEARCH-perf-data.md`).

---

## Threat-model / standards anchors

| Source | Year | Body | Relevant insight | URL |
|--------|------|------|-----------------|-----|
| RFC 3986 §3 | 2005 | IETF | URI generic syntax: hierarchical components must have consistent semantics across instances of the scheme | [link](https://datatracker.ietf.org/doc/html/rfc3986#section-3) |
| RFC 7512 | 2015 | IETF | PKCS#11 URI scheme uses semicolon-delimited typed pairs (`pkcs11:token=...;object=...`) — an alternative to slash-positional. | [link](https://www.rfc-editor.org/rfc/rfc7512.html) |

RFC 7512's lesson: when components are semantically heterogeneous (token, object, type), use named pairs rather than positional slashes. This is an argument for query params over multi-segment paths.

---

## Failure modes / CVEs to avoid

- **`Error::Ambiguous(Vec<Entry>)`.** New `keyring-core` 1.0 variant. Multiple matches at the lookup tuple. With Approach A this should not happen for `Entry::new(service, account)` because the 2-tuple is a unique key on every supported platform; with Approach B + a `?target=...` modifier that does not narrow uniquely, it can. hasp must handle this variant and surface a typed error to the caller. Document that ambient context (Linux multiple collections) can produce ambiguity if the URL doesn't disambiguate.
- **Naming collisions across consumers.** If both Spall and Ferrule use `keyring://spall/...` and `keyring://ferrule/...`, no collision. If a third tool uses `keyring://app/db-password` and the user installs both, collision is possible. Document that the `service` component should always include a project-distinguishing prefix.
- **Windows roaming profile sync.** Credentials written via `keyring://spall/github-token` on machine A roam to machine B in AD-joined enterprises (CVE-2022-30170 lateral-movement vector). Not a URL-grammar issue per se, but worth documenting alongside the keyring backend's threat model.

---

## Design insights for hasp

1. **Adopt Approach B: canonical `keyring://service/account` + optional `?target=...` (and future modifier query params).** Honest mapping to the platform primitive. No leaky abstraction. Power users can address platform-specific corners via opt-in modifiers; default users never see them.
2. **Define the `EntryUrl` parser strictly:** require exactly one host (= service) and exactly one path segment (= account). Reject any URL with more path segments, with empty service, with empty account. Returning `Err(Error::InvalidUrl(...))` is correct; silently ignoring extra segments is not.
3. **Expose `?target=...` only — do not add other ad-hoc query params at v1.** If `keyring-core` adds another modifier later, hasp can add a corresponding query param at that time. Conservative grammar v1 is easier to extend than restrict.
4. **Document the OS keyring's 2-tuple nature in the user guide.** Explain that it is *not* a 3-level store like 1Password; consumers needing named-field storage (multiple secrets per logical record) should use multiple flat keys (`spall/github-access`, `spall/github-refresh`) or pick `op://` or `vault://`.
5. **Spall's WISHLIST text gets revised.** `keyring://spall/github/token` becomes `keyring://spall/github-token`; `keyring://spall/github-access-token` and `keyring://spall/github-refresh-token` for the OAuth2 PKCE case. Cost: one search-and-replace in Spall's not-yet-written code. This change should be noted back to Spall now, before integration.
6. **Ferrule integration is a no-op.** Ferrule's `Entry::new("ferrule", name)` calls become `hasp::get(&format!("keyring://ferrule/{}", name))`. The 2-tuple maps directly. No URL-grammar revision needed on Ferrule's side.
7. **Reserve the `target` modifier query string.** Specify in docs that the literal string `target` is reserved for the keyring-core modifier bag and may not be used as a different parameter name in `keyring://` URLs. Same applies to any future `keyring-core` modifier name.

---

## Decision criteria (enforced)

NOT valid: matching Spall's WISHLIST text verbatim; minimizing the renaming cost for any consumer.

ONLY valid:
- Architectural correctness (URL grammar must map cleanly to platform primitive without leaky abstractions)
- Threat-model soundness (`Error::Ambiguous` must not be silently swallowed)
- Long-term maintainability (grammar shipped at v1 lives forever; restrict-then-extend is safe, extend-then-restrict is not)
- Honest about the underlying primitive (OS keyring is 2-tuple; do not pretend otherwise)

---

## Recommendation

**Approach B — canonical `keyring://service/account` with optional `?target=...` (and future modifier) query params.**

**Confidence:** High.

**Rationale:**
- Maps 1:1 to `keyring-core` 1.0's `Entry::new` and `Entry::new_with_modifiers` API ([docs.rs/keyring-core](https://docs.rs/keyring-core/latest/keyring_core/)).
- No leaky abstraction across platforms — the URL says exactly what it means.
- Future-proof: opt-in modifiers via query params extend cleanly; new modifiers in `keyring-core` can be exposed without changing the canonical address shape.
- Aligns with the Agent 2 cross-cutting finding that 1Password is the **only** mainstream tool with a genuine 3-level URL scheme, and 1Password's data model natively supports it. OS keyring does not, so a 3-level URL would be a workaround in disguise ([1Password CLI](https://developer.1password.com/docs/cli/secret-reference-syntax/)).

**Key risk:** Spall's WISHLIST mentions a 3-component URL. Surface this as a design decision back to Spall (paragraph in the keyring backend docs + a note in the Spall wishlist response): the canonical URL is 2-component; multi-field secrets become multiple flat URLs. Spall can absorb the change before any of its code is written.

**Threat-model note:** Approach B preserves hasp's redaction posture (URLs in logs may include the `service` and `account` path; both are meant to be loggable identifiers, not secret values). The `?target=...` query param is also non-secret; it identifies a collection or modifier, not a secret. No change to hasp's existing redaction discipline.

**If wrong:** If we discover that 3-component URLs are genuinely needed by a consumer that emerges later, the path forward is **not** to retrofit `keyring://` with a 3-component grammar (would break existing consumers). It is to introduce a new scheme, e.g., `keyring-target://target/service/account`, that lives alongside the 2-component scheme. URLs are forever; new schemes are cheap.

**Rejected alternatives:**
- **Approach A (no query params, ever):** rejected because it leaves Linux Secret Service collection-awareness off the table forever. Adding query params later is fine; making the URL grammar query-free at v1 is gratuitously restrictive.
- **Approach C (3-component canonical):** rejected because the same URL has different semantics on different platforms. Architecturally inferior and a permanent footgun.
- **Approach D (refer Spall to op://):** rejected as primary, retained as supplementary doc guidance for genuine multi-field-per-item cases.

---

## Definitive `keyring://` URL grammar (v1)

```
keyring://<service>/<account>[?target=<target>]
```

| Component | Required | Maps to | Notes |
|-----------|----------|---------|-------|
| `service` | yes | `keyring_core::Entry::new(service, _)` first arg | URL host. Non-empty. URL-encoded if it contains reserved chars. |
| `account` | yes | `keyring_core::Entry::new(_, account)` second arg | First (and only) URL path segment. Non-empty. |
| `target` | no | `keyring_core::Entry::new_with_modifiers({"target": ...}, ...)` | Query parameter. Platform-specific semantics; documented per-platform. Omit for default behavior. |

**Reserved (must NOT appear in v1):** any path segment beyond the first; URL fragment; query parameters other than `target`. Parser returns `hasp::Error::InvalidUrl(...)` on violation.

**Examples:**

```
keyring://ferrule/prod-db                                # Ferrule's existing pattern (no migration)
keyring://spall/github-access                            # Spall OAuth2 access token
keyring://spall/github-refresh                           # Spall OAuth2 refresh token
keyring://my-app/api-key?target=prod-collection          # Linux: pin to a specific Secret Service collection
keyring://my-app/api-key?target=internet:api.example.com # macOS: Internet item with server URL
```

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| `keyring-core` 1.0 docs | docs | API surface for backend impl | [docs.rs](https://docs.rs/keyring-core/latest/keyring_core/) |
| 1Password secret reference syntax | docs | Only mainstream 3-level URL prior art | [link](https://developer.1password.com/docs/cli/secret-reference-syntax/) |
| envchain README | repo | 2-tuple workaround for 3-component need | [link](https://github.com/sorah/envchain/blob/master/README.md) |
| RFC 3986 §3 | RFC | URI generic syntax — semantic-consistency guidance | [link](https://datatracker.ietf.org/doc/html/rfc3986#section-3) |
| RFC 7512 | RFC | PKCS#11 URI — typed-pairs alternative | [link](https://www.rfc-editor.org/rfc/rfc7512.html) |
| Ferrule `credentials.rs` | source | Existing `Entry::new("ferrule", name)` usage | `~/code/rustpunk/ferrule/ferrule-config/src/credentials.rs:21` |
| Spall WISHLIST | source | Documents `keyring://spall/github/token` 3-component aspiration | `docs/internal/spall/WISHLIST.md` |
| `keyring-core::Error::Ambiguous` | docs | Failure mode for non-unique modifier queries | [docs.rs](https://docs.rs/keyring-core/latest/keyring_core/error/enum.Error.html) |
