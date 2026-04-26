# hasp Wishlist — From `spall`

> Last updated: 2026-04-26
>
> Author: spall Wave 2 completion → Wave 3 planning
>
> Context: `spall` is a dynamic OpenAPI 3.x CLI (`~/code/rustpunk/spall/`).
> Wave 2 is complete. Wave 3 introduces structured auth providers.
> Instead of spall reinventing credential storage, we want to consume
> `hasp` as a dependency. This document prioritizes hasp features
> by **spall's dependency order**.

---

## 1. Priority Stack (P0 → P3)

### P0 — `keyring://` backend (OS credential store)

**Why P0:** Wave 3's `spall` needs to persist long-lived tokens after
interactive setup (e.g., `spall auth login <api>` → browser PKCE → store
token in OS keyring → `spall <api> <op>` retrieves automatically).

**Minimum viable API:**

```rust
// hasp library surface (from spall's perspective)
let secret = hasp::get("keyring://spall/github/token")?;
// secret: secrecy::SecretString or equivalent zeroized+redacted type
```

**Nice to have:**
- Service name prefix defaulting to `spall` when called from spall.
- Cross-platform: macOS Keychain, Windows Credential Manager, Linux Secret Service / kwallet / keepassxc.
- `hasp::put("keyring://spall/github/token", "ghp_xxx")?` for initial storage.

**Reference crates:** `keyring` v3 (evaluate v4 RC before committing).

---

### P1 — `env://` backend (already trivial, but unify)

**Why P1:** `spall` Wave 1 already resolves `SPALL_<API>_TOKEN` env vars.
Moving this into `hasp` means spall can use one resolver for *all* secret
sources without branching logic.

**Desired shape:**

```rust
let secret = hasp::get("env://SPALL_GITHUB_TOKEN")?;
```

Spall's TOML config would reference this URL:

```toml
[auth]
token = "env://SPALL_GITHUB_TOKEN"
```

**Backwards compat note:** `spall` should continue supporting bare env var
resolution as a fallback when `hasp` is not compiled in (feature-gated dependency).

---

### P2 — Library-first, `secrecy` at the boundary

**Why P2:** `spall` already uses `secrecy::SecretString` everywhere. If `hasp`
returns raw `String`, spall has to wrap it — that's a redaction footgun at
the integration boundary.

**Request:** `hasp::get()` returns a type that implements:
1. `Zeroize` on drop.
2. `Display` → `[REDACTED]`.
3. `ExposeSecret` or equivalent accessor for the raw bytes.
4. `std::error::Error` on failure — never `anyhow` at the library surface.

Ideally, `hasp` re-exports or depends on `secrecy` directly so spall can
pass the wrapper through without unwrapping.

**Open question:** Does `hasp` depend on `secrecy`, or does `hasp` define its own
wrapper and provide `Into<secrecy::SecretString>`? Spall mildly prefers
direct dependence (one less conversion), but either works.

---

### P3 — Profile aliases + config file

**Why P3:** Spall's per-API TOML (`~/.config/spall/apis/github.toml`)
wants to reference secrets by short alias:

```toml
[auth]
# Today (Wave 1-2) — inline env reference
token_env = "GITHUB_TOKEN"

# Desired (Wave 3+) — URL-style, backend-agnostic
token = "keyring://spall/github/token"
# or
token = "env://GITHUB_TOKEN"
# or
token = "op://Vault/GitHub/credential"
```

**Request:** Hasp ships a small config loader (TOML/JSON/YAML) that maps
aliases to fully-qualified URLs. Spall would point hasp at
`~/.config/spall/hasp-profiles.toml`:

```toml
[github]
token = "keyring://spall/github/token"

[github.staging]
token = "env://GITHUB_STAGING_TOKEN"
```

Then spall resolves:

```rust
let url = hasp::resolve_alias("&spall/github/token")?;
let secret = hasp::get(url)?;
```

**Why `hasp` should own this:** URL scheme is hasp's lingua franca.
Re-inventing alias expansion in every consumer is wasteful.

---

## 2. Wave 3 Auth Providers (spall-side roadmap)

This is the spall feature set that *drives* the hasp wishlist above.

| Provider | Secret Source | hasp backend |
|----------|--------------|--------------|
| API Key (header/query) | token string | any |
| Bearer token | token string | any |
| Basic Auth | `user:pass` or separate | any |
| OAuth2 Authorization Code + PKCE | short-lived access token, refresh token | `keyring://` for refresh token persistence |

**OAuth2 PKCE flow:** This is entirely spall's domain — spall will implement
its own browser-based PKCE flow and use `hasp` only for the final token
storage step (`hasp::get` / `hasp::put` against `keyring://`). If hasp
eventually grows an OAuth2 helper for other consumers, spall will not
consume it.

---

## 3. Spall's Consumption Boundary (not hasp's scope boundary)

The items below are things **spall has no use for** and will not consume,
regardless of whether hasp builds them for other projects:

- **OAuth2 / auth bootstrap flows** — spall handles this internally;
  if hasp builds it, spall simply won't call it.
- **Secret rotation** — operational concern, not CLI convenience.
- **Password/key generation** — unrelated domain.
- **Bulk file encryption** — spall defers to `age`/`sops`/`cocoon` directly.
- **TLS/cert lifecycle** — separate problem.

This is a *dependency wishlist*, not a product specification. Hasp remains
free to serve other consumers with whatever features they need.

---

## 4. Integration Sketch (spall side)

### Cargo.toml

```toml
# spall-config/Cargo.toml
[dependencies]
hasp = { version = "0.1", default-features = false, features = ["env", "keyring"], optional = true }

[features]
default = []
hasp-auth = ["dep:hasp"]
```

Why feature-gate, not hard dependency:
- `hasp` pulls in `keyring-core` → native OS libraries → potential build issues on exotic targets.
- Spall's Wave 1–2 behavior (env vars only) must continue to work without `hasp`.
- `hasp` itself is feature-gated; spall mirrors that discipline.

### credentials.rs

```rust
// spall-config/src/credentials.rs  (Wave 3)

#[cfg(feature = "hasp-auth")]
pub fn resolve_token(entry: &ApiEntry) -> Option<SecretString> {
    // 1. Check --spall-auth override (highest priority)
    // 2. Check per-API config [auth] token URL
    if let Some(url) = &entry.auth_token_url {
        match hasp::get(url) {
            Ok(secret) => return Some(secret),
            Err(hasp::Error::NotFound(_)) => { /* fall through to interactive */ }
            Err(hasp::Error::PermissionDenied(_)) => {
                eprintln!("Warning: keyring permission denied: {}", url);
            }
            Err(hasp::Error::Backend { ref kind, .. }) if kind.is_transient() => {
                eprintln!("Warning: keyring transient failure, retrying...");
            }
            Err(e) => {
                eprintln!("Warning: could not fetch secret from {}: {}", url, e);
            }
        }
    }
    // 3. Fallback to Wave 1 env var (deprecated but supported)
    // 4. Interactive prompt (with rpassword)
    None
}

#[cfg(not(feature = "hasp-auth"))]
pub fn resolve_token(entry: &ApiEntry) -> Option<SecretString> {
    // Wave 1–2 behavior: direct env var lookup
    let resolver = CredentialResolver { api_name: entry.name.clone() };
    std::env::var(resolver.env_var_name())
        .ok()
        .filter(|s| !s.is_empty())
        .map(SecretString::new)
}
```

---

## 5. Spall Response to Keyring URL Grammar Change

**Spall accepts the 2-component canonical grammar.**

The WISHLIST originally proposed `keyring://spall/github/token` (3-component).
This has been revised per `RESEARCH-keyring-url-grammar.md` to canonical 2-component:

```toml
# Single API key / Bearer token
token = "keyring://spall/github-token"

# OAuth2 access + refresh token pair
token = "keyring://spall/github-access"
refresh_token = "keyring://spall/github-refresh"
```

Naming rule for spall:
- `keyring://spall/<api>-token` for API keys / Bearer tokens.
- `keyring://spall/<api>-access` and `keyring://spall/<api>-refresh` for OAuth2 pairs.

The underlying OS keyring is a 2-tuple `(service, account)`; pretending otherwise is a
leaky abstraction that would have different semantics per-platform. Spall handles
multi-field secrets (access + refresh) by using two flat entries rather than a single
multi-field URL.

---

## 6. Spall Response: Wave 3 Backend Scope

**Spall needs only `env://` + `keyring://` for Wave 3.**

Spall does not need `file://`, `op://`, `vault://`, or cloud backends in Wave 3.
That's Wave 4+ territory.

| Provider | Secret source | hasp backend |
|----------|---------------|--------------|
| API Key (header/query param) | token string | `keyring://` or `env://` |
| Bearer token | token string | `keyring://` or `env://` |
| Basic Auth | `user:pass` pair | `keyring://` or `env://` |
| OAuth2 PKCE (refresh token) | long-lived refresh token | `keyring://` for persistence |

Note: `env://` is a convenience refactor, not a blocker. Spall already resolves env vars
natively in Wave 1–2. Moving it into `hasp` means `spall-config` can use a single
`hasp::get()` call for both `env://` and `keyring://` sources without branching logic.

---

## 7. Spall Response: Feature Gating is Mandatory

Yes. `hasp` must be an optional dependency in `spall-config`, gated behind a
`hasp-auth` feature. Both `hasp`'s own design and `spall`'s architecture demand it.

See §4 for the exact `Cargo.toml` and `credentials.rs` implementation.

Rationale:
- `hasp` pulls in `keyring-core` → native OS libraries → potential build issues on exotic targets.
- Spall's Wave 1–2 behavior (env vars only) must continue to work without `hasp`.
- `hasp` itself is feature-gated (env, keyring, etc.); spall mirrors that discipline.

---

## 8. Answers to Open Questions

These are the answers from `hasp` research to the questions Spall originally posed.

### 1. Keyring v3 vs v4?

**Answer:** Neither. `hasp` pins `keyring-core = "1.0"` (released 2026-04-26).

- `keyring` v3 is EOL (maintainers marked 3.6.3 as the final v3 release).
- `keyring` v4 README explicitly says *"Do not depend on this crate!"* — it is now sample/CLI code only.
- `keyring-core` 1.0 is the actively maintained library path, with runtime store selection (fixes the KWallet vs Secret Service ambient-detection bug) and per-platform store crates.

Spall does not need to care about the crate name — `hasp-backend-keyring` abstracts it.
When Spall integrates, it drops any direct `keyring` dependency and consumes through `hasp`.

### 2. Error type granularity?

**Answer:** Spall's needs map directly to `hasp`'s locked error taxonomy.

| Spall need | hasp variant | Spall action |
|---|---|---|
| Secret not found | `Error::NotFound` | Prompt user interactively |
| Backend unavailable | `Error::Backend { kind: Transient, .. }` | Warn, retry with backoff (via `err.is_transient()`) |
| Permission denied | `Error::PermissionDenied` | Warn, don't panic, continue to fallback |
| Invalid creds | `Error::AuthenticationFailed` | Warn, likely creds expired |
| Rate limited | `Error::Backend { kind: Throttled, .. }` | Honor Retry-After, then retry |

The `is_transient()` predicate returns true for both `Transient` and `Throttled`,
so Spall can write:

```rust
Err(e) if e.is_transient() => { /* warn, retry */ }
```

### 3. Async?

**Answer:** Sync library API only. `hasp-core` is sync-first. `hasp` does not pull in
`tokio` or any runtime as a library dependency. Spall's preference for sync is confirmed
as the correct architecture — `spawn_blocking` is available when needed, but the core
trait is blocking.

### 4. When should spall start depending on hasp?

**Answer:** After `hasp` publishes `0.1.0-alpha.1` with `env://` + `keyring://`
backends. Target: Wave 0+1 completion per `hasp/notes/scaffold.md` §6.

Spall can prepare the integration behind the `hasp-auth` feature flag now; enable it
once the `hasp` crate hits crates.io with the required backends.
