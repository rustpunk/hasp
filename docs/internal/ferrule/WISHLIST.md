# hasp Wishlist — From `ferrule`

> Last updated: 2026-04-26
>
> Author: ferrule Wave 2 → Wave 3 planning
>
> Context: `ferrule` is a Rust-native database query CLI
> (`~/code/rustpunk/ferrule/`). Wave 2 adds REPL, bookmarks,
> parameterized queries, EXPLAIN, dump/load, and watch mode.
> Wave 3 introduces connection profiles with richer credential
> sources and team-shared connection registries. Instead of ferrule
> inventing new credential stores per backend, we want to consume
> `hasp` as a dependency. This document prioritizes hasp features
> by **ferrule's dependency order**.

---

## 1. Priority Stack (P0 → P3)

### P0 — `keyring://` backend (OS credential store)

**Why P0:** Ferrule Wave 1.5 already uses OS keyring via the `keyring`
crate v3 (`ferrule-config/src/credentials.rs`). It stores passwords as
`service=ferrule`, `user=<connection_name>`. Replacing this with `hasp`
means ferrule's credential code shrinks from ~80 lines to a single
`hasp::get()` call, and we get cross-platform keyring parity for free.

**Minimum viable API:**

```rust
// ferrule-config/src/credentials.rs  (future)
use hasp::{get, HaspError};
use secrecy::SecretString;

pub fn resolve_keyring_password(name: &str) -> Option<SecretString> {
    let url = format!("keyring://ferrule/{}", name);
    match get(&url) {
        Ok(secret) => Some(secret.into()),
        Err(HaspError::NotFound) => None,
        Err(e) => {
            eprintln!("Warning: keyring lookup failed: {}", e);
            None
        }
    }
}
```

**Nice to have:**
- `keyring` v3 compatibility (ferrule is already on v3; v4 RC can be
  evaluated for Wave 3 but is not a blocker).
- Cross-platform coverage: macOS Keychain, Windows Credential Manager,
  Linux Secret Service / kwallet / keepassxc.
- `hasp::put("keyring://ferrule/mydb", "s3cr3t")` for the `ferrule conn
  set-password` command.

**Out of scope for ferrule:** We do not need `hasp` to own the
interactive password prompt — ferrule already uses `rpassword` and
prefers to keep the TTY prompt in its own CLI layer.

---

### P1 — `env://` backend

**Why P1:** Ferrule Wave 1.5 resolves `FERRULE_<NAME>_PASSWORD` env vars
as the second step in its credential resolution stack. Moving this into
`hasp` means one resolver path for *all* secret sources, and ferrule's
`.ferrule.toml` connection URLs can reference env vars via `hasp` URLs:

```toml
[connection.production]
url = "postgres://user@host/db"
# Today: ferrule hardcodes FERRULE_PRODUCTION_PASSWORD
# Desired: explicit indirection
password_url = "env://FERRULE_PRODUCTION_PASSWORD"
```

**Desired shape:**

```rust
let secret = hasp::get("env://FERRULE_PRODUCTION_PASSWORD")?;
```

**Backwards compat:** `ferrule` will continue supporting bare env var
resolution as a fallback when the `hasp` feature is disabled, but new
team-shared registry files should use explicit `env://` URLs.

---

### P2 — `file://` backend (Docker secrets, systemd-creds)

**Why P2:** Ferrule is often deployed in containers. Docker secrets and
Kubernetes secrets are mounted as files (`/run/secrets/db_password`).
A `file://` backend lets ferrule connection profiles reference these
without baking paths into connection URLs:

```toml
[connection.production]
url = "postgres://user@host/db"
password_url = "file:///run/secrets/db_password"
```

**Desired shape:**

```rust
let secret = hasp::get("file:///run/secrets/db_password")?;
// trims trailing newlines automatically
```

This is strictly more secure than `env://` in container orchestration
because the secret is not visible in `/proc/<pid>/environ`.

---

### P3 — Library-first, `secrecy` at the boundary

**Why P3:** Ferrule already wraps every password in
`secrecy::SecretString`. If `hasp` returns raw `String` or `Vec<u8>`,
ferrule must wrap it — that's a redaction footgun at the integration
boundary. `hasp` should guarantee zeroization and redaction so ferrule
can pass secrets through without unwrapping.

**Request:** `hasp::get()` returns a type that implements:
1. `Zeroize` on drop.
2. `Display` → `[REDACTED]` (no accidental `println!` leaks).
3. `ExposeSecret` or equivalent accessor for the raw bytes.
4. `std::error::Error` on failure — never `anyhow` at the library surface.

**Preference:** `hasp` re-exports or depends on `secrecy` directly so
ferrule can consume `secrecy::SecretString` without conversion. If `hasp`
defines its own wrapper, an `Into<secrecy::SecretString>` impl is
required.

---

## 2. Ferrule Credential Resolution Stack (today vs desired)

### Today (Wave 1.5)

```
1. --password CLI flag
2. FERRULE_<NAME>_PASSWORD env var          ← hardcoded
3. OS keyring (keyring crate)                  ← direct dep
4. Interactive prompt (TTY only, rpassword)
5. Fail with diagnostic
```

### Desired (Wave 3+)

```
1. --password CLI flag
2. password_url from profile / registry         ← points to hasp URL
   e.g. password_url = "keyring://ferrule/production"
        password_url = "env://FERRULE_PRODUCTION_PASSWORD"
        password_url = "file:///run/secrets/db_password"
   Resolved via hasp::get(password_url)
3. Fallback to legacy FERRULE_<NAME>_PASSWORD
4. Interactive prompt
5. Fail with diagnostic
```

The `password_url` field is optional; when absent, ferrule falls back
to the legacy stack so existing `.ferrule.toml` files keep working.

---

## 3. Profile Aliases + Config File

**Why ferrule cares:** Ferrule's connection registry
(`~/.config/ferrule/connections.toml`) and `.ferrule.toml` project configs
are the canonical place where users name their databases. `hasp` profile
aliases should be *composable* with ferrule's existing config, not
replace it.

**Desired integration:**

Ferrule's `ConnectionProfile` gains an optional `password_url` field:

```toml
[connection.production]
url = "postgres://user@host/db"
password_url = "keyring://ferrule/production"
```

When ferrule resolves a connection, it:
1. Parses the base URL.
2. If `password_url` is present, calls `hasp::get(password_url)`.
3. If the password is found, injects it into the URL via `set_password()`.
4. If absent or `hasp` is disabled, falls through the legacy stack.

Ferrule does *not* need `hasp` to own alias expansion for connection
names — ferrule already has `ConnectionRegistry` and `.ferrule.toml`.
What ferrule *does* need is for `hasp` URLs to be stable and
well-documented so they can be embedded in ferrule config files without
surprises.

---

## 4. Enterprise Backends (P4 — future)

These are backends ferrule does not need for Wave 3 but would enable
in enterprise/team deployments without ferrule adding any code:

| Backend | Use case |
|---------|----------|
| `aws-sm://` | RDS password rotated via AWS SM |
| `vault://` | HashiCorp Vault dynamic DB credentials |
| `gcp-sm://` | Cloud SQL secrets |
| `azure-kv://` | Azure SQL secrets |
| `op://` | 1Password team vault for DB passwords |
| `bw://` | Bitwarden team vault |

Because ferrule resolves passwords generically via `hasp::get()`, adding
any of these backends is a **zero-line change** in ferrule — users just
change their `password_url`.

---

## 5. Ferrule-side Consumption Boundary

The items below are things **ferrule has no use for** and will not
consume, regardless of whether `hasp` builds them:

- **OAuth2 / auth bootstrap flows** — database connections use static
  passwords or TLS certs; ferrule handles TLS via `rustls`/`native-tls`
  and does not need OAuth2.
- **Secret rotation** — operational concern, handled by DBA tooling.
- **Password/key generation** — unrelated domain.
- **Bulk file encryption** — ferrule defers to `age`/`sops` directly.
- **TLS/cert lifecycle** — separate problem; ferrule accepts
  `--insecure` or CA bundles via connection URL params.

---

## 6. Integration Sketch (ferrule side)

```rust
// ferrule-config/src/credentials.rs  (future Wave 3)

pub async fn resolve_password_stack(
    name: &str,
    explicit: Option<SecretString>,
    password_url: Option<&str>,
) -> Result<Option<SecretString>, CliError> {
    if let Some(pwd) = explicit {
        return Ok(Some(pwd));
    }

    // 1. Try hasp URL if configured
    #[cfg(feature = "hasp")]
    if let Some(url) = password_url {
        match hasp::get(url) {
            Ok(secret) => return Ok(Some(secret.into())),
            Err(hasp::HaspError::NotFound) => {}
            Err(e) => eprintln!("Warning: hasp lookup failed for {}: {}", url, e),
        }
    }

    // 2. Legacy env var (Wave 1.5 compat)
    if let Some(pwd) = resolve_env_password(name) {
        return Ok(Some(pwd));
    }

    // 3. Legacy keyring (direct dep, fallback when hasp disabled)
    if let Some(pwd) = resolve_keyring_password(name) {
        return Ok(Some(pwd));
    }

    // 4. Interactive prompt
    ...
}
```

**Feature gating:** `ferrule-config` gates `hasp` behind a `hasp` feature flag, replacing the current direct `keyring = "3"` dependency when enabled. When the `hasp` feature is off, ferrule falls back to the legacy credential stack (direct env var lookup + direct keyring v3). Default builds keep the legacy stack; enterprise/container builds enable `hasp`.

```toml
# ferrule-config/Cargo.toml
[dependencies]
hasp = { version = "0.1", default-features = false, features = ["env", "keyring", "file"], optional = true }

[features]
default = ["keyring"]
keyring = ["dep:keyring"]          # legacy path; drops to nothing when hasp migrates
hasp = ["dep:hasp"]                # new path (replaces direct keyring dep)
```

Rationale for gating over hard dependency:
- `hasp` pulls `keyring-core` → native OS libraries; some build targets may fail.
- Ferrule's existing Wave 1–2 credential stack must continue to work without `hasp`.
- `hasp` is itself feature-gated per backend; ferrule mirrors that discipline.

```rust
// ferrule-config/src/credentials.rs (future Wave 3)

#[cfg(feature = "hasp")]
pub fn resolve_password_stack(
    name: &str,
    explicit: Option<SecretString>,
    password_url: Option<&str>,
) -> Result<Option<SecretString>, CliError> {
    if let Some(pwd) = explicit {
        return Ok(Some(pwd));
    }

    // 1. Try hasp URL if configured
    if let Some(url) = password_url {
        match hasp::get(url) {
            Ok(secret) => return Ok(Some(secret)),
            Err(hasp::Error::NotFound(_)) => { /* fall through to legacy stack */ }
            Err(hasp::Error::PermissionDenied(_)) => {
                eprintln!("Warning: hasp permission denied for {}", url);
            }
            Err(hasp::Error::Backend { ref kind, .. }) if kind.is_transient() => {
                eprintln!("Warning: hasp transient failure for {}, retrying...", url);
            }
            Err(e) => {
                eprintln!("Warning: hasp lookup failed for {}: {}", url, e);
            }
        }
    }

    // 2. Legacy env var (Wave 1.5 compat)
    if let Some(pwd) = resolve_env_password(name) {
        return Ok(Some(pwd));
    }
    // 3. Legacy keyring via direct dep (only if hasp feature not enabled)
    #[cfg(all(feature = "keyring", not(feature = "hasp")))]
    if let Some(pwd) = resolve_keyring_password(name) {
        return Ok(Some(pwd));
    }
    // 4. Interactive prompt
    ...
}

#[cfg(not(feature = "hasp"))]
pub fn resolve_password_stack(
    name: &str,
    explicit: Option<SecretString>,
    _password_url: Option<&str>,
) -> Result<Option<SecretString>, CliError> {
    // Wave 1–5 legacy behavior
    ...
}
```

---

---

## 7. Ferrule Response: Keyring URL Grammar

**Zero migration cost. Ferrule's existing pattern is already the canonical 2-component form.**

Ferrule's existing code calls `keyring::Entry::new("ferrule", name)` — a 2-tuple `(service, account)`.
This maps directly to the canonical `hasp` URL:

```toml
[connection.production]
url = "postgres://user@host/db"
password_url = "keyring://ferrule/production"
```

Ferrule does not need to change any config files or URL conventions. The `keyring://ferrule/{connection_name}`
pattern Ferrule already uses is the correct canonical form per `RESEARCH-keyring-url-grammar.md`.

---

## 8. Ferrule Response: `file://` Newline Trimming

**Accepted — `hasp` trims one trailing `\n` or `\r\n` by default; opt-out via `?raw=true`.**

Docker secrets and Kubernetes secrets mounted as files typically end with a trailing newline
(from `echo "secret" > /run/secrets/db_password`). The `file://` backend trims exactly one
line terminator by default:

```toml
password_url = "file:///run/secrets/db_password"        # trimmed (default)
password_url = "file:///run/secrets/db_password?raw=true"  # verbatim bytes
```

This matches Ferrule's WISHLIST preference. The policy is documented in
`RESEARCH-file-trim.md` with prior art from HashiCorp Vault (`-field` strips) and the
Argo Workflows / smallstep incident lessons.

---

## 9. Ferrule Response: Feature Gating Strategy

Confirmed. The §6 integration sketch shows the exact `Cargo.toml` and `credentials.rs`
implementations. Key points:

- `hasp` is an **optional** dependency behind a `hasp` feature flag in `ferrule-config`.
- Default builds keep the legacy direct `keyring = "3"` dependency.
- Enterprise/container builds enable `hasp` via `--features hasp`.
- When `hasp` is enabled, the legacy direct `keyring` dep is gated out;
  `hasp::get("keyring://ferrule/...")` replaces `keyring::Entry::new("ferrule", ...)`.
- The `password_url` field in `.ferrule.toml` is ignored when the `hasp` feature is off;
  ferrule falls through to the legacy stack.

---

## 10. Answers to Open Questions

These are the answers from `hasp` research to the questions Ferrule originally posed.

### 1. Keyring v3 vs v4?

**Answer:** Neither. `hasp` pins `keyring-core = "1.0"` (released 2026-04-26).

- `keyring` v3 is EOL (maintainers marked 3.6.3 as the final v3 release).
- `keyring` v4 README explicitly says *"Do not depend on this crate!"* — it is sample/CLI code only.
- `keyring-core` 1.0 is the actively maintained library path with runtime store selection
  (fixes the KWallet vs Secret Service ambient-detection bug) and per-platform store crates.

**Ferrule migration path:**

```toml
# Before (ferrule-config/Cargo.toml)
keyring = { version = "3", optional = true }

# After (ferrule-config/Cargo.toml when hasp feature is enabled)
hasp = { version = "0.1", default-features = false, features = ["env", "keyring", "file"], optional = true }
```

Ferrule's direct `keyring` dependency disappears entirely. `hasp-backend-keyring` owns the
OS keyring integration. No `Entry::new` calls remain in Ferrule code; all become `hasp::get(url)`.

### 2. Error type granularity?

**Answer:** Ferrule's needs map directly to `hasp`'s locked error taxonomy.

| Ferrule need | hasp variant | Ferrule action |
|---|---|---|
| Secret not found | `Error::NotFound` | Fall through to next resolver (env → interactive) |
| Backend unavailable | `Error::Backend { kind: Transient, .. }` | Warn, continue (via `err.is_transient()`) |
| Permission denied | `Error::PermissionDenied` | Warn, don't panic, continue to fallback |
| Malformed URL | `Error::InvalidUrl` or `Error::UrlParse` | Hard error — log diagnostic |
| Invalid credentials | `Error::AuthenticationFailed` | Warn, likely creds expired |
| Rate limited | `Error::Backend { kind: Throttled, .. }` | Warn, honor Retry-After if present, retry |

The `is_transient()` predicate returns true for both `Transient` and `Throttled`,
so Ferrule can retry on a single match arm:

```rust
Err(e) if e.is_transient() => { /* warn, retry or continue */ }
```

`InvalidUrl` is distinct from `UrlParse`: `UrlParse` means "not even a URL"
(malformed syntax at the `url` crate layer); `InvalidUrl` means "this URL does not
satisfy the backend's grammar" (e.g., `keyring://ferrule/a/b` has too many path
segments). Both are hard errors with clear diagnostics.

### 3. Sync vs async?

**Answer:** Sync library API only. Ferrule's preference is confirmed as the correct architecture.

`hasp-core` is sync-first. The optional `async` feature on `hasp-core` merely provides
`spawn_blocking` convenience wrappers for async callers; the core `Backend` trait is
blocking I/O. Ferrule's `tokio::current_thread` runtime can call `hasp::get()` directly
without `spawn_blocking` — keyring, file, and env I/O are fast enough that blocking is
simpler and avoids extra runtime complexity.

### 4. `file://` newline trimming?

**Answer:** Yes, `hasp` trims by default. Ferrule's preference is the chosen policy.

```
file:///run/secrets/db_password              → trims one trailing \n or \r\n (default)
file:///run/secrets/db_password?raw=true    → verbatim bytes, no trim
```

Full rationale in `RESEARCH-file-trim.md`, including prior art (Vault `-field` strips),
failure modes (Argo Workflows #981, smallstep/cli #428), and the decision criteria.

### 5. When should ferrule start depending on hasp?

**Answer:** In two phases.

- **Phase 1 (available now):** `hasp 0.1.0-alpha.1` with `env://` + `keyring://`.
  Ferrule can migrate its P0 (keyring) and P1 (env) use cases.
  Target: after Wave 0+1 completion per `hasp/notes/scaffold.md` §6.

- **Phase 2 (slightly later):** `hasp 0.1.0-alpha.2` adds `file://` (Wave 1.5).
  Ferrule's P2 (Docker secrets, systemd-creds) use case becomes available.
  No API change on Ferrule's side — just a URL change from `keyring://` to `file://`.

Ferrule can prepare the `hasp` feature flag integration now; enable it once the crate
hits crates.io with the required backends. The `password_url` field in `.ferrule.toml`
can be documented in Ferrule's docs immediately (it's just a URL string).

---

## 11. Ferrule Response to Review Questions

Ferrule formally accepts all five architectural decisions surfaced in the review prompt.

### 1. 2-component `keyring://` grammar — accepted, zero migration cost

Ferrule's existing `keyring::Entry::new("ferrule", name)` is already the canonical
2-tuple `(service, account)`. The URL `keyring://ferrule/{connection_name}` maps 1:1.
No config files, bookmarks, or CLI args need to change.

### 2. `file://` default-trim policy — accepted

Ferrule's WISHLIST explicitly requested this for Docker secrets / Kubernetes secrets /
systemd-creds. The `RESEARCH-file-trim.md` justification (Vault `-field` strips; Argo #981;
smallstep #428) confirms the default matches operational reality.

### 3. Feature-gating strategy — accepted as proposed

```toml
# ferrule-config/Cargo.toml
[features]
default = ["keyring"]          # legacy direct keyring v3
hasp = ["dep:hasp"]            # new unified path
```

- Default builds continue to work on every target (no surprise OS keyring linkage).
- Enterprise/container builds opt in via `--features hasp`.
- When `hasp` is off, `password_url` in `.ferrule.toml` is gracefully ignored.
- No forced migration for existing users.

### 4. Wave 3 backend scope — `env://` + `keyring://` + `file://` only

Enterprise backends (`aws-sm://`, `vault://`, `gcp-sm://`, `azure-kv://`, `op://`, `bw://`)
are P4 / beyond Wave 3. Because Ferrule resolves passwords generically via `hasp::get()`,
adding any of those later is a **zero-line code change** in Ferrule — users just change
their `password_url`.

### 5. Integration timing — sketch now, wire later

The public API is locked (`Backend` trait, `Error`/`BackendFailureKind` enums, URL grammars,
`secrecy::SecretString` boundary). The integration is mechanical — §6 already contains the
exact `#[cfg(feature = "hasp")]` match arms and `resolve_password_stack()` shape.

Ferrule will:
1. Add the `hasp` feature flag and `password_url` field to `ConnectionProfile` now.
2. Implement the `#[cfg(feature = "hasp")]` branch in `resolve_password_stack()` now.
3. Leave the feature off in `default = ["keyring"]` until `hasp 0.1.0-alpha.1` is on crates.io.
4. When `hasp` publishes, flip the dep from path/git to versioned and enable the feature.

Risk mitigation: `#[non_exhaustive]` on `hasp::Error` means adding variants won't break
Ferrule's match arms. If the API surface shifts unexpectedly, the damage is confined to
one `cfg` block.
