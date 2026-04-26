# RESEARCH-ferrule-parity

> Decision: do hasp's URL conventions and `SecretString` surface align with Ferrule's existing model? Any divergence?
>
> Date: 2026-04-26
> Audience: hasp-core authors, Ferrule integration owner
> Status: review note — direct read of Ferrule source

---

## Sources reviewed

- `~/code/rustpunk/ferrule/ferrule-config/src/credentials.rs` (74 lines)
- `~/code/rustpunk/ferrule/ferrule-core/src/url.rs` (76 lines)
- `~/code/rustpunk/ferrule/ferrule-config/Cargo.toml` (relevant deps)
- `~/code/rustpunk/ferrule/Cargo.toml` (workspace)
- `~/code/rustpunk/ferrule/ferrule-core/Cargo.toml` (relevant deps)

---

## What Ferrule does today

### Workspace dependencies

```toml
# ferrule/Cargo.toml
secrecy = "0.10"

# ferrule-config/Cargo.toml
secrecy = { workspace = true }
keyring = { version = "3", optional = true }
[features]
default = ["keyring"]
keyring = ["dep:keyring"]

# ferrule-core/Cargo.toml
secrecy = { workspace = true }
```

Both crates use `secrecy = "0.10"` (workspace). Keyring is feature-gated at `keyring-rs v3.x` and **on by default**.

### `ferrule-config/src/credentials.rs`

Three operations, all returning or accepting `secrecy::SecretString`:

```rust
// resolve_env_password(name) — reads FERRULE_{NAME}_PASSWORD
//   returns Option<SecretString>
//   wraps the env var value at the boundary: SecretString::new(v.into())

// resolve_keyring_password(name) — calls keyring::Entry::new("ferrule", name)
//   returns Option<SecretString>
//   collapses "not found" + "keyring unavailable" + "empty value" → None

// set_keyring_password(name, password: &SecretString) -> Result<(), ConfigError>
//   uses ExposeSecret to write the bytes
//   maps keyring::Error → ConfigError::KeyringError(String)

// delete_keyring_password(name) -> Result<(), ConfigError>
```

Key invariants:
- Wrapping in `SecretString` happens **at the boundary** — values become secrets the moment they leave the env or the keyring.
- `SecretString::new(v.into())` is the secrecy 0.10 idiom (`SecretBox::new(Box<str>)`).
- The `#[cfg(feature = "keyring")]` and `#[cfg(not(feature = "keyring"))]` paths exist in parallel — disabling the feature returns `None` on read and a typed error on write.

### `ferrule-core/src/url.rs`

`DatabaseUrl` is a wrapper around `url::Url`:

```rust
pub struct DatabaseUrl {
    raw: String,
    parsed: Url,
}

impl DatabaseUrl {
    pub fn parse(raw: &str) -> Result<Self, CoreError> { ... }
    pub fn scheme(&self) -> &str { ... }
    pub fn username(&self) -> &str { ... }
    pub fn password(&self) -> Option<SecretString> {
        self.parsed.password().map(|p| SecretString::new(p.into()))
    }
    pub fn host(&self) -> Option<&str> { ... }
    pub fn port(&self) -> Option<u16> { ... }
    pub fn path(&self) -> &str { ... }
    pub fn database(&self) -> &str { ... }
    pub fn set_password(&mut self, password: Option<&str>) { ... }
    pub fn params(&self) -> IndexMap<String, String> { ... }
    pub fn redacted(&self) -> String {
        let mut url = self.parsed.clone();
        let _ = url.set_password(Some("***"));
        url.to_string()
    }
    pub fn raw(&self) -> &str { ... }
}
```

Patterns:
- Parses with `url::Url::parse` and wraps. The `raw` String is retained alongside the parsed form.
- `password()` returns `Option<SecretString>` — wraps at the boundary the same way `credentials.rs` does.
- `redacted()` produces a logging-safe form by replacing the password with `"***"`. Other URL components (scheme, user, host, path, query) are not redacted — they are considered loggable identifiers.
- Errors flow through a `CoreError::InvalidUrl(String)` variant.

---

## Alignment with hasp design

### Identical alignments

1. **`secrecy = "0.10"`.** Ferrule pins it; hasp will pin the same. `SecretString` is the boundary type on both sides. Zero conversion at integration time. `RESEARCH-secrets-zeroization.md` recommends Approach A (depend directly on `secrecy`); this matches Ferrule.
2. **`SecretString::new(v.into())` constructor pattern.** Ferrule uses this (the 0.10 idiom). hasp will use the same. Migrating Ferrule from its direct `keyring::Entry::new` call to `hasp::get(...)` does not change the wrapping pattern at all.
3. **Wrap at the boundary.** Ferrule wraps the env-var value and the keyring value in `SecretString` immediately. hasp's locked decision is the same — backends construct `SecretString` from raw bytes the moment they receive them.
4. **`url::Url` for URL parsing.** Ferrule uses `url::Url::parse` in `DatabaseUrl::parse`. hasp's per-backend URL structs will also parse from `url::Url`. Same dep, same idiom.
5. **Redaction posture for URLs.** Ferrule's `DatabaseUrl::redacted()` redacts the password and leaves scheme/host/path visible. hasp's `redacted_url(...)` helper will follow the same convention — userinfo password is redacted, identifying components are loggable.
6. **Feature-gated keyring.** Ferrule has `keyring = { version = "3", optional = true }` and `default = ["keyring"]`. hasp's plan is to feature-gate every backend (per scaffold §2). Cleanly aligned.

### Divergences (all non-blocking)

1. **Ferrule pins `keyring = "3"`. hasp will pin `keyring-core = "1"` (per `RESEARCH-keyring-v3-vs-v4.md` recommendation).** When Ferrule integrates with hasp, Ferrule's direct `keyring` dependency disappears entirely — `ferrule-config/src/credentials.rs` becomes:
   ```rust
   let url = format!("keyring://ferrule/{}", name);
   match hasp::get(&url) {
       Ok(secret) => Some(secret.into()),
       Err(hasp::Error::NotFound) => None,
       Err(_) => { /* warn */ None },
   }
   ```
   Ferrule no longer pins `keyring` at all. hasp's choice cascades.

2. **Ferrule's `resolve_keyring_password` collapses "not found" + "keyring unavailable" + "empty value" → `None`.** hasp returns distinct errors: `Error::NotFound` for missing entry, `Error::Backend { kind: Permanent, ... }` for daemon-unavailable, etc. Post-migration, Ferrule **gains** the ability to distinguish these — e.g., warn loudly when the keyring daemon is missing rather than silently falling through to the next resolver. This is strictly more capability; Ferrule's current code can be refactored to map `Error::NotFound` → `None` (silent fall-through) and other errors → warn-and-fall-through. Ferrule's WISHLIST §7.2 explicitly asks for this granularity.

3. **Ferrule's `set_keyring_password` returns `Result<(), ConfigError>` with `ConfigError::KeyringError(String)` as the variant.** hasp's `put` returns `Result<(), hasp::Error>` with structured variants. After integration, Ferrule's wrapper (if it keeps one) maps `hasp::Error` → `ConfigError`; or Ferrule drops the wrapper and propagates `hasp::Error` directly. Either is fine; non-blocking.

4. **Ferrule's `DatabaseUrl::redacted()` replaces password with literal `"***"`.** hasp's redaction helper will follow the same pattern. If hasp ships a `hasp::redact_url(&url::Url) -> String` helper, Ferrule could adopt it and delete its own `redacted()` method — minor consolidation. Non-blocking.

5. **Ferrule reads `FERRULE_{NAME}_PASSWORD` env vars in `resolve_env_password` directly via `std::env::var`.** Post-hasp, this becomes `hasp::get("env://FERRULE_{NAME}_PASSWORD")`. Same wrapping (`SecretString::new(v.into())`) happens inside hasp's `env://` backend. No behavior change.

6. **Ferrule's `keyring::Entry::new("ferrule", name)` is 2-tuple, mapping to `keyring://ferrule/<name>`.** Per `RESEARCH-keyring-url-grammar.md`, the canonical hasp URL is 2-component. **Zero migration cost on the URL side** — `ferrule` is the service, `<name>` is the account, exactly as today.

### Ferrule WISHLIST cross-references

Ferrule's `docs/internal/ferrule/WISHLIST.md` requests:
- P0: `keyring://` backend — covered (Wave 1).
- P1: `env://` backend — covered (Wave 0).
- P2: `file://` backend with newline trim — covered (Wave 1.5; trim default per `RESEARCH-file-trim.md`).
- P3: `secrecy::SecretString` at boundary — already aligned.
- §7.1: Keyring v3 vs v4 — answered in `RESEARCH-keyring-v3-vs-v4.md` (Approach B: `keyring-core` 1.0; Ferrule will need to migrate off direct `keyring` v3 dep at integration time).
- §7.2: Error type granularity — addressed by `RESEARCH-error-taxonomy.md`; hasp's distinct `NotFound`/`Backend{kind}` variants give Ferrule the granularity it asks for.
- §7.3: Sync vs async — sync (locked).
- §7.4: file:// newline trimming — answered: trim by default, opt-out via `?raw=true` (`RESEARCH-file-trim.md`).
- §7.5: When can ferrule depend — once hasp ships 0.1.0-alpha.1 with `env://` + `keyring://`.

---

## Open items

1. **Ferrule's `set_password()` on `DatabaseUrl` mutates the URL in place.** hasp's `put` is on the URL store, not on a mutable URL object. This is fine — they serve different purposes; Ferrule's mutator stays in `DatabaseUrl` for the connection-string path, while `hasp::put` writes to the backing store via a separate URL.
2. **Ferrule has `IndexMap` (preserves order) for `params()`; hasp may use a `HashMap` for backend URL params.** Order matters in some database connection-string contexts (Postgres parameter precedence) but does not for hasp backend URL parsing (no precedence dependence). Non-blocking divergence in different domains.
3. **No `Cargo.lock` is currently committed in hasp** (per `CLAUDE.md`). Once `[[bin]]` lands and `Cargo.lock` is committed, Ferrule's lockfile will pin a different `keyring`/`keyring-core` resolution than hasp's during the migration window. Document this — it's not a hasp bug, just a coordination point.

---

## Recommendation

**No blocking divergence.** Ferrule's existing patterns are exactly the patterns hasp will use:

- `secrecy = "0.10"` shared.
- `SecretString` at the library boundary.
- Wrap at the source.
- `url::Url` for parsing.
- Feature-gated keyring.
- Logging-safe redaction via password-replacement.

**Integration path (Ferrule side, post-hasp 0.1.0-alpha.1):**

1. Replace `ferrule-config/src/credentials.rs` calls with `hasp::get("keyring://ferrule/<name>")` and `hasp::get("env://FERRULE_<NAME>_PASSWORD")`.
2. Map `hasp::Error::NotFound` → `None` (silent fallthrough); other errors → warn-and-fallthrough.
3. Drop the direct `keyring = "3"` dep from `ferrule-config/Cargo.toml`.
4. Replace `ferrule = ["dep:keyring"]` feature with `hasp = ["dep:hasp"]`.

**Confidence:** High. The patterns are identical. The migration is mechanical.

**Threat-model note:** Ferrule's `DatabaseUrl::redacted()` is the canonical pattern hasp should adopt for its own log-safe URL serialization — `set_password(Some("***"))` then `to_string()`. This preserves scheme/host/path (loggable) and redacts only the userinfo. Confirms the locked posture.

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| Ferrule `credentials.rs` | source | Direct credential-resolution pattern | `~/code/rustpunk/ferrule/ferrule-config/src/credentials.rs` |
| Ferrule `url.rs` | source | DatabaseUrl + redaction pattern | `~/code/rustpunk/ferrule/ferrule-core/src/url.rs` |
| Ferrule WISHLIST | doc | hasp consumer requirements | `docs/internal/ferrule/WISHLIST.md` |
| `RESEARCH-secrets-zeroization.md` | sibling | secrecy 0.10 recommendation | `docs/internal/research/RESEARCH-secrets-zeroization.md` |
| `RESEARCH-keyring-v3-vs-v4.md` | sibling | Ferrule must migrate to keyring-core 1.0 at integration | `docs/internal/research/RESEARCH-keyring-v3-vs-v4.md` |
| `RESEARCH-keyring-url-grammar.md` | sibling | `keyring://ferrule/<name>` is canonical 2-component, no migration | `docs/internal/research/RESEARCH-keyring-url-grammar.md` |
| `RESEARCH-error-taxonomy.md` | sibling | Granular errors give Ferrule the distinguishing power its WISHLIST requested | `docs/internal/research/RESEARCH-error-taxonomy.md` |
| `RESEARCH-file-trim.md` | sibling | file:// trim policy answers Ferrule WISHLIST §7.4 | `docs/internal/research/RESEARCH-file-trim.md` |
