# Plan: Proxy Support for `hasp`

Date: 2026-04-28  
Status: planning — no code yet  
Scope: library + CLI  
Reference impls reviewed: [`ferrule`](https://github.com/rustpunk/ferrule), [`spall`](https://github.com/rustpunk/spall)

---

## 1. Executive Summary

Corporate networks force outbound traffic through HTTP CONNECT proxies (Squid, Zscaler, Blue Coat). `hasp` must work behind these proxies without surprising users or forcing them to set env vars they do not control.

The plan is **two-phase**:

1. **Phase 1 — Transparent env-var support** (near-zero code): `vault://`, `gcp-sm://`, and `azure-kv://` already use `reqwest`, which honours `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` by default. AWS SDK (`aws-sm://`, `aws-ssm://`) uses its own HTTP stack; we will document that it currently requires env vars.
2. **Phase 2 — Explicit proxy configuration** (library + CLI): add a `ProxyConfig` type to `hasp-core`, plumb it through backend constructors, and expose `--proxy-url` in `hasp-cli` plus per-profile `proxy_url` in `profiles.toml`. This gives users authenticated proxies, per-profile proxy selection, and `NO_PROXY` without touching global env.

---

## 2. Current State Analysis

| Backend | HTTP stack | Env vars work today? | Explicit config possible today? |
|---|---|---|---|
| `vault://` | `reqwest::blocking` | ✅ yes — `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` | ❌ no — `build_client()` uses `Client::builder()` defaults |
| `gcp-sm://` | `reqwest::blocking` | ✅ yes | ❌ no |
| `azure-kv://` | `reqwest::blocking` | ✅ yes | ❌ no |
| `aws-sm://` | AWS SDK (smithy-runtime / hyper) | ⚠️ `HTTPS_PROXY` is respected **if** the default HTTP client is used; the current `aws_config::defaults().load()` path does *not* guarantee proxy support on all platforms/feature sets | ❌ no |
| `aws-ssm://` | AWS SDK (smithy-runtime / hyper) | ⚠️ same as `aws-sm` | ❌ no |
| `op://` | delegates to `op` CLI | N/A — `op` binary honours its own proxy env | N/A |
| `bw://` | delegates to `bw` CLI | N/A | N/A |
| `keyring://` | OS IPC | N/A | N/A |
| `file://` / `env://` | no network | N/A | N/A |

**Observation:** most users will be served by Phase 1 (env vars). Phase 2 targets authenticated proxies and CI environments where env vars are undesirable.

---

## 3. Design Goals & Invariants

1. **Library-first.** Proxy configuration is a concrete type in `hasp-core`, not a CLI string. The CLI resolves strings into `ProxyConfig`; backends consume `ProxyConfig`.
2. **No default-feature bloat.** Proxy code is small (parsing + `NO_PROXY` matching), but if it pulls in a new crate, that crate must be lightweight. `url` is already a dependency; `secrecy` is already a dependency. No `tokio`, no `hyper`, no `clap` in `hasp-core`.
3. **Env-var fallback is always active.** Even after Phase 2, unsetting explicit proxy config must fall back to env vars so that existing users keep working.
4. **Secrets discipline.** Proxy credentials (username/password) are wrapped in `secrecy::SecretString` at parse time. Proxy passwords never appear in `Debug`, `Display`, or error messages.
5. **URL symmetry with `ferrule`.** Proxy resolution layers, `NO_PROXY` syntax, and env-var names follow `ferrule` exactly so muscle memory transfers across rustpunk tools.

---

## 4. Detailed Design

### 4.1 `hasp-core` additions

```rust
// hasp-core/src/proxy.rs
use secrecy::SecretString;

/// Parsed HTTP CONNECT proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Original URL string (for diagnostics only).
    pub url: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<SecretString>,
}

impl ProxyConfig {
    /// Parse `http://proxy:8080` or `http://user:pass@proxy:3128`.
    pub fn parse(url: &str) -> Result<Self, Error>;
}

/// curl-compatible `NO_PROXY` check.
pub fn is_no_proxy(target_host: &str) -> bool;

/// Resolve proxy from the standard env-var stack.
///
/// Checks `ALL_PROXY`, then `HTTPS_PROXY` / `HTTP_PROXY`, honouring
/// `NO_PROXY`. Returns `None` when no proxy is configured.
pub fn resolve_proxy_from_env(target_host: &str) -> Option<ProxyConfig>;
```

**`NO_PROXY` rules** (copied from `ferrule`):
- `*` — disables proxy for every host.
- `localhost,127.0.0.1` — exact matches, comma-separated.
- `.example.com` — suffix match (`db.example.com` hits, `example.com` does not).
- Port numbers in patterns are ignored.

**Error mapping:** `ProxyConfig::parse` returns `Error::InvalidUrl` (already in `hasp-core`). No new error variants required.

### 4.2 Backend constructor changes

Add an optional `proxy: Option<&ProxyConfig>` parameter at construction time, not on each method call, because proxying is a transport concern, not a per-request concern.

```rust
// vault
impl VaultBackend {
    pub fn new() -> Self { Self::with_proxy(None) }
    pub fn with_proxy(proxy: Option<ProxyConfig>) -> Self { ... }
}

// gcp-sm
impl GcpSmBackend {
    pub fn new() -> Self { Self::with_proxy(None) }
    pub fn with_proxy(proxy: Option<ProxyConfig>) -> Self { ... }
}

// azure-kv
impl AzureKvBackend {
    pub fn new() -> Self { Self::with_proxy(None) }
    pub fn with_proxy(proxy: Option<ProxyConfig>) -> Self { ... }
}

// aws-sm
impl AwsSmBackend {
    pub fn new() -> Self { Self::with_proxy(None) }
    pub fn with_proxy(proxy: Option<ProxyConfig>) -> Self { ... }
}

// aws-ssm
impl AwsSsmBackend {
    pub fn new() -> Self { Self::with_proxy(None) }
    pub fn with_proxy(proxy: Option<ProxyConfig>) -> Self { ... }
}
```

**Non-HTTP backends** (`env`, `file`, `keyring`, `op`, `bw`) keep their existing constructors; `with_proxy` is a no-op or absent.

### 4.3 `Store` changes (`hasp` root crate)

Introduce a builder so callers can pass proxy config without changing `Store::with_defaults()`'s signature (preserving backward compatibility).

```rust
pub struct StoreBuilder {
    proxy: Option<ProxyConfig>,
    backends: Vec<Backend>,
}

impl StoreBuilder {
    pub fn empty() -> Self;
    pub fn with_defaults() -> Self;
    pub fn proxy(mut self, proxy: Option<ProxyConfig>) -> Self;
    pub fn register(mut self, backend: Backend) -> Self;
    pub fn build(self) -> Store;
}
```

`Store::with_defaults()` becomes a thin wrapper:
```rust
pub fn with_defaults() -> Self {
    StoreBuilder::with_defaults().build()
}
```

Inside `StoreBuilder::with_defaults()`, when `proxy` is `Some`, pass it to every backend constructor that accepts it.

### 4.4 reqwest-based backends (`vault`, `gcp-sm`, `azure-kv`)

Change the internal `build_client()` / `client()` helper from:
```rust
reqwest::blocking::Client::builder()
    .timeout(Duration::from_secs(10))
    .build()
```
to:
```rust
let mut builder = reqwest::blocking::Client::builder()
    .timeout(Duration::from_secs(10));

if let Some(proxy) = &self.proxy {
    // reqwest already respects env vars by default, but if the user
    // supplied an explicit proxy we override so that profile-level
    // proxy_url takes precedence over env.
    let reqwest_proxy = reqwest::Proxy::all(&proxy.url)
        .map_err(|e| Error::Backend { ... })?;
    builder = builder.proxy(reqwest_proxy);
}

builder.build()
```

**Note:** When `proxy` is `None`, we intentionally do **not** call `.no_proxy()`. This keeps the default env-var behaviour.

### 4.5 AWS SDK backends (`aws-sm`, `aws-ssm`)

The AWS SDK does not expose a simple `ProxyConfig` object. The standard pattern is:
1. If env vars are sufficient, do nothing (Phase 1).
2. For explicit proxy config, we must configure a **custom HTTP client**.

The recommended path in aws-sdk-rust 1.x is to use `aws_smithy_runtime::client::http::hyper::HyperClientBuilder` or to set the `HTTPS_PROXY` env var programmatically. However, constructing a custom hyper client with proxy support pulls in `hyper-proxy` or `hyper-util`, adding heavy dependencies to the AWS backends.

**Decision:** For Phase 2, the AWS backends document that explicit proxy configuration is **env-var only**. If a user passes `proxy` to `AwsSmBackend::with_proxy`, the backend sets `HTTPS_PROXY` / `HTTP_PROXY` in the local Tokio runtime's env snapshot before calling `aws_config::defaults().load()`.

A cleaner future option (deferred) is to use `aws_config::HttpClient` with a `reqwest`-based smithy connector, unifying the HTTP stack. This is listed under "Open Questions / Deferred".

### 4.6 CLI changes (`hasp-cli`)

Add a global `--proxy-url` flag:
```rust
#[derive(Parser)]
struct Cli {
    #[arg(long, global = true, help = "HTTP CONNECT proxy URL")]
    proxy_url: Option<String>,
    // ...
}
```

**Proxy resolution layers** (first hit wins):
1. `--proxy-url <URL>` CLI flag.
2. `proxy_url = "..."` in the active profile (`profiles.toml`).
3. `HASP_<PROFILE>_PROXY_URL=<URL>` env var (where `<PROFILE>` is upper-cased with `-` → `_`).
4. `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY` env vars.
5. No proxy.

`NO_PROXY` is honoured at layer 4. Layers 1–3 bypass `NO_PROXY` because they are explicit user intent.

**Implementation:** expand `profiles.rs` to parse `proxy_url`:
```toml
[profiles.prod]
db_password = "aws-sm://us-east-1/prod/db-password"
proxy_url = "http://proxy.corp.example.com:8080"
```

When `proxy_url` is set at the profile level, it applies to **all** URLs resolved through that profile. If a user needs per-backend proxy granularity, they can split aliases across profiles.

### 4.7 Profile config schema change

The current `profiles.toml` is flat:
```toml
[profiles.prod]
key = "url"
```

We extend it by allowing a per-profile `proxy_url` key. Because keys are URL strings (they contain `://`), `proxy_url` is unambiguous — it does not parse as a valid URL for any hasp backend.

```toml
[profiles.corp]
proxy_url = "http://user:pass@proxy.corp.example.com:8080"
vault_token = "vault://prod/data/token"
```

**Migration:** existing files without `proxy_url` continue to parse. The `RawProfiles` deserializer can reject a `proxy_url` that is not a valid proxy URL at load time, or defer validation to resolution time. Deferring is preferred so that `load_profiles()` stays infallible for disk errors.

---

## 5. Error & Secrets Posture

- `ProxyConfig::parse` uses `secrecy::SecretString` for the password.
- `Debug` on `ProxyConfig` must redact the password: `ProxyConfig { url: "http://user:[REDACTED]@proxy:3128", host: "proxy", port: 3128, username: Some("user"), password: Some(SecretString { ... }) }`.
- The CLI `--proxy-url` string is parsed immediately; if it contains a password, the `SecretString` wrapper is applied before the string is dropped. The raw CLI arg is not retained.
- Proxy passwords never appear in `hasp_core::Error` messages. Network errors from the proxy may include the proxy host/port for diagnostics, but never the password.

---

## 6. Testing Strategy

| Test | Type | Location | Notes |
|---|---|---|---|
| `ProxyConfig::parse` round-trip | Unit | `hasp-core/src/proxy.rs (#[cfg(test)])` | Valid/invalid URLs, default port 8080, auth parsing, percent-encoded creds |
| `is_no_proxy` matching | Unit | `hasp-core/src/proxy.rs` | `*`, exact, suffix `.example.com`, comma lists, port stripping |
| `resolve_proxy_from_env` | Unit | `hasp-core/src/proxy.rs` | With/without env vars, `ALL_PROXY` precedence, `NO_PROXY` interaction |
| reqwest backend through proxy | Integration | `hasp/tests/integration.rs` | Spin up a tiny `tiny_http` or `httptest` proxy that requires `Proxy-Authorization`, assert that Vault backend reaches a mock Vault server through it |
| AWS backend through proxy | Integration | `hasp/tests/integration.rs` | Document as `#[ignore = "requires local mitmproxy or squid")]`; primarily manual |
| CLI `--proxy-url` arg | Integration | `hasp-cli/tests/cli.rs` | Use a local proxy that logs `CONNECT` requests; assert the flag is parsed and passed |
| Profile `proxy_url` parsing | Unit | `hasp-cli/src/profiles.rs` | TOML with and without `proxy_url` |

**CI strategy:** unit tests run in CI. Integration tests that need a real proxy are `#[ignore]` and run manually or in a future Docker-based CI job.

---

## 7. Implementation Order

1. **Phase 1 — Document env-var support** (no code)
   - Add a "Proxy" section to `docs/src/troubleshooting.md` stating that `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` work for `vault://`, `gcp-sm://`, `azure-kv://` today.
   - Add a note that AWS backends (`aws-sm://`, `aws-ssm://`) require `HTTPS_PROXY` env var.

2. **Phase 2 — Core proxy type**
   - Add `hasp-core/src/proxy.rs` with `ProxyConfig`, `is_no_proxy`, `resolve_proxy_from_env`.
   - Add unit tests.
   - Cut a small PR so `hasp-core` gains the type before backend wiring.

3. **Phase 3 — reqwest backends**
   - `VaultBackend::with_proxy`
   - `GcpSmBackend::with_proxy`
   - `AzureKvBackend::with_proxy`
   - Update `StoreBuilder` in `hasp/src/lib.rs`.
   - Integration tests with a mock proxy.

4. **Phase 4 — AWS backends (env-only)**
   - Document AWS limitation.
   - Optionally set `HTTPS_PROXY` in the local scope before `aws_config::defaults().load()` if explicit proxy is provided.

5. **Phase 5 — CLI & profiles**
   - Add `--proxy-url` to `hasp-cli/src/main.rs`.
   - Add `proxy_url` parsing to `profiles.rs`.
   - Add proxy resolution logic (layers 1–3) in `main.rs`.
   - Wire `StoreBuilder::proxy(...)` in the CLI `run()` function.

6. **Phase 6 — Documentation & book**
   - `docs/src/proxy.md` (paralleling `ferrule/docs/src/proxy.md`).
   - Update `docs/src/profiles.md` with `proxy_url`.

---

## 8. Open Questions / Deferred

1. **AWS SDK explicit proxy.** Should we switch the AWS backends to a `reqwest`-based smithy HTTP client so that explicit `ProxyConfig` works identically across all HTTP backends? This would add `reqwest` as a transitive dep of the AWS crates, but it is already present for Vault/GCP/Azure. The alternative is to accept env-var-only for AWS.

2. **SOCKS5.** `ferrule` deferred SOCKS5. `hasp` should do the same. If a network requires SOCKS5, users can run a local SOCKS5-to-HTTP-CONNECT adapter (e.g. `proxychains-ng`). Document this as the recommended workaround.

3. **Per-backend proxy granularity.** The current plan is one proxy per `Store`. If a user needs `vault://` through one proxy and `gcp-sm://` through another, they must construct two `Store` instances. Is this acceptable? (Yes — it matches `ferrule`'s per-connection model and keeps the API simple.)

4. **`op://` and `bw://` proxying.** These delegate to CLI binaries. If the 1Password or Bitwarden CLI needs a proxy, it respects its own env vars (`OP_PROXY` for `op`, HTTP_PROXY for `bw`). We do not plan to intercept or configure these.

5. **Async `Backend` trait.** If `hasp` ever moves to async backends, `ProxyConfig` transfers unchanged. The `http_connect` function in `ferrule` returns a `TcpStream`, which is more relevant to database TCP connections than HTTP API calls. For hasp, `reqwest::Proxy` + the AWS env vars are sufficient; a manual HTTP CONNECT handshake is only needed if we add a non-HTTP backend that speaks raw TCP.

---

## 9. File Touch List (predicted)

### Phase 2 (core)
- `crates/hasp-core/src/lib.rs` — re-export proxy module
- `crates/hasp-core/src/proxy.rs` — new
- `crates/hasp-core/Cargo.toml` — no new deps (uses existing `url`, `secrecy`)

### Phase 3 (backends)
- `crates/hasp-backend-vault/src/lib.rs` — `with_proxy`, `build_client` change
- `crates/hasp-backend-gcp-sm/src/lib.rs` — `with_proxy`, `client` change
- `crates/hasp-backend-azure-kv/src/lib.rs` — `with_proxy`, `client` change
- `crates/hasp/src/lib.rs` — `StoreBuilder` + `with_proxy` wiring

### Phase 4 (AWS)
- `crates/hasp-backend-aws-sm/src/lib.rs` — `with_proxy`, env-var injection (optional)
- `crates/hasp-backend-aws-ssm/src/lib.rs` — same

### Phase 5 (CLI)
- `crates/hasp-cli/src/main.rs` — `--proxy-url`, resolution layers, `StoreBuilder` usage
- `crates/hasp-cli/src/profiles.rs` — `proxy_url` parsing

### Phase 6 (docs)
- `docs/src/proxy.md` — new
- `docs/src/profiles.md` — add `proxy_url` example
- `docs/src/troubleshooting.md` — env-var quick reference
