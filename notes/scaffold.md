# hasp Scaffold Plan

All architectural decisions below are locked. This document serves as the build order and topology reference for implementation.

---

## 1. Decisions Locked

| Concern | Decision |
|---|---|
| **I/O model** | Sync-first core trait. Optional `async` feature on `hasp-core` provides Tokio `spawn_blocking` convenience wrappers on `Store`. |
| **Backend dispatch** | Static enum (`Backend { Env(EnvBackend), File(FileBackend), ... }`) in root `hasp` crate, with a `Custom(Arc<dyn CustomBackend>)` escape hatch in `hasp-core`. |
| **URL parsing** | Central router extracts scheme from `url::Url` and dispatches. Each backend receives `&url::Url` and converts it to a typed internal `BackendUrl` internally. No central normalization layer. |
| **Operations** | Unified `Backend` trait: `get`, `put`, `list`, `delete`, `exists`. Unsupported operations return `hasp_core::Error::UnsupportedOperation`. |
| **Errors** | Flat `thiserror` enum in `hasp-core`. Top-level variants: `NotFound`, `PermissionDenied`, `AuthenticationFailed`, `PreconditionFailed`, `Backend { scheme, kind, message }`. `BackendFailureKind { Transient, Throttled, Permanent }` (no `Unknown` — collapses to `Permanent`). Both enums `#[non_exhaustive]`. Provides `Error::is_transient(&self) -> bool` predicate. See `docs/internal/research/RESEARCH-error-taxonomy.md`. |
| **Layout** | Cargo workspace: `hasp-core` + `hasp-backend-*` + root `hasp` (batteries-included library) + `hasp-cli`. |
| **Profile resolution** | Lives in `hasp-cli` only (NOT in `hasp-core`). The library is URL-in, secret-out; the CLI loads `~/.config/hasp/profiles.toml` (XDG on Linux/macOS, AppData on Windows) and expands `@profile/key` before calling `hasp::get`. TTY prompt logic (`rpassword`) likewise lives in `hasp-cli` only. Decision rationale: `docs/internal/research/RESEARCH-profile-resolver-scope.md` (Agent 2 surveyed 19 secrets CLIs; unanimous CLI-only placement). |
| **Secret wrapper** | `secrecy::SecretString` is the library boundary type. Fetched secrets are wrapped; the CLI unwraps deliberately on the stdout path. |
| **CLI / library firewall** | Root `hasp` is a library crate. `hasp-cli` is a separate binary crate that renames its bin to `hasp` (`[[bin]] name = "hasp"`). CLI may use `anyhow`; the library never does. |

---

## 2. Workspace Topology

```
hasp/
  Cargo.toml                        # workspace manifest
  crates/
    hasp-core/                      # contracts, errors, router, async shim (NO profile/TOML/TTY deps)
    hasp-backend-env/               # env://VAR (stdlib only)
    hasp-backend-file/              # file:///path (stdlib only)
    hasp-backend-keyring/           # keyring://service/account[?target=...]
    hasp-backend-op/                # op://Vault/Item/field (subprocess)
    hasp-backend-aws-sm/            # aws-sm://name?region=...
    hasp-backend-aws-ssm/           # aws-ssm:///path?with-decryption=true
    hasp-backend-vault/             # vault://kv/data/...
    hasp-backend-gcp-sm/            # gcp-sm://projects/.../secrets/...
    hasp-backend-azure-kv/          # azure-kv://<vault>.vault.azure.net/secrets/<name>
    hasp-backend-bw/                # bw://item-uuid/login.password
    hasp/                           # root library: Backend enum, Store, batteries-included API
    hasp-cli/                       # clap binary, thin shell over root `hasp`
```

---

## 3. Crate Dependency Graph

```
hasp-cli ──► hasp (all features) ──► hasp-core
                │                      │
                ├──► hasp-backend-env  │
                ├──► hasp-backend-file │
                ├──► hasp-backend-keyring
                ├──► hasp-backend-op
                └──► ... (cloud backends)

Each hasp-backend-* ──► hasp-core
```

- `hasp-core` depends on `url`, `thiserror`, `secrecy`. NO `toml`/`serde`/`dirs`/`rpassword` (those live in `hasp-cli`). Optional Cargo features: `async` (Tokio `spawn_blocking` shim), `memory-lock` (off-by-default `mlock`/`memfd_secret`/`VirtualLock` posture per `RESEARCH-secrets-zeroization.md`).
- No backend crate depends on another backend crate.
- `hasp-cli` depends on `hasp` (root) with all features, plus `clap`, `anyhow`, `dirs`.

---

## 4. Core Types (`hasp-core`)

### `Error`

Locked per `docs/internal/research/RESEARCH-error-taxonomy.md`. Both enums are `#[non_exhaustive]` to allow additive variants without semver bump on consumers using a wildcard match arm. `ProfileNotFound` / `ProfileKeyNotFound` live in `hasp-cli`'s own error type, not here (per `RESEARCH-profile-resolver-scope.md`).

```rust
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid URL: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("invalid URL for backend: {0}")]
    InvalidUrl(String),

    #[error("unsupported scheme: {0}")]
    UnknownScheme(String),

    #[error("{scheme} does not support {operation}")]
    UnsupportedOperation {
        scheme: &'static str,
        operation: &'static str,
    },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    #[error("backend '{scheme}' failed: {message}")]
    Backend {
        scheme: &'static str,
        kind: BackendFailureKind,
        message: String,
    },
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailureKind {
    Transient,   // 5xx, timeout, connect-refused, gRPC UNAVAILABLE/DEADLINE_EXCEEDED
    Throttled,   // HTTP 429, AWS ThrottlingException, gRPC RESOURCE_EXHAUSTED — honor Retry-After
    Permanent,   // validation, unrecognized fields, anything not captured above
}

impl Error {
    /// True iff a retry has any chance of succeeding without external action.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Backend { kind: BackendFailureKind::Transient | BackendFailureKind::Throttled, .. }
        )
    }
}
```

Mapping notes per backend (full table in `RESEARCH-error-taxonomy.md`):
- `keyring://`: `keyring_core::Error::NoEntry → NotFound`; `NoStorageAccess → Backend{Permanent}` (locked); `PlatformFailure → Backend{Transient}`; `Ambiguous(_) → Backend{Permanent}`; `NotSupportedByStore → UnsupportedOperation`.
- `vault://`: 404 → `NotFound` (Vault collapses 404 with no-permission intentionally); 403 → `PermissionDenied`; 429 → `Backend{Throttled}`; 503 sealed → `PreconditionFailed`.
- `gcp-sm://`: `UNAUTHENTICATED → AuthenticationFailed`; `PERMISSION_DENIED → PermissionDenied`; `NOT_FOUND → NotFound`; `RESOURCE_EXHAUSTED → Backend{Throttled}`; `UNAVAILABLE/DEADLINE_EXCEEDED → Backend{Transient}`; `FAILED_PRECONDITION → PreconditionFailed`.
- `azure-kv://`: 401 → `AuthenticationFailed`; 403 + `SecretDisabled` → `PreconditionFailed`; other 403 → `PermissionDenied`; 404 → `NotFound`; 429 → `Backend{Throttled}`.
- `aws-sm://` / `aws-ssm://`: `ResourceNotFoundException`/`ParameterNotFound → NotFound`; `AccessDeniedException → PermissionDenied`; `UnrecognizedClientException`/`ExpiredTokenException → AuthenticationFailed`; `ThrottlingException` → `Backend{Throttled}`; SDK `Timeout`/`Dispatch` → `Backend{Transient}`.

### `Backend` trait

```rust
pub trait Backend: Send + Sync {
    fn scheme(&self) -> &'static str;
    fn get(&self, url: &url::Url) -> Result<secrecy::SecretString, Error>;
    fn put(&self, url: &url::Url, value: &secrecy::SecretString) -> Result<(), Error>;
    fn list(&self, url: &url::Url) -> Result<Vec<Entry>, Error>;
    fn delete(&self, url: &url::Url) -> Result<(), Error>;
    fn exists(&self, url: &url::Url) -> Result<bool, Error>;
}
```

### `CustomBackend` trait (escape hatch)

Same shape as `Backend`, used by `root::Backend::Custom(Arc<dyn CustomBackend>)`.

### `Entry`

```rust
pub struct Entry {
    pub name: String,
    pub url: url::Url,
}
```

### `ProfileResolver` — moved out

`ProfileResolver` does NOT live in `hasp-core`. It lives in `hasp-cli` (or, if a future CLI consumer needs to share the alias loader, in a small standalone `hasp-profiles` support crate that does not pollute `hasp-core`'s deps).

`hasp-core` has no `toml`, `serde`, `dirs`, or `rpassword` dependency. The library is `url` + `thiserror` + `secrecy` + the trait. See `docs/internal/research/RESEARCH-profile-resolver-scope.md` for the prior-art evidence (19 surveyed secrets CLIs unanimously place alias logic in the CLI, never in the library).

---

## 5. Root `hasp` Crate (Batteries-Included API)

```rust
pub enum Backend {
    #[cfg(feature = "env")]
    Env(hasp_backend_env::EnvBackend),
    #[cfg(feature = "file")]
    File(hasp_backend_file::FileBackend),
    #[cfg(feature = "keyring")]
    Keyring(hasp_backend_keyring::KeyringBackend),
    #[cfg(feature = "op")]
    Op(hasp_backend_op::OpBackend),
    #[cfg(feature = "aws-sm")]
    AwsSm(hasp_backend_aws_sm::AwsSmBackend),
    // ... additional feature-gated variants
    Custom(std::sync::Arc<dyn CustomBackend>),
}

pub struct Store {
    backends: HashMap<&'static str, Backend>,
}

impl Store {
    pub fn with_defaults() -> Self;          // registers all enabled backends
    pub fn register(&mut self, backend: Backend);
    pub fn get(&self, url: &str) -> Result<SecretString, Error>;
    pub fn put(&self, url: &str, value: &SecretString) -> Result<(), Error>;
    pub fn list(&self, url: &str) -> Result<Vec<Entry>, Error>;
    pub fn delete(&self, url: &str) -> Result<(), Error>;
    pub fn exists(&self, url: &str) -> Result<bool, Error>;
}

// Convenience free functions using Store::with_defaults():
pub fn get(url: &str) -> Result<SecretString, Error>;
pub fn put(url: &str, value: &SecretString) -> Result<(), Error>;
// ... etc
```

---

## 6. Backend Implementation Waves

| Wave | Backends | Goal |
|---|---|---|
| **0** | `env` | Prove trait boundary, URL routing, testing pattern. Pure stdlib. |
| **1** | `keyring` | Prove feature-gated conditional compilation + OS-specific crate wrapping. Spall is blocked on this. |
| **1.5** | `file` | Fill out stdlib-only suite. No urgency. |
| **2** | `op` | Prove subprocess backend pattern. |
| **3** | `vault`, `aws-sm`, `aws-ssm` | Prove HTTP SDK integration pattern, credential assumptions. |
| **4** | `gcp-sm`, `azure-kv`, `bw` | Fill remaining URL schemes once patterns are solid. |

The root `hasp` crate ships after Wave 1 (env + keyring) so Spall can immediately start consuming `hasp = { features = ["env", "keyring"] }`. `file` and `op` follow as Wave 1.5–2. `hasp-cli` ships once Wave 2 is solid.

---

## 7. Per-Backend URL Grammar

Each backend crate defines a private or `pub` URL type parsed from `&url::Url`:

```rust
// hasp-backend-env
pub struct EnvUrl {
    pub var_name: String,
}
impl TryFrom<&url::Url> for EnvUrl { ... } // host = var name

// hasp-backend-aws-sm
pub struct AwsSmUrl {
    pub name: String,
    pub region: Option<String>,
    pub version: Option<String>,
}
impl TryFrom<&url::Url> for AwsSmUrl { ... } // host = name, query = region/version
```

No central parser knows these grammars. The backend owns its own validation.

---

## 8. CLI Design (`hasp-cli`)

Thin shell over root `hasp::Store`.

```
hasp get <url>
hasp put <url> [-|value]        # - reads from stdin
hasp ls <url-prefix>
hasp rm <url>
hasp exists <url>               # exit 0 if found, 1 if not
hasp profiles list
hasp profiles resolve <alias>
```

- Profile alias expansion happens in the CLI before any `hasp::get()` call.
- The CLI loads `~/.config/hasp/profiles.toml` using `dirs`.
- Output: raw secret bytes to stdout for `get`. Table or newline-delimited list for `ls`. Nothing for `put`/`rm` on success.

---

## 9. Testing Strategy

- **Unit**: Each `hasp-backend-*` tests its own URL parser and backend logic with mocked or controlled I/O (temp files, env var scoping, mock keyring, fake op binary).
- **Integration**: Root `hasp` crate has tests that construct a `Store`, register backends, and exercise `get`/`put`/`exists` through the full router.
- **Bin**: `hasp-cli` uses `assert_cmd` + `predicates` for end-to-end CLI testing.
- **Feature combinatorics**: CI tests `--no-default-features`, `default-features`, `--all-features` on root `hasp`.

---

## 10. Pre-Implementation Checklist

Before `cargo new` or the first `lib.rs` line, complete these research / vetting steps (all now complete — see `docs/internal/research/`):

- [x] **Secrets zeroization posture** (`RESEARCH-secrets-zeroization.md`).
- [x] **Keyring crate selection** (`RESEARCH-keyring-v3-vs-v4.md`).
- [x] **Keyring URL grammar** (`RESEARCH-keyring-url-grammar.md`).
- [x] **Profile resolver scope** (`RESEARCH-profile-resolver-scope.md`).
- [x] **File newline trim policy** (`RESEARCH-file-trim.md`).
- [x] **Error taxonomy** (`RESEARCH-error-taxonomy.md`).
- [x] **Ferrule parity review** (`RESEARCH-ferrule-parity.md`).
- [ ] **Skill review**: read `.claude/skills/comment-style/SKILL.md` before writing the first `.rs` file.
- [ ] **Cloud backend research** (`RESEARCH-aws-sm.md`, `RESEARCH-vault.md`, etc.) — defer to before Wave 3.

## 11. Build Order (First Sprint — Spall-Unlock Priority)

Spall is blocked pending a usable `env://` + `keyring://` surface. The first sprint targets Wave 0+1.

1. Create workspace `Cargo.toml` with members.
2. Bootstrap `crates/hasp-core/` with `Error`, `BackendFailureKind`, `Backend` trait, `Entry`, URL parsing helpers. (No profile resolver — that lives in `hasp-cli`.)
3. Bootstrap `crates/hasp-backend-env/` — pure stdlib, independently testable.
4. Bootstrap `crates/hasp/` root crate with the `Backend` enum + `Store`, gated behind `env` feature only.
5. Integration test in `crates/hasp/tests/` proving router works end-to-end.
6. **Day 2-3**: Add `crates/hasp-backend-keyring/` after crate vetting. Enable its feature on root `hasp`.
7. Integration tests across env + keyring.
8. Publish `hasp` 0.1.0-alpha.1 with env + keyring features so downstream (Spall) can start integrating.
9. Add `crates/hasp-backend-file/` as Wave 1.5 — fills out stdlib suite, non-blocking.

Do **not** touch `hasp-cli` or cloud backends until Wave 2 is reached. The CLI is not a blocker for Spall.

## 12. Spall Integration Notes

Spall (and future Rustpunk projects) depend on `hasp` as a library. Key consumption patterns from `docs/internal/spall/WISHLIST.md`:

```
keyring://spall/github-token         # Spall OAuth2 token (2-component canonical)
keyring://ferrule/prod-db            # Ferrule's existing pattern
keyring://my-app/api-key?target=prod # Linux Secret Service collection override
```

Spall must distinguish `NotFound` → prompt user, `PermissionDenied` → warn, `Backend` → retry or fallback.
`hasp` is consumed via `Cargo.toml` feature flags; Spall explicitly wants surgical dependency footprint.
Spall does not use profile aliases, the CLI, or any `hasp-cli` artifact.

Spall's open questions answered here:
- **keyring backend**: `keyring-core = "1.0"` (not `keyring` v3 or v4); see `RESEARCH-keyring-v3-vs-v4.md`
- **Error granularity**: `NotFound`, `PermissionDenied`, `Backend { kind, .. }` provide the taxonomy
- **Async/sync**: sync only; Spall confirmed preference
- **When to start depending**: after `hasp` 0.1.0-alpha.1 publishes with env + keyring

## 13. Pre-Implementation Checklist (Updated)

Before Day 1 commit:

- [x] **Research `RESEARCH-secrets-zeroization.md`** — `hasp-core` depends on `secrecy = "0.10"`; optional `memory-lock` feature for future daemon use.
- [x] **Research `RESEARCH-keyring-v3-vs-v4.md`** — pin `keyring-core = "1.0"` (not `keyring` v3 or v4).
- [x] **Research `RESEARCH-keyring-url-grammar.md`** — canonical `keyring://service/account` (2-component) + optional `?target=...` modifier.
- [x] **Research `RESEARCH-profile-resolver-scope.md`** — `ProfileResolver` and TTY prompt live in `hasp-cli` only.
- [x] **Research `RESEARCH-file-trim.md`** — default strip one trailing `\n`/`\r\n`; opt-out via `?raw=true`.
- [x] **Research `RESEARCH-error-taxonomy.md`** — flat `#[non_exhaustive]` enum with `BackendFailureKind { Transient, Throttled, Permanent }`.
- [x] **Research `RESEARCH-ferrule-parity.md`** — no blocking divergences.
- [ ] **Read `.claude/skills/comment-style/SKILL.md`** before first `.rs` edit.

Before Wave 1.5 (`file`):
- [x] Ferrule URL parity review — complete; zero divergences.

Before Wave 2 (`op`):
- [x] No additional research needed; subprocess pattern is well-understood.

Before Wave 3 (cloud):
- [ ] Backend research notes per cloud provider (`RESEARCH-aws-sm.md`, `RESEARCH-vault.md`, etc.).
