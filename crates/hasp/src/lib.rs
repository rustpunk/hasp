//! Unified secrets library for Rust.
//!
//! `hasp` provides a single `Store` type that dispatches `get` / `put`
//! / `list` / `delete` / `exists` to multiple backends addressed by
//! URL scheme:
//!
//! - `aws-sm://region/secret-name` — AWS Secrets Manager (feature `aws-sm`)
//! - `aws-ssm://region/parameter-name` — AWS SSM Parameter Store (feature `aws-ssm`)
//! - `env://VAR_NAME` — environment variables (feature `env`)
//! - `file:///path/to/secret` — local files (feature `file`)
//! - `gcp-sm://project/secret-id?version=3` — Google Cloud Secret Manager (feature `gcp-sm`)
//! - `azure-kv://vault/secret-name?version=3` — Azure Key Vault (feature `azure-kv`)
//! - `keyring://service/account` — OS keyring (feature `keyring`)
//! - `op://vault/item/field` — 1Password CLI (feature `op`)
//! - `vault://mount/path?field=key` — HashiCorp Vault (feature `vault`)
//! - `bw://item/field.path` — Bitwarden CLI (feature `bw`)
//!
//! Each backend is feature-gated so consumers pay only for the stores
//! they use.
//!
//! # Example
//!
//! ```no_run
//! use hasp::Store;
//!
//! let store = Store::with_defaults();
//! let secret = store.get("env://HOME").unwrap();
//! ```
//!
//! The library boundary type for secret values is `secrecy::SecretString`.
//! Backends wrap raw bytes at the earliest possible moment so `Debug`
//! output never leaks secret values.

#[cfg(unix)]
pub use hasp_core::SyslogSink;
pub use hasp_core::{
    apply_mitigations, check_refusal_conditions, harden_process, scheme_from_url, AuditEvent,
    AuditSink, Backend as BackendTrait, BackendFailureKind, Entry, Error, ExposeSecret, FileSink,
    HardenRefusal, MitigationOutcome, NoopSink, ProxyConfig, RetryBackend, SecretString,
    StderrSink, Verb,
};

#[cfg(feature = "aws-sm")]
pub use hasp_backend_aws_sm::AwsSmBackend;

#[cfg(feature = "aws-ssm")]
pub use hasp_backend_aws_ssm::AwsSsmBackend;

#[cfg(feature = "env")]
pub use hasp_backend_env::EnvBackend;

#[cfg(feature = "file")]
pub use hasp_backend_file::FileBackend;

#[cfg(feature = "keyring")]
pub use hasp_backend_keyring::KeyringBackend;

#[cfg(feature = "op")]
pub use hasp_backend_op::OpBackend;

#[cfg(feature = "vault")]
pub use hasp_backend_vault::VaultBackend;

#[cfg(feature = "bw")]
pub use hasp_backend_bw::BwBackend;

#[cfg(feature = "gcp-sm")]
pub use hasp_backend_gcp_sm::GcpSmBackend;

#[cfg(feature = "azure-kv")]
pub use hasp_backend_azure_kv::AzureKvBackend;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use url::Url;

pub type Backend = Arc<dyn hasp_core::Backend>;

/// Wrap an externally-provided backend.
pub fn custom_backend(inner: Arc<dyn hasp_core::Backend>) -> Backend {
    inner
}

#[cfg(feature = "aws-sm")]
/// Create an AWS Secrets Manager backend.
pub fn aws_sm() -> Backend {
    Arc::new(AwsSmBackend::new())
}

#[cfg(feature = "aws-ssm")]
/// Create an AWS SSM Parameter Store backend.
pub fn aws_ssm() -> Backend {
    Arc::new(AwsSsmBackend::new())
}

#[cfg(feature = "env")]
/// Create an environment-variable backend.
pub fn env() -> Backend {
    Arc::new(EnvBackend)
}

#[cfg(feature = "file")]
/// Create a file backend.
pub fn file() -> Backend {
    Arc::new(FileBackend)
}

#[cfg(feature = "keyring")]
/// Create an OS keyring backend.
pub fn keyring() -> Backend {
    Arc::new(KeyringBackend::new())
}

#[cfg(feature = "op")]
/// Create a 1Password CLI backend.
pub fn op() -> Backend {
    Arc::new(OpBackend::new())
}

#[cfg(feature = "vault")]
/// Create a HashiCorp Vault backend.
pub fn vault() -> Backend {
    Arc::new(VaultBackend::new())
}

#[cfg(feature = "bw")]
/// Create a Bitwarden CLI backend.
pub fn bw() -> Backend {
    Arc::new(BwBackend::new())
}

#[cfg(feature = "gcp-sm")]
/// Create a GCP Secret Manager backend.
pub fn gcp_sm() -> Backend {
    Arc::new(GcpSmBackend::new())
}

#[cfg(feature = "azure-kv")]
/// Create an Azure Key Vault backend.
pub fn azure_kv() -> Backend {
    Arc::new(AzureKvBackend::new())
}

/// Fluent builder for a [`Store`] with optional proxy configuration.
///
/// Create a builder with `StoreBuilder::with_defaults()`, optionally
/// call `.proxy(Some(config))` and `.cache_ttl(Some(Duration::from_secs(60)))`,
/// then finish with `.build()`.
pub struct StoreBuilder {
    proxy: Option<ProxyConfig>,
    defaults: bool,
    extra_backends: Vec<Backend>,
    ttl: Option<Duration>,
    retry: Option<(u32, Duration)>,
    audit_sink: Option<Arc<dyn AuditSink>>,
}

impl StoreBuilder {
    /// Create an empty builder.
    pub fn empty() -> Self {
        Self {
            proxy: None,
            defaults: false,
            extra_backends: Vec::new(),
            ttl: None,
            retry: None,
            audit_sink: None,
        }
    }

    /// Create a builder pre-loaded with all default backends enabled by
    /// Cargo features.
    pub fn with_defaults() -> Self {
        Self {
            proxy: None,
            defaults: true,
            extra_backends: Vec::new(),
            ttl: None,
            retry: None,
            audit_sink: None,
        }
    }

    /// Set the HTTP CONNECT proxy for backends that support it.
    pub fn proxy(mut self, proxy: Option<ProxyConfig>) -> Self {
        self.proxy = proxy;
        self
    }

    /// Set a TTL for the `Store` memoization cache. `None` disables caching.
    pub fn cache_ttl(mut self, ttl: Option<Duration>) -> Self {
        self.ttl = ttl;
        self
    }

    /// Append an extra backend to the store after the defaults.
    pub fn register(mut self, backend: Backend) -> Self {
        self.extra_backends.push(backend);
        self
    }

    /// Enable retry with exponential backoff for transient failures.
    ///
    /// When set, every default backend that communicates over HTTP will
    /// be wrapped in a [`RetryBackend`] with the given max retries and
    /// base delay. Local backends (`env`, `file`, `keyring`, `op`, `bw`)
    /// are never wrapped — their errors are not transient.
    pub fn with_retry(mut self, max_retries: u32, base_delay: Duration) -> Self {
        self.retry = Some((max_retries, base_delay));
        self
    }

    /// Install an [`AuditSink`] that receives structured start/done
    /// events from every `Store` verb.
    ///
    /// Events are value-free by construction (see
    /// [`hasp_core::audit`]). If unset, the store emits no audit
    /// events — equivalent to a [`NoopSink`].
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Build the final [`Store`].
    pub fn build(self) -> Store {
        let mut store = Store::empty();
        store.ttl = self.ttl;
        store.audit_sink = self.audit_sink;

        if self.defaults {
            register_default_backends(&mut store, &self.proxy, self.retry);
        }

        for backend in self.extra_backends {
            store.register(backend);
        }

        store
    }
}

impl Default for StoreBuilder {
    fn default() -> Self {
        Self::empty()
    }
}

/// Register all default backends enabled by Cargo features.
///
/// Each backend crate is feature-gated so only enabled backends are
/// included in the final binary. Proxy configuration is passed to
/// backends that support HTTP CONNECT/SOCKS5 proxies.
#[allow(unused_variables)]
fn register_default_backends(
    store: &mut Store,
    proxy: &Option<ProxyConfig>,
    retry: Option<(u32, Duration)>,
) {
    let wrap = |b: Backend| {
        if let Some((max, delay)) = retry {
            Arc::new(RetryBackend::new(b).max_retries(max).base_delay(delay)) as Backend
        } else {
            b
        }
    };

    #[cfg(feature = "aws-sm")]
    store.register(wrap(Arc::new(AwsSmBackend::with_proxy(proxy.clone()))));
    #[cfg(feature = "aws-ssm")]
    store.register(wrap(Arc::new(AwsSsmBackend::with_proxy(proxy.clone()))));
    #[cfg(feature = "env")]
    store.register(crate::env());
    #[cfg(feature = "file")]
    store.register(crate::file());
    #[cfg(feature = "keyring")]
    store.register(crate::keyring());
    #[cfg(feature = "op")]
    store.register(crate::op());
    #[cfg(feature = "vault")]
    store.register(wrap(Arc::new(VaultBackend::with_proxy(proxy.clone()))));
    #[cfg(feature = "bw")]
    store.register(crate::bw());
    #[cfg(feature = "gcp-sm")]
    store.register(wrap(Arc::new(GcpSmBackend::with_proxy(proxy.clone()))));
    #[cfg(feature = "azure-kv")]
    store.register(wrap(Arc::new(AzureKvBackend::with_proxy(proxy.clone()))));
}

struct CacheEntry {
    secret: SecretString,
    fetched_at: Instant,
}

/// Batteries-included secret store.
pub struct Store {
    backends: HashMap<&'static str, Backend>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    ttl: Option<Duration>,
    audit_sink: Option<Arc<dyn AuditSink>>,
}

impl Store {
    /// Create an empty store with no backends registered.
    pub fn empty() -> Self {
        Self {
            backends: HashMap::new(),
            cache: RwLock::new(HashMap::new()),
            ttl: None,
            audit_sink: None,
        }
    }

    /// Emit an audit event, if an `AuditSink` is installed.
    fn audit(&self, event: AuditEvent) {
        if let Some(sink) = &self.audit_sink {
            sink.emit(&event);
        }
    }

    /// Audit-emit a `*.done` event derived from a `Result`.
    fn audit_done<T>(
        &self,
        verb: Verb,
        scheme: &str,
        ok_outcome: &'static str,
        result: &Result<T, Error>,
    ) {
        let event = match result {
            Ok(_) => AuditEvent::done(verb, scheme.to_owned(), ok_outcome),
            Err(e) => AuditEvent::done(verb, scheme.to_owned(), "error").with_error_kind(e.kind()),
        };
        self.audit(event);
    }

    /// Create a store with the given backends.
    ///
    /// Backends are registered in iteration order; later backends with the
    /// same scheme replace earlier ones.
    pub fn with_backends(backends: impl IntoIterator<Item = Backend>) -> Self {
        let mut store = Self::empty();
        for backend in backends {
            store.register(backend);
        }
        store
    }

    /// Create a builder pre-loaded with all default backends enabled by
    /// Cargo features.
    pub fn with_defaults() -> Self {
        StoreBuilder::with_defaults().build()
    }

    /// Return a [`StoreBuilder`] for fluent configuration.
    pub fn builder() -> StoreBuilder {
        StoreBuilder::empty()
    }

    /// Register an additional backend.
    ///
    /// If a backend for the same scheme already exists, it is replaced.
    pub fn register(&mut self, backend: Backend) {
        self.backends.insert(backend.scheme(), backend);
    }

    /// Fetch a secret by URL.
    ///
    /// If the store was configured with a TTL, the result is memoized and
    /// subsequent calls for the same URL return a clone of the cached
    /// secret without hitting the backend again.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn get(&self, url: &str) -> Result<SecretString, Error> {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let scheme = parsed_url.scheme().to_owned();
        self.audit(AuditEvent::start(Verb::Get, scheme.clone()));
        let result = self.get_inner(&parsed_url, url);
        self.audit_done(Verb::Get, &scheme, "ok", &result);
        result
    }

    fn get_inner(&self, parsed_url: &Url, url: &str) -> Result<SecretString, Error> {
        let scheme = parsed_url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;

        if let Some(ttl) = self.ttl {
            if let Ok(cache) = self.cache.read() {
                if let Some(entry) = cache.get(url) {
                    if entry.fetched_at.elapsed() <= ttl {
                        return Ok(entry.secret.clone());
                    }
                }
            }
        }

        let secret = backend.get(parsed_url)?;

        if self.ttl.is_some() {
            if let Ok(mut cache) = self.cache.write() {
                cache.insert(
                    url.to_owned(),
                    CacheEntry {
                        secret: secret.clone(),
                        fetched_at: Instant::now(),
                    },
                );
            }
        }

        Ok(secret)
    }

    /// Resolve a URL to its backend without performing I/O.
    ///
    /// Returns the scheme, the backend's scheme name, and whether the
    /// URL has a fresh cached entry (if TTL is enabled). Used by the
    /// CLI for `--explain` / `--dry-run` diagnostics.
    pub fn resolve(&self, url: &str) -> Result<(String, &'static str, bool), Error> {
        let parsed_url = Url::parse(url)?;
        let scheme = parsed_url.scheme().to_owned();
        let backend = self
            .backends
            .get(parsed_url.scheme())
            .ok_or_else(|| Error::UnknownScheme(scheme.clone()))?;

        // Validate per-backend URL grammar so `--explain` rejects the
        // same URLs `get`/`put` would; the dry-run path must not lie.
        backend.validate(&parsed_url)?;

        let cached = if let Some(ttl) = self.ttl {
            if let Ok(cache) = self.cache.read() {
                cache
                    .get(url)
                    .is_some_and(|entry| entry.fetched_at.elapsed() <= ttl)
            } else {
                false
            }
        } else {
            false
        };

        Ok((scheme, backend.scheme(), cached))
    }

    /// Store a secret by URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn put(&self, url: &str, value: &SecretString) -> Result<(), Error> {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let scheme = parsed_url.scheme().to_owned();
        self.audit(AuditEvent::start(Verb::Put, scheme.clone()));
        let result = self.put_inner(&parsed_url, url, value);
        self.audit_done(Verb::Put, &scheme, "ok", &result);
        result
    }

    fn put_inner(&self, parsed_url: &Url, url: &str, value: &SecretString) -> Result<(), Error> {
        let scheme = parsed_url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.put(parsed_url, value)?;

        if self.ttl.is_some() {
            if let Ok(mut cache) = self.cache.write() {
                cache.remove(url);
            }
        }

        Ok(())
    }

    /// List entries matching the URL.
    ///
    /// For backends that support prefix filtering, the path component of
    /// the URL is used as a prefix: only entries whose name or path starts
    /// with the given prefix are returned. Backends that natively filter
    /// by prefix (SSM, Vault) are unchanged; backends that return a flat
    /// project/region scope (AWS SM, GCP SM, Azure KV) get client-side
    /// filtering applied automatically. Backends that do not support
    /// listing at all (`env://`, `file://`, `keyring://`, `op://`, `bw://`)
    /// return `UnsupportedOperation`.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn list(&self, url: &str) -> Result<Vec<Entry>, Error> {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let scheme = parsed_url.scheme().to_owned();
        self.audit(AuditEvent::start(Verb::List, scheme.clone()));
        let result = self.list_inner(&parsed_url);
        self.audit_done(Verb::List, &scheme, "ok", &result);
        result
    }

    fn list_inner(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        let scheme = url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        let mut entries = backend.list(url)?;

        let prefix = url.path().trim_start_matches('/').trim_end_matches('/');
        if !prefix.is_empty() {
            let prefix_with_slash = format!("{prefix}/");
            entries.retain(|e| {
                let entry_path = e.url.path().trim_start_matches('/').trim_end_matches('/');
                entry_path == prefix || entry_path.starts_with(&prefix_with_slash)
            });
        }

        Ok(entries)
    }

    /// Delete a secret by URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn delete(&self, url: &str) -> Result<(), Error> {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let scheme = parsed_url.scheme().to_owned();
        self.audit(AuditEvent::start(Verb::Delete, scheme.clone()));
        let result = self.delete_inner(&parsed_url, url);
        self.audit_done(Verb::Delete, &scheme, "ok", &result);
        result
    }

    fn delete_inner(&self, parsed_url: &Url, url: &str) -> Result<(), Error> {
        let scheme = parsed_url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.delete(parsed_url)?;

        if self.ttl.is_some() {
            if let Ok(mut cache) = self.cache.write() {
                cache.remove(url);
            }
        }

        Ok(())
    }

    /// Check whether a secret exists by URL.
    ///
    /// If the store was configured with a TTL and the URL has a fresh
    /// cached entry, this returns `true` without hitting the backend.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn exists(&self, url: &str) -> Result<bool, Error> {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let scheme = parsed_url.scheme().to_owned();
        self.audit(AuditEvent::start(Verb::Exists, scheme.clone()));
        let result = self.exists_inner(&parsed_url, url);
        let outcome = match &result {
            Ok(true) => "present",
            Ok(false) => "absent",
            Err(_) => "error",
        };
        let event = match &result {
            Ok(_) => AuditEvent::done(Verb::Exists, scheme.clone(), outcome),
            Err(e) => {
                AuditEvent::done(Verb::Exists, scheme.clone(), outcome).with_error_kind(e.kind())
            }
        };
        self.audit(event);
        result
    }

    fn exists_inner(&self, parsed_url: &Url, url: &str) -> Result<bool, Error> {
        let scheme = parsed_url.scheme();

        if let Some(ttl) = self.ttl {
            if let Ok(cache) = self.cache.read() {
                if let Some(entry) = cache.get(url) {
                    if entry.fetched_at.elapsed() <= ttl {
                        return Ok(true);
                    }
                }
            }
        }

        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.exists(parsed_url)
    }

    /// Fetch multiple secrets by URL, returning per-item results.
    ///
    /// Cache hits are deduplicated: identical URLs share the same
    /// backend call. Errors are collected per item; the method never
    /// short-circuits on the first failure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hasp::Store;
    ///
    /// let store = Store::with_defaults();
    /// let results = store.batch_get(&["env://HOME", "env://USER", "env://MISSING"]);
    /// ```
    pub fn batch_get(&self, urls: &[&str]) -> Vec<Result<SecretString, Error>> {
        let mut out = Vec::with_capacity(urls.len());
        // Deduplicate identical URLs to avoid redundant backend calls.
        let mut resolved: HashMap<String, Result<SecretString, Error>> = HashMap::new();

        for url in urls {
            if let Some(cached) = resolved.get(*url) {
                out.push(cached.clone());
                continue;
            }

            let result = self.get(url);
            resolved.insert(url.to_string(), result.clone());
            out.push(result);
        }

        out
    }

    /// Store multiple secrets by URL, returning per-item results.
    ///
    /// Each item is processed independently; errors are collected
    /// per item and successful puts invalidate the corresponding
    /// cache entry.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hasp::{Store, SecretString};
    ///
    /// let store = Store::with_defaults();
    /// let items: Vec<(&str, &SecretString)> = vec![];
    /// let results = store.bulk_put(&items);
    /// ```
    pub fn bulk_put(&self, items: &[(&str, &SecretString)]) -> Vec<Result<(), Error>> {
        // `put` already invalidates the cache entry on success.
        items
            .iter()
            .map(|(url, value)| self.put(url, value))
            .collect()
    }

    /// Copy a secret from one backend to another.
    ///
    /// `cp` is the only verb that reads *and* writes a secret in a
    /// single invocation, which widens the in-process exposure window
    /// relative to a back-to-back `get` + `put`. The implementation
    /// keeps the value in `SecretString` end-to-end and drops both the
    /// fetched and (optionally) verified copies as soon as the
    /// operation completes.
    ///
    /// # Behavior
    ///
    /// 1. Refuses when source and destination URLs are identical
    ///    (avoids version-counter inflation on backends that version
    ///    writes).
    /// 2. With `dry_run`, resolves both URLs and returns
    ///    `Ok(CopyOutcome { copied: false, .. })` without calling
    ///    `get` or `put`.
    /// 3. Honors `IfExists`: `Fail` returns `PreconditionFailed` when
    ///    the destination already has a value; `Skip` returns
    ///    `Ok(CopyOutcome { copied: false, .. })`; `Overwrite` writes
    ///    unconditionally.
    /// 4. With `verify`, re-reads the destination after the put and
    ///    constant-time compares it against the source value. A
    ///    mismatch yields `PreconditionFailed` with a generic message
    ///    (no byte-level diff).
    ///
    /// # Errors
    ///
    /// Propagates the backend's errors for `get` / `put` / `exists`.
    /// Returns `Error::UnsupportedOperation` when the destination
    /// backend does not implement `put`.
    pub fn copy(&self, src: &str, dst: &str, opts: CopyOptions) -> Result<CopyOutcome, Error> {
        let src_url = match Url::parse(src) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let dst_url = match Url::parse(dst) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let src_scheme = src_url.scheme().to_owned();
        let dst_scheme = dst_url.scheme().to_owned();
        self.audit(
            AuditEvent::start(Verb::Cp, src_scheme.clone()).with_dst_scheme(dst_scheme.clone()),
        );
        let result = self.copy_inner(&src_url, &dst_url, src, dst, &opts);
        let event = match &result {
            Ok(o) => {
                let outcome = if opts.dry_run {
                    "dry_run"
                } else if o.copied {
                    "copied"
                } else {
                    "skipped"
                };
                AuditEvent::done(Verb::Cp, src_scheme.clone(), outcome)
                    .with_dst_scheme(dst_scheme.clone())
            }
            Err(e) => AuditEvent::done(Verb::Cp, src_scheme.clone(), "error")
                .with_dst_scheme(dst_scheme.clone())
                .with_error_kind(e.kind()),
        };
        self.audit(event);
        result
    }

    fn copy_inner(
        &self,
        src_url: &Url,
        dst_url: &Url,
        src: &str,
        dst: &str,
        opts: &CopyOptions,
    ) -> Result<CopyOutcome, Error> {
        if src_url.as_str() == dst_url.as_str() {
            return Err(Error::InvalidUrl(
                "source and destination are identical".into(),
            ));
        }

        // Resolve both backends up front so dry-run can report the plan.
        let src_scheme = src_url.scheme();
        let dst_scheme = dst_url.scheme();
        let _src_backend = self
            .backends
            .get(src_scheme)
            .ok_or_else(|| Error::UnknownScheme(src_scheme.to_owned()))?;
        let _dst_backend = self
            .backends
            .get(dst_scheme)
            .ok_or_else(|| Error::UnknownScheme(dst_scheme.to_owned()))?;

        if opts.dry_run {
            return Ok(CopyOutcome {
                copied: false,
                verified: false,
            });
        }

        if !matches!(opts.if_exists, IfExists::Overwrite) {
            match self.exists(dst) {
                Ok(true) => match opts.if_exists {
                    IfExists::Fail => {
                        return Err(Error::PreconditionFailed(format!(
                            "destination {dst} already has a value; pass --force or \
                             --if-exists=overwrite to clobber, or --if-exists=skip to no-op"
                        )));
                    }
                    IfExists::Skip => {
                        return Ok(CopyOutcome {
                            copied: false,
                            verified: false,
                        });
                    }
                    IfExists::Overwrite => unreachable!(),
                },
                Ok(false) => {}
                // exists() not implemented on dst — proceed.
                // The subsequent put will still surface a real error
                // if it conflicts at the backend layer.
                Err(Error::UnsupportedOperation { .. }) => {}
                Err(e) => return Err(e),
            }
        }

        let secret = self.get(src)?;
        self.put(dst, &secret)?;

        let verified = if opts.verify {
            let readback = self.get(dst)?;
            let a = secret.expose_secret().as_bytes();
            let b = readback.expose_secret().as_bytes();
            use hasp_core::subtle::ConstantTimeEq;
            if a.len() != b.len() || a.ct_eq(b).unwrap_u8() == 0 {
                return Err(Error::PreconditionFailed(
                    "verify failed: source and destination differ after copy".into(),
                ));
            }
            true
        } else {
            false
        };

        Ok(CopyOutcome {
            copied: true,
            verified,
        })
    }

    /// Compare two secrets for byte-equality across (possibly different)
    /// backends.
    ///
    /// `diff` is the read-only sibling of `copy`: both URLs are
    /// fetched and compared. The returned [`DiffOutcome`] is binary —
    /// no byte counts, positions, common prefixes, or hashes are
    /// observable via the return value.
    ///
    /// # Behavior
    ///
    /// 1. Refuses when source and destination URLs are identical.
    /// 2. Both schemes must resolve to a registered backend — same
    ///    pre-flight check as `copy`, so an unknown scheme surfaces
    ///    before any I/O.
    /// 3. Equal-length secrets are compared via
    ///    [`hasp_core::subtle::ConstantTimeEq`] (the same path
    ///    `cp --verify` uses).
    /// 4. Both secrets stay inside `SecretString` end-to-end; they are
    ///    dropped (zeroized) as soon as `compare` returns.
    ///
    /// # Side-channel scope
    ///
    /// The **return value** discloses only the binary equality. An
    /// observer who can measure wall-clock latency of `compare` may
    /// still infer that the two secrets had different lengths (the
    /// length check short-circuits before `ct_eq`). For the threat
    /// model `diff` is built for — drift detection between known
    /// stores — this is the same posture as `cp --verify` and is
    /// accepted. Length-equal secrets that differ byte-wise are
    /// timing-flat to the extent `subtle::ConstantTimeEq` provides.
    ///
    /// # Errors
    ///
    /// Propagates the backend's errors for `get` on either side.
    /// Returns [`Error::InvalidUrl`] when the two URLs are identical
    /// (same as `copy`).
    pub fn compare(&self, a: &str, b: &str) -> Result<DiffOutcome, Error> {
        let a_url = match Url::parse(a) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let b_url = match Url::parse(b) {
            Ok(u) => u,
            Err(e) => return Err(Error::UrlParse(e)),
        };
        let a_scheme = a_url.scheme().to_owned();
        let b_scheme = b_url.scheme().to_owned();
        self.audit(
            AuditEvent::start(Verb::Diff, a_scheme.clone()).with_dst_scheme(b_scheme.clone()),
        );
        let result = self.compare_inner(&a_url, &b_url, a, b);
        let event = match &result {
            Ok(DiffOutcome::Match) => AuditEvent::done(Verb::Diff, a_scheme.clone(), "match")
                .with_dst_scheme(b_scheme.clone()),
            Ok(DiffOutcome::Differ) => AuditEvent::done(Verb::Diff, a_scheme.clone(), "differ")
                .with_dst_scheme(b_scheme.clone()),
            Err(e) => AuditEvent::done(Verb::Diff, a_scheme.clone(), "error")
                .with_dst_scheme(b_scheme.clone())
                .with_error_kind(e.kind()),
        };
        self.audit(event);
        result
    }

    fn compare_inner(
        &self,
        a_url: &Url,
        b_url: &Url,
        a: &str,
        b: &str,
    ) -> Result<DiffOutcome, Error> {
        if a_url.as_str() == b_url.as_str() {
            return Err(Error::InvalidUrl(
                "source and destination are identical".into(),
            ));
        }

        // Surface unknown schemes before any fetch — symmetrical with
        // `copy_inner` so the diff dry-run path stays honest.
        let a_scheme = a_url.scheme();
        let b_scheme = b_url.scheme();
        let _a_backend = self
            .backends
            .get(a_scheme)
            .ok_or_else(|| Error::UnknownScheme(a_scheme.to_owned()))?;
        let _b_backend = self
            .backends
            .get(b_scheme)
            .ok_or_else(|| Error::UnknownScheme(b_scheme.to_owned()))?;

        let secret_a = self.get(a)?;
        let secret_b = self.get(b)?;
        let bytes_a = secret_a.expose_secret().as_bytes();
        let bytes_b = secret_b.expose_secret().as_bytes();
        use hasp_core::subtle::ConstantTimeEq;
        // Length-mismatch implies inequality but is intentionally not
        // reported as a separate outcome — the boolean is the whole
        // observable, identical to the `cp --verify` posture.
        if bytes_a.len() == bytes_b.len() && bytes_a.ct_eq(bytes_b).unwrap_u8() == 1 {
            Ok(DiffOutcome::Match)
        } else {
            Ok(DiffOutcome::Differ)
        }
    }
}

/// Result of [`Store::compare`].
///
/// Binary by design — a mismatch must not reveal byte counts, common
/// prefixes, or any other length-derived signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOutcome {
    /// Both secrets compared byte-equal.
    Match,
    /// The secrets differed (length or content).
    Differ,
}

/// What to do when the destination of a `copy` already holds a value.
///
/// Default is `Fail`: secrets are valuable and silent clobbering is a
/// worse outcome than a non-zero exit demanding `--force`. This
/// deliberately departs from Unix `cp`'s overwrite-by-default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IfExists {
    /// Return `PreconditionFailed` when the destination is occupied.
    #[default]
    Fail,
    /// Write the source value over the destination unconditionally.
    Overwrite,
    /// Return `Ok(CopyOutcome { copied: false, .. })` and leave the
    /// destination untouched.
    Skip,
}

/// Options for [`Store::copy`].
#[derive(Debug, Clone, Default)]
pub struct CopyOptions {
    /// Disposition when the destination already holds a value.
    pub if_exists: IfExists,
    /// Resolve both URLs and return without reading or writing.
    pub dry_run: bool,
    /// Re-read the destination after writing and constant-time compare
    /// against the source value.
    pub verify: bool,
}

/// Outcome of a successful `copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyOutcome {
    /// True when a `put` actually executed against the destination.
    /// False for `dry_run` and for `IfExists::Skip` when the
    /// destination already had a value.
    pub copied: bool,
    /// True only when `opts.verify` was set and the readback matched.
    pub verified: bool,
}

use std::sync::OnceLock;

/// Lazily-initialized default `Store` shared across free-function calls.
static DEFAULT_STORE: OnceLock<Store> = OnceLock::new();

fn default_store() -> &'static Store {
    DEFAULT_STORE.get_or_init(Store::with_defaults)
}

/// Fetch a secret using a default `Store`.
pub fn get(url: &str) -> Result<SecretString, Error> {
    default_store().get(url)
}

/// Store a secret using a default `Store`.
pub fn put(url: &str, value: &SecretString) -> Result<(), Error> {
    default_store().put(url, value)
}

/// List entries using a default `Store`.
pub fn list(url: &str) -> Result<Vec<Entry>, Error> {
    default_store().list(url)
}

/// Delete a secret using a default `Store`.
pub fn delete(url: &str) -> Result<(), Error> {
    default_store().delete(url)
}

/// Check whether a secret exists using a default `Store`.
pub fn exists(url: &str) -> Result<bool, Error> {
    default_store().exists(url)
}
