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

pub use hasp_core::{
    scheme_from_url, Backend as BackendTrait, BackendFailureKind, Entry, Error, ExposeSecret,
    ProxyConfig, SecretString,
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

/// Opaque handle to a backend instance.
///
/// All backends implement `hasp_core::Backend`. This wrapper provides
/// cheap cloning (`Arc`) and dynamic dispatch so `Store` can hold
/// heterogeneous backends in a single map.
pub struct Backend(Arc<dyn hasp_core::Backend>);

impl Backend {
    /// Wrap any type implementing `hasp_core::Backend`.
    pub fn new<T>(inner: T) -> Self
    where
        T: hasp_core::Backend + 'static,
    {
        Self(Arc::new(inner))
    }

    #[cfg(feature = "aws-sm")]
    pub fn aws_sm() -> Self {
        Self::new(AwsSmBackend::new())
    }

    #[cfg(feature = "aws-ssm")]
    pub fn aws_ssm() -> Self {
        Self::new(AwsSsmBackend::new())
    }

    #[cfg(feature = "env")]
    pub fn env() -> Self {
        Self::new(EnvBackend)
    }

    #[cfg(feature = "file")]
    pub fn file() -> Self {
        Self::new(FileBackend)
    }

    #[cfg(feature = "keyring")]
    pub fn keyring() -> Self {
        Self::new(KeyringBackend::new())
    }

    #[cfg(feature = "op")]
    pub fn op() -> Self {
        Self::new(OpBackend::new())
    }

    #[cfg(feature = "vault")]
    pub fn vault() -> Self {
        Self::new(VaultBackend::new())
    }

    #[cfg(feature = "bw")]
    pub fn bw() -> Self {
        Self::new(BwBackend::new())
    }

    #[cfg(feature = "gcp-sm")]
    pub fn gcp_sm() -> Self {
        Self::new(GcpSmBackend::new())
    }

    #[cfg(feature = "azure-kv")]
    pub fn azure_kv() -> Self {
        Self::new(AzureKvBackend::new())
    }

    /// Wrap an externally-provided backend.
    pub fn custom(inner: Arc<dyn hasp_core::Backend>) -> Self {
        Self(inner)
    }
}

impl hasp_core::Backend for Backend {
    fn scheme(&self) -> &'static str {
        self.0.scheme()
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        self.0.get(url)
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        self.0.put(url, value)
    }

    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        self.0.list(url)
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        self.0.delete(url)
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        self.0.exists(url)
    }
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
}

impl StoreBuilder {
    /// Create an empty builder.
    pub fn empty() -> Self {
        Self {
            proxy: None,
            defaults: false,
            extra_backends: Vec::new(),
            ttl: None,
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

    /// Build the final [`Store`].
    pub fn build(self) -> Store {
        let mut store = Store::empty();
        store.ttl = self.ttl;

        if self.defaults {
            #[cfg(feature = "aws-sm")]
            store.register(Backend::new(AwsSmBackend::with_proxy(self.proxy.clone())));
            #[cfg(feature = "aws-ssm")]
            store.register(Backend::new(AwsSsmBackend::with_proxy(self.proxy.clone())));
            #[cfg(feature = "env")]
            store.register(Backend::env());
            #[cfg(feature = "file")]
            store.register(Backend::file());
            #[cfg(feature = "keyring")]
            store.register(Backend::keyring());
            #[cfg(feature = "op")]
            store.register(Backend::op());
            #[cfg(feature = "vault")]
            store.register(Backend::new(VaultBackend::with_proxy(self.proxy.clone())));
            #[cfg(feature = "bw")]
            store.register(Backend::bw());
            #[cfg(feature = "gcp-sm")]
            store.register(Backend::new(GcpSmBackend::with_proxy(self.proxy.clone())));
            #[cfg(feature = "azure-kv")]
            store.register(Backend::new(AzureKvBackend::with_proxy(self.proxy.clone())));
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

struct CacheEntry {
    secret: SecretString,
    fetched_at: Instant,
}

/// Batteries-included secret store.
pub struct Store {
    backends: HashMap<&'static str, Backend>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    ttl: Option<Duration>,
}

impl Store {
    /// Create an empty store with no backends registered.
    pub fn empty() -> Self {
        Self {
            backends: HashMap::new(),
            cache: RwLock::new(HashMap::new()),
            ttl: None,
        }
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
        let parsed_url = Url::parse(url)?;
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

        let secret = backend.get(&parsed_url)?;

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

    /// Store a secret by URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn put(&self, url: &str, value: &SecretString) -> Result<(), Error> {
        let parsed_url = Url::parse(url)?;
        let scheme = parsed_url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.put(&parsed_url, value)?;

        if self.ttl.is_some() {
            if let Ok(mut cache) = self.cache.write() {
                cache.remove(url);
            }
        }

        Ok(())
    }

    /// List entries matching the URL.
    ///
    /// For backends that support prefix filtering (all backends), the
    /// path component of the URL is used as a prefix: only entries whose
    /// name or path starts with the given prefix are returned. Backends
    /// that natively filter by prefix (SSM, Vault) are unchanged; backends
    /// that return a flat project/region scope (AWS SM, GCP SM, Azure KV)
    /// get client-side filtering applied automatically.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn list(&self, url: &str) -> Result<Vec<Entry>, Error> {
        let url = Url::parse(url)?;
        let scheme = url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        let mut entries = backend.list(&url)?;

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
        let parsed_url = Url::parse(url)?;
        let scheme = parsed_url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.delete(&parsed_url)?;

        if self.ttl.is_some() {
            if let Ok(mut cache) = self.cache.write() {
                cache.remove(url);
            }
        }

        Ok(())
    }

    /// Check whether a secret exists by URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn exists(&self, url: &str) -> Result<bool, Error> {
        let url = Url::parse(url)?;
        let scheme = url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.exists(&url)
    }
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
