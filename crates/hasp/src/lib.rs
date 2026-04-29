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
    scheme_from_url, Backend as BackendTrait, BackendFailureKind, CustomBackend, Entry, Error,
    ExposeSecret, ProxyConfig, SecretString,
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
use url::Url;

/// Dispatches to a concrete backend based on URL scheme.
///
/// Built-in variants are enabled by Cargo features. The `Custom` variant
/// allows runtime registration of foreign backends.
pub enum Backend {
    /// AWS Secrets Manager backend (`aws-sm://`).
    #[cfg(feature = "aws-sm")]
    AwsSm(AwsSmBackend),

    /// AWS SSM Parameter Store backend (`aws-ssm://`).
    #[cfg(feature = "aws-ssm")]
    AwsSsm(AwsSsmBackend),

    /// Environment-variable backend (`env://`).
    #[cfg(feature = "env")]
    Env(EnvBackend),

    /// File backend (`file://`).
    #[cfg(feature = "file")]
    File(FileBackend),

    /// OS keyring backend (`keyring://`).
    #[cfg(feature = "keyring")]
    Keyring(KeyringBackend),

    /// 1Password CLI backend (`op://`).
    #[cfg(feature = "op")]
    Op(OpBackend),

    /// HashiCorp Vault HTTP backend (`vault://`).
    #[cfg(feature = "vault")]
    Vault(VaultBackend),

    /// Bitwarden CLI backend (`bw://`).
    #[cfg(feature = "bw")]
    Bw(BwBackend),

    /// Google Cloud Secret Manager REST backend (`gcp-sm://`).
    #[cfg(feature = "gcp-sm")]
    GcpSm(GcpSmBackend),

    /// Azure Key Vault REST backend (`azure-kv://`).
    #[cfg(feature = "azure-kv")]
    AzureKv(AzureKvBackend),

    /// Dynamically-registered backend.
    Custom(Arc<dyn CustomBackend>),
}

/// Declaratively dispatches a method call to every built-in backend variant.
macro_rules! dispatch_backend {
    ($self:expr, $method:ident $(, $arg:expr)* $(,)?) => {
        match $self {
            #[cfg(feature = "aws-sm")]
            Backend::AwsSm(b) => b.$method($($arg),*),
            #[cfg(feature = "aws-ssm")]
            Backend::AwsSsm(b) => b.$method($($arg),*),
            #[cfg(feature = "env")]
            Backend::Env(b) => b.$method($($arg),*),
            #[cfg(feature = "file")]
            Backend::File(b) => b.$method($($arg),*),
            #[cfg(feature = "keyring")]
            Backend::Keyring(b) => b.$method($($arg),*),
            #[cfg(feature = "op")]
            Backend::Op(b) => b.$method($($arg),*),
            #[cfg(feature = "vault")]
            Backend::Vault(b) => b.$method($($arg),*),
            #[cfg(feature = "bw")]
            Backend::Bw(b) => b.$method($($arg),*),
            #[cfg(feature = "gcp-sm")]
            Backend::GcpSm(b) => b.$method($($arg),*),
            #[cfg(feature = "azure-kv")]
            Backend::AzureKv(b) => b.$method($($arg),*),
            Backend::Custom(b) => b.$method($($arg),*),
        }
    };
}

impl Backend {
    /// Returns the URL scheme handled by this backend instance.
    pub fn scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "aws-sm")]
            Backend::AwsSm(_) => "aws-sm",
            #[cfg(feature = "aws-ssm")]
            Backend::AwsSsm(_) => "aws-ssm",
            #[cfg(feature = "env")]
            Backend::Env(_) => "env",
            #[cfg(feature = "file")]
            Backend::File(_) => "file",
            #[cfg(feature = "keyring")]
            Backend::Keyring(_) => "keyring",
            #[cfg(feature = "op")]
            Backend::Op(_) => "op",
            #[cfg(feature = "vault")]
            Backend::Vault(_) => "vault",
            #[cfg(feature = "bw")]
            Backend::Bw(_) => "bw",
            #[cfg(feature = "gcp-sm")]
            Backend::GcpSm(_) => "gcp-sm",
            #[cfg(feature = "azure-kv")]
            Backend::AzureKv(_) => "azure-kv",
            Backend::Custom(b) => b.scheme(),
        }
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        dispatch_backend!(self, get, url)
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        dispatch_backend!(self, put, url, value)
    }

    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        dispatch_backend!(self, list, url)
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        dispatch_backend!(self, delete, url)
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        dispatch_backend!(self, exists, url)
    }
}

/// Fluent builder for a [`Store`] with optional proxy configuration.
///
/// Create a builder with `StoreBuilder::with_defaults()`, optionally
/// call `.proxy(Some(config))`, then finish with `.build()`.
pub struct StoreBuilder {
    proxy: Option<ProxyConfig>,
    defaults: bool,
    extra_backends: Vec<Backend>,
}

impl StoreBuilder {
    /// Create an empty builder.
    pub fn empty() -> Self {
        Self {
            proxy: None,
            defaults: false,
            extra_backends: Vec::new(),
        }
    }

    /// Create a builder pre-loaded with all default backends enabled by
    /// Cargo features.
    pub fn with_defaults() -> Self {
        Self {
            proxy: None,
            defaults: true,
            extra_backends: Vec::new(),
        }
    }

    /// Set the HTTP CONNECT proxy for backends that support it.
    pub fn proxy(mut self, proxy: Option<ProxyConfig>) -> Self {
        self.proxy = proxy;
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

        if self.defaults {
            #[cfg(feature = "aws-sm")]
            {
                store.register(Backend::AwsSm(AwsSmBackend::with_proxy(self.proxy.clone())));
            }
            #[cfg(feature = "aws-ssm")]
            {
                store.register(Backend::AwsSsm(AwsSsmBackend::with_proxy(
                    self.proxy.clone(),
                )));
            }
            #[cfg(feature = "env")]
            {
                store.register(Backend::Env(EnvBackend));
            }
            #[cfg(feature = "file")]
            {
                store.register(Backend::File(FileBackend));
            }
            #[cfg(feature = "keyring")]
            {
                store.register(Backend::Keyring(KeyringBackend::new()));
            }
            #[cfg(feature = "op")]
            {
                store.register(Backend::Op(OpBackend::new()));
            }
            #[cfg(feature = "vault")]
            {
                store.register(Backend::Vault(VaultBackend::with_proxy(self.proxy.clone())));
            }
            #[cfg(feature = "bw")]
            {
                store.register(Backend::Bw(BwBackend::new()));
            }
            #[cfg(feature = "gcp-sm")]
            {
                store.register(Backend::GcpSm(GcpSmBackend::with_proxy(self.proxy.clone())));
            }
            #[cfg(feature = "azure-kv")]
            {
                store.register(Backend::AzureKv(AzureKvBackend::with_proxy(
                    self.proxy.clone(),
                )));
            }
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

/// Batteries-included secret store.
pub struct Store {
    backends: HashMap<&'static str, Backend>,
}

impl Store {
    /// Create an empty store with no backends registered.
    pub fn empty() -> Self {
        Self {
            backends: HashMap::new(),
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

    /// Create a store with all default backends registered.
    ///
    /// Which backends are available depends on Cargo features:
    /// - `aws-sm`
    /// - `bw`
    /// - `env` (enabled by default)
    /// - `file`
    /// - `keyring`
    /// - `op`
    /// - `vault`
    pub fn with_defaults() -> Self {
        StoreBuilder::with_defaults().build()
    }

    /// Register an additional backend.
    ///
    /// If a backend for the same scheme already exists, it is replaced.
    pub fn register(&mut self, backend: Backend) {
        self.backends.insert(backend.scheme(), backend);
    }

    /// Fetch a secret by URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn get(&self, url: &str) -> Result<SecretString, Error> {
        let url = Url::parse(url)?;
        let scheme = url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.get(&url)
    }

    /// Store a secret by URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownScheme` if no backend handles the URL's scheme.
    pub fn put(&self, url: &str, value: &SecretString) -> Result<(), Error> {
        let url = Url::parse(url)?;
        let scheme = url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.put(&url, value)
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
        let url = Url::parse(url)?;
        let scheme = url.scheme();
        let backend = self
            .backends
            .get(scheme)
            .ok_or_else(|| Error::UnknownScheme(scheme.to_owned()))?;
        backend.delete(&url)
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
