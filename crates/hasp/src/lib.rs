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
//! - `keyring://service/account` — OS keyring (feature `keyring`)
//! - `op://vault/item/field` — 1Password CLI (feature `op`)
//! - `vault://mount/path?field=key` — HashiCorp Vault (feature `vault`)
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
//! The library boundary type for secret values is [`secrecy::SecretString`].
//! Backends wrap raw bytes at the earliest possible moment so `Debug`
//! output never leaks secret values.

pub use hasp_core::{
    scheme_from_url, Backend as BackendTrait, BackendFailureKind, CustomBackend, Entry, Error,
    ExposeSecret, SecretString,
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

    /// Dynamically-registered backend.
    Custom(Arc<dyn CustomBackend>),
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
            Backend::Custom(b) => b.scheme(),
        }
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        match self {
            #[cfg(feature = "aws-sm")]
            Backend::AwsSm(b) => b.get(url),
            #[cfg(feature = "aws-ssm")]
            Backend::AwsSsm(b) => b.get(url),
            #[cfg(feature = "env")]
            Backend::Env(b) => b.get(url),
            #[cfg(feature = "file")]
            Backend::File(b) => b.get(url),
            #[cfg(feature = "keyring")]
            Backend::Keyring(b) => b.get(url),
            #[cfg(feature = "op")]
            Backend::Op(b) => b.get(url),
            #[cfg(feature = "vault")]
            Backend::Vault(b) => b.get(url),
            Backend::Custom(b) => b.get(url),
        }
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        match self {
            #[cfg(feature = "aws-sm")]
            Backend::AwsSm(b) => b.put(url, value),
            #[cfg(feature = "aws-ssm")]
            Backend::AwsSsm(b) => b.put(url, value),
            #[cfg(feature = "env")]
            Backend::Env(b) => b.put(url, value),
            #[cfg(feature = "file")]
            Backend::File(b) => b.put(url, value),
            #[cfg(feature = "keyring")]
            Backend::Keyring(b) => b.put(url, value),
            #[cfg(feature = "op")]
            Backend::Op(b) => b.put(url, value),
            #[cfg(feature = "vault")]
            Backend::Vault(b) => b.put(url, value),
            Backend::Custom(b) => b.put(url, value),
        }
    }

    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        match self {
            #[cfg(feature = "aws-sm")]
            Backend::AwsSm(b) => b.list(url),
            #[cfg(feature = "aws-ssm")]
            Backend::AwsSsm(b) => b.list(url),
            #[cfg(feature = "env")]
            Backend::Env(b) => b.list(url),
            #[cfg(feature = "file")]
            Backend::File(b) => b.list(url),
            #[cfg(feature = "keyring")]
            Backend::Keyring(b) => b.list(url),
            #[cfg(feature = "op")]
            Backend::Op(b) => b.list(url),
            #[cfg(feature = "vault")]
            Backend::Vault(b) => b.list(url),
            Backend::Custom(b) => b.list(url),
        }
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        match self {
            #[cfg(feature = "aws-sm")]
            Backend::AwsSm(b) => b.delete(url),
            #[cfg(feature = "aws-ssm")]
            Backend::AwsSsm(b) => b.delete(url),
            #[cfg(feature = "env")]
            Backend::Env(b) => b.delete(url),
            #[cfg(feature = "file")]
            Backend::File(b) => b.delete(url),
            #[cfg(feature = "keyring")]
            Backend::Keyring(b) => b.delete(url),
            #[cfg(feature = "op")]
            Backend::Op(b) => b.delete(url),
            #[cfg(feature = "vault")]
            Backend::Vault(b) => b.delete(url),
            Backend::Custom(b) => b.delete(url),
        }
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        match self {
            #[cfg(feature = "aws-sm")]
            Backend::AwsSm(b) => b.exists(url),
            #[cfg(feature = "aws-ssm")]
            Backend::AwsSsm(b) => b.exists(url),
            #[cfg(feature = "env")]
            Backend::Env(b) => b.exists(url),
            #[cfg(feature = "file")]
            Backend::File(b) => b.exists(url),
            #[cfg(feature = "keyring")]
            Backend::Keyring(b) => b.exists(url),
            #[cfg(feature = "op")]
            Backend::Op(b) => b.exists(url),
            #[cfg(feature = "vault")]
            Backend::Vault(b) => b.exists(url),
            Backend::Custom(b) => b.exists(url),
        }
    }
}

/// Batteries-included secret store.
///
/// Construct with `Store::with_defaults()` to register all backends
/// enabled by Cargo features, or build an empty store and add backends
/// manually with `register`.
pub struct Store {
    backends: HashMap<&'static str, Backend>,
}

impl Store {
    /// Create a store with all default backends registered.
    ///
    /// Which backends are available depends on Cargo features:
    /// - `aws-sm`
    /// - `env` (enabled by default)
    /// - `file`
    /// - `keyring`
    /// - `op`
    /// - `vault`
    pub fn with_defaults() -> Self {
        let mut backends = HashMap::new();
        #[cfg(feature = "aws-sm")]
        {
            backends.insert("aws-sm", Backend::AwsSm(AwsSmBackend::new()));
        }
        #[cfg(feature = "aws-ssm")]
        {
            backends.insert("aws-ssm", Backend::AwsSsm(AwsSsmBackend::new()));
        }
        #[cfg(feature = "env")]
        {
            backends.insert("env", Backend::Env(EnvBackend));
        }
        #[cfg(feature = "file")]
        {
            backends.insert("file", Backend::File(FileBackend));
        }
        #[cfg(feature = "keyring")]
        {
            backends.insert("keyring", Backend::Keyring(KeyringBackend::new()));
        }
        #[cfg(feature = "op")]
        {
            backends.insert("op", Backend::Op(OpBackend::new()));
        }
        #[cfg(feature = "vault")]
        {
            backends.insert("vault", Backend::Vault(VaultBackend::new()));
        }
        Self { backends }
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
        backend.list(&url)
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
