//! Core contracts for the hasp secrets library.
//!
//! This crate defines the `Backend` trait, the error taxonomy,
//! and the `Entry` type shared by every backend implementation.
//! It intentionally has no profile, TTY, or config dependencies —
//! those live in `hasp-cli`.

pub mod error;
pub mod field;
pub mod hardening;
pub mod proxy;
pub mod retry;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use error::{BackendFailureKind, Error};
pub use field::{extract_field, extract_field_from_str};
pub use hardening::{
    apply_mitigations, check_refusal_conditions, harden_process, HardenRefusal, MitigationOutcome,
};
pub use proxy::{is_no_proxy, resolve_proxy_from_env, ProxyConfig};
pub use retry::RetryBackend;
pub use secrecy::{ExposeSecret, SecretString};
pub use subtle;

use url::Url;

/// Unified backend trait for secret stores.
///
/// Each backend owns its URL grammar and maps native errors into
/// `hasp_core::Error`. Secrets are wrapped in `SecretString` at the
/// earliest possible boundary — before returning from `get`.
///
/// Implementors must ensure that secret values never appear in
/// `Debug` output or error messages.
pub trait Backend: Send + Sync {
    /// Returns the URL scheme this backend handles (e.g., `"env"`).
    fn scheme(&self) -> &'static str;

    /// Fetch the secret at the given URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the secret does not exist.
    /// Returns `Error::Backend { kind: Transient, .. }` for retryable
    /// platform failures.
    fn get(&self, url: &Url) -> Result<SecretString, Error>;

    /// Store a secret at the given URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedOperation` if the backend is
    /// read-only (e.g., `env://`).
    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error>;

    /// List entries matching the URL prefix or pattern.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedOperation` if listing is not
    /// supported by the backend.
    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error>;

    /// Delete the secret at the given URL.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedOperation` if deletion is not
    /// supported by the backend.
    fn delete(&self, url: &Url) -> Result<(), Error>;

    /// Returns `true` if a secret exists at the given URL.
    fn exists(&self, url: &Url) -> Result<bool, Error>;

    /// Validate URL grammar without performing I/O.
    ///
    /// Backends override by delegating to their existing URL `TryFrom`.
    /// Used by `Store::resolve` so `--explain` rejects the same URLs
    /// `get` would — keeps the dry-run path honest about what an actual
    /// operation would do. Default impl is a no-op for backends that
    /// have no grammar to validate beyond the scheme.
    fn validate(&self, _url: &Url) -> Result<(), Error> {
        Ok(())
    }
}

/// A named entry returned by `Backend::list`.
///
/// `name` is the human-readable identifier; `url` is the canonical
/// address that can be passed back to `Store::get`.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub url: Url,
}

/// Extract the scheme prefix from a URL string.
///
/// Returns the substring before `://`, or an error if the separator
/// is absent. This is the only central URL knowledge in `hasp-core`;
/// all grammar validation lives in backend crates.
pub fn scheme_from_url(url: &str) -> Result<&str, Error> {
    url.split_once("://")
        .map(|(scheme, _)| scheme)
        .ok_or_else(|| Error::InvalidUrl("missing scheme separator".into()))
}
