//! `env://` backend for hasp.
//!
//! Grammar: `env://VAR_NAME` where the host component is the
//! environment variable name.
//!
//! Supported operations:
//! - `get`: reads `std::env::var(var_name)`
//! - `exists`: checks `std::env::var(var_name).is_ok()`
//! - `put`, `list`, `delete`: `UnsupportedOperation`
//!
//! Platform-specific failure modes:
//! - None (stdlib only). `NotFound` is returned when the variable is unset.

use hasp_core::{Backend, Entry, Error, SecretString};
use url::Url;

/// URL shape for `env://` addresses.
///
/// Host = variable name. No path, no query, no fragment.
pub struct EnvUrl {
    pub var_name: String,
}

impl TryFrom<&Url> for EnvUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "env" {
            return Err(Error::InvalidUrl("expected env:// scheme".into()));
        }
        let var_name = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("env:// requires a host (variable name)".into()))?
            .to_owned();
        if var_name.is_empty() {
            return Err(Error::InvalidUrl(
                "env:// variable name must not be empty".into(),
            ));
        }
        if url.path() != "/" && !url.path().is_empty() {
            return Err(Error::InvalidUrl("env:// does not accept a path".into()));
        }
        if url.query().is_some() {
            return Err(Error::InvalidUrl(
                "env:// does not accept query parameters".into(),
            ));
        }
        Ok(EnvUrl { var_name })
    }
}

/// Stdlib-only backend that reads secrets from environment variables.
///
/// `put` returns `UnsupportedOperation` because a child process cannot
/// set environment variables in its parent.
pub struct EnvBackend;

impl Backend for EnvBackend {
    fn scheme(&self) -> &'static str {
        "env"
    }

    fn validate(&self, url: &Url) -> Result<(), Error> {
        EnvUrl::try_from(url).map(|_| ())
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        let env_url = EnvUrl::try_from(url)?;
        match std::env::var(&env_url.var_name) {
            Ok(value) => Ok(SecretString::new(value.into())),
            Err(std::env::VarError::NotPresent) => Err(Error::NotFound(format!(
                "env var '{}' not set",
                env_url.var_name
            ))),
            Err(std::env::VarError::NotUnicode(_)) => Err(Error::Backend {
                scheme: "env",
                kind: hasp_core::BackendFailureKind::Permanent,
                message: format!("env var '{}' is not valid Unicode", env_url.var_name),
            }),
        }
    }

    fn put(&self, _url: &Url, _value: &SecretString) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "env",
            operation: "put",
        })
    }

    fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
        Err(Error::UnsupportedOperation {
            scheme: "env",
            operation: "list",
        })
    }

    fn delete(&self, _url: &Url) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "env",
            operation: "delete",
        })
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        let env_url = EnvUrl::try_from(url)?;
        Ok(std::env::var(&env_url.var_name).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_url() {
        let url = Url::parse("env://HOME").unwrap();
        let env_url = EnvUrl::try_from(&url).unwrap();
        assert_eq!(env_url.var_name, "HOME");
    }

    #[test]
    fn parse_missing_host_fails() {
        let url = Url::parse("env:///").unwrap();
        assert!(EnvUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_path_fails() {
        let url = Url::parse("env://HOME/extra").unwrap();
        assert!(EnvUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_query_fails() {
        let url = Url::parse("env://HOME?foo=bar").unwrap();
        assert!(EnvUrl::try_from(&url).is_err());
    }
}
