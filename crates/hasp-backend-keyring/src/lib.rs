//! `keyring://` backend for hasp.
//!
//! Grammar: `keyring://service/account[?target=...]`
//!
//! - `service` (host): Required. Maps to the keyring service name.
//! - `account` (first path segment): Required. Maps to the keyring account name.
//! - `target` (query parameter, optional): Platform-specific modifier.
//!
//! Supported operations:
//! - `get`, `put`, `exists`, `delete`: full support
//! - `list`: `UnsupportedOperation`
//!
//! Platform-specific failure modes:
//! - **macOS**: Keychain ACL may reject access after binary re-sign or move.
//! - **Windows**: Credentials may roam across AD-joined machines.
//! - **Linux (Secret Service)**: Requires a DBus session bus; fails in
//!   headless containers without a secrets daemon.
//! - **Linux (Keyutils)**: Alternative to Secret Service; not enabled by default.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::OnceLock;
use url::Url;

/// URL shape for `keyring://` addresses.
///
/// Host = service, first path segment = account, optional `?target=...` query.
pub struct KeyringUrl {
    pub service: String,
    pub account: String,
    pub target: Option<String>,
}

impl TryFrom<&Url> for KeyringUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "keyring" {
            return Err(Error::InvalidUrl("expected keyring:// scheme".into()));
        }
        let service = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("keyring:// requires a host (service)".into()))?
            .to_owned();
        if service.is_empty() {
            return Err(Error::InvalidUrl(
                "keyring:// service must not be empty".into(),
            ));
        }

        let mut segments = url.path_segments().into_iter().flatten();
        let account = segments
            .next()
            .ok_or_else(|| Error::InvalidUrl("keyring:// requires an account path segment".into()))?
            .to_owned();
        if account.is_empty() {
            return Err(Error::InvalidUrl(
                "keyring:// account must not be empty".into(),
            ));
        }
        if segments.next().is_some() {
            return Err(Error::InvalidUrl(
                "keyring:// supports exactly one path segment (account)".into(),
            ));
        }

        let target = url
            .query_pairs()
            .find(|(k, _)| k == "target")
            .map(|(_, v)| v.into_owned());

        for (k, _) in url.query_pairs() {
            if k != "target" {
                return Err(Error::InvalidUrl(format!(
                    "keyring:// unknown query parameter: {}",
                    k
                )));
            }
        }

        Ok(KeyringUrl {
            service,
            account,
            target,
        })
    }
}

/// OS keyring backend.
///
/// Initialization is lazy and thread-safe. The first operation triggers
/// per-platform store selection via `keyring_core::set_default_store`. If a
/// default store has already been set (for example, by a test harness), the
/// backend will not replace it.
pub struct KeyringBackend;

impl KeyringBackend {
    /// Create a new keyring backend.
    ///
    /// The actual platform store initialization happens lazily on the first
    /// secret operation.
    pub fn new() -> Self {
        Self
    }
}

static INIT: OnceLock<Result<(), String>> = OnceLock::new();

fn ensure_init() -> Result<(), Error> {
    INIT.get_or_init(|| {
        // If a default store is already present (e.g., injected by tests),
        // do not replace it.
        if keyring_core::get_default_store().is_some() {
            return Ok(());
        }

        let result = create_platform_store();
        match result {
            Ok(store) => {
                keyring_core::set_default_store(store);
                Ok(())
            }
            Err(e) => Err(format!("keyring store initialization failed: {e}")),
        }
    })
    .clone()
    .map_err(|msg| Error::Backend {
        scheme: "keyring",
        kind: BackendFailureKind::Permanent,
        message: msg,
    })
}

#[cfg(target_os = "macos")]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    apple_native_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
}

#[cfg(target_os = "windows")]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    windows_native_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
}

#[cfg(target_os = "linux")]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    dbus_secret_service_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    Err(keyring_core::Error::NotSupportedByStore(
        "unsupported platform for keyring backend".into(),
    ))
}

fn map_keyring_error(err: keyring_core::Error, operation: &'static str) -> Error {
    use keyring_core::Error as K;
    match err {
        K::NoEntry => Error::NotFound("keyring entry not found".into()),
        K::NoStorageAccess(_) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: "keyring locked or unavailable".into(),
        },
        K::PlatformFailure(_) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Transient,
            message: format!("keyring platform failure: {err}"),
        },
        K::Ambiguous(_) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: "multiple keyring entries match".into(),
        },
        K::NotSupportedByStore(_) => Error::UnsupportedOperation {
            scheme: "keyring",
            operation,
        },
        K::TooLong(attr, limit) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: format!("keyring value too long: '{attr}' exceeds {limit}"),
        },
        K::BadDataFormat(_, underlying) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: format!("keyring data format error: {underlying}"),
        },
        K::BadEncoding(_) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: "keyring password is not valid UTF-8".into(),
        },
        K::BadStoreFormat(reason) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: format!("keyring store format error: {reason}"),
        },
        K::Invalid(attr, reason) => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: format!("keyring invalid '{attr}': {reason}"),
        },
        K::NoDefaultStore => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: "keyring default store not initialized".into(),
        },
        _ => Error::Backend {
            scheme: "keyring",
            kind: BackendFailureKind::Permanent,
            message: format!("keyring unexpected error: {err}"),
        },
    }
}

fn make_entry(url: &KeyringUrl) -> Result<keyring_core::Entry, Error> {
    if let Some(ref target) = url.target {
        let modifiers = HashMap::from([("target", target.as_str())]);
        keyring_core::Entry::new_with_modifiers(&url.service, &url.account, &modifiers)
            .map_err(|e| map_keyring_error(e, "get"))
    } else {
        keyring_core::Entry::new(&url.service, &url.account)
            .map_err(|e| map_keyring_error(e, "get"))
    }
}

impl Default for KeyringBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for KeyringBackend {
    fn scheme(&self) -> &'static str {
        "keyring"
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        ensure_init()?;
        let keyring_url = KeyringUrl::try_from(url)?;
        let entry = make_entry(&keyring_url)?;
        let password = entry
            .get_password()
            .map_err(|e| map_keyring_error(e, "get"))?;
        Ok(SecretString::new(password.into()))
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        ensure_init()?;
        let keyring_url = KeyringUrl::try_from(url)?;
        let entry = make_entry(&keyring_url)?;
        entry
            .set_password(value.expose_secret())
            .map_err(|e| map_keyring_error(e, "put"))?;
        Ok(())
    }

    fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
        Err(Error::UnsupportedOperation {
            scheme: "keyring",
            operation: "list",
        })
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        ensure_init()?;
        let keyring_url = KeyringUrl::try_from(url)?;
        let entry = make_entry(&keyring_url)?;
        entry
            .delete_credential()
            .map_err(|e| map_keyring_error(e, "delete"))?;
        Ok(())
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        ensure_init()?;
        let keyring_url = KeyringUrl::try_from(url)?;
        let entry = make_entry(&keyring_url)?;
        match entry.get_password() {
            Ok(_) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(e) => Err(map_keyring_error(e, "exists")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_url() {
        let url = Url::parse("keyring://my-app/db-pass").unwrap();
        let k = KeyringUrl::try_from(&url).unwrap();
        assert_eq!(k.service, "my-app");
        assert_eq!(k.account, "db-pass");
        assert!(k.target.is_none());
    }

    #[test]
    fn parse_url_with_target() {
        let url = Url::parse("keyring://my-app/db-pass?target=prod").unwrap();
        let k = KeyringUrl::try_from(&url).unwrap();
        assert_eq!(k.service, "my-app");
        assert_eq!(k.account, "db-pass");
        assert_eq!(k.target, Some("prod".into()));
    }

    #[test]
    fn parse_missing_service_fails() {
        let url = Url::parse("keyring:///account").unwrap();
        assert!(KeyringUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_missing_account_fails() {
        let url = Url::parse("keyring://service").unwrap();
        assert!(KeyringUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_extra_path_fails() {
        let url = Url::parse("keyring://service/account/extra").unwrap();
        assert!(KeyringUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_unknown_query_fails() {
        let url = Url::parse("keyring://service/account?unknown=val").unwrap();
        assert!(KeyringUrl::try_from(&url).is_err());
    }
}
