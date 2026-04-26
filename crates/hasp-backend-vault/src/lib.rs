//! `vault://` backend for hasp.
//!
//! Grammar: `vault://<mount>/<path>?field=<key>`
//!   - `<mount>`  — Vault secrets engine mount point (host component).
//!   - `<path>`   — secret path within the mount, including KV-v2 `data/`
//!     prefix when applicable.
//!   - `?field=`  — optional key to extract from the JSON `data.data`
//!     object. When absent, the entire object is serialized.
//!
//! Supported operations: `get`, `exists`.
//! `put`, `list`, `delete`: `UnsupportedOperation`.
//!
//! Authentication is ambient only: `VAULT_ADDR` and `VAULT_TOKEN`.
//! If either is missing, every operation fails fast with
//! `AuthenticationFailed` before any network request, preventing
//! indefinite connection attempts against an undefined endpoint.
//!
//! Vault's HTTP API intentionally collapses 403 and 404 to prevent
//! existence oracles. This backend follows that choice: both map to
//! `NotFound` on `get` and to `false` on `exists`.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, SecretString};
use std::time::Duration;
use url::Url;

/// URL shape for `vault://` addresses.
///
/// `mount`, `path`, and `field` are identifiers, not secret values.
/// They may appear in error messages (redacted per URL discipline).
#[derive(Debug)]
pub struct VaultUrl {
    pub mount: String,
    pub path: String,
    pub field: Option<String>,
}

impl TryFrom<&Url> for VaultUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "vault" {
            return Err(Error::InvalidUrl("expected vault:// scheme".into()));
        }

        let mount = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("vault:// requires a mount point (host)".into()))?
            .to_owned();
        if mount.is_empty() {
            return Err(Error::InvalidUrl("vault:// mount must not be empty".into()));
        }

        let path = url.path().to_owned();

        let mut field = None;
        for (k, v) in url.query_pairs() {
            if k == "field" {
                field = Some(v.into_owned());
            } else {
                return Err(Error::InvalidUrl(format!(
                    "vault:// unknown query parameter: {k}"
                )));
            }
        }

        Ok(VaultUrl { mount, path, field })
    }
}

/// HTTP backend for HashiCorp Vault.
///
/// Construction is a no-op; errors surface on first use. Every request
/// builds a fresh `reqwest::blocking::Client` so the backend remains
/// a zero-sized type.
#[derive(Debug)]
pub struct VaultBackend;

impl VaultBackend {
    /// Create a new `VaultBackend`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for VaultBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for VaultBackend {
    fn scheme(&self) -> &'static str {
        "vault"
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        check_ambient_credentials()?;
        let vault_url = VaultUrl::try_from(url)?;
        let (token, addr) = ambient_credentials()?;
        let request_url = build_request_url(&addr, &vault_url.mount, &vault_url.path);

        let client = build_client()?;
        let response = client
            .get(&request_url)
            .header("X-Vault-Token", token)
            .send()
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(map_vault_status(status, url));
        }

        let body: serde_json::Value = response.json().map_err(|e| Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Permanent,
            message: format!("invalid JSON from Vault: {e}"),
        })?;

        extract_secret(&body, vault_url.field.as_deref())
    }

    fn put(&self, _url: &Url, _value: &SecretString) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "vault",
            operation: "put",
        })
    }

    fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
        Err(Error::UnsupportedOperation {
            scheme: "vault",
            operation: "list",
        })
    }

    fn delete(&self, _url: &Url) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "vault",
            operation: "delete",
        })
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        check_ambient_credentials()?;
        let vault_url = VaultUrl::try_from(url)?;
        let (token, addr) = ambient_credentials()?;
        let request_url = build_request_url(&addr, &vault_url.mount, &vault_url.path);

        let client = build_client()?;
        let response = client
            .get(&request_url)
            .header("X-Vault-Token", token)
            .send()
            .map_err(map_reqwest_error)?;

        match response.status() {
            reqwest::StatusCode::OK => Ok(true),
            reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND => Ok(false),
            status => Err(map_vault_status(status, url)),
        }
    }
}

/// Build a `reqwest::blocking::Client` with a 10-second timeout.
///
/// The timeout prevents indefinite hangs when Vault is unreachable.
fn build_client() -> Result<reqwest::blocking::Client, Error> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Permanent,
            message: format!("failed to build HTTP client: {e}"),
        })
}

/// Return the ambient Vault address and token.
///
/// Fails with `AuthenticationFailed` if either variable is missing.
fn ambient_credentials() -> Result<(String, String), Error> {
    let token = std::env::var("VAULT_TOKEN").map_err(|_| {
        Error::AuthenticationFailed("no ambient Vault credentials; set VAULT_TOKEN".into())
    })?;
    let addr = std::env::var("VAULT_ADDR").map_err(|_| {
        Error::AuthenticationFailed("no ambient Vault address; set VAULT_ADDR".into())
    })?;
    Ok((token, addr))
}

/// Fail fast if no ambient Vault credentials are present.
fn check_ambient_credentials() -> Result<(), Error> {
    ambient_credentials().map(|_| ())
}

/// Construct the full Vault API URL.
///
/// Trims trailing slashes from `addr` and appends `/v1/<mount><path>`.
fn build_request_url(addr: &str, mount: &str, path: &str) -> String {
    format!("{}/v1/{}{path}", addr.trim_end_matches('/'), mount)
}

/// Map `reqwest` network errors into the locked `hasp_core::Error` taxonomy.
///
/// Timeouts and connection failures are `Transient`; everything else is
/// `Permanent`.
fn map_reqwest_error(err: reqwest::Error) -> Error {
    if err.is_timeout() || err.is_connect() {
        Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Transient,
            message: format!("Vault request failed: {err}"),
        }
    } else {
        Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Permanent,
            message: format!("Vault request failed: {err}"),
        }
    }
}

/// Map Vault HTTP status codes into the locked `hasp_core::Error` taxonomy.
///
/// 403 and 404 both map to `NotFound` per Vault's intentional
/// collapse of permission-denied and not-found.
fn map_vault_status(status: reqwest::StatusCode, url: &Url) -> Error {
    match status {
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND => {
            Error::NotFound(url.to_string())
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Throttled,
            message: format!("Vault returned HTTP {status}"),
        },
        status if status.is_server_error() => Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Transient,
            message: format!("Vault returned HTTP {status}"),
        },
        status => Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Permanent,
            message: format!("Vault returned HTTP {status}"),
        },
    }
}

/// Extract the secret value from a Vault KV read response.
///
/// Locates `data.data` then either extracts the named `field` or serializes
/// the entire object. Secret values are wrapped in `SecretString` at this
/// boundary.
fn extract_secret(body: &serde_json::Value, field: Option<&str>) -> Result<SecretString, Error> {
    let data = body
        .get("data")
        .and_then(|d| d.get("data"))
        .ok_or_else(|| Error::Backend {
            scheme: "vault",
            kind: BackendFailureKind::Permanent,
            message: "Vault response missing data.data field".into(),
        })?;

    let value = match field {
        Some(f) => data
            .get(f)
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::NotFound(format!("field '{f}' not found in secret")))?
            .to_owned(),
        None => data.to_string(),
    };

    Ok(SecretString::new(value.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hasp_core::ExposeSecret;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: String,
        old: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let old = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.into(),
                old,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    #[test]
    fn parse_valid_url_with_field() {
        let url = Url::parse("vault://secret/data/myapp/config?field=password").unwrap();
        let v = VaultUrl::try_from(&url).unwrap();
        assert_eq!(v.mount, "secret");
        assert_eq!(v.path, "/data/myapp/config");
        assert_eq!(v.field, Some("password".into()));
    }

    #[test]
    fn parse_valid_url_without_field() {
        let url = Url::parse("vault://kv/data/prod/db").unwrap();
        let v = VaultUrl::try_from(&url).unwrap();
        assert_eq!(v.mount, "kv");
        assert_eq!(v.path, "/data/prod/db");
        assert_eq!(v.field, None);
    }

    #[test]
    fn parse_valid_url_root_path() {
        let url = Url::parse("vault://secret/").unwrap();
        let v = VaultUrl::try_from(&url).unwrap();
        assert_eq!(v.mount, "secret");
        assert_eq!(v.path, "/");
        assert_eq!(v.field, None);
    }

    #[test]
    fn parse_missing_host_fails() {
        let url = Url::parse("vault:///data/myapp/config").unwrap();
        assert!(VaultUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_empty_mount_fails() {
        let url = Url::parse("vault:///").unwrap();
        assert!(VaultUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_unknown_query_fails() {
        let url = Url::parse("vault://secret/data/app?raw=true").unwrap();
        assert!(VaultUrl::try_from(&url).is_err());
    }

    #[test]
    fn error_map_403_to_not_found() {
        let url = Url::parse("vault://secret/data/myapp/config").unwrap();
        let err = map_vault_status(reqwest::StatusCode::FORBIDDEN, &url);
        assert!(matches!(err, Error::NotFound(ref s) if s == "vault://secret/data/myapp/config"));
    }

    #[test]
    fn error_map_404_to_not_found() {
        let url = Url::parse("vault://secret/data/myapp/config").unwrap();
        let err = map_vault_status(reqwest::StatusCode::NOT_FOUND, &url);
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn error_map_429_to_throttled() {
        let url = Url::parse("vault://secret/data/myapp/config").unwrap();
        let err = map_vault_status(reqwest::StatusCode::TOO_MANY_REQUESTS, &url);
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Throttled,
                ..
            }
        ));
    }

    #[test]
    fn error_map_500_to_transient() {
        let url = Url::parse("vault://secret/data/myapp/config").unwrap();
        let err = map_vault_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR, &url);
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Transient,
                ..
            }
        ));
    }

    #[test]
    fn error_map_418_to_permanent() {
        let url = Url::parse("vault://secret/data/myapp/config").unwrap();
        let err = map_vault_status(reqwest::StatusCode::IM_A_TEAPOT, &url);
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Permanent,
                ..
            }
        ));
    }

    #[test]
    fn extract_field_found() {
        let body = serde_json::json!({
            "data": {
                "data": {
                    "password": "secret123"
                }
            }
        });
        let secret = extract_secret(&body, Some("password")).unwrap();
        assert_eq!(secret.expose_secret(), "secret123");
    }

    #[test]
    fn extract_field_missing() {
        let body = serde_json::json!({
            "data": {
                "data": {
                    "password": "secret123"
                }
            }
        });
        let err = extract_secret(&body, Some("missing")).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn extract_no_field_returns_json() {
        let body = serde_json::json!({
            "data": {
                "data": {
                    "password": "secret123"
                }
            }
        });
        let secret = extract_secret(&body, None).unwrap();
        assert_eq!(secret.expose_secret(), r#"{"password":"secret123"}"#);
    }

    #[test]
    fn extract_missing_data_data() {
        let body = serde_json::json!({ "data": {} });
        let err = extract_secret(&body, Some("password")).unwrap_err();
        assert!(matches!(err, Error::Backend { .. }));
    }

    #[test]
    fn preflight_auth_no_token_fails_fast() {
        let _lock = ENV_LOCK.lock().unwrap();

        let old_token = std::env::var("VAULT_TOKEN").ok();
        let old_addr = std::env::var("VAULT_ADDR").ok();
        std::env::remove_var("VAULT_TOKEN");
        std::env::remove_var("VAULT_ADDR");

        let result = check_ambient_credentials();

        match old_token {
            Some(v) => std::env::set_var("VAULT_TOKEN", v),
            None => std::env::remove_var("VAULT_TOKEN"),
        }
        match old_addr {
            Some(v) => std::env::set_var("VAULT_ADDR", v),
            None => std::env::remove_var("VAULT_ADDR"),
        }

        assert!(
            matches!(result, Err(Error::AuthenticationFailed(_))),
            "expected AuthenticationFailed when no ambient credentials are present"
        );
    }

    #[test]
    fn preflight_auth_token_no_addr_fails_fast() {
        let _lock = ENV_LOCK.lock().unwrap();

        let old_token = std::env::var("VAULT_TOKEN").ok();
        let old_addr = std::env::var("VAULT_ADDR").ok();
        std::env::remove_var("VAULT_TOKEN");
        std::env::remove_var("VAULT_ADDR");

        let _guard = EnvGuard::set("VAULT_TOKEN", "test-token");
        let result = check_ambient_credentials();

        match old_token {
            Some(v) => std::env::set_var("VAULT_TOKEN", v),
            None => std::env::remove_var("VAULT_TOKEN"),
        }
        match old_addr {
            Some(v) => std::env::set_var("VAULT_ADDR", v),
            None => std::env::remove_var("VAULT_ADDR"),
        }

        assert!(
            matches!(result, Err(Error::AuthenticationFailed(_))),
            "expected AuthenticationFailed when VAULT_ADDR is missing"
        );
    }

    #[test]
    fn preflight_auth_both_present_ok() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _token_guard = EnvGuard::set("VAULT_TOKEN", "test-token");
        let _addr_guard = EnvGuard::set("VAULT_ADDR", "http://localhost:8200");
        assert!(check_ambient_credentials().is_ok());
    }
}
