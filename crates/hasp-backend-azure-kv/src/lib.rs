//! `azure-kv://` backend for hasp.
//!
//! Grammar: `azure-kv://<vault-name>/<secret-name>?version=<version>`
//!   - `<vault-name>`  — Azure Key Vault name (host). Must be non-empty.
//!   - `<secret-name>` — Path segment after the host. Must be non-empty.
//!   - `?version`      — Optional version string. Defaults to latest (empty).
//!
//! Supported operations: `get`, `exists`.
//! `put`, `list`, `delete`: `UnsupportedOperation`.
//!
//! Authentication is ambient only. `azure_identity::create_credential`
//! resolves the standard Azure credential chain (service principal env vars,
//! managed identity, Azure CLI) transparently. No auth-bootstrap flows or
//! token refresh logic lives in this crate.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, SecretString};
use serde::Deserialize;
use std::time::Duration;
use url::Url;

/// URL shape for `azure-kv://` addresses.
///
/// `vault_name` and `secret_name` are identifiers, not secret values.
/// They may appear in error messages (redacted per URL discipline).
#[derive(Debug)]
pub struct AzureKvUrl {
    pub vault_name: String,
    pub secret_name: String,
    pub version: Option<String>,
}

impl TryFrom<&Url> for AzureKvUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "azure-kv" {
            return Err(Error::InvalidUrl("expected azure-kv:// scheme".into()));
        }

        let vault_name = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("azure-kv:// requires a vault name (host)".into()))?
            .to_owned();
        if vault_name.is_empty() {
            return Err(Error::InvalidUrl(
                "azure-kv:// vault name must not be empty".into(),
            ));
        }

        let secret_name = url.path().trim_start_matches('/').to_owned();
        if secret_name.is_empty() {
            return Err(Error::InvalidUrl(
                "azure-kv:// secret name must not be empty".into(),
            ));
        }

        let mut version = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "version" => version = Some(v.into_owned()),
                _ => {
                    return Err(Error::InvalidUrl(format!(
                        "azure-kv:// unknown query parameter: {k}"
                    )));
                }
            }
        }

        Ok(AzureKvUrl {
            vault_name,
            secret_name,
            version,
        })
    }
}

/// Azure Key Vault REST backend.
///
/// Construction attempts to build a Tokio runtime inside a `Result` so the
/// async Azure credential flow can be used from the sync `Backend` trait.
/// The runtime is `current_thread` to keep the backend lightweight. If
/// runtime creation fails, the error is stored and replayed on first use.
pub struct AzureKvBackend {
    init: Result<tokio::runtime::Runtime, Error>,
}

impl std::fmt::Debug for AzureKvBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKvBackend")
            .field("init", &self.init.is_ok())
            .finish()
    }
}

impl AzureKvBackend {
    const SCHEME: &'static str = "azure-kv";
    const API_VERSION: &'static str = "7.5";
    const TOKEN_SCOPE: &'static str = "https://vault.azure.net/.default";

    /// Create a new `AzureKvBackend`.
    ///
    /// Errors on construction are deferred to first use so
    /// `Store::with_defaults()` never panics.
    pub fn new() -> Self {
        Self {
            init: tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| Error::Backend {
                    scheme: Self::SCHEME,
                    kind: BackendFailureKind::Permanent,
                    message: format!("failed to create tokio runtime: {e}"),
                }),
        }
    }

    fn runtime(&self) -> Result<&tokio::runtime::Runtime, Error> {
        self.init.as_ref().map_err(|e| e.clone())
    }

    fn block_on<F>(&self, future: F) -> Result<F::Output, Error>
    where
        F: std::future::Future,
    {
        let rt = self.runtime()?;
        Ok(rt.block_on(future))
    }

    /// Obtain a fresh access token via the Azure identity credential chain.
    fn token(&self) -> Result<String, Error> {
        self.block_on(async {
            let credential = azure_identity::create_credential().map_err(|e| {
                let msg = e.to_string();
                if msg.to_lowercase().contains("credential") {
                    Error::AuthenticationFailed(format!(
                        "no ambient Azure credentials; set AZURE_CLIENT_ID/SECRET/TENANT_ID or log in with Azure CLI: {msg}"
                    ))
                } else {
                    Error::Backend {
                        scheme: Self::SCHEME,
                        kind: BackendFailureKind::Permanent,
                        message: format!("failed to discover Azure credentials: {msg}"),
                    }
                }
            })?;

            let access_token = credential
                .get_token(&[Self::TOKEN_SCOPE])
                .await
                .map_err(|e| Error::AuthenticationFailed(format!(
                    "failed to acquire Azure access token: {e}"
                )))?;

            let bearer = access_token.token.secret().to_string();
            Ok(bearer)
        })?
    }

    /// Build a `reqwest::blocking::Client` ready for Azure.
    fn client(&self) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client construction is infallible with default features")
    }

    /// Build the Azure Key Vault REST URL.
    fn build_url(&self, url: &AzureKvUrl) -> String {
        let version_path = match &url.version {
            Some(v) if !v.is_empty() => format!("/{v}"),
            _ => String::new(),
        };
        format!(
            "https://{}.vault.azure.net/secrets/{}{version_path}?api-version={}",
            url.vault_name,
            url.secret_name,
            Self::API_VERSION,
        )
    }
}

impl Default for AzureKvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for AzureKvBackend {
    fn scheme(&self) -> &'static str {
        Self::SCHEME
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        let kv_url = AzureKvUrl::try_from(url)?;
        let token = self.token()?;
        let request_url = self.build_url(&kv_url);

        let client = self.client();
        let response = client
            .get(&request_url)
            .bearer_auth(&token)
            .send()
            .map_err(map_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_http_status(status, url));
        }

        let payload: SecretResponse = response.json().map_err(|e| Error::Backend {
            scheme: Self::SCHEME,
            kind: BackendFailureKind::Permanent,
            message: format!("invalid JSON from Azure Key Vault: {e}"),
        })?;

        let value = payload.value.ok_or_else(|| Error::Backend {
            scheme: Self::SCHEME,
            kind: BackendFailureKind::Permanent,
            message: "Azure Key Vault returned a secret without a value field".into(),
        })?;

        Ok(SecretString::new(value.into()))
    }

    fn put(&self, _url: &Url, _value: &SecretString) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: Self::SCHEME,
            operation: "put",
        })
    }

    fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
        Err(Error::UnsupportedOperation {
            scheme: Self::SCHEME,
            operation: "list",
        })
    }

    fn delete(&self, _url: &Url) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: Self::SCHEME,
            operation: "delete",
        })
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        let kv_url = AzureKvUrl::try_from(url)?;
        let token = self.token()?;
        let request_url = self.build_url(&kv_url);

        let client = self.client();
        let response = client
            .get(&request_url)
            .bearer_auth(&token)
            .send()
            .map_err(map_reqwest_error)?;

        match response.status() {
            reqwest::StatusCode::OK => Ok(true),
            reqwest::StatusCode::NOT_FOUND => Ok(false),
            status => Err(map_http_status(status, url)),
        }
    }
}

/// Response body from the Azure Key Vault `GetSecret` endpoint.
///
/// `value` is the plaintext secret string.
#[derive(Debug, Deserialize)]
struct SecretResponse {
    value: Option<String>,
}

/// Map `reqwest` network errors into the locked `hasp_core::Error` taxonomy.
fn map_reqwest_error(err: reqwest::Error) -> Error {
    let kind = if err.is_timeout() || err.is_connect() {
        BackendFailureKind::Transient
    } else {
        BackendFailureKind::Permanent
    };
    Error::Backend {
        scheme: "azure-kv",
        kind,
        message: format!("Azure Key Vault request failed: {err}"),
    }
}

/// Map Azure Key Vault HTTP status codes into the locked `hasp_core::Error`
/// taxonomy.
///
/// Reference:
/// <https://docs.microsoft.com/en-us/rest/api/keyvault/common-error-response>
fn map_http_status(status: reqwest::StatusCode, url: &Url) -> Error {
    match status {
        reqwest::StatusCode::NOT_FOUND => Error::NotFound(url.to_string()),
        reqwest::StatusCode::FORBIDDEN => {
            Error::PermissionDenied(format!("azure-kv:// permission denied for {url}"))
        }
        reqwest::StatusCode::UNAUTHORIZED => {
            Error::AuthenticationFailed(format!("azure-kv:// authentication failed for {url}"))
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => Error::Backend {
            scheme: "azure-kv",
            kind: BackendFailureKind::Throttled,
            message: format!("Azure Key Vault throttled the request (HTTP {status})"),
        },
        status if status.is_server_error() => Error::Backend {
            scheme: "azure-kv",
            kind: BackendFailureKind::Transient,
            message: format!("Azure Key Vault returned HTTP {status}"),
        },
        status if status.as_u16() == 400 => {
            Error::InvalidUrl(format!("azure-kv:// invalid request (HTTP {status})"))
        }
        _ => Error::Backend {
            scheme: "azure-kv",
            kind: BackendFailureKind::Permanent,
            message: format!("Azure Key Vault returned HTTP {status}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_url_simple() {
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let kv = AzureKvUrl::try_from(&url).unwrap();
        assert_eq!(kv.vault_name, "my-vault");
        assert_eq!(kv.secret_name, "my-secret");
        assert_eq!(kv.version, None);
    }

    #[test]
    fn parse_valid_url_with_version() {
        let url = Url::parse("azure-kv://my-vault/my-secret?version=abc123").unwrap();
        let kv = AzureKvUrl::try_from(&url).unwrap();
        assert_eq!(kv.vault_name, "my-vault");
        assert_eq!(kv.secret_name, "my-secret");
        assert_eq!(kv.version, Some("abc123".into()));
    }

    #[test]
    fn parse_valid_url_with_path() {
        let url = Url::parse("azure-kv://my-vault/secrets/app/db-password").unwrap();
        let kv = AzureKvUrl::try_from(&url).unwrap();
        assert_eq!(kv.vault_name, "my-vault");
        assert_eq!(kv.secret_name, "secrets/app/db-password");
    }

    #[test]
    fn parse_missing_host_fails() {
        let url = Url::parse("azure-kv:///my-secret").unwrap();
        assert!(AzureKvUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_empty_vault_name_fails() {
        let url = Url::parse("azure-kv://my-vault/").unwrap();
        assert!(AzureKvUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_unknown_query_fails() {
        let url = Url::parse("azure-kv://my-vault/my-secret?raw=true").unwrap();
        assert!(AzureKvUrl::try_from(&url).is_err());
    }

    #[test]
    fn build_url_without_version() {
        let backend = AzureKvBackend::new();
        let kv = AzureKvUrl {
            vault_name: "my-vault".into(),
            secret_name: "my-secret".into(),
            version: None,
        };
        let url = backend.build_url(&kv);
        assert_eq!(
            url,
            "https://my-vault.vault.azure.net/secrets/my-secret?api-version=7.5"
        );
    }

    #[test]
    fn build_url_with_version() {
        let backend = AzureKvBackend::new();
        let kv = AzureKvUrl {
            vault_name: "my-vault".into(),
            secret_name: "my-secret".into(),
            version: Some("v1".into()),
        };
        let url = backend.build_url(&kv);
        assert_eq!(
            url,
            "https://my-vault.vault.azure.net/secrets/my-secret/v1?api-version=7.5"
        );
    }

    #[test]
    fn error_map_404_to_not_found() {
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::NOT_FOUND, &url);
        assert!(matches!(err, Error::NotFound(ref s) if s == "azure-kv://my-vault/my-secret"));
    }

    #[test]
    fn error_map_403_to_permission_denied() {
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::FORBIDDEN, &url);
        assert!(matches!(err, Error::PermissionDenied(ref s) if s.contains("permission denied")));
    }

    #[test]
    fn error_map_401_to_authentication_failed() {
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::UNAUTHORIZED, &url);
        assert!(
            matches!(err, Error::AuthenticationFailed(ref s) if s.contains("authentication failed"))
        );
    }

    #[test]
    fn error_map_429_to_throttled() {
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::TOO_MANY_REQUESTS, &url);
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
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR, &url);
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
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::IM_A_TEAPOT, &url);
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Permanent,
                ..
            }
        ));
    }

    #[test]
    fn unsupported_operations() {
        let backend = AzureKvBackend::new();
        let url = Url::parse("azure-kv://my-vault/my-secret").unwrap();
        let dummy = SecretString::new("x".into());

        assert!(matches!(
            backend.put(&url, &dummy),
            Err(Error::UnsupportedOperation {
                scheme: "azure-kv",
                operation: "put",
            })
        ));
        assert!(matches!(
            backend.list(&url),
            Err(Error::UnsupportedOperation {
                scheme: "azure-kv",
                operation: "list",
            })
        ));
        assert!(matches!(
            backend.delete(&url),
            Err(Error::UnsupportedOperation {
                scheme: "azure-kv",
                operation: "delete",
            })
        ));
    }

    #[test]
    fn backend_scheme() {
        let backend = AzureKvBackend::new();
        assert_eq!(backend.scheme(), "azure-kv");
    }
}
