//! `gcp-sm://` backend for hasp.
//!
//! Grammar: `gcp-sm://<project-id>/<secret-id>?version=<version>`
//!   - `<project-id>` — GCP project identifier (host). Must be non-empty.
//!   - `<secret-id>`  — Secret ID (path). Identifiers must match
//!     `^[a-zA-Z0-9-_]{1,255}$` per GCP. Leading `/` is stripped.
//!   - `?version`     — Optional version label. Defaults to `latest`.
//!
//! Supported operations: `get`, `exists`.
//! `put`, `list`, `delete`: `UnsupportedOperation`.
//!
//! Authentication is ambient only: `GOOGLE_APPLICATION_CREDENTIALS`
//! or VM metadata service. `gcp-auth` resolves these transparently.
//! No auth-bootstrap flows or credential refresh logic lives in this
//! crate.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, SecretString};
use serde::Deserialize;
use url::Url;

/// URL shape for `gcp-sm://` addresses.
///
/// `project_id` and `secret_id` are identifiers, not secret values.
/// They may appear in error messages (redacted per URL discipline).
#[derive(Debug)]
pub struct GcpSmUrl {
    pub project_id: String,
    pub secret_id: String,
    pub version: String,
}

impl TryFrom<&Url> for GcpSmUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "gcp-sm" {
            return Err(Error::InvalidUrl("expected gcp-sm:// scheme".into()));
        }

        let project_id = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("gcp-sm:// requires a project-id (host)".into()))?
            .to_owned();
        if project_id.is_empty() {
            return Err(Error::InvalidUrl(
                "gcp-sm:// project-id must not be empty".into(),
            ));
        }

        let secret_id = url.path().trim_start_matches('/').to_owned();
        if secret_id.is_empty() {
            return Err(Error::InvalidUrl(
                "gcp-sm:// secret-id must not be empty".into(),
            ));
        }

        let mut version = String::from("latest");

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "version" => version = v.into_owned(),
                _ => {
                    return Err(Error::InvalidUrl(format!(
                        "gcp-sm:// unknown query parameter: {k}"
                    )));
                }
            }
        }

        Ok(GcpSmUrl {
            project_id,
            secret_id,
            version,
        })
    }
}

/// Google Cloud Secret Manager REST backend.
///
/// Construction attempts to build a Tokio runtime inside a `Mutex` so the
/// async GCP credential flow can be used from the sync `Backend` trait.
/// The runtime is `current_thread` to keep the backend lightweight. If
/// runtime creation fails, the error is stored and replayed on first
/// use.
pub struct GcpSmBackend {
    init: Result<tokio::runtime::Runtime, Error>,
}

impl std::fmt::Debug for GcpSmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpSmBackend")
            .field("init", &self.init.is_ok())
            .finish()
    }
}

impl GcpSmBackend {
    const SCHEME: &'static str = "gcp-sm";
    const BASE_URL: &'static str = "https://secretmanager.googleapis.com/v1";

    /// Create a new `GcpSmBackend`.
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

    const SCOPES: &[&str] = &["https://www.googleapis.com/auth/cloud-platform"];

    /// Obtain a fresh access token.
    fn token(&self) -> Result<String, Error> {
        self.block_on(async {
            let provider = gcp_auth::provider().await.map_err(|e| Error::Backend {
                scheme: Self::SCHEME,
                kind: BackendFailureKind::Permanent,
                message: format!("failed to discover GCP credentials: {e}"),
            })?;
            let token = provider
                .token(Self::SCOPES)
                .await
                .map_err(|e| Error::Backend {
                    scheme: Self::SCHEME,
                    kind: BackendFailureKind::Permanent,
                    message: format!("failed to acquire GCP access token: {e}"),
                })?;
            Ok(token.as_str().to_owned())
        })?
    }

    /// Build a `reqwest::blocking::Client` ready for GCP.
    fn client(&self) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client construction is infallible with default features")
    }
}

impl Default for GcpSmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for GcpSmBackend {
    fn scheme(&self) -> &'static str {
        Self::SCHEME
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        let gcp_url = GcpSmUrl::try_from(url)?;
        let token = self.token()?;

        let request_url = format!(
            "{}/projects/{}/secrets/{}/versions/{}:access",
            Self::BASE_URL,
            gcp_url.project_id,
            gcp_url.secret_id,
            gcp_url.version,
        );

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

        let payload: AccessResponse = response.json().map_err(|e| Error::Backend {
            scheme: Self::SCHEME,
            kind: BackendFailureKind::Permanent,
            message: format!("invalid JSON from GCP Secret Manager: {e}"),
        })?;

        let decoded = payload
            .payload
            .ok_or_else(|| Error::Backend {
                scheme: Self::SCHEME,
                kind: BackendFailureKind::Permanent,
                message: "GCP Secret Manager returned a secret version without data".into(),
            })?
            .data;

        // GCP returns base64-encoded binary data; we decode it here.
        // If the data is plain text JSON, it is still base64. We decode
        // to bytes and then interpret as UTF-8, matching the hasp
        // text-oriented contract.
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &decoded,
        )
        .map_err(|e| Error::Backend {
            scheme: Self::SCHEME,
            kind: BackendFailureKind::Permanent,
            message: format!("failed to decode base64 secret value: {e}"),
        })?;

        let text = String::from_utf8(bytes).map_err(|e| Error::Backend {
            scheme: Self::SCHEME,
            kind: BackendFailureKind::Permanent,
            message: format!("secret value is not valid UTF-8: {e}"),
        })?;

        Ok(SecretString::new(text.into()))
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
        let gcp_url = GcpSmUrl::try_from(url)?;
        let token = self.token()?;

        // A lightweight metadata-only call: GetSecret (not GetSecretVersion).
        let request_url = format!(
            "{}/projects/{}/secrets/{}",
            Self::BASE_URL,
            gcp_url.project_id,
            gcp_url.secret_id,
        );

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

/// Response body from the `:access` endpoint.
///
/// `payload.data` is a base64-encoded string.
#[derive(Debug, Deserialize)]
struct AccessResponse {
    payload: Option<SecretData>,
}

#[derive(Debug, Deserialize)]
struct SecretData {
    data: String,
}

/// Map `reqwest` network errors into the locked `hasp_core::Error` taxonomy.
fn map_reqwest_error(err: reqwest::Error) -> Error {
    let kind = if err.is_timeout() || err.is_connect() {
        BackendFailureKind::Transient
    } else {
        BackendFailureKind::Permanent
    };
    Error::Backend {
        scheme: "gcp-sm",
        kind,
        message: format!("GCP request failed: {err}"),
    }
}

/// Map GCP HTTP status codes into the locked `hasp_core::Error` taxonomy.
///
/// Reference:
/// <https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access>
fn map_http_status(status: reqwest::StatusCode, url: &Url) -> Error {
    match status {
        reqwest::StatusCode::NOT_FOUND => Error::NotFound(url.to_string()),
        reqwest::StatusCode::FORBIDDEN => Error::PermissionDenied(format!(
            "gcp-sm:// permission denied for {url}"
        )),
        reqwest::StatusCode::UNAUTHORIZED => Error::AuthenticationFailed(format!(
            "gcp-sm:// authentication failed for {url}"
        )),
        reqwest::StatusCode::TOO_MANY_REQUESTS => Error::Backend {
            scheme: "gcp-sm",
            kind: BackendFailureKind::Throttled,
            message: format!("GCP Secret Manager throttled the request (HTTP {status})"),
        },
        status if status.is_server_error() => Error::Backend {
            scheme: "gcp-sm",
            kind: BackendFailureKind::Transient,
            message: format!("GCP Secret Manager returned HTTP {status}"),
        },
        status if status.as_u16() == 409 => Error::PreconditionFailed(format!(
            "gcp-sm:// precondition failed (HTTP {status})"
        )),
        status if status.as_u16() == 400 => Error::InvalidUrl(format!(
            "gcp-sm:// invalid request (HTTP {status})"
        )),
        _ => Error::Backend {
            scheme: "gcp-sm",
            kind: BackendFailureKind::Permanent,
            message: format!("GCP Secret Manager returned HTTP {status}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_url_simple() {
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
        let gcp = GcpSmUrl::try_from(&url).unwrap();
        assert_eq!(gcp.project_id, "my-project");
        assert_eq!(gcp.secret_id, "my-secret");
        assert_eq!(gcp.version, "latest");
    }

    #[test]
    fn parse_valid_url_with_path() {
        let url = Url::parse("gcp-sm://my-project/secrets/app/db-password").unwrap();
        let gcp = GcpSmUrl::try_from(&url).unwrap();
        assert_eq!(gcp.project_id, "my-project");
        assert_eq!(gcp.secret_id, "secrets/app/db-password");
    }

    #[test]
    fn parse_valid_url_with_version() {
        let url = Url::parse("gcp-sm://my-project/my-secret?version=3").unwrap();
        let gcp = GcpSmUrl::try_from(&url).unwrap();
        assert_eq!(gcp.version, "3");
    }

    #[test]
    fn parse_missing_host_fails() {
        let url = Url::parse("gcp-sm:///my-secret").unwrap();
        assert!(GcpSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_empty_path_fails() {
        let url = Url::parse("gcp-sm://my-project/").unwrap();
        assert!(GcpSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_unknown_query_fails() {
        let url = Url::parse("gcp-sm://my-project/my-secret?raw=true").unwrap();
        assert!(GcpSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn error_map_404_to_not_found() {
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::NOT_FOUND, &url);
        assert!(matches!(err, Error::NotFound(ref s) if s == "gcp-sm://my-project/my-secret"));
    }

    #[test]
    fn error_map_403_to_permission_denied() {
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::FORBIDDEN, &url);
        assert!(matches!(err, Error::PermissionDenied(ref s) if s.contains("permission denied")));
    }

    #[test]
    fn error_map_401_to_authentication_failed() {
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::UNAUTHORIZED, &url);
        assert!(
            matches!(err, Error::AuthenticationFailed(ref s) if s.contains("authentication failed"))
        );
    }

    #[test]
    fn error_map_429_to_throttled() {
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
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
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
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
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
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
    fn error_map_400_to_invalid_url() {
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
        let err = map_http_status(reqwest::StatusCode::BAD_REQUEST, &url);
        assert!(matches!(err, Error::InvalidUrl(ref s) if s.contains("invalid request")));
    }

    #[test]
    fn unsupported_operations() {
        let backend = GcpSmBackend::new();
        let url = Url::parse("gcp-sm://my-project/my-secret").unwrap();
        let dummy = SecretString::new("x".into());

        assert!(matches!(
            backend.put(&url, &dummy),
            Err(Error::UnsupportedOperation {
                scheme: "gcp-sm",
                operation: "put"
            })
        ));
        assert!(matches!(
            backend.list(&url),
            Err(Error::UnsupportedOperation {
                scheme: "gcp-sm",
                operation: "list"
            })
        ));
        assert!(matches!(
            backend.delete(&url),
            Err(Error::UnsupportedOperation {
                scheme: "gcp-sm",
                operation: "delete"
            })
        ));
    }

    #[test]
    fn backend_scheme() {
        let backend = GcpSmBackend::new();
        assert_eq!(backend.scheme(), "gcp-sm");
    }
}
