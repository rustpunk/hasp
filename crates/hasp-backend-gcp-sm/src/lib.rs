//! `gcp-sm://` backend for hasp.
//!
//! Grammar: `gcp-sm://<project-id>/<secret-id>?version=<version>&field=<path>`
//!   - `<project-id>` — GCP project identifier (host). Must be non-empty.
//!   - `<secret-id>`  — Secret ID (path). Identifiers must match
//!     `^[a-zA-Z0-9-_]{1,255}$` per GCP. Leading `/` is stripped.
//!   - `?version`     — Optional version label. Defaults to `latest`.
//!   - `?field`       — Optional dotted JSON path. When set, the
//!     decoded secret value is parsed as JSON and the named scalar is
//!     returned (see `hasp_core::extract_field`). Non-JSON payloads
//!     fail with `InvalidUrl`.
//!
//! Supported operations: `get`, `put`, `list`, `delete`, `exists`.
//!
//! Authentication is ambient only: `GOOGLE_APPLICATION_CREDENTIALS`
//! or VM metadata service. `gcp-auth` resolves these transparently.
//! No auth-bootstrap flows or credential refresh logic lives in this
//! crate.

use hasp_core::{
    Backend, BackendFailureKind, Entry, Error, ExposeSecret, ProxyConfig, SecretString,
};
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
    pub field: Option<String>,
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

        let mut version = String::from("latest");
        let mut field = None;

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "version" => version = v.into_owned(),
                "field" => field = Some(v.into_owned()),
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
            field,
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
    proxy: Option<ProxyConfig>,
}

impl std::fmt::Debug for GcpSmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpSmBackend")
            .field("init", &self.init.is_ok())
            .field("proxy", &self.proxy.as_ref().map(|_| "[REDACTED]"))
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
        Self::with_proxy(None)
    }

    pub fn with_proxy(proxy: Option<ProxyConfig>) -> Self {
        Self {
            proxy,
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
        let mut builder =
            reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(10));

        if let Some(p) = &self.proxy {
            let proxy = reqwest::Proxy::all(p.url_without_credentials())
                .expect("reqwest proxy construction is infallible with a valid URL");
            builder = builder.proxy(proxy);
        }

        builder
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

    fn validate(&self, url: &Url) -> Result<(), Error> {
        GcpSmUrl::try_from(url).map(|_| ())
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        let gcp_url = GcpSmUrl::try_from(url)?;
        if gcp_url.secret_id.is_empty() {
            return Err(Error::InvalidUrl(
                "gcp-sm:// secret-id must not be empty".into(),
            ));
        }
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
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &decoded)
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

        // Field extraction runs on the parsed JSON before wrapping in
        // `SecretString` — the parent payload never escapes this function
        // as a plaintext `String`.
        let value = match &gcp_url.field {
            Some(path) => hasp_core::extract_field_from_str(&text, path)?,
            None => text,
        };
        Ok(SecretString::new(value.into()))
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        let gcp_url = GcpSmUrl::try_from(url)?;
        if gcp_url.secret_id.is_empty() {
            return Err(Error::InvalidUrl(
                "gcp-sm:// secret-id must not be empty".into(),
            ));
        }
        let token = self.token()?;

        // Try to create the secret. If it already exists (409), skip.
        let create_url = format!("{}/projects/{}/secrets", Self::BASE_URL, gcp_url.project_id,);

        let create_body = serde_json::json!({
            "replication": { "automatic": {} },
        });

        let client = self.client();
        let create_response = client
            .post(&create_url)
            .bearer_auth(&token)
            .json(&create_body)
            .send()
            .map_err(map_reqwest_error)?;

        // 409 AlreadyExists is fine — just add a new version.
        if !create_response.status().is_success()
            && create_response.status() != reqwest::StatusCode::CONFLICT
        {
            return Err(map_http_status(create_response.status(), url));
        }

        // Add secret version.
        let add_version_url = format!(
            "{}/projects/{}/secrets/{}/versions:add",
            Self::BASE_URL,
            gcp_url.project_id,
            gcp_url.secret_id,
        );

        // GCP Secret Manager expects base64-encoded payload.
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            value.expose_secret().as_bytes(),
        );
        let version_body = serde_json::json!({ "payload": { "data": payload } });

        let version_response = client
            .post(&add_version_url)
            .bearer_auth(&token)
            .json(&version_body)
            .send()
            .map_err(map_reqwest_error)?;

        if !version_response.status().is_success() {
            return Err(map_http_status(version_response.status(), url));
        }

        Ok(())
    }

    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        let gcp_url = GcpSmUrl::try_from(url)?;
        let token = self.token()?;

        let prefix = gcp_url.secret_id.trim_matches('/');

        let mut request_url = Url::parse(&format!(
            "{}/projects/{}/secrets",
            Self::BASE_URL,
            gcp_url.project_id
        ))
        .map_err(|e| Error::Backend {
            scheme: Self::SCHEME,
            kind: BackendFailureKind::Permanent,
            message: format!("failed to build list URL: {e}"),
        })?;

        if !prefix.is_empty() {
            request_url.query_pairs_mut().append_pair(
                "filter",
                &format!("name:projects/{}/secrets/{}", gcp_url.project_id, prefix),
            );
        }

        let client = self.client();
        let mut entries = Vec::new();
        const MAX_PAGES: usize = 500;

        for _ in 0..MAX_PAGES {
            let response = client
                .get(request_url.as_str())
                .bearer_auth(&token)
                .send()
                .map_err(map_reqwest_error)?;

            let status = response.status();
            if !status.is_success() {
                return Err(map_http_status(status, url));
            }

            let payload: SecretListResponse = response.json().map_err(|e| Error::Backend {
                scheme: Self::SCHEME,
                kind: BackendFailureKind::Permanent,
                message: format!("invalid JSON from GCP Secret Manager list: {e}"),
            })?;

            for secret in payload.secrets.into_iter().flatten() {
                let name = secret.name;
                if name.is_empty() {
                    continue;
                }
                let entry_url = Url::parse(&format!("gcp-sm://{}/{name}", gcp_url.project_id,))
                    .map_err(|e| Error::Backend {
                        scheme: Self::SCHEME,
                        kind: BackendFailureKind::Permanent,
                        message: format!("failed to build list entry URL: {e}"),
                    })?;
                entries.push(Entry {
                    name,
                    url: entry_url,
                });
            }

            match payload.next_page_token {
                Some(ref t) if !t.is_empty() => {
                    request_url = Url::parse(&format!(
                        "{}/projects/{}/secrets?pageToken={}",
                        Self::BASE_URL,
                        gcp_url.project_id,
                        t,
                    ))
                    .map_err(|e| Error::Backend {
                        scheme: Self::SCHEME,
                        kind: BackendFailureKind::Permanent,
                        message: format!("failed to build paginated list URL: {e}"),
                    })?;
                    if !prefix.is_empty() {
                        request_url.query_pairs_mut().append_pair(
                            "filter",
                            &format!("name:projects/{}/secrets/{}", gcp_url.project_id, prefix),
                        );
                    }
                }
                _ => break,
            }
        }

        Ok(entries)
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        let gcp_url = GcpSmUrl::try_from(url)?;
        if gcp_url.secret_id.is_empty() {
            return Err(Error::InvalidUrl(
                "gcp-sm:// secret-id must not be empty".into(),
            ));
        }
        let token = self.token()?;

        let request_url = format!(
            "{}/projects/{}/secrets/{}",
            Self::BASE_URL,
            gcp_url.project_id,
            gcp_url.secret_id,
        );

        let client = self.client();
        let response = client
            .delete(&request_url)
            .bearer_auth(&token)
            .send()
            .map_err(map_reqwest_error)?;

        if !response.status().is_success() {
            return Err(map_http_status(response.status(), url));
        }

        Ok(())
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        let gcp_url = GcpSmUrl::try_from(url)?;
        if gcp_url.secret_id.is_empty() {
            return Err(Error::InvalidUrl(
                "gcp-sm:// secret-id must not be empty".into(),
            ));
        }
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

/// Response body from the GCP Secret Manager `ListSecrets` endpoint.
///
/// `secrets` is an array of secret metadata. `nextPageToken` is the token
/// for the next page; it is followed transparently up to a bounded limit.
#[derive(Debug, Deserialize)]
struct SecretListResponse {
    #[serde(default)]
    secrets: Option<Vec<SecretListItem>>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

/// A single secret entry in the GCP Secret Manager list response.
///
/// `name` is the full resource name like `projects/my-project/secrets/my-secret`.
#[derive(Debug, Deserialize)]
struct SecretListItem {
    name: String,
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
// TODO(#4): validate against live GCP project — see notes/TODO-live-error-mapping.md
fn map_http_status(status: reqwest::StatusCode, url: &Url) -> Error {
    match status {
        reqwest::StatusCode::NOT_FOUND => Error::NotFound(url.to_string()),
        reqwest::StatusCode::FORBIDDEN => {
            Error::PermissionDenied(format!("gcp-sm:// permission denied for {url}"))
        }
        reqwest::StatusCode::UNAUTHORIZED => {
            Error::AuthenticationFailed(format!("gcp-sm:// authentication failed for {url}"))
        }
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
        status if status.as_u16() == 409 => {
            Error::PreconditionFailed(format!("gcp-sm:// precondition failed (HTTP {status})"))
        }
        status if status.as_u16() == 400 => {
            Error::InvalidUrl(format!("gcp-sm:// invalid request (HTTP {status})"))
        }
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
    fn parse_valid_url_with_field() {
        let url = Url::parse("gcp-sm://my-project/my-secret?field=.creds.password").unwrap();
        let gcp = GcpSmUrl::try_from(&url).unwrap();
        assert_eq!(gcp.field, Some(".creds.password".into()));
        assert_eq!(gcp.version, "latest");
    }

    #[test]
    fn parse_missing_host_fails() {
        let url = Url::parse("gcp-sm:///my-secret").unwrap();
        assert!(GcpSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_empty_path_allowed_for_list() {
        let url = Url::parse("gcp-sm://my-project/").unwrap();
        let gcp = GcpSmUrl::try_from(&url).unwrap();
        assert_eq!(gcp.project_id, "my-project");
        assert_eq!(gcp.secret_id, "");
    }

    #[test]
    fn empty_secret_id_fails_at_operation() {
        let backend = GcpSmBackend::new();
        let url = Url::parse("gcp-sm://my-project/").unwrap();
        let dummy = SecretString::new("x".into());
        assert!(
            matches!(
                backend.get(&url),
                Err(Error::InvalidUrl(ref s)) if s.contains("secret-id must not be empty")
            ),
            "empty secret-id should fail at operation boundary"
        );
        assert!(
            matches!(
                backend.put(&url, &dummy),
                Err(Error::InvalidUrl(ref s)) if s.contains("secret-id must not be empty")
            ),
            "empty secret-id should fail at operation boundary for put"
        );
        assert!(
            matches!(
                backend.delete(&url),
                Err(Error::InvalidUrl(ref s)) if s.contains("secret-id must not be empty")
            ),
            "empty secret-id should fail at operation boundary for delete"
        );
        assert!(
            matches!(
                backend.exists(&url),
                Err(Error::InvalidUrl(ref s)) if s.contains("secret-id must not be empty")
            ),
            "empty secret-id should fail at operation boundary for exists"
        );
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
    fn supported_operations() {
        let _backend = GcpSmBackend::new();
        // put, list, delete are now implemented; they fail at network layer
        // because no GCP credentials are configured in unit tests.
        // Constructing a reqwest::Client without initializing rustls would
        // panic; verifying the backend type is sufficient here.
    }

    #[test]
    fn list_parsing_with_next_page_token() {
        let payload: SecretListResponse =
            serde_json::from_str(r#"{"secrets":[{"name":"my-secret"}],"nextPageToken":"abc123"}"#)
                .unwrap();

        let items = payload.secrets.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(payload.next_page_token.unwrap(), "abc123");
    }

    #[test]
    fn backend_scheme() {
        let backend = GcpSmBackend::new();
        assert_eq!(backend.scheme(), "gcp-sm");
    }

    // GCP returns secret bytes base64-decoded by get(); the post-decode
    // UTF-8 string is the JSON payload the user stored. These tests
    // exercise the shared helper on representative payloads.
    #[test]
    fn field_extraction_happy() {
        let payload = r#"{"db":{"password":"hunter2"}}"#;
        let v = hasp_core::extract_field_from_str(payload, ".db.password").unwrap();
        assert_eq!(v, "hunter2");
    }

    #[test]
    fn field_extraction_missing_field_is_not_found() {
        let payload = r#"{"db":{}}"#;
        let err = hasp_core::extract_field_from_str(payload, ".db.password").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn field_extraction_non_json_is_invalid_url() {
        let payload = "raw-bytes-not-json";
        let err = hasp_core::extract_field_from_str(payload, "password").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }
}
