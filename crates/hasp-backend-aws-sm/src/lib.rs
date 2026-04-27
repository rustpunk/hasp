//! `aws-sm://` backend for hasp.
//!
//! Grammar: `aws-sm://<region>/<secret-name>?version-stage=<stage>&version-id=<id>`
//!   - `<region>`       — AWS region (host). Must be non-empty.
//!   - `<secret-name>`  — Secret name or ARN (path). Leading `/` is stripped.
//!   - `?version-stage` — Optional version stage (e.g. `AWSCURRENT`,
//!     `AWSPREVIOUS`). Mutually exclusive with `version-id`.
//!   - `?version-id`    — Optional version UUID. Mutually exclusive with
//!     `version-stage`.
//!
//! Supported operations: `get`, `put`, `list`, `delete`, `exists`.
//!
//! Authentication is ambient only: `AWS_ACCESS_KEY_ID` +
//! `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, IAM role via IMDS/ECS/EKS, or
//! any other source supported by the AWS default credential chain. No
//! auth-bootstrap flows or credential refresh logic lives in this crate.
//!
//! AWS Secrets Manager can store text or binary values. Only text secrets
//! are supported by this backend; binary secrets return a permanent backend
//! error because the hasp `Backend` contract is text-oriented.
//!
//! Region is required in the URL so the same secret name can be addressed
//! across partitions, and so the URL is self-contained (no ambient region
//! dependency).

use hasp_core::{Backend, BackendFailureKind, Entry, Error, ExposeSecret, SecretString};
use url::Url;

/// URL shape for `aws-sm://` addresses.
///
/// Region and secret name are identifiers, not secret values. They may
/// appear in error messages (redacted per URL discipline).
#[derive(Debug)]
pub struct AwsSmUrl {
    pub region: String,
    pub secret_name: String,
    pub version_stage: Option<String>,
    pub version_id: Option<String>,
}

impl TryFrom<&Url> for AwsSmUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "aws-sm" {
            return Err(Error::InvalidUrl("expected aws-sm:// scheme".into()));
        }

        let region = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("aws-sm:// requires a region (host)".into()))?
            .to_owned();
        if region.is_empty() {
            return Err(Error::InvalidUrl(
                "aws-sm:// region must not be empty".into(),
            ));
        }

        let secret_name = url.path().trim_start_matches('/').to_owned();
        if secret_name.is_empty() {
            return Err(Error::InvalidUrl(
                "aws-sm:// secret name must not be empty".into(),
            ));
        }

        let mut version_stage = None;
        let mut version_id = None;

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "version-stage" => version_stage = Some(v.into_owned()),
                "version-id" => version_id = Some(v.into_owned()),
                _ => {
                    return Err(Error::InvalidUrl(format!(
                        "aws-sm:// unknown query parameter: {k}"
                    )));
                }
            }
        }

        if version_stage.is_some() && version_id.is_some() {
            return Err(Error::InvalidUrl(
                "aws-sm:// version-stage and version-id are mutually exclusive".into(),
            ));
        }

        Ok(AwsSmUrl {
            region,
            secret_name,
            version_stage,
            version_id,
        })
    }
}

/// AWS Secrets Manager SDK backend.
///
/// Construction attempts to build a Tokio runtime so the async AWS SDK
/// can be used from the sync `Backend` trait. The runtime is
/// `current_thread` to keep the backend lightweight for short-lived CLI
/// invocations. If runtime creation fails, the error is stored and
/// replayed on the first operation.
#[derive(Debug)]
pub struct AwsSmBackend {
    init: Result<tokio::runtime::Runtime, Error>,
}

impl AwsSmBackend {
    /// Create a new `AwsSmBackend`.
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
                    scheme: "aws-sm",
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
}

impl Default for AwsSmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for AwsSmBackend {
    fn scheme(&self) -> &'static str {
        "aws-sm"
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        let aws_url = AwsSmUrl::try_from(url)?;
        self.block_on(get_secret(&aws_url))?
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        let aws_url = AwsSmUrl::try_from(url)?;
        self.block_on(put_secret(&aws_url, value.expose_secret()))?
    }

    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        let aws_url = AwsSmUrl::try_from(url)?;
        self.block_on(list_secrets(&aws_url))?
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        let aws_url = AwsSmUrl::try_from(url)?;
        self.block_on(delete_secret(&aws_url))?
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        let aws_url = AwsSmUrl::try_from(url)?;
        match self.block_on(describe_secret(&aws_url))? {
            Ok(()) => Ok(true),
            Err(Error::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Build an AWS SDK config scoped to the given region.
async fn aws_config_for_region(region: &str) -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await
}

/// Fetch a secret value via `GetSecretValue`.
///
/// Binary secrets are rejected because the hasp contract is text-only.
async fn get_secret(aws_url: &AwsSmUrl) -> Result<SecretString, Error> {
    let config = aws_config_for_region(&aws_url.region).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let mut builder = client.get_secret_value().secret_id(&aws_url.secret_name);

    if let Some(stage) = &aws_url.version_stage {
        builder = builder.version_stage(stage);
    }
    if let Some(id) = &aws_url.version_id {
        builder = builder.version_id(id);
    }

    let output = builder.send().await.map_err(map_get_error)?;

    match output.secret_string {
        Some(text) => Ok(SecretString::new(text.into())),
        None => {
            if output.secret_binary.is_some() {
                Err(Error::Backend {
                    scheme: "aws-sm",
                    kind: BackendFailureKind::Permanent,
                    message: "secret contains binary data; aws-sm:// only supports text secrets"
                        .into(),
                })
            } else {
                Err(Error::Backend {
                    scheme: "aws-sm",
                    kind: BackendFailureKind::Permanent,
                    message: "AWS returned a secret with neither text nor binary value".into(),
                })
            }
        }
    }
}

/// Probe secret existence via `DescribeSecret`.
///
/// `DescribeSecret` is metadata-only; no secret value crosses the wire.
async fn describe_secret(aws_url: &AwsSmUrl) -> Result<(), Error> {
    let config = aws_config_for_region(&aws_url.region).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    client
        .describe_secret()
        .secret_id(&aws_url.secret_name)
        .send()
        .await
        .map_err(map_describe_error)?;

    Ok(())
}

/// Create or update a secret value via `CreateSecret` / `PutSecretValue`.
///
/// Tries `CreateSecret` first; on `AlreadyExistsException`, falls back to
/// `PutSecretValue` to update the existing secret.
async fn put_secret(aws_url: &AwsSmUrl, value: &str) -> Result<(), Error> {
    let config = aws_config_for_region(&aws_url.region).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let create_result = client
        .create_secret()
        .name(&aws_url.secret_name)
        .secret_string(value)
        .send()
        .await;

    match create_result {
        Ok(_) => Ok(()),
        Err(err) => {
            if let Some(service_err) = err.as_service_error() {
                let code = service_err.meta().code().unwrap_or("Unknown");
                if code == "AlreadyExistsException" {
                    client
                        .put_secret_value()
                        .secret_id(&aws_url.secret_name)
                        .secret_string(value)
                        .send()
                        .await
                        .map_err(map_put_error)?;
                    Ok(())
                } else {
                    Err(map_create_error(err))
                }
            } else {
                Err(map_generic_error(err))
            }
        }
    }
}

/// List secrets via `ListSecrets`.
///
/// Returns every secret in the region as an `Entry`. Transparent pagination
/// follows `NextToken` until exhausted (bounded at 500 pages).
async fn list_secrets(aws_url: &AwsSmUrl) -> Result<Vec<Entry>, Error> {
    let config = aws_config_for_region(&aws_url.region).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let mut entries = Vec::new();
    let mut next_token: Option<String> = None;
    const MAX_PAGES: usize = 500;

    for _ in 0..MAX_PAGES {
        let mut builder = client.list_secrets();
        if let Some(ref token) = next_token {
            builder = builder.next_token(token);
        }

        let output = builder.send().await.map_err(map_list_error)?;
        next_token = output.next_token.clone();

        for secret in output.secret_list.into_iter().flatten() {
            let name = secret.name.unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let entry_url = Url::parse(&format!("aws-sm://{}/{name}", aws_url.region))
                .map_err(|e| Error::Backend {
                    scheme: "aws-sm",
                    kind: BackendFailureKind::Permanent,
                    message: format!("failed to build list entry URL: {e}"),
                })?;
            entries.push(Entry {
                name,
                url: entry_url,
            });
        }

        if next_token.is_none() {
            break;
        }
    }

    Ok(entries)
}

/// Delete a secret via `DeleteSecret` with soft-delete (recovery window).
///
/// `ForceDeleteWithoutRecovery` is `false` so AWS retains the secret for the
/// service-managed recovery period.
async fn delete_secret(aws_url: &AwsSmUrl) -> Result<(), Error> {
    let config = aws_config_for_region(&aws_url.region).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    client
        .delete_secret()
        .secret_id(&aws_url.secret_name)
        .force_delete_without_recovery(false)
        .send()
        .await
        .map_err(map_delete_error)?;

    Ok(())
}

/// Map a `GetSecretValue` SDK error into the locked `hasp_core::Error`
/// taxonomy.
fn map_get_error(
    err: aws_sdk_secretsmanager::error::SdkError<
        aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError,
    >,
) -> Error {
    if let Some(service_err) = err.as_service_error() {
        let code = service_err.meta().code().unwrap_or("Unknown");
        let message = service_err.meta().message().unwrap_or("no message");
        return from_service_error(code, message);
    }
    map_generic_error(err)
}

/// Map a `DescribeSecret` SDK error into the locked `hasp_core::Error`
/// taxonomy.
fn map_describe_error(
    err: aws_sdk_secretsmanager::error::SdkError<
        aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretError,
    >,
) -> Error {
    if let Some(service_err) = err.as_service_error() {
        let code = service_err.meta().code().unwrap_or("Unknown");
        let message = service_err.meta().message().unwrap_or("no message");
        return from_service_error(code, message);
    }
    map_generic_error(err)
}

/// Map a `CreateSecret` SDK error into the locked `hasp_core::Error` taxonomy.
fn map_create_error(
    err: aws_sdk_secretsmanager::error::SdkError<
        aws_sdk_secretsmanager::operation::create_secret::CreateSecretError,
    >,
) -> Error {
    if let Some(service_err) = err.as_service_error() {
        let code = service_err.meta().code().unwrap_or("Unknown");
        let message = service_err.meta().message().unwrap_or("no message");
        return from_service_error(code, message);
    }
    map_generic_error(err)
}

/// Map a `PutSecretValue` SDK error into the locked `hasp_core::Error` taxonomy.
fn map_put_error(
    err: aws_sdk_secretsmanager::error::SdkError<
        aws_sdk_secretsmanager::operation::put_secret_value::PutSecretValueError,
    >,
) -> Error {
    if let Some(service_err) = err.as_service_error() {
        let code = service_err.meta().code().unwrap_or("Unknown");
        let message = service_err.meta().message().unwrap_or("no message");
        return from_service_error(code, message);
    }
    map_generic_error(err)
}

/// Map a `ListSecrets` SDK error into the locked `hasp_core::Error` taxonomy.
fn map_list_error(
    err: aws_sdk_secretsmanager::error::SdkError<
        aws_sdk_secretsmanager::operation::list_secrets::ListSecretsError,
    >,
) -> Error {
    if let Some(service_err) = err.as_service_error() {
        let code = service_err.meta().code().unwrap_or("Unknown");
        let message = service_err.meta().message().unwrap_or("no message");
        return from_service_error(code, message);
    }
    map_generic_error(err)
}

/// Map a `DeleteSecret` SDK error into the locked `hasp_core::Error` taxonomy.
fn map_delete_error(
    err: aws_sdk_secretsmanager::error::SdkError<
        aws_sdk_secretsmanager::operation::delete_secret::DeleteSecretError,
    >,
) -> Error {
    if let Some(service_err) = err.as_service_error() {
        let code = service_err.meta().code().unwrap_or("Unknown");
        let message = service_err.meta().message().unwrap_or("no message");
        return from_service_error(code, message);
    }
    map_generic_error(err)
}

/// Convert AWS service error metadata into a stable `hasp_core::Error`.
fn from_service_error(code: &str, message: &str) -> Error {
    match code {
        "ResourceNotFoundException" => {
            Error::NotFound(format!("aws-sm:// secret not found: {message}"))
        }
        "InvalidParameterException" => {
            Error::InvalidUrl(format!("aws-sm:// invalid parameter: {message}"))
        }
        "InvalidRequestException" | "MalformedPolicyDocumentException" | "EncryptionFailure" => {
            Error::PreconditionFailed(format!("aws-sm:// request precondition failed: {message}"))
        }
        "AccessDeniedException" => {
            Error::PermissionDenied(format!("aws-sm:// permission denied: {message}"))
        }
        "ThrottlingException" => Error::Backend {
            scheme: "aws-sm",
            kind: BackendFailureKind::Throttled,
            message: format!("AWS throttled the request: {message}"),
        },
        "DecryptionFailure" | "InternalServiceError" => Error::Backend {
            scheme: "aws-sm",
            kind: BackendFailureKind::Transient,
            message: format!("AWS service error ({code}): {message}"),
        },
        _ => Error::Backend {
            scheme: "aws-sm",
            kind: BackendFailureKind::Permanent,
            message: format!("AWS service error ({code}): {message}"),
        },
    }
}

/// Map non-service SDK errors (timeouts, dispatch failures, construction
/// failures) into the locked `hasp_core::Error` taxonomy.
fn map_generic_error<E: std::fmt::Display>(
    err: aws_sdk_secretsmanager::error::SdkError<E>,
) -> Error {
    use aws_sdk_secretsmanager::error::SdkError;
    match err {
        SdkError::TimeoutError(_) => Error::Backend {
            scheme: "aws-sm",
            kind: BackendFailureKind::Transient,
            message: "AWS request timed out".into(),
        },
        SdkError::DispatchFailure(_) => Error::Backend {
            scheme: "aws-sm",
            kind: BackendFailureKind::Transient,
            message: "AWS request dispatch failed".into(),
        },
        _ => Error::Backend {
            scheme: "aws-sm",
            kind: BackendFailureKind::Permanent,
            message: format!("AWS SDK error: {err}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_url_simple() {
        let url = Url::parse("aws-sm://us-east-1/my-secret").unwrap();
        let aws = AwsSmUrl::try_from(&url).unwrap();
        assert_eq!(aws.region, "us-east-1");
        assert_eq!(aws.secret_name, "my-secret");
        assert_eq!(aws.version_stage, None);
        assert_eq!(aws.version_id, None);
    }

    #[test]
    fn parse_valid_url_with_path_secret() {
        let url = Url::parse("aws-sm://us-west-2/prod/app/db-password").unwrap();
        let aws = AwsSmUrl::try_from(&url).unwrap();
        assert_eq!(aws.region, "us-west-2");
        assert_eq!(aws.secret_name, "prod/app/db-password");
    }

    #[test]
    fn parse_valid_url_with_version_stage() {
        let url = Url::parse("aws-sm://eu-west-1/my-secret?version-stage=AWSPREVIOUS").unwrap();
        let aws = AwsSmUrl::try_from(&url).unwrap();
        assert_eq!(aws.version_stage, Some("AWSPREVIOUS".into()));
        assert_eq!(aws.version_id, None);
    }

    #[test]
    fn parse_valid_url_with_version_id() {
        let url =
            Url::parse("aws-sm://ap-south-1/my-secret?version-id=abcd-1234-efgh-5678").unwrap();
        let aws = AwsSmUrl::try_from(&url).unwrap();
        assert_eq!(aws.version_id, Some("abcd-1234-efgh-5678".into()));
        assert_eq!(aws.version_stage, None);
    }

    #[test]
    fn parse_missing_host_fails() {
        let url = Url::parse("aws-sm:///my-secret").unwrap();
        assert!(AwsSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_empty_path_fails() {
        let url = Url::parse("aws-sm://us-east-1/").unwrap();
        assert!(AwsSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_unknown_query_fails() {
        let url = Url::parse("aws-sm://us-east-1/my-secret?raw=true").unwrap();
        assert!(AwsSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_mutually_exclusive_version_params_fails() {
        let url = Url::parse(
            "aws-sm://us-east-1/my-secret?version-stage=AWSCURRENT&version-id=abcd-1234",
        )
        .unwrap();
        assert!(AwsSmUrl::try_from(&url).is_err());
    }

    #[test]
    fn error_map_resource_not_found() {
        let err = from_service_error("ResourceNotFoundException", "secret not found");
        assert!(matches!(err, Error::NotFound(ref s) if s.contains("secret not found")));
    }

    #[test]
    fn error_map_invalid_parameter() {
        let err = from_service_error("InvalidParameterException", "bad param");
        assert!(matches!(err, Error::InvalidUrl(ref s) if s.contains("bad param")));
    }

    #[test]
    fn error_map_invalid_request() {
        let err = from_service_error("InvalidRequestException", "bad request");
        assert!(matches!(err, Error::PreconditionFailed(ref s) if s.contains("bad request")));
    }

    #[test]
    fn error_map_access_denied() {
        let err = from_service_error("AccessDeniedException", "denied");
        assert!(matches!(err, Error::PermissionDenied(ref s) if s.contains("denied")));
    }

    #[test]
    fn error_map_throttling() {
        let err = from_service_error("ThrottlingException", "slow down");
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Throttled,
                ..
            }
        ));
    }

    #[test]
    fn error_map_decryption_failure_is_transient() {
        let err = from_service_error("DecryptionFailure", "kms down");
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Transient,
                ..
            }
        ));
    }

    #[test]
    fn error_map_internal_service_error_is_transient() {
        let err = from_service_error("InternalServiceError", "oops");
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Transient,
                ..
            }
        ));
    }

    #[test]
    fn error_map_unknown_code_is_permanent() {
        let err = from_service_error("SomeWeirdException", "unknown");
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Permanent,
                ..
            }
        ));
    }

    #[test]
    fn error_map_encryption_failure_is_precondition_failed() {
        let err = from_service_error("EncryptionFailure", "kms failure");
        assert!(
            matches!(err, Error::PreconditionFailed(ref s) if s.contains("kms failure"))
        );
    }

    #[test]
    fn supported_operations() {
        let _backend = AwsSmBackend::new();
        // put, list, delete are now implemented; they fail at network layer
        // because no AWS credentials are configured in unit tests.
    }

    #[test]
    fn backend_new_ok() {
        let _backend = AwsSmBackend::new();
    }

    #[test]
    fn backend_scheme() {
        let backend = AwsSmBackend::new();
        assert_eq!(backend.scheme(), "aws-sm");
    }
}
