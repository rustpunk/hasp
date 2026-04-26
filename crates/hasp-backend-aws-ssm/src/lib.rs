//! `aws-ssm://` backend for hasp.
//!
//! Grammar: `aws-ssm://<region>/<parameter-name>?with-decryption=<bool>`
//!   - `<region>`          — AWS region (host). Must be non-empty.
//!   - `<parameter-name>`  — Parameter Store name (path). All leading
//!     `/` characters are stripped; hierarchical parameters that require a
//!     leading `/` must be encoded with a double slash after the host.
//!   - `?with-decryption`  — Optional boolean (default `true`). Pass
//!     `false` to fetch a `SecureString` value without invoking KMS.
//!
//! Supported operations: `get`, `exists`.
//! `put`, `list`, `delete`: `UnsupportedOperation`.
//!
//! Authentication is ambient only: `AWS_ACCESS_KEY_ID` +
//! `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, IAM role via IMDS/ECS/EKS, or
//! any other source supported by the AWS default credential chain. No
//! auth-bootstrap flows or credential refresh logic lives in this crate.
//!
//! SSM parameters may be `String`, `StringList`, or `SecureString`.
//! All three expose their value as text through this backend.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, SecretString};
use url::Url;

/// URL shape for `aws-ssm://` addresses.
///
/// Region and parameter name are identifiers, not secret values. They may
/// appear in error messages (redacted per URL discipline).
#[derive(Debug)]
pub struct AwsSsmUrl {
    pub region: String,
    pub parameter_name: String,
    pub with_decryption: bool,
}

impl TryFrom<&Url> for AwsSsmUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "aws-ssm" {
            return Err(Error::InvalidUrl("expected aws-ssm:// scheme".into()));
        }

        let region = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("aws-ssm:// requires a region (host)".into()))?
            .to_owned();
        if region.is_empty() {
            return Err(Error::InvalidUrl(
                "aws-ssm:// region must not be empty".into(),
            ));
        }

        let parameter_name = url.path().trim_start_matches('/').to_owned();
        if parameter_name.is_empty() {
            return Err(Error::InvalidUrl(
                "aws-ssm:// parameter name must not be empty".into(),
            ));
        }

        let mut with_decryption = true;

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "with-decryption" => {
                    with_decryption = match v.as_ref() {
                        "true" => true,
                        "false" => false,
                        _ => {
                            return Err(Error::InvalidUrl(format!(
                                "aws-ssm:// with-decryption must be true or false, got {v}"
                            )));
                        }
                    };
                }
                _ => {
                    return Err(Error::InvalidUrl(format!(
                        "aws-ssm:// unknown query parameter: {k}"
                    )));
                }
            }
        }

        Ok(AwsSsmUrl {
            region,
            parameter_name,
            with_decryption,
        })
    }
}

/// AWS SSM Parameter Store SDK backend.
///
/// Construction attempts to build a Tokio runtime so the async AWS SDK
/// can be used from the sync `Backend` trait. The runtime is
/// `current_thread` to keep the backend lightweight for short-lived CLI
/// invocations. If runtime creation fails, the error is stored and
/// replayed on the first operation.
#[derive(Debug)]
pub struct AwsSsmBackend {
    init: Result<tokio::runtime::Runtime, Error>,
}

impl AwsSsmBackend {
    /// Create a new `AwsSsmBackend`.
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
                    scheme: "aws-ssm",
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

impl Default for AwsSsmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for AwsSsmBackend {
    fn scheme(&self) -> &'static str {
        "aws-ssm"
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        let aws_url = AwsSsmUrl::try_from(url)?;
        self.block_on(get_parameter(&aws_url, aws_url.with_decryption))?
    }

    fn put(&self, _url: &Url, _value: &SecretString) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "aws-ssm",
            operation: "put",
        })
    }

    fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
        Err(Error::UnsupportedOperation {
            scheme: "aws-ssm",
            operation: "list",
        })
    }

    fn delete(&self, _url: &Url) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "aws-ssm",
            operation: "delete",
        })
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        let aws_url = AwsSsmUrl::try_from(url)?;
        match self.block_on(get_parameter(&aws_url, false)) {
            Ok(_) => Ok(true),
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

/// Fetch a parameter value via `GetParameter`.
///
/// `with_decryption` controls whether KMS decrypts a `SecureString`.
/// For `exists` checks this should be `false` to avoid unnecessary KMS
/// calls; for `get` it should follow the URL query parameter.
async fn get_parameter(aws_url: &AwsSsmUrl, with_decryption: bool) -> Result<SecretString, Error> {
    let config = aws_config_for_region(&aws_url.region).await;
    let client = aws_sdk_ssm::Client::new(&config);

    let output = client
        .get_parameter()
        .name(&aws_url.parameter_name)
        .with_decryption(with_decryption)
        .send()
        .await
        .map_err(map_get_error)?;

    let parameter = output.parameter.ok_or_else(|| Error::Backend {
        scheme: "aws-ssm",
        kind: BackendFailureKind::Permanent,
        message: "AWS returned an empty parameter object".into(),
    })?;

    let value = parameter.value.ok_or_else(|| Error::Backend {
        scheme: "aws-ssm",
        kind: BackendFailureKind::Permanent,
        message: "AWS returned a parameter with no value".into(),
    })?;

    Ok(SecretString::new(value.into()))
}

/// Map a `GetParameter` SDK error into the locked `hasp_core::Error`
/// taxonomy.
fn map_get_error(
    err: aws_sdk_ssm::error::SdkError<aws_sdk_ssm::operation::get_parameter::GetParameterError>,
) -> Error {
    if let Some(service_err) = err.as_service_error() {
        let code = service_err.meta().code().unwrap_or("Unknown");
        let message = service_err.meta().message().unwrap_or("no message");
        return from_service_error(code, message);
    }
    map_generic_error(err)
}

/// Convert AWS SSM service error metadata into a stable `hasp_core::Error`.
fn from_service_error(code: &str, message: &str) -> Error {
    match code {
        "ParameterNotFound" | "ParameterVersionNotFound" => {
            Error::NotFound(format!("aws-ssm:// parameter not found: {message}"))
        }
        "InvalidParameterException" | "InvalidParameterValue" | "ParameterPatternMismatch" => {
            Error::InvalidUrl(format!("aws-ssm:// invalid parameter: {message}"))
        }
        "InvalidRequestException" => {
            Error::PreconditionFailed(format!("aws-ssm:// request precondition failed: {message}"))
        }
        "AccessDeniedException" => {
            Error::PermissionDenied(format!("aws-ssm:// permission denied: {message}"))
        }
        "UnauthorizedException" => {
            Error::AuthenticationFailed(format!("aws-ssm:// authentication failed: {message}"))
        }
        "ThrottlingException" | "TooManyUpdates" => Error::Backend {
            scheme: "aws-ssm",
            kind: BackendFailureKind::Throttled,
            message: format!("AWS throttled the request: {message}"),
        },
        "InternalServerError" => Error::Backend {
            scheme: "aws-ssm",
            kind: BackendFailureKind::Transient,
            message: format!("AWS service error ({code}): {message}"),
        },
        "HierarchyDepthLimitExceeded" | "ParameterAlreadyExists" | "ParameterLimitExceeded" => {
            Error::PreconditionFailed(format!("aws-ssm:// precondition failed: {message}"))
        }
        "InvalidKeyId" | "UnsupportedParameterType" => Error::Backend {
            scheme: "aws-ssm",
            kind: BackendFailureKind::Permanent,
            message: format!("AWS service error ({code}): {message}"),
        },
        _ => Error::Backend {
            scheme: "aws-ssm",
            kind: BackendFailureKind::Permanent,
            message: format!("AWS service error ({code}): {message}"),
        },
    }
}

/// Map non-service SDK errors (timeouts, dispatch failures, construction
/// failures) into the locked `hasp_core::Error` taxonomy.
fn map_generic_error<E: std::fmt::Display>(err: aws_sdk_ssm::error::SdkError<E>) -> Error {
    use aws_sdk_ssm::error::SdkError;
    match err {
        SdkError::TimeoutError(_) => Error::Backend {
            scheme: "aws-ssm",
            kind: BackendFailureKind::Transient,
            message: "AWS request timed out".into(),
        },
        SdkError::DispatchFailure(_) => Error::Backend {
            scheme: "aws-ssm",
            kind: BackendFailureKind::Transient,
            message: "AWS request dispatch failed".into(),
        },
        _ => Error::Backend {
            scheme: "aws-ssm",
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
        let url = Url::parse("aws-ssm://us-east-1/my-param").unwrap();
        let aws = AwsSsmUrl::try_from(&url).unwrap();
        assert_eq!(aws.region, "us-east-1");
        assert_eq!(aws.parameter_name, "my-param");
        assert!(aws.with_decryption);
    }

    #[test]
    fn parse_valid_url_with_path() {
        let url = Url::parse("aws-ssm://us-west-2/prod/app/db-password").unwrap();
        let aws = AwsSsmUrl::try_from(&url).unwrap();
        assert_eq!(aws.region, "us-west-2");
        assert_eq!(aws.parameter_name, "prod/app/db-password");
    }

    #[test]
    fn parse_valid_url_with_decryption_false() {
        let url = Url::parse("aws-ssm://eu-west-1/my-param?with-decryption=false").unwrap();
        let aws = AwsSsmUrl::try_from(&url).unwrap();
        assert!(!aws.with_decryption);
    }

    #[test]
    fn parse_valid_url_with_decryption_true() {
        let url = Url::parse("aws-ssm://ap-south-1/my-param?with-decryption=true").unwrap();
        let aws = AwsSsmUrl::try_from(&url).unwrap();
        assert!(aws.with_decryption);
    }

    #[test]
    fn parse_missing_host_fails() {
        let url = Url::parse("aws-ssm:///my-param").unwrap();
        assert!(AwsSsmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_empty_path_fails() {
        let url = Url::parse("aws-ssm://us-east-1/").unwrap();
        assert!(AwsSsmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_unknown_query_fails() {
        let url = Url::parse("aws-ssm://us-east-1/my-param?version=1").unwrap();
        assert!(AwsSsmUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_invalid_decryption_value_fails() {
        let url = Url::parse("aws-ssm://us-east-1/my-param?with-decryption=maybe").unwrap();
        assert!(AwsSsmUrl::try_from(&url).is_err());
    }

    #[test]
    fn error_map_parameter_not_found() {
        let err = from_service_error("ParameterNotFound", "parameter not found");
        assert!(matches!(err, Error::NotFound(ref s) if s.contains("parameter not found")));
    }

    #[test]
    fn error_map_parameter_version_not_found() {
        let err = from_service_error("ParameterVersionNotFound", "version gone");
        assert!(matches!(err, Error::NotFound(ref s) if s.contains("version gone")));
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
    fn error_map_unauthorized() {
        let err = from_service_error("UnauthorizedException", "who are you");
        assert!(matches!(err, Error::AuthenticationFailed(ref s) if s.contains("who are you")));
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
    fn error_map_internal_server_error_is_transient() {
        let err = from_service_error("InternalServerError", "oops");
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
    fn backend_new_ok() {
        let _backend = AwsSsmBackend::new();
    }

    #[test]
    fn backend_scheme() {
        let backend = AwsSsmBackend::new();
        assert_eq!(backend.scheme(), "aws-ssm");
    }

    #[test]
    fn unsupported_operations() {
        let backend = AwsSsmBackend::new();
        let url = Url::parse("aws-ssm://us-east-1/test").unwrap();
        let dummy = SecretString::new("x".into());

        assert!(matches!(
            backend.put(&url, &dummy),
            Err(Error::UnsupportedOperation {
                scheme: "aws-ssm",
                operation: "put"
            })
        ));
        assert!(matches!(
            backend.list(&url),
            Err(Error::UnsupportedOperation {
                scheme: "aws-ssm",
                operation: "list"
            })
        ));
        assert!(matches!(
            backend.delete(&url),
            Err(Error::UnsupportedOperation {
                scheme: "aws-ssm",
                operation: "delete"
            })
        ));
    }
}
