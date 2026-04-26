use thiserror::Error;

/// hasp library-surface errors. Stable across all backends; backend impls
/// map their native error vocabulary into these variants.
///
/// This enum is intentionally flat so consumers can match on variants
/// without string-matching nested SDK-style error hierarchies.
#[non_exhaustive]
#[derive(Debug, Error, Clone)]
pub enum Error {
    /// URL parse failure at the `url` crate layer (malformed URI).
    #[error("invalid URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// URL parsed but does not satisfy a backend-specific grammar rule
    /// (e.g. wrong path-segment count, missing required component).
    #[error("invalid URL for backend: {0}")]
    InvalidUrl(String),

    /// URL scheme is not registered in this Store.
    #[error("unsupported scheme: {0}")]
    UnknownScheme(String),

    /// Backend recognized the URL but does not implement the requested verb
    /// (e.g. `env://` does not support `put`).
    #[error("{scheme} does not support {operation}")]
    UnsupportedOperation {
        scheme: &'static str,
        operation: &'static str,
    },

    /// The addressed secret does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// Caller's credentials are valid; caller is not authorized for this resource.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Caller's credentials are missing, invalid, or expired.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Resource is in a state that blocks the operation, even though the caller
    /// has permission and the resource exists.
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    /// Backend-specific failure that does not fit a more-specific variant.
    /// `kind` provides retry guidance; `message` carries diagnostic detail
    /// (backend error code, HTTP status, sub-error). Never includes secret values.
    #[error("backend '{scheme}' failed: {message}")]
    Backend {
        scheme: &'static str,
        kind: BackendFailureKind,
        message: String,
    },
}

/// Retry-policy classification for `Error::Backend`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailureKind {
    /// Temporary failure; retry with exponential backoff.
    Transient,

    /// Backend is rate-limiting the caller. Retry honoring any Retry-After
    /// signal surfaced in `Backend.message`.
    Throttled,

    /// Permanent failure; retry will not help without external action.
    Permanent,
}

impl Error {
    /// True if a retry has any chance of succeeding without external action.
    ///
    /// Returns `true` for `Backend { kind: Transient | Throttled, .. }`.
    /// Returns `false` for everything else, including `NotFound`,
    /// `PermissionDenied`, `AuthenticationFailed`, `PreconditionFailed`.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Backend {
                kind: BackendFailureKind::Transient | BackendFailureKind::Throttled,
                ..
            }
        )
    }
}
