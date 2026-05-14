//! Helper for wrapping secret bytes in a `SecretString` with optional
//! memory-locking when the `memory-lock` feature is enabled.

use crate::SecretString;

/// Wrap `value` in a `SecretString`.
///
/// When the `memory-lock` feature is enabled, the backing allocation
/// is locked into physical memory and configured to be excluded from
/// core dumps and process forks via `lock_secret_pages`. On failure
/// (e.g., `RLIMIT_MEMLOCK` exhausted) the secret is still wrapped and
/// returned — the degrade is silent at this call site. Callers that
/// want to surface the outcome can call
/// `hasp_core::lock_secret_pages(s.expose_secret().as_bytes())` directly.
///
/// # Usage pattern for backend implementors
///
/// ```no_run
/// use hasp_core::secret_mem::wrap_secret;
/// // Instead of:
/// //   Ok(hasp_core::SecretString::new(value.into()))
/// // Write:
/// //   Ok(wrap_secret(value))
/// ```
pub fn wrap_secret(value: String) -> SecretString {
    let s = SecretString::new(value.into_boxed_str());
    #[cfg(feature = "memory-lock")]
    {
        use crate::ExposeSecret;
        let _ = crate::hardening::lock_secret_pages(s.expose_secret().as_bytes());
    }
    s
}
