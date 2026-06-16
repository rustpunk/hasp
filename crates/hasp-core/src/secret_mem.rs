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
/// ## Scope of the lock
///
/// `lock_secret_pages` pins the pages backing the **final** `SecretString`
/// allocation. It does **not** address heap residue from prior
/// allocations:
///
/// - `String::into_boxed_str()` may shrink-to-fit, freeing the
///   original `String` buffer without zeroization.
/// - The caller's `String` may have been grown via `push_str` /
///   `read_to_string`, leaving the secret bytes in freed segments.
///
/// In practice this is acceptable for unprivileged CLI processes —
/// the residue lives in the same uid's address space that already had
/// the plaintext on the stack — but it is **not** a defense against
/// kernel-side swap or post-mortem heap forensics. Callers that need
/// the stronger guarantee should fetch directly into a pre-allocated
/// `SecretString` (e.g., via a sized `Read` interface) rather than
/// growing a `String` and wrapping it.
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
