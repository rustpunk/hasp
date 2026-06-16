//! Helpers for wrapping secret bytes in a `SecretString` with optional
//! memory-locking when the `memory-lock` feature is enabled, and for
//! reading a secret value into a pre-sized buffer (the heap-residue
//! mitigation path for backends with a known transport size).

use crate::SecretString;
use std::io::Read;

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
/// the stronger guarantee should fetch via [`Backend::get_into`] (or
/// build the value with [`read_to_secret_string`]) so the plaintext
/// lives in a buffer allocated to exact fit, never grown.
///
/// [`Backend::get_into`]: crate::Backend::get_into
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

/// Read a UTF-8 secret of known size into a `SecretString` with an
/// exact-fit allocation.
///
/// `size_hint` should be the transport-reported size (file metadata,
/// `Content-Length`). The function reserves that many bytes up front,
/// then `read_to_string` reads to EOF. When the source matches the
/// hint, the buffer never reallocates — the byte sequence touches one
/// heap allocation only, eliminating the realloc-leak path described
/// on [`wrap_secret`].
///
/// When the source is larger than the hint (a benign race between
/// `metadata` and `read`), `read_to_string` grows the buffer as
/// needed — semantically correct, residue-equivalent to the unsized
/// `read_to_string` baseline. The exact-fit win is the common case,
/// not a hard guarantee.
///
/// # Errors
///
/// Forwards I/O errors from the reader. Returns
/// `io::ErrorKind::OutOfMemory` when the up-front reservation fails.
pub fn read_to_secret_string<R: Read>(
    mut reader: R,
    size_hint: usize,
) -> std::io::Result<SecretString> {
    let mut buf = String::new();
    buf.try_reserve_exact(size_hint)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e.to_string()))?;
    reader.read_to_string(&mut buf)?;
    Ok(wrap_secret(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSecret;
    use std::io::Cursor;

    #[test]
    fn read_to_secret_string_exact_size() {
        let payload = "exact-fit-secret";
        let s = read_to_secret_string(Cursor::new(payload), payload.len()).unwrap();
        assert_eq!(s.expose_secret(), payload);
    }

    #[test]
    fn read_to_secret_string_grows_when_source_exceeds_hint() {
        let payload = "longer-than-hint";
        let s = read_to_secret_string(Cursor::new(payload), 4).unwrap();
        assert_eq!(s.expose_secret(), payload);
    }

    #[test]
    fn read_to_secret_string_empty() {
        let s = read_to_secret_string(Cursor::new(""), 0).unwrap();
        assert_eq!(s.expose_secret(), "");
    }
}
