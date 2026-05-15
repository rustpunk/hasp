//! Property-based URL parsing tests via the public `Store` API.
//!
//! Each registered backend parses its URL internally. These tests exercise
//! the parse path indirectly through `Store::get`/`exists`, asserting that
//! malformed URLs never cause panics and unknown schemes are rejected.
//!
//! TODO: per-backend URL property tests for AWS, GCP, Azure, Vault (they require
//! network or heavy mocking — see ideation "Quality: Property-based URL parsing").

use hasp::{Error, Store};
use proptest::prelude::*;

/// Closed set of feature-gated scheme strings the workspace might
/// register. Any generator output that matches one of these is
/// `prop_assume!`-skipped — for a registered scheme, the answer is
/// "backend-specific URL parse error" or "backend init error", not
/// the `UnknownScheme` invariant under test here.
const REGISTERED_SCHEMES: &[&str] = &[
    "env", "file", "keyring", "op", "vault", "bw", "aws-sm", "aws-ssm", "gcp-sm", "azure-kv",
];

// Any URL with an unknown scheme must yield Error::UnknownScheme.
proptest! {
    #[test]
    fn unknown_scheme_always_unknown(scheme in "[a-z]+", rest in "[A-Za-z0-9/._-]+") {
        prop_assume!(!REGISTERED_SCHEMES.contains(&scheme.as_str()));
        let store = Store::with_defaults();
        let url = format!("{}://{}", scheme, rest);
        let result = store.get(&url);
        prop_assert!(
            matches!(result, Err(Error::UnknownScheme(ref s)) if s == &scheme),
            "expected UnknownScheme({scheme}), got {result:?}"
        );
    }
}

#[cfg(feature = "env")]
proptest! {
    #[test]
    fn env_valid_url_doesnt_panic(var in "[A-Z_][A-Z0-9_]{0,60}") {
        let store = Store::with_defaults();
        let url = format!("env://{var}");
        let _ = store.get(&url);
    }
}

#[cfg(feature = "file")]
proptest! {
    #[test]
    fn file_valid_url_doesnt_panic(path in "/[A-Za-z0-9_/-]+\\.[a-z]+") {
        let store = Store::with_defaults();
        let url = format!("file://{path}");
        let _ = store.get(&url);
    }
}
