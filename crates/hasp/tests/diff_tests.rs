#[cfg(all(feature = "env", feature = "file"))]
mod diff_tests {
    use hasp::{DiffOutcome, Store};
    use hasp_core::test_utils::{EnvGuard, ENV_LOCK};

    fn write_file(path: &std::path::Path, value: &str) {
        std::fs::write(path, value).unwrap();
    }

    #[test]
    fn file_to_file_match() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        write_file(&a, "same-value");
        write_file(&b, "same-value");

        let a_url = format!("file://{}", a.display());
        let b_url = format!("file://{}", b.display());

        let store = Store::with_defaults();
        let outcome = store.compare(&a_url, &b_url).expect("compare succeeds");
        assert_eq!(outcome, DiffOutcome::Match);
    }

    #[test]
    fn file_to_file_differ() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        write_file(&a, "alpha");
        write_file(&b, "beta");

        let a_url = format!("file://{}", a.display());
        let b_url = format!("file://{}", b.display());

        let store = Store::with_defaults();
        let outcome = store.compare(&a_url, &b_url).expect("compare succeeds");
        assert_eq!(outcome, DiffOutcome::Differ);
    }

    #[test]
    fn length_mismatch_reports_differ_not_error() {
        // A different-length pair is still a binary Differ — diff
        // must not surface a length-derived signal as a separate
        // outcome (would leak that source and dest were the same
        // length but content-different, narrowing the search space).
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        write_file(&a, "short");
        write_file(&b, "considerably-longer-value");

        let a_url = format!("file://{}", a.display());
        let b_url = format!("file://{}", b.display());

        let store = Store::with_defaults();
        let outcome = store.compare(&a_url, &b_url).expect("compare succeeds");
        assert_eq!(outcome, DiffOutcome::Differ);
    }

    #[test]
    fn env_to_file_cross_backend() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set("HASP_DIFF_VAR", "value-from-env");

        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f.txt");
        write_file(&f, "value-from-env");
        let f_url = format!("file://{}", f.display());

        let store = Store::with_defaults();
        let outcome = store
            .compare("env://HASP_DIFF_VAR", &f_url)
            .expect("compare across env and file");
        assert_eq!(outcome, DiffOutcome::Match);
    }

    #[test]
    fn same_url_self_diff_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        write_file(&f, "x");
        let url = format!("file://{}", f.display());

        let store = Store::with_defaults();
        let err = store
            .compare(&url, &url)
            .expect_err("self-diff must refuse");
        match err {
            hasp::Error::InvalidUrl(msg) => assert!(msg.contains("identical")),
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn unknown_scheme_propagates_before_io() {
        let store = Store::with_defaults();
        let err = store
            .compare("nope://a", "env://X")
            .expect_err("unknown scheme on a");
        assert!(matches!(err, hasp::Error::UnknownScheme(_)));
    }

    #[test]
    fn missing_secret_propagates_as_not_found() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();
        // env://A unset, env://B unset — first get fails fast.
        let err = store
            .compare("env://HASP_DIFF_MISSING_A", "env://HASP_DIFF_MISSING_B")
            .expect_err("missing env vars surface as NotFound");
        assert!(matches!(err, hasp::Error::NotFound(_)));
    }
}
