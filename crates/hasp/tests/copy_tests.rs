#[cfg(all(feature = "env", feature = "file"))]
mod copy_tests {
    use hasp::ExposeSecret;
    use hasp::{CopyOptions, IfExists, SecretString, Store};
    use hasp_core::test_utils::{EnvGuard, ENV_LOCK};

    fn write_file(path: &std::path::Path, value: &str) {
        std::fs::write(path, value).unwrap();
    }

    fn read_file(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn file_to_file_happy_path_default_fail_when_dst_missing() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        write_file(&src_path, "alpha");

        let src_url = format!("file://{}", src_path.display());
        let dst_url = format!("file://{}", dst_path.display());

        let store = Store::with_defaults();
        let outcome = store
            .copy(&src_url, &dst_url, CopyOptions::default())
            .expect("copy succeeds when dst missing");
        assert!(outcome.copied);
        assert!(!outcome.verified);
        assert_eq!(read_file(&dst_path), "alpha");
    }

    #[test]
    fn file_to_file_fail_when_dst_exists() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        write_file(&src_path, "fresh");
        write_file(&dst_path, "stale");

        let src_url = format!("file://{}", src_path.display());
        let dst_url = format!("file://{}", dst_path.display());

        let store = Store::with_defaults();
        let err = store
            .copy(&src_url, &dst_url, CopyOptions::default())
            .expect_err("copy with default Fail must refuse when dst occupied");
        match err {
            hasp::Error::PreconditionFailed(_) => {}
            other => panic!("expected PreconditionFailed, got {other:?}"),
        }
        // dst untouched
        assert_eq!(read_file(&dst_path), "stale");
    }

    #[test]
    fn file_to_file_overwrite_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        write_file(&src_path, "fresh");
        write_file(&dst_path, "stale");

        let src_url = format!("file://{}", src_path.display());
        let dst_url = format!("file://{}", dst_path.display());

        let store = Store::with_defaults();
        let outcome = store
            .copy(
                &src_url,
                &dst_url,
                CopyOptions {
                    if_exists: IfExists::Overwrite,
                    ..Default::default()
                },
            )
            .expect("overwrite must succeed regardless of dst state");
        assert!(outcome.copied);
        assert_eq!(read_file(&dst_path), "fresh");
    }

    #[test]
    fn file_to_file_skip_leaves_dst_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        write_file(&src_path, "fresh");
        write_file(&dst_path, "stale");

        let src_url = format!("file://{}", src_path.display());
        let dst_url = format!("file://{}", dst_path.display());

        let store = Store::with_defaults();
        let outcome = store
            .copy(
                &src_url,
                &dst_url,
                CopyOptions {
                    if_exists: IfExists::Skip,
                    ..Default::default()
                },
            )
            .expect("skip succeeds when dst exists");
        assert!(!outcome.copied);
        assert_eq!(read_file(&dst_path), "stale");
    }

    #[test]
    fn env_to_file_cross_backend() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set("HASP_COPY_SRC", "from-env");

        let dir = tempfile::tempdir().unwrap();
        let dst_path = dir.path().join("dst.txt");

        let dst_url = format!("file://{}", dst_path.display());
        let store = Store::with_defaults();
        let outcome = store
            .copy("env://HASP_COPY_SRC", &dst_url, CopyOptions::default())
            .expect("env to file copy succeeds");
        assert!(outcome.copied);
        assert_eq!(read_file(&dst_path), "from-env");
    }

    #[test]
    fn file_to_env_rejects_with_unsupported_operation() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        write_file(&src_path, "x");
        let src_url = format!("file://{}", src_path.display());

        let store = Store::with_defaults();
        let err = store
            .copy(&src_url, "env://SOME_VAR", CopyOptions::default())
            .expect_err("env:// does not support put");
        match err {
            hasp::Error::UnsupportedOperation { scheme: "env", .. } => {}
            other => panic!("expected UnsupportedOperation, got {other:?}"),
        }
    }

    #[test]
    fn same_url_self_copy_refused() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("a.txt");
        write_file(&src_path, "x");
        let url = format!("file://{}", src_path.display());

        let store = Store::with_defaults();
        let err = store
            .copy(&url, &url, CopyOptions::default())
            .expect_err("self-copy must refuse");
        match err {
            hasp::Error::InvalidUrl(msg) => {
                assert!(msg.contains("identical"));
            }
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn dry_run_does_not_read_or_write() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        write_file(&src_path, "real");
        // dst absent

        let src_url = format!("file://{}", src_path.display());
        let dst_url = format!("file://{}", dst_path.display());

        let store = Store::with_defaults();
        let outcome = store
            .copy(
                &src_url,
                &dst_url,
                CopyOptions {
                    dry_run: true,
                    ..Default::default()
                },
            )
            .expect("dry run resolves both backends");
        assert!(!outcome.copied);
        assert!(!dst_path.exists(), "dry_run must not create dst");
    }

    #[test]
    fn verify_happy_path_returns_verified_true() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        write_file(&src_path, "value");

        let src_url = format!("file://{}", src_path.display());
        let dst_url = format!("file://{}", dst_path.display());

        let store = Store::with_defaults();
        let outcome = store
            .copy(
                &src_url,
                &dst_url,
                CopyOptions {
                    verify: true,
                    ..Default::default()
                },
            )
            .expect("verify happy path");
        assert!(outcome.copied);
        assert!(outcome.verified);
    }

    #[test]
    fn copy_preserves_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        // Include a value with leading/trailing whitespace and a newline
        // to confirm the file backend round-trips it. File backend
        // trims one trailing newline on read by default (see
        // RESEARCH-file-trim.md), so we use a value without one to
        // keep the byte-equal invariant.
        let value = "abc\n\ndef ghi";
        write_file(&src_path, value);

        let src_url = format!("file://{}", src_path.display());
        let dst_url = format!("file://{}", dst_path.display());

        let store = Store::with_defaults();
        let outcome = store
            .copy(
                &src_url,
                &dst_url,
                CopyOptions {
                    verify: true,
                    ..Default::default()
                },
            )
            .expect("copy + verify");
        assert!(outcome.verified);

        let src_secret = store.get(&src_url).unwrap();
        let dst_secret = store.get(&dst_url).unwrap();
        assert_eq!(
            src_secret.expose_secret(),
            dst_secret.expose_secret(),
            "round-trip bytes must match"
        );
    }

    #[test]
    fn unknown_scheme_on_src_propagates() {
        let store = Store::with_defaults();
        let err = store
            .copy("nope://x", "env://Y", CopyOptions::default())
            .expect_err("unknown src scheme");
        assert!(matches!(err, hasp::Error::UnknownScheme(_)));
    }

    #[test]
    fn unknown_scheme_on_dst_propagates() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set("HASP_COPY_UNK_SRC", "v");
        let store = Store::with_defaults();
        let err = store
            .copy(
                "env://HASP_COPY_UNK_SRC",
                "nope://x",
                CopyOptions::default(),
            )
            .expect_err("unknown dst scheme");
        assert!(matches!(err, hasp::Error::UnknownScheme(_)));
    }

    #[test]
    fn copy_busts_dst_cache_via_put() {
        use std::time::Duration;
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EnvGuard::set("HASP_COPY_CACHE_SRC", "from-src");

        let dir = tempfile::tempdir().unwrap();
        let dst_path = dir.path().join("cached.txt");
        write_file(&dst_path, "before");
        let dst_url = format!("file://{}", dst_path.display());

        let store = hasp::StoreBuilder::with_defaults()
            .cache_ttl(Some(Duration::from_secs(60)))
            .build();
        // Prime the cache for dst_url.
        let cached_before = store.get(&dst_url).unwrap();
        assert_eq!(cached_before.expose_secret(), "before");

        // Copy with overwrite — should invalidate the cache so the
        // next get returns the new value.
        let _ = store
            .copy(
                "env://HASP_COPY_CACHE_SRC",
                &dst_url,
                CopyOptions {
                    if_exists: IfExists::Overwrite,
                    ..Default::default()
                },
            )
            .unwrap();

        let cached_after = store.get(&dst_url).unwrap();
        assert_eq!(cached_after.expose_secret(), "from-src");
    }

    /// `SecretString::new` is intentionally not exercised here in the
    /// trivial way that consumers might — `cp` accepts URLs, never
    /// values, so this test merely confirms the import compiles.
    #[allow(dead_code)]
    fn _import_check(_s: SecretString) {}
}
