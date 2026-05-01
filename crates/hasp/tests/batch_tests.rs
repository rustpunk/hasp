#[cfg(feature = "env")]
mod batch_tests {
    use hasp::{Store, SecretString};
    use hasp_core::test_utils::{EnvGuard, ENV_LOCK};
    use hasp::ExposeSecret;

    #[test]
    fn batch_get_deduplicates_and_collects() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _a = EnvGuard::set("HASP_BATCH_A", "alpha");
        let _b = EnvGuard::set("HASP_BATCH_B", "beta");

        let store = Store::with_defaults();
        let urls = [
            "env://HASP_BATCH_A",
            "env://HASP_BATCH_B",
            "env://HASP_BATCH_A", // duplicate
            "env://HASP_BATCH_MISSING",
        ];
        let results = store.batch_get(&urls);

        assert_eq!(results.len(), 4);
        assert_eq!(results[0].as_ref().unwrap().expose_secret(), "alpha");
        assert_eq!(results[1].as_ref().unwrap().expose_secret(), "beta");
        assert_eq!(results[2].as_ref().unwrap().expose_secret(), "alpha");
        assert!(results[3].is_err());
    }

    #[test]
    fn bulk_put_collects_per_item() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.txt");
        let path_b = dir.path().join("b.txt");

        let url_a = format!("file://{}", path_a.display());
        let url_b = format!("file://{}", path_b.display());
        let val_a = SecretString::new("val-a".into());
        let val_b = SecretString::new("val-b".into());

        let store = Store::with_defaults();
        let items: Vec<(&str, &SecretString)> = vec![
            (&url_a, &val_a),
            (&url_b, &val_b),
        ];
        let results = store.bulk_put(&items);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());

        assert_eq!(
            std::fs::read_to_string(&path_a).unwrap(),
            "val-a"
        );
        assert_eq!(
            std::fs::read_to_string(&path_b).unwrap(),
            "val-b"
        );
    }

    #[test]
    fn bulk_put_one_failure_others_succeed() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.txt");

        let url_env = "env://HASP_BULK_PUT_X".to_string();
        let url_file = format!("file://{}", path.display());
        let val_env = SecretString::new("x".into());
        let val_file = SecretString::new("val".into());

        let store = Store::with_defaults();
        let items: Vec<(&str, &SecretString)> = vec![
            (&url_env, &val_env),
            (&url_file, &val_file),
        ];
        let results = store.bulk_put(&items);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_err());
        assert!(results[1].is_ok());
    }
}
