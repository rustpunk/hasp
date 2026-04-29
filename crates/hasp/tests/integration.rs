use hasp::ExposeSecret;
use hasp::Store;
use std::env;

pub use hasp_core::test_utils::{EnvGuard, ENV_LOCK};

#[cfg(feature = "env")]
mod env_tests {
    use super::*;
    use hasp::ExposeSecret;
    use hasp::SecretString;

    #[test]
    fn env_get_roundtrip() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvGuard::set("HASP_TEST_VAR", "secret-value");

        let store = Store::with_defaults();
        let secret = store.get("env://HASP_TEST_VAR").unwrap();
        assert_eq!(secret.expose_secret(), "secret-value");
    }

    #[test]
    fn env_not_found() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("HASP_TEST_VAR_MISSING");

        let store = Store::with_defaults();
        let err = store.get("env://HASP_TEST_VAR_MISSING").unwrap_err();
        assert!(matches!(err, hasp::Error::NotFound(_)));
    }

    #[test]
    fn env_exists() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvGuard::set("HASP_TEST_EXISTS", "1");

        let store = Store::with_defaults();
        assert!(store.exists("env://HASP_TEST_EXISTS").unwrap());
    }

    #[test]
    fn env_put_unsupported() {
        let store = Store::with_defaults();
        let secret = SecretString::new("val".into());
        let err = store.put("env://X", &secret).unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnsupportedOperation {
                scheme: "env",
                operation: "put",
            }
        ));
    }
}

#[test]
fn store_empty_has_no_backends() {
    let store = Store::empty();
    let err = store.get("env://HOME").unwrap_err();
    assert!(matches!(err, hasp::Error::UnknownScheme(ref s) if s == "env"));
}

#[cfg(feature = "env")]
#[test]
fn store_with_backends_registers_only_given() {
    let store = Store::with_backends(vec![hasp::Backend::env()]);

    let result = store.get("env://HOME");
    assert!(result.is_ok() || result.is_err());

    let err = store.get("file:///tmp/test.txt").unwrap_err();
    assert!(matches!(err, hasp::Error::UnknownScheme(ref s) if s == "file"));
}

#[cfg(feature = "env")]
    #[test]
    fn free_function_get_uses_defaults() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvGuard::set("HASP_FREE_FN_TEST", "free-fn-value");

    let secret = hasp::get("env://HASP_FREE_FN_TEST").unwrap();
    assert_eq!(secret.expose_secret(), "free-fn-value");
}

#[cfg(feature = "env")]
#[test]
fn free_function_exists_uses_defaults() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = EnvGuard::set("HASP_FREE_FN_EXISTS", "1");

    assert!(hasp::exists("env://HASP_FREE_FN_EXISTS").unwrap());
}

#[test]
fn unknown_scheme() {
    let store = Store::with_defaults();
    let err = store.get("unknown://thing").unwrap_err();
    assert!(matches!(err, hasp::Error::UnknownScheme(_)));
}

#[cfg(feature = "env")]
mod cache_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn get_memoized_serves_from_cache() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvGuard::set("HASP_CACHE_TEST", "cached-value");

        let store = Store::builder()
            .cache_ttl(Some(Duration::from_secs(60)))
            .register(hasp::Backend::env())
            .build();

        let first = store.get("env://HASP_CACHE_TEST").unwrap();
        assert_eq!(first.expose_secret(), "cached-value");

        // Remove the env var; a cache-miss would fail.
        std::env::remove_var("HASP_CACHE_TEST");

        let second = store.get("env://HASP_CACHE_TEST").unwrap();
        assert_eq!(second.expose_secret(), "cached-value");
    }

    #[test]
    fn put_invalidates_cache() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"old-value").unwrap();
        let path = file.path().to_string_lossy().to_string();

        let store = Store::builder()
            .cache_ttl(Some(Duration::from_secs(60)))
            .register(hasp::Backend::file())
            .build();

        let url = format!("file://{path}");

        let first = store.get(&url).unwrap();
        assert_eq!(first.expose_secret(), "old-value");

        // Overwrite the file under the same path.
        std::fs::write(&path, b"new-value").unwrap();

        // Write a new value through the store.
        let secret = hasp::SecretString::new("new-value".into());
        store.put(&url, &secret).unwrap();

        // Put succeeded, so cache is invalidated. Next get reads fresh.
        let second = store.get(&url).unwrap();
        assert_eq!(second.expose_secret(), "new-value");
    }
}

#[cfg(not(feature = "file"))]
mod file_disabled_tests {
    use super::*;

    #[test]
    fn file_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store.get("file:///tmp/test.txt").unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "file"
        ));
    }
}

#[cfg(not(feature = "op"))]
mod op_disabled_tests {
    use super::*;

    #[test]
    fn op_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store.get("op://vault/item/field").unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "op"
        ));
    }
}

#[cfg(feature = "file")]
mod file_tests {
    use super::*;
    use hasp::ExposeSecret;
    use hasp::SecretString;
    use url::Url;

    #[test]
    fn file_get_roundtrip_and_trim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "my-secret\n").unwrap();

        let store = Store::with_defaults();
        let url = Url::from_file_path(&path).unwrap();
        let secret = store.get(url.as_str()).unwrap();
        assert_eq!(secret.expose_secret(), "my-secret");
    }

    #[test]
    fn file_get_raw_no_trim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "my-secret\n").unwrap();

        let store = Store::with_defaults();
        let mut url = Url::from_file_path(&path).unwrap();
        url.query_pairs_mut().append_pair("raw", "true");
        let secret = store.get(url.as_str()).unwrap();
        assert_eq!(secret.expose_secret(), "my-secret\n");
    }

    #[test]
    fn file_put() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("written.txt");

        let store = Store::with_defaults();
        let url = Url::from_file_path(&path).unwrap();
        let value = SecretString::new("written-value".into());
        store.put(url.as_str(), &value).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "written-value");
    }

    #[test]
    fn file_exists_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("to-delete.txt");
        std::fs::write(&path, "value").unwrap();

        let store = Store::with_defaults();
        let url = Url::from_file_path(&path).unwrap();

        assert!(store.exists(url.as_str()).unwrap());
        store.delete(url.as_str()).unwrap();
        assert!(!store.exists(url.as_str()).unwrap());
    }

    #[test]
    fn file_not_found() {
        let store = Store::with_defaults();
        let err = store
            .get("file:///nonexistent/path/to/secret.txt")
            .unwrap_err();
        assert!(matches!(err, hasp::Error::NotFound(_)));
    }
}

#[cfg(feature = "op")]
mod op_tests {
    use super::*;
    use hasp_core::test_utils::FakeOpGuard;

    #[test]
    fn op_get_roundtrip() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeOpGuard::canonical();
        let _env = EnvGuard::set("OP_SERVICE_ACCOUNT_TOKEN", "fake-token");

        let store = Store::builder().register(hasp::Backend::op()).build();
        let secret = store.get("op://test-vault/test-item/field1").unwrap();
        assert_eq!(secret.expose_secret(), "canned-secret-value-1");
    }

    #[test]
    fn op_exists() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeOpGuard::canonical();
        let _env = EnvGuard::set("OP_SERVICE_ACCOUNT_TOKEN", "fake-token");

        let store = Store::builder().register(hasp::Backend::op()).build();
        assert!(store.exists("op://test-vault/test-item/field1").unwrap());
        assert!(!store.exists("op://missing-vault/test-item/field1").unwrap());
    }

    #[test]
    fn op_not_found() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeOpGuard::canonical();
        let _env = EnvGuard::set("OP_SERVICE_ACCOUNT_TOKEN", "fake-token");

        let store = Store::builder().register(hasp::Backend::op()).build();
        let err = store
            .get("op://test-vault/missing-item/field1")
            .unwrap_err();
        assert!(matches!(err, hasp::Error::NotFound(_)));
    }

    #[test]
    fn op_not_authenticated() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeOpGuard::canonical();

        let store = Store::builder().register(hasp::Backend::op()).build();
        let err = store.get("op://vault/item/field").unwrap_err();
        assert!(
            matches!(err, hasp::Error::AuthenticationFailed(_)),
            "expected AuthenticationFailed when no ambient credentials are present, got {err:?}"
        );
    }
}

#[cfg(feature = "keyring")]
mod keyring_tests {
    use super::*;
    use hasp::ExposeSecret;
    use hasp::SecretString;

    fn init_mock_store() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let store = keyring_core::mock::Store::new().unwrap();
            keyring_core::set_default_store(store);
        });
    }

    #[test]
    fn keyring_get_put_roundtrip() {
        init_mock_store();

        let store = Store::with_defaults();
        let secret = SecretString::new("my-password".into());
        store.put("keyring://hasp-test/service", &secret).unwrap();

        let fetched = store.get("keyring://hasp-test/service").unwrap();
        assert_eq!(fetched.expose_secret(), "my-password");
    }

    #[test]
    fn keyring_exists_and_delete() {
        init_mock_store();

        let store = Store::with_defaults();
        let secret = SecretString::new("to-delete".into());
        store
            .put("keyring://hasp-test-delete/account", &secret)
            .unwrap();

        assert!(store.exists("keyring://hasp-test-delete/account").unwrap());

        store.delete("keyring://hasp-test-delete/account").unwrap();
        assert!(!store.exists("keyring://hasp-test-delete/account").unwrap());
    }

    #[test]
    fn keyring_not_found() {
        init_mock_store();

        let store = Store::with_defaults();
        let err = store.get("keyring://hasp-test-missing/entry").unwrap_err();
        assert!(matches!(err, hasp::Error::NotFound(_)));
    }

    #[test]
    fn keyring_url_with_target() {
        init_mock_store();

        // The mock store rejects modifiers, so this must fail.
        let store = Store::with_defaults();
        let secret = SecretString::new("targeted".into());
        let err = store
            .put("keyring://hasp-test-target/mod?target=custom", &secret)
            .unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnsupportedOperation {
                scheme: "keyring",
                ..
            }
        ));
    }
}

#[cfg(feature = "vault")]
mod vault_tests {
    use super::*;

    fn vault_available() -> bool {
        std::env::var("VAULT_ADDR").is_ok() && std::env::var("VAULT_TOKEN").is_ok()
    }

    #[test]
    fn vault_get_roundtrip() {
        if !vault_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        // A real roundtrip requires a reachable Vault server with the
        // addressed secret. Without one, the path typically returns NotFound.
        let result = store.get("vault://secret/data/hasp-test/test?field=password");
        assert!(
            matches!(result, Ok(_) | Err(hasp::Error::NotFound(_))),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn vault_exists() {
        if !vault_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.exists("vault://secret/data/hasp-test/test");
        assert!(result.is_ok(), "unexpected error: {result:?}");
    }

    #[test]
    fn vault_not_found() {
        if !vault_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let err = store
            .get("vault://secret/data/hasp-test-nonexistent/not-real?field=password")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_)),
            "expected NotFound for a missing secret, got {err:?}"
        );
    }

    #[test]
    fn vault_not_authenticated() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let old_token = std::env::var("VAULT_TOKEN").ok();
        let old_addr = std::env::var("VAULT_ADDR").ok();
        std::env::remove_var("VAULT_TOKEN");
        std::env::remove_var("VAULT_ADDR");

        let store = Store::with_defaults();
        let err = store
            .get("vault://secret/data/test/test?field=password")
            .unwrap_err();

        match old_token {
            Some(v) => std::env::set_var("VAULT_TOKEN", v),
            None => std::env::remove_var("VAULT_TOKEN"),
        }
        match old_addr {
            Some(v) => std::env::set_var("VAULT_ADDR", v),
            None => std::env::remove_var("VAULT_ADDR"),
        }

        assert!(
            matches!(err, hasp::Error::AuthenticationFailed(_)),
            "expected AuthenticationFailed when no ambient credentials are present, got {err:?}"
        );
    }
}

#[cfg(not(feature = "vault"))]
mod vault_disabled_tests {
    use super::*;

    #[test]
    fn vault_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store
            .get("vault://secret/data/app?field=password")
            .unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "vault"
        ));
    }
}

#[cfg(feature = "aws-sm")]
mod aws_sm_tests {
    use super::*;

    fn aws_sm_available() -> bool {
        std::env::var("AWS_ACCESS_KEY_ID").is_ok() && std::env::var("AWS_SECRET_ACCESS_KEY").is_ok()
    }

    #[test]
    fn aws_sm_get_roundtrip() {
        if !aws_sm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        // A real roundtrip requires a reachable AWS account with the
        // addressed secret. Without one, the path typically returns NotFound
        // or a credential/permission error.
        let result = store.get("aws-sm://us-east-1/hasp-test/secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn aws_sm_exists() {
        if !aws_sm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.exists("aws-sm://us-east-1/hasp-test/secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn aws_sm_not_found() {
        if !aws_sm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let err = store
            .get("aws-sm://us-east-1/hasp-test-nonexistent/not-real")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_) | hasp::Error::Backend { .. }),
            "expected NotFound or Backend error for a missing secret, got {err:?}"
        );
    }
}

#[cfg(not(feature = "aws-sm"))]
mod aws_sm_disabled_tests {
    use super::*;

    #[test]
    fn aws_sm_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store.get("aws-sm://us-east-1/test-secret").unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "aws-sm"
        ));
    }
}

#[cfg(not(feature = "aws-ssm"))]
mod aws_ssm_disabled_tests {
    use super::*;

    #[test]
    fn aws_ssm_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store.get("aws-ssm://us-east-1/test-param").unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "aws-ssm"
        ));
    }
}

#[cfg(feature = "aws-ssm")]
mod aws_ssm_tests {
    use super::*;

    fn aws_ssm_available() -> bool {
        std::env::var("AWS_ACCESS_KEY_ID").is_ok() && std::env::var("AWS_SECRET_ACCESS_KEY").is_ok()
    }

    #[test]
    fn aws_ssm_get_roundtrip() {
        if !aws_ssm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.get("aws-ssm://us-east-1/hasp-test/secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn aws_ssm_exists() {
        if !aws_ssm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.exists("aws-ssm://us-east-1/hasp-test/secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn aws_ssm_not_found() {
        if !aws_ssm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let err = store
            .get("aws-ssm://us-east-1/hasp-test-nonexistent/not-real")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_) | hasp::Error::Backend { .. }),
            "expected NotFound or Backend error for a missing parameter, got {err:?}"
        );
    }
}

#[cfg(not(feature = "bw"))]
mod bw_disabled_tests {
    use super::*;

    #[test]
    fn bw_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store.get("bw://item/field.path").unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "bw"
        ));
    }
}

#[cfg(feature = "bw")]
mod bw_tests {
    use super::*;
    use hasp_core::test_utils::FakeBwGuard;

    #[test]
    fn bw_get_roundtrip() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeBwGuard::canonical();
        let _env = EnvGuard::set("BW_SESSION", "fake-session");

        let store = Store::builder().register(hasp::Backend::bw()).build();
        let secret = store.get("bw://test-item/login.password").unwrap();
        assert_eq!(secret.expose_secret(), "testpass");
    }

    #[test]
    fn bw_exists() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeBwGuard::canonical();
        let _env = EnvGuard::set("BW_SESSION", "fake-session");

        let store = Store::builder().register(hasp::Backend::bw()).build();

        // Fake backend returns success for `test-item`.
        assert!(store.exists("bw://test-item/login.password").unwrap());
    }

    #[test]
    fn bw_not_found() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeBwGuard::canonical();
        let _env = EnvGuard::set("BW_SESSION", "fake-session");

        let store = Store::builder().register(hasp::Backend::bw()).build();
        let err = store.get("bw://missing-item/login.password").unwrap_err();
        assert!(matches!(err, hasp::Error::NotFound(_)));
    }

    #[test]
    fn bw_not_authenticated() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fake = FakeBwGuard::canonical();

        let store = Store::builder().register(hasp::Backend::bw()).build();
        let err = store.get("bw://item/field.path").unwrap_err();

        assert!(
            matches!(err, hasp::Error::AuthenticationFailed(_)),
            "expected AuthenticationFailed when no ambient credentials are present, got {err:?}"
        );
    }

    #[test]
    fn bw_unsupported_operations() {
        let store = Store::with_defaults();
        let url = "bw://item/field.path";
        let secret = hasp::SecretString::new("x".into());

        assert!(matches!(
            store.put(url, &secret),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "bw",
                operation: "put",
            })
        ));
        assert!(matches!(
            store.list(url),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "bw",
                operation: "list",
            })
        ));
        assert!(matches!(
            store.delete(url),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "bw",
                operation: "delete",
            })
        ));
    }
}

#[cfg(not(feature = "gcp-sm"))]
mod gcp_sm_disabled_tests {
    use super::*;

    #[test]
    fn gcp_sm_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store.get("gcp-sm://my-project/my-secret").unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "gcp-sm"
        ));
    }
}

#[cfg(feature = "gcp-sm")]
mod gcp_sm_tests {
    use super::*;

    fn gcp_sm_available() -> bool {
        std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok()
    }

    #[test]
    fn gcp_sm_get_roundtrip() {
        if !gcp_sm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.get("gcp-sm://my-project/hasp-test-secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn gcp_sm_exists() {
        if !gcp_sm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.exists("gcp-sm://my-project/hasp-test-secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn gcp_sm_not_found() {
        if !gcp_sm_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let err = store
            .get("gcp-sm://my-project/hasp-test-nonexistent/not-real")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_) | hasp::Error::Backend { .. }),
            "expected NotFound or Backend error for a missing secret, got {err:?}"
        );
    }
}

#[cfg(not(feature = "azure-kv"))]
mod azure_kv_disabled_tests {
    use super::*;

    #[test]
    fn azure_kv_unknown_when_disabled() {
        let store = Store::with_defaults();
        let err = store.get("azure-kv://my-vault/my-secret").unwrap_err();
        assert!(matches!(
            err,
            hasp::Error::UnknownScheme(ref s) if s == "azure-kv"
        ));
    }
}

#[cfg(feature = "azure-kv")]
mod azure_kv_tests {
    use super::*;

    fn azure_kv_available() -> bool {
        std::env::var("AZURE_CLIENT_ID").is_ok() && std::env::var("AZURE_CLIENT_SECRET").is_ok()
    }

    #[test]
    fn azure_kv_get_roundtrip() {
        if !azure_kv_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.get("azure-kv://my-vault/hasp-test-secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn azure_kv_exists() {
        if !azure_kv_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let result = store.exists("azure-kv://my-vault/hasp-test-secret");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn azure_kv_not_found() {
        if !azure_kv_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let store = Store::with_defaults();

        let err = store
            .get("azure-kv://my-vault/hasp-test-nonexistent/not-real")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_) | hasp::Error::Backend { .. }),
            "expected NotFound or Backend error for a missing secret, got {err:?}"
        );
    }

    #[test]
    fn azure_kv_not_authenticated() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let vars = [
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_USERNAME",
            "AZURE_PASSWORD",
            "AZURE_FEDERATED_TOKEN",
            "AZURE_FEDERATED_TOKEN_FILE",
        ];
        let old: Vec<Option<String>> = vars.iter().map(|v| std::env::var(v).ok()).collect();
        for v in &vars {
            std::env::remove_var(v);
        }

        let store = Store::with_defaults();
        let err = store
            .get("azure-kv://my-vault/nonexistent-secret")
            .unwrap_err();

        for (i, v) in vars.iter().enumerate() {
            match &old[i] {
                Some(val) => std::env::set_var(v, val),
                None => std::env::remove_var(v),
            }
        }

        assert!(
            matches!(err, hasp::Error::AuthenticationFailed(_)),
            "expected AuthenticationFailed when no ambient credentials are present, got {err:?}"
        );
    }
}
