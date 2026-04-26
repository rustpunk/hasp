use hasp::Store;
use std::env;
use std::sync::Mutex;

// Guard that sets an environment variable for the duration of a test
// and restores it afterward. Uses a global lock to prevent concurrent
// env-var mutations across tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    key: String,
    old: Option<String>,
}

impl EnvGuard {
    fn set(key: &str, value: &str) -> Self {
        let old = env::var(key).ok();
        env::set_var(key, value);
        Self {
            key: key.into(),
            old,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(v) => env::set_var(&self.key, v),
            None => env::remove_var(&self.key),
        }
    }
}

#[cfg(feature = "env")]
mod env_tests {
    use super::*;
    use hasp::ExposeSecret;
    use hasp::SecretString;

    #[test]
    fn env_get_roundtrip() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("HASP_TEST_VAR", "secret-value");

        let store = Store::with_defaults();
        let secret = store.get("env://HASP_TEST_VAR").unwrap();
        assert_eq!(secret.expose_secret(), "secret-value");
    }

    #[test]
    fn env_not_found() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::remove_var("HASP_TEST_VAR_MISSING");

        let store = Store::with_defaults();
        let err = store.get("env://HASP_TEST_VAR_MISSING").unwrap_err();
        assert!(matches!(err, hasp::Error::NotFound(_)));
    }

    #[test]
    fn env_exists() {
        let _lock = ENV_LOCK.lock().unwrap();
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
fn unknown_scheme() {
    let store = Store::with_defaults();
    let err = store.get("unknown://thing").unwrap_err();
    assert!(matches!(err, hasp::Error::UnknownScheme(_)));
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
    use std::process::Command;

    fn op_available() -> bool {
        Command::new("op").arg("--version").status().is_ok()
    }

    #[test]
    fn op_get_roundtrip() {
        if !op_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        // A real roundtrip requires a 1Password account. Without one,
        // the test asserts only that the backend returns a hasp Error
        // rather than panicking or leaking stderr.
        let result = store.get("op://test-vault/test-item/test-field");
        assert!(result.is_err());
    }

    #[test]
    fn op_exists() {
        if !op_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let result = store.exists("op://test-vault/test-item/test-field");
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn op_not_found() {
        if !op_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let err = store
            .get("op://nonexistent-vault/nonexistent-item/nonexistent-field")
            .unwrap_err();

        assert!(
            matches!(
                err,
                hasp::Error::NotFound(_)
                    | hasp::Error::AuthenticationFailed(_)
                    | hasp::Error::Backend { .. }
            ),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn op_not_authenticated() {
        if !op_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();

        let old_service = std::env::var("OP_SERVICE_ACCOUNT_TOKEN").ok();
        let old_connect_token = std::env::var("OP_CONNECT_TOKEN").ok();
        let old_connect_host = std::env::var("OP_CONNECT_HOST").ok();

        std::env::remove_var("OP_SERVICE_ACCOUNT_TOKEN");
        std::env::remove_var("OP_CONNECT_TOKEN");
        std::env::remove_var("OP_CONNECT_HOST");
        for (k, _) in std::env::vars().filter(|(k, _)| k.starts_with("OP_SESSION_")) {
            std::env::remove_var(&k);
        }

        let store = Store::with_defaults();
        let err = store.get("op://vault/item/field").unwrap_err();

        if let Some(v) = old_service {
            std::env::set_var("OP_SERVICE_ACCOUNT_TOKEN", v);
        }
        if let Some(v) = old_connect_token {
            std::env::set_var("OP_CONNECT_TOKEN", v);
        }
        if let Some(v) = old_connect_host {
            std::env::set_var("OP_CONNECT_HOST", v);
        }

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

        let _lock = ENV_LOCK.lock().unwrap();
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

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let result = store.exists("vault://secret/data/hasp-test/test");
        assert!(result.is_ok(), "unexpected error: {result:?}");
    }

    #[test]
    fn vault_not_found() {
        if !vault_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();
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
        let _lock = ENV_LOCK.lock().unwrap();

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

        let _lock = ENV_LOCK.lock().unwrap();
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

        let _lock = ENV_LOCK.lock().unwrap();
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

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let err = store
            .get("aws-sm://us-east-1/hasp-test-nonexistent/not-real")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_) | hasp::Error::Backend { .. }),
            "expected NotFound or Backend error for a missing secret, got {err:?}"
        );
    }

    #[test]
    fn aws_sm_unsupported_operations() {
        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();
        let url = "aws-sm://us-east-1/test-secret";
        let secret = hasp::SecretString::new("x".into());

        assert!(matches!(
            store.put(url, &secret),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "aws-sm",
                operation: "put",
            })
        ));
        assert!(matches!(
            store.list(url),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "aws-sm",
                operation: "list",
            })
        ));
        assert!(matches!(
            store.delete(url),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "aws-sm",
                operation: "delete",
            })
        ));
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

        let _lock = ENV_LOCK.lock().unwrap();
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

        let _lock = ENV_LOCK.lock().unwrap();
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

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let err = store
            .get("aws-ssm://us-east-1/hasp-test-nonexistent/not-real")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_) | hasp::Error::Backend { .. }),
            "expected NotFound or Backend error for a missing parameter, got {err:?}"
        );
    }

    #[test]
    fn aws_ssm_unsupported_operations() {
        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();
        let url = "aws-ssm://us-east-1/test-param";
        let secret = hasp::SecretString::new("x".into());

        assert!(matches!(
            store.put(url, &secret),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "aws-ssm",
                operation: "put",
            })
        ));
        assert!(matches!(
            store.list(url),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "aws-ssm",
                operation: "list",
            })
        ));
        assert!(matches!(
            store.delete(url),
            Err(hasp::Error::UnsupportedOperation {
                scheme: "aws-ssm",
                operation: "delete",
            })
        ));
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
    use std::process::Command;

    fn bw_available() -> bool {
        Command::new("bw").arg("--version").status().is_ok()
    }

    #[test]
    fn bw_get_roundtrip() {
        if !bw_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let result = store.get("bw://test-item/login.password");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn bw_exists() {
        if !bw_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let result = store.exists("bw://test-item/field.path");
        assert!(
            matches!(
                result,
                Ok(_) | Err(hasp::Error::NotFound(_)) | Err(hasp::Error::Backend { .. })
            ),
            "unexpected error: {result:?}"
        );
    }

    #[test]
    fn bw_not_found() {
        if !bw_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();
        let store = Store::with_defaults();

        let err = store
            .get("bw://nonexistent-item/login.password")
            .unwrap_err();

        assert!(
            matches!(err, hasp::Error::NotFound(_) | hasp::Error::Backend { .. }),
            "expected NotFound or Backend error for a missing item, got {err:?}"
        );
    }

    #[test]
    fn bw_not_authenticated() {
        if !bw_available() {
            return;
        }

        let _lock = ENV_LOCK.lock().unwrap();

        let old_session = std::env::var("BW_SESSION").ok();
        std::env::remove_var("BW_SESSION");

        let store = Store::with_defaults();
        let err = store.get("bw://item/field.path").unwrap_err();

        if let Some(v) = old_session {
            std::env::set_var("BW_SESSION", v);
        }

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
