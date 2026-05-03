use hasp_backend_env::EnvBackend;
use hasp_core::{Backend, SecretString};
use secrecy::ExposeSecret;
use url::Url;

#[test]
fn get_existing_env_var_returns_secret() {
    let var = "HASP_ENV_TEST_GET_OK";
    std::env::set_var(var, "secret-value");

    let backend = EnvBackend;
    let url = Url::parse(&format!("env://{var}")).unwrap();
    let secret = backend.get(&url).unwrap();
    assert_eq!(secret.expose_secret(), "secret-value");

    std::env::remove_var(var);
}

#[test]
fn get_missing_env_var_returns_not_found() {
    let var = "HASP_ENV_TEST_GET_MISSING";
    std::env::remove_var(var);

    let backend = EnvBackend;
    let url = Url::parse(&format!("env://{var}")).unwrap();
    let err = backend.get(&url).unwrap_err();
    assert!(matches!(err, hasp_core::Error::NotFound(_)));
}

#[test]
fn put_returns_unsupported() {
    let backend = EnvBackend;
    let url = Url::parse("env://HASP_ENV_TEST_PUT").unwrap();
    let val = SecretString::new("x".into());
    let err = backend.put(&url, &val).unwrap_err();
    assert!(matches!(
        err,
        hasp_core::Error::UnsupportedOperation {
            scheme: "env",
            operation: "put",
        }
    ));
}

#[test]
fn delete_returns_unsupported() {
    let backend = EnvBackend;
    let url = Url::parse("env://HASP_ENV_TEST_DELETE").unwrap();
    let err = backend.delete(&url).unwrap_err();
    assert!(matches!(
        err,
        hasp_core::Error::UnsupportedOperation {
            scheme: "env",
            operation: "delete",
        }
    ));
}

#[test]
fn exists_returns_true_for_existing() {
    let var = "HASP_ENV_TEST_EXISTS_OK";
    std::env::set_var(var, "1");

    let backend = EnvBackend;
    let url = Url::parse(&format!("env://{var}")).unwrap();
    assert!(backend.exists(&url).unwrap());

    std::env::remove_var(var);
}

#[test]
fn exists_returns_false_for_missing() {
    let var = "HASP_ENV_TEST_EXISTS_MISSING";
    std::env::remove_var(var);

    let backend = EnvBackend;
    let url = Url::parse(&format!("env://{var}")).unwrap();
    assert!(!backend.exists(&url).unwrap());
}

#[test]
fn list_returns_unsupported() {
    let backend = EnvBackend;
    let url = Url::parse("env://HASP_ENV_TEST_LIST").unwrap();
    let err = backend.list(&url).unwrap_err();
    assert!(matches!(
        err,
        hasp_core::Error::UnsupportedOperation {
            scheme: "env",
            operation: "list",
        }
    ));
}
