use hasp_backend_file::FileBackend;
use hasp_core::{Backend, SecretString};
use secrecy::ExposeSecret;
use url::Url;

#[test]
fn get_existing_file_returns_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "file-secret").unwrap();

    let backend = FileBackend;
    let url = Url::from_file_path(&path).unwrap();
    let secret = backend.get(&url).unwrap();
    assert_eq!(secret.expose_secret(), "file-secret");
}

#[test]
fn get_missing_file_returns_not_found() {
    let backend = FileBackend;
    let url = Url::parse("file:///nonexistent/path/to/secret.txt").unwrap();
    let err = backend.get(&url).unwrap_err();
    assert!(matches!(err, hasp_core::Error::NotFound(_)));
}

#[test]
fn put_writes_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("written.txt");

    let backend = FileBackend;
    let url = Url::from_file_path(&path).unwrap();
    let val = SecretString::new("new-value".into());
    backend.put(&url, &val).unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents, "new-value");
}

#[test]
fn put_creates_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/dir/secret.txt");

    let backend = FileBackend;
    let url = Url::from_file_path(&path).unwrap();
    let val = SecretString::new("nested-value".into());
    backend.put(&url, &val).unwrap();

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "nested-value");
}

#[test]
fn delete_removes_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("to-delete.txt");
    std::fs::write(&path, "x").unwrap();

    let backend = FileBackend;
    let url = Url::from_file_path(&path).unwrap();
    assert!(backend.exists(&url).unwrap());

    backend.delete(&url).unwrap();
    assert!(!backend.exists(&url).unwrap());
}

#[test]
fn delete_missing_file_returns_not_found() {
    let backend = FileBackend;
    let url = Url::parse("file:///nonexistent/delete-me.txt").unwrap();
    let err = backend.delete(&url).unwrap_err();
    assert!(matches!(err, hasp_core::Error::NotFound(_)));
}

#[test]
fn exists_returns_true_for_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exists.txt");
    std::fs::write(&path, "x").unwrap();

    let backend = FileBackend;
    let url = Url::from_file_path(&path).unwrap();
    assert!(backend.exists(&url).unwrap());
}

#[test]
fn exists_returns_false_for_missing() {
    let backend = FileBackend;
    let url = Url::parse("file:///nonexistent/missing.txt").unwrap();
    assert!(!backend.exists(&url).unwrap());
}

#[test]
fn list_returns_unsupported() {
    let backend = FileBackend;
    let url = Url::parse("file:///etc/secrets").unwrap();
    let err = backend.list(&url).unwrap_err();
    assert!(matches!(
        err,
        hasp_core::Error::UnsupportedOperation {
            scheme: "file",
            operation: "list",
        }
    ));
}

#[test]
fn get_trims_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newline.txt");
    std::fs::write(&path, "value\n").unwrap();

    let backend = FileBackend;
    let url = Url::from_file_path(&path).unwrap();
    let secret = backend.get(&url).unwrap();
    assert_eq!(secret.expose_secret(), "value");
}

#[test]
fn get_raw_preserves_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.txt");
    std::fs::write(&path, "value\n").unwrap();

    let backend = FileBackend;
    let mut url = Url::from_file_path(&path).unwrap();
    url.query_pairs_mut().append_pair("raw", "true");
    let secret = backend.get(&url).unwrap();
    assert_eq!(secret.expose_secret(), "value\n");
}
