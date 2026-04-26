//! `file://` backend for hasp.
//!
//! Grammar:
//! - `file:///absolute/path` — absolute path (host empty or `localhost`)
//! - `file://./relative/path` — relative to current working directory (host = `.`)
//! - `?raw=true` — disables the default newline trim
//!
//! Supported operations: `get`, `put`, `exists`, `delete`.
//! `list` returns `UnsupportedOperation`.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, ExposeSecret, SecretString};
use std::path::PathBuf;
use url::Url;

/// URL shape for `file://` addresses.
///
/// `path` is the platform-native file path extracted from the URL.
/// `raw` disables the default newline trimming performed on `get`.
pub struct FileUrl {
    pub path: PathBuf,
    pub raw: bool,
}

impl TryFrom<&Url> for FileUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "file" {
            return Err(Error::InvalidUrl("expected file:// scheme".into()));
        }

        let host = url.host_str();
        let is_localhost = host.is_none_or(|h| h == "localhost");
        let is_relative = host == Some(".");

        if !is_localhost && !is_relative {
            return Err(Error::InvalidUrl(format!(
                "file:// host must be empty, 'localhost', or '.', got '{}'",
                host.unwrap_or("")
            )));
        }

        let mut raw = false;
        for (k, v) in url.query_pairs() {
            if k == "raw" && v == "true" {
                raw = true;
            } else {
                return Err(Error::InvalidUrl(format!(
                    "file:// unknown query parameter or value: {}={}",
                    k, v
                )));
            }
        }

        let path = if is_relative {
            let p = url.path();
            if p == "/" {
                return Err(Error::InvalidUrl(
                    "file:// relative path must not be empty".into(),
                ));
            }
            PathBuf::from(&p[1..])
        } else {
            url.to_file_path()
                .map_err(|_| Error::InvalidUrl("file:// invalid absolute path".into()))?
        };

        Ok(FileUrl { path, raw })
    }
}

/// Stdlib-only backend that reads secrets from files.
///
/// Default behavior strips exactly one trailing `\n` or `\r\n` from the
/// file contents — matching the dominant convention for Docker secrets,
/// Kubernetes secrets, and systemd-creds. Use `?raw=true` for verbatim
/// bytes.
pub struct FileBackend;

impl Backend for FileBackend {
    fn scheme(&self) -> &'static str {
        "file"
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        let file_url = FileUrl::try_from(url)?;
        let mut contents =
            std::fs::read_to_string(&file_url.path).map_err(|e| map_io_error(e, &file_url.path))?;
        if !file_url.raw {
            trim_one_trailing_newline(&mut contents);
        }
        Ok(SecretString::new(contents.into()))
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        let file_url = FileUrl::try_from(url)?;
        if let Some(parent) = file_url.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| map_io_error(e, parent))?;
            }
        }
        std::fs::write(&file_url.path, value.expose_secret())
            .map_err(|e| map_io_error(e, &file_url.path))?;
        Ok(())
    }

    fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
        Err(Error::UnsupportedOperation {
            scheme: "file",
            operation: "list",
        })
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        let file_url = FileUrl::try_from(url)?;
        std::fs::remove_file(&file_url.path).map_err(|e| map_io_error(e, &file_url.path))?;
        Ok(())
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        let file_url = FileUrl::try_from(url)?;
        Ok(file_url.path.exists())
    }
}

/// Strips exactly one trailing `\r\n` or `\n` from the given string.
///
/// Mutates in place to avoid an extra allocation. This is the default
/// behavior for `file://` reads because most secret files are created
/// with `echo "secret" > file`, which appends an unwanted newline.
fn trim_one_trailing_newline(s: &mut String) {
    if s.ends_with("\r\n") {
        let new_len = s.len().saturating_sub(2);
        s.truncate(new_len);
    } else if s.ends_with('\n') {
        let new_len = s.len().saturating_sub(1);
        s.truncate(new_len);
    }
}

fn map_io_error(err: std::io::Error, path: &std::path::Path) -> Error {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::NotFound => Error::NotFound(format!("file not found: {}", path.display())),
        ErrorKind::PermissionDenied => {
            Error::PermissionDenied(format!("permission denied: {}", path.display()))
        }
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => Error::Backend {
            scheme: "file",
            kind: BackendFailureKind::Transient,
            message: format!("file I/O transient failure: {err}"),
        },
        _ => Error::Backend {
            scheme: "file",
            kind: BackendFailureKind::Permanent,
            message: format!("file I/O permanent failure: {err}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_absolute_url() {
        let url = Url::parse("file:///etc/secrets/db.txt").unwrap();
        let f = FileUrl::try_from(&url).unwrap();
        assert_eq!(f.path, PathBuf::from("/etc/secrets/db.txt"));
        assert!(!f.raw);
    }

    #[test]
    fn parse_localhost_url() {
        let url = Url::parse("file://localhost/etc/secrets/db.txt").unwrap();
        let f = FileUrl::try_from(&url).unwrap();
        assert_eq!(f.path, PathBuf::from("/etc/secrets/db.txt"));
        assert!(!f.raw);
    }

    #[test]
    fn parse_relative_url() {
        let url = Url::parse("file://./secrets/db.txt").unwrap();
        let f = FileUrl::try_from(&url).unwrap();
        assert_eq!(f.path, PathBuf::from("secrets/db.txt"));
        assert!(!f.raw);
    }

    #[test]
    fn parse_raw_true() {
        let url = Url::parse("file:///etc/secrets/db.txt?raw=true").unwrap();
        let f = FileUrl::try_from(&url).unwrap();
        assert_eq!(f.path, PathBuf::from("/etc/secrets/db.txt"));
        assert!(f.raw);
    }

    #[test]
    fn parse_invalid_host_fails() {
        let url = Url::parse("file://otherhost/etc/secrets/db.txt").unwrap();
        assert!(FileUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_unknown_query_fails() {
        let url = Url::parse("file:///etc/secrets/db.txt?foo=bar").unwrap();
        assert!(FileUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_relative_empty_path_fails() {
        let url = Url::parse("file://./").unwrap();
        assert!(FileUrl::try_from(&url).is_err());
    }

    #[test]
    fn trim_crlf() {
        let mut s = "hello\r\n".to_string();
        trim_one_trailing_newline(&mut s);
        assert_eq!(s, "hello");
    }

    #[test]
    fn trim_lf() {
        let mut s = "hello\n".to_string();
        trim_one_trailing_newline(&mut s);
        assert_eq!(s, "hello");
    }

    #[test]
    fn trim_prefers_crlf() {
        let mut s = "hello\r\n\n".to_string();
        trim_one_trailing_newline(&mut s);
        assert_eq!(s, "hello\r\n");
    }

    #[test]
    fn trim_no_op_when_no_newline() {
        let mut s = "hello".to_string();
        trim_one_trailing_newline(&mut s);
        assert_eq!(s, "hello");
    }

    #[test]
    fn backend_get_roundtrip_and_trim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "my-secret\n").unwrap();

        let backend = FileBackend;
        let url = Url::from_file_path(&path).unwrap();
        let secret = backend.get(&url).unwrap();
        assert_eq!(secret.expose_secret(), "my-secret");
    }

    #[test]
    fn backend_get_raw_no_trim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "my-secret\n").unwrap();

        let backend = FileBackend;
        let mut url = Url::from_file_path(&path).unwrap();
        url.query_pairs_mut().append_pair("raw", "true");
        let secret = backend.get(&url).unwrap();
        assert_eq!(secret.expose_secret(), "my-secret\n");
    }

    #[test]
    fn backend_put_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/secret.txt");

        let backend = FileBackend;
        let url = Url::from_file_path(&path).unwrap();
        let value = SecretString::new("new-secret".into());
        backend.put(&url, &value).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "new-secret");
    }

    #[test]
    fn backend_exists_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("to-delete.txt");
        std::fs::write(&path, "value").unwrap();

        let backend = FileBackend;
        let url = Url::from_file_path(&path).unwrap();

        assert!(backend.exists(&url).unwrap());
        backend.delete(&url).unwrap();
        assert!(!backend.exists(&url).unwrap());
    }

    #[test]
    fn backend_get_not_found() {
        let backend = FileBackend;
        let url = Url::parse("file:///nonexistent/path/to/secret.txt").unwrap();
        let err = backend.get(&url).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn backend_list_unsupported() {
        let backend = FileBackend;
        let url = Url::parse("file:///etc/secrets").unwrap();
        let result = backend.list(&url);
        assert!(matches!(
            result,
            Err(Error::UnsupportedOperation {
                scheme: "file",
                operation: "list",
            })
        ));
    }
}
