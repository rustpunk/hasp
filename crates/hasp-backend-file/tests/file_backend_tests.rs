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
fn get_into_matches_get_default_trim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trimmed.txt");
    std::fs::write(&path, "trimmed-secret\n").unwrap();

    let backend = FileBackend;
    let url = Url::from_file_path(&path).unwrap();

    let mut slot = SecretString::new(String::new().into_boxed_str());
    backend.get_into(&url, &mut slot).unwrap();
    let getter = backend.get(&url).unwrap();
    assert_eq!(slot.expose_secret(), getter.expose_secret());
    assert_eq!(slot.expose_secret(), "trimmed-secret");
}

#[test]
fn get_into_matches_get_raw() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.txt");
    std::fs::write(&path, "raw-secret\n").unwrap();

    let backend = FileBackend;
    let mut url = Url::from_file_path(&path).unwrap();
    url.query_pairs_mut().append_pair("raw", "true");

    let mut slot = SecretString::new(String::new().into_boxed_str());
    backend.get_into(&url, &mut slot).unwrap();
    assert_eq!(slot.expose_secret(), "raw-secret\n");
}

#[test]
fn get_into_raw_length_matches_payload() {
    // The "no realloc" property of the sized-read helper is verified
    // by inspection (try_reserve_exact + read_to_string + capacity-
    // equal-length into_boxed_str). At the test level we can only
    // assert the observable: with `?raw=true`, get_into returns
    // bytes whose length matches the source file exactly — no
    // trim, no truncation, no padding. A regression that switches
    // to an unsized read or accidentally trims the raw path would
    // fail here.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exact.txt");
    let payload = "exact-fit-bytes";
    std::fs::write(&path, payload).unwrap();

    let backend = FileBackend;
    let mut url = Url::from_file_path(&path).unwrap();
    url.query_pairs_mut().append_pair("raw", "true");

    let mut slot = SecretString::new(String::new().into_boxed_str());
    backend.get_into(&url, &mut slot).unwrap();
    assert_eq!(slot.expose_secret().len(), payload.len());
    assert_eq!(slot.expose_secret(), payload);
}

#[test]
fn get_into_default_is_get_for_other_backends() {
    // The trait default forwards to `get`. Exercise it via a tiny
    // shim backend whose `get` is the only thing implemented, to
    // prove the contract.
    struct ConstBackend(&'static str);
    impl Backend for ConstBackend {
        fn scheme(&self) -> &'static str {
            "const"
        }
        fn get(&self, _: &Url) -> Result<SecretString, hasp_core::Error> {
            Ok(SecretString::new(self.0.into()))
        }
        fn put(&self, _: &Url, _: &SecretString) -> Result<(), hasp_core::Error> {
            Err(hasp_core::Error::UnsupportedOperation {
                scheme: "const",
                operation: "put",
            })
        }
        fn list(&self, _: &Url) -> Result<Vec<hasp_core::Entry>, hasp_core::Error> {
            Err(hasp_core::Error::UnsupportedOperation {
                scheme: "const",
                operation: "list",
            })
        }
        fn delete(&self, _: &Url) -> Result<(), hasp_core::Error> {
            Err(hasp_core::Error::UnsupportedOperation {
                scheme: "const",
                operation: "delete",
            })
        }
        fn exists(&self, _: &Url) -> Result<bool, hasp_core::Error> {
            Ok(true)
        }
    }
    let backend = ConstBackend("default-impl-secret");
    let url = Url::parse("const://anything").unwrap();
    let mut slot = SecretString::new(String::new().into_boxed_str());
    backend.get_into(&url, &mut slot).unwrap();
    assert_eq!(slot.expose_secret(), "default-impl-secret");
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
fn list_glob_flat_wildcard() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.secret");
    let b = dir.path().join("b.secret");
    let c = dir.path().join("c.txt");
    std::fs::write(&a, "A").unwrap();
    std::fs::write(&b, "B").unwrap();
    std::fs::write(&c, "C").unwrap();

    let backend = FileBackend;
    let pattern = format!("{}/*.secret", dir.path().display());
    let url = Url::parse(&format!("file://{pattern}")).unwrap();
    let mut entries = backend.list(&url).unwrap();
    entries.sort_by_key(|e| e.name.clone());

    assert_eq!(entries.len(), 2);
    assert!(entries[0].name.contains("a.secret"));
    assert!(entries[1].name.contains("b.secret"));
}

#[test]
fn list_glob_recursive_wildcard() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let a = dir.path().join("top.key");
    let b = sub.join("nested.key");
    std::fs::write(&a, "A").unwrap();
    std::fs::write(&b, "B").unwrap();

    let backend = FileBackend;
    let pattern = format!("{}/**/*.key", dir.path().display());
    let url = Url::parse(&format!("file://{pattern}")).unwrap();
    let mut entries = backend.list(&url).unwrap();
    entries.sort_by_key(|e| e.name.clone());

    assert_eq!(entries.len(), 2, "expected 2 entries, got {entries:?}");
}

#[test]
fn list_glob_no_match_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FileBackend;
    let pattern = format!("{}/*.nomatch", dir.path().display());
    let url = Url::parse(&format!("file://{pattern}")).unwrap();
    let entries = backend.list(&url).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn list_glob_excludes_hidden_files_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let visible = dir.path().join("visible.txt");
    let hidden = dir.path().join(".hidden.txt");
    std::fs::write(&visible, "V").unwrap();
    std::fs::write(&hidden, "H").unwrap();

    let backend = FileBackend;
    let pattern = format!("{}/*.txt", dir.path().display());
    let url = Url::parse(&format!("file://{pattern}")).unwrap();
    let entries = backend.list(&url).unwrap();

    assert_eq!(entries.len(), 1);
    assert!(entries[0].name.contains("visible.txt"));
}

#[test]
fn list_glob_includes_hidden_files_with_param() {
    let dir = tempfile::tempdir().unwrap();
    let visible = dir.path().join("visible.txt");
    let hidden = dir.path().join(".hidden.txt");
    std::fs::write(&visible, "V").unwrap();
    std::fs::write(&hidden, "H").unwrap();

    let backend = FileBackend;
    // Explicitly pattern-match the hidden file with `?hidden=1`.
    let pattern = format!("{}/.hidden.txt", dir.path().display());
    let url = Url::parse(&format!("file://{pattern}?hidden=1")).unwrap();
    let entries = backend.list(&url).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].name.contains(".hidden.txt"));
}

#[test]
fn list_glob_excludes_symlinks_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.txt");
    let link = dir.path().join("link.txt");
    std::fs::write(&real, "R").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).unwrap();
    #[cfg(not(unix))]
    std::fs::write(&link, "R").unwrap(); // Windows: just write to skip

    let backend = FileBackend;
    let pattern = format!("{}/*.txt", dir.path().display());
    let url = Url::parse(&format!("file://{pattern}")).unwrap();
    let entries = backend.list(&url).unwrap();

    #[cfg(unix)]
    {
        // Only the real file should appear; the symlink is filtered.
        assert_eq!(entries.len(), 1, "symlink not filtered: {entries:?}");
        assert!(entries[0].name.contains("real.txt"));
    }
    #[cfg(not(unix))]
    {
        // No symlink was created above, both are regular files.
        assert_eq!(entries.len(), 2);
    }
}

#[cfg(unix)]
#[test]
fn list_glob_does_not_follow_symlinked_directory_mid_pattern() {
    // Regression: a symlinked subdirectory pointing outside the
    // pattern root must not redirect a `**` traversal. With
    // ?follow_symlinks=0 (default), files reached through such a
    // symlink must be filtered.
    let inside = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_secret = outside.path().join("escape.key");
    std::fs::write(&outside_secret, "should-not-leak").unwrap();

    let symlinked_dir = inside.path().join("legit");
    std::os::unix::fs::symlink(outside.path(), &symlinked_dir).unwrap();

    let backend = FileBackend;
    let pattern = format!("{}/**/*.key", inside.path().display());
    let url = Url::parse(&format!("file://{pattern}")).unwrap();
    let entries = backend.list(&url).unwrap();

    // The escape file at /outside/escape.key must NOT appear in the
    // results even though `inside/legit/escape.key` matches the glob
    // through the symlinked subdir.
    for e in &entries {
        assert!(
            !e.name.contains("escape.key"),
            "symlinked subdirectory leaked path outside pattern root: {entries:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn list_glob_follows_symlinked_dir_when_explicitly_opted_in() {
    let inside = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_secret = outside.path().join("via-symlink.key");
    std::fs::write(&outside_secret, "ok").unwrap();
    let symlinked_dir = inside.path().join("linked");
    std::os::unix::fs::symlink(outside.path(), &symlinked_dir).unwrap();

    let backend = FileBackend;
    let pattern = format!("{}/**/*.key", inside.path().display());
    let url = Url::parse(&format!("file://{pattern}?follow_symlinks=1")).unwrap();
    let entries = backend.list(&url).unwrap();
    assert!(
        entries.iter().any(|e| e.name.contains("via-symlink.key")),
        "follow_symlinks=1 should expose files through symlinked dirs: {entries:?}"
    );
}

#[test]
fn list_entries_are_directly_gettable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.key");
    std::fs::write(&path, "value\n").unwrap();

    let backend = FileBackend;
    let pattern = format!("{}/*.key", dir.path().display());
    let url = Url::parse(&format!("file://{pattern}")).unwrap();
    let entries = backend.list(&url).unwrap();
    assert_eq!(entries.len(), 1);

    // Each Entry URL must be get()-able without error.
    let fetched = backend.get(&entries[0].url).unwrap();
    assert_eq!(fetched.expose_secret(), "value");
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
