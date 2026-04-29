use std::sync::Mutex;

/// Global lock to prevent concurrent env-var mutations across tests.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Guard that sets an environment variable for the duration of a test
/// and restores it afterward.
pub struct EnvGuard {
    key: String,
    old: Option<String>,
}

impl EnvGuard {
    /// Set `key` to `value`, saving the previous value (if any).
    pub fn set(key: &str, value: &str) -> Self {
        let old = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key: key.into(),
            old,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(v) => std::env::set_var(&self.key, v),
            None => std::env::remove_var(&self.key),
        }
    }
}

/// RAII guard that creates a fake `op` binary in a temp directory
/// and prepends that directory to `$PATH`, restoring the original
/// `$PATH` on drop. The fake binary echoes canned responses or errors
/// depending on the command-line arguments it receives.
///
/// Keep in sync with `hasp-backend-op/src/lib.rs` CLI args.
pub struct FakeOpGuard {
    _tmpdir: tempfile::TempDir,
    old_path: String,
}

impl FakeOpGuard {
    /// Create a temp directory containing a fake `op` binary that:
    /// - Requires `OP_SERVICE_ACCOUNT_TOKEN` to be set.
    /// - On `read --no-color op://...` returns a canned secret.
    /// - On `item list --vault ...` returns exit 0 (exists) or exit 1 (not found).
    /// - On `--version` prints `2.30.3`.
    pub fn canonical() -> Self {
        let target_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmpdir = tempfile::Builder::new()
            .prefix("hasp-test-")
            .tempdir_in(&target_dir)
            .expect("fake op tempdir");
        let bin_dir = tmpdir.path();

        let script = r#"#!/bin/sh
# Fake op binary for hasp integration tests.
# Stays in sync with crates/hasp-backend-op/src/lib.rs.

if [ "$1" = "--version" ]; then
    echo "2.30.3"
    exit 0
fi

if [ -z "$OP_SERVICE_ACCOUNT_TOKEN" ]; then
    echo "not signed in" >&2
    exit 1
fi

if [ "$1" = "read" ] && [ "$2" = "--no-color" ]; then
    ref="$3"
    case "$ref" in
        op://test-vault/test-item/field1)
            printf '%s' 'canned-secret-value-1'\n
            exit 0
            ;;
        op://test-vault/test-item/field2)
            printf '%s' 'canned-secret-value-2'\n
            exit 0
            ;;
        op://test-vault/missing-item/*)
            echo "[ERROR] item not found" >&2
            exit 1
            ;;
        *)
            echo "unexpected op read: $ref" >&2
            exit 1
            ;;
    esac
fi

if [ "$1" = "item" ] && [ "$2" = "list" ]; then
    vault="$4"
    if [ "$vault" = "test-vault" ]; then
        echo '[{"title": "test-item"}]'
        exit 0
    else
        echo "no items found" >&2
        exit 1
    fi
fi

echo "unexpected op args: $*" >&2
exit 1
"#;

        let op_bin = bin_dir.join("op");
        std::fs::write(&op_bin, script).expect("write fake op");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&op_bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&op_bin, perms).expect("chmod fake op");
        }

        let old_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.display(), old_path);
        std::env::set_var("PATH", &new_path);

        Self {
            _tmpdir: tmpdir,
            old_path,
        }
    }
}

impl Drop for FakeOpGuard {
    fn drop(&mut self) {
        std::env::set_var("PATH", &self.old_path);
    }
}

/// RAII guard that creates a fake `bw` binary in a temp directory
/// and prepends that directory to `$PATH`, restoring the original
/// `$PATH` on drop.
///
/// Keep in sync with `hasp-backend-bw/src/lib.rs` CLI args.
pub struct FakeBwGuard {
    _tmpdir: tempfile::TempDir,
    old_path: String,
}

impl FakeBwGuard {
    /// Create a temp directory containing a fake `bw` binary that:
    /// - Requires `BW_SESSION` to be set.
    /// - On `get item <name>` returns JSON shaped like Bitwarden's output.
    /// - On `--version` prints `2024.6.0`.
    pub fn canonical() -> Self {
        use std::env;

        let target_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmpdir = tempfile::Builder::new()
            .prefix("hasp-test-")
            .tempdir_in(&target_dir)
            .expect("fake bw tempdir");
        let bin_dir = tmpdir.path();

        let script = r#"#!/bin/sh
# Fake bw binary for hasp integration tests.
# Stays in sync with crates/hasp-backend-bw/src/lib.rs.

if [ "$1" = "--version" ]; then
    echo "2024.6.0"
    exit 0
fi

if [ -z "$BW_SESSION" ]; then
    echo "session expired" >&2
    exit 1
fi

if [ "$1" = "get" ] && [ "$2" = "item" ]; then
    name="$3"
    case "$name" in
        test-item)
            cat <<'JSON'
{"success":true,"data":{"name":"test-item","login":{"username":"testuser","password":"testpass"},"notes":"canned notes","fields":[{"name":"custom","value":"custom-field"}]}}
JSON
            exit 0
            ;;
        missing-item)
            echo "not found" >&2
            exit 1
            ;;
        *)
            echo "unexpected bw get item: $name" >&2
            exit 1
            ;;
    esac
fi

echo "unexpected bw args: $*" >&2
exit 1
"#;

        let bw_bin = bin_dir.join("bw");
        std::fs::write(&bw_bin, script).expect("write fake bw");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&bw_bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bw_bin, perms).expect("chmod fake bw");
        }

        let old_path = env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.display(), old_path);
        env::set_var("PATH", &new_path);

        Self {
            _tmpdir: tmpdir,
            old_path,
        }
    }
}

impl Drop for FakeBwGuard {
    fn drop(&mut self) {
        std::env::set_var("PATH", &self.old_path);
    }
}
