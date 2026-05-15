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
            printf '%s\n' 'canned-secret-value-1'
            exit 0
            ;;
        op://test-vault/test-item/field2)
            printf '%s\n' 'canned-secret-value-2'
            exit 0
            ;;
        op://test-vault/missing-item/*)
            echo "could not find item" >&2
            exit 1
            ;;
        op://missing-vault/*)
            echo "isn't a vault" >&2
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
        # --format=json case — synthesize a minimal items array.
        # Last positional may be --format=json; either way the vault
        # is at $4 by construction.
        case "$*" in
            *--format=json*)
                printf '%s' '[{"id":"uuid-test-item","title":"test-item"}]'
                ;;
            *)
                echo '[{"title": "test-item"}]'
                ;;
        esac
        exit 0
    elif [ "$vault" = "missing-vault" ]; then
        echo "isn't a vault" >&2
        exit 1
    else
        echo "no items found" >&2
        exit 1
    fi
fi

if [ "$1" = "item" ] && [ "$2" = "edit" ]; then
    item="$3"
    # $4 is --vault, $5 is vault name, $6+ are field=value assignments.
    vault="$5"
    if [ "$vault" = "test-vault" ] && [ "$item" = "test-item" ]; then
        # Edit succeeds for any field assignment on existing items.
        exit 0
    fi
    echo "could not find item" >&2
    exit 1
fi

if [ "$1" = "item" ] && [ "$2" = "create" ]; then
    # `op item create --vault <vault> --title <item> --category password <field>=<value>`
    # We don't validate the full arg shape — just succeed for known vaults.
    for arg in "$@"; do
        case "$arg" in
            test-vault) exit 0 ;;
            missing-vault) echo "isn't a vault" >&2; exit 1 ;;
        esac
    done
    exit 0
fi

if [ "$1" = "item" ] && [ "$2" = "delete" ]; then
    item="$3"
    # $4 is --vault, $5 is vault name.
    vault="$5"
    if [ "$vault" = "test-vault" ] && [ "$item" = "test-item" ]; then
        exit 0
    fi
    echo "could not find item" >&2
    exit 1
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

# Strip leading flags that bw supports.
while [ "$1" = "--response" ] || [ "$1" = "--nointeraction" ]; do
    shift
done

if [ "$1" = "get" ] && [ "$2" = "item" ]; then
    name="$3"
    case "$name" in
        test-item|uuid-test-item)
            cat <<'JSON'
{"success":true,"data":{"id":"uuid-test-item","name":"test-item","type":1,"login":{"username":"testuser","password":"testpass"},"notes":"canned notes","fields":[{"name":"custom","value":"custom-field"}]}}
JSON
            exit 0
            ;;
        missing-item)
            cat <<'JSON'
{"success":false,"message":"not found."}
JSON
            exit 1
            ;;
        *)
            echo "unexpected bw get item: $name" >&2
            exit 1
            ;;
    esac
fi

if [ "$1" = "list" ] && [ "$2" = "items" ]; then
    # `bw list items [--search <term>]`. Echo a minimal items array.
    search=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --search) search="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    if [ -z "$search" ] || [ "$search" = "test" ]; then
        cat <<'JSON'
{"success":true,"data":[{"id":"uuid-test-item","name":"test-item","type":1},{"id":"uuid-note","name":"test-note","type":2}]}
JSON
        exit 0
    fi
    cat <<'JSON'
{"success":true,"data":[]}
JSON
    exit 0
fi

if [ "$1" = "edit" ] && [ "$2" = "item" ]; then
    id="$3"
    # Drain stdin (the base64 payload). hasp must use the stdin variant
    # rather than positional argv; if the fake bin still observes a
    # positional argument, the implementation regressed.
    if [ -n "$4" ]; then
        echo "fake bw: edit must not pass payload on argv (got positional $4)" >&2
        exit 1
    fi
    cat >/dev/null
    case "$id" in
        uuid-test-item)
            echo '{"success":true,"data":{"object":"item","id":"uuid-test-item"}}'
            exit 0
            ;;
        *)
            echo '{"success":false,"message":"Not found."}'
            exit 1
            ;;
    esac
fi

if [ "$1" = "create" ] && [ "$2" = "item" ]; then
    # Drain stdin (the base64 payload). Same argv-shape contract.
    if [ -n "$3" ]; then
        echo "fake bw: create must not pass payload on argv (got positional $3)" >&2
        exit 1
    fi
    cat >/dev/null
    echo '{"success":true,"data":{"object":"item","id":"uuid-created-item"}}'
    exit 0
fi

if [ "$1" = "delete" ] && [ "$2" = "item" ]; then
    id="$3"
    case "$id" in
        uuid-test-item)
            echo '{"success":true,"data":null}'
            exit 0
            ;;
        *)
            echo '{"success":false,"message":"Not found."}'
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
