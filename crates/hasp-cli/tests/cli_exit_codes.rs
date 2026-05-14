//! Exit-code convention tests.
//!
//! Asserts that every `hasp_core::Error` variant the CLI surfaces maps
//! to the documented code (0/1/2/3/4/5/6). All cases are driven by
//! `env://` and `file://` to keep these creds-free.

use hasp_core::test_utils::{EnvGuard, ENV_LOCK};
use std::process::Command;

fn hasp() -> Command {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("hasp");
    let mut cmd = Command::new(&path);
    cmd.env_remove("HASP_TEST_INTEGRATION");
    cmd
}

fn code(args: &[&str]) -> i32 {
    hasp().args(args).output().unwrap().status.code().unwrap()
}

#[test]
fn success_get_env() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::set("HASP_EXIT_SUCCESS", "v");
    assert_eq!(code(&["get", "env://HASP_EXIT_SUCCESS"]), 0);
}

#[test]
fn usage_bad_url() {
    // url::Url::parse rejects bare alphanumerics — surfaces as UrlParse.
    assert_eq!(code(&["get", "not a url"]), 1);
}

#[test]
fn usage_unknown_scheme() {
    assert_eq!(code(&["get", "nosuchscheme://foo"]), 1);
}

#[test]
fn usage_unknown_profile_alias() {
    // Empty profiles path → @undefined cannot resolve.
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("profiles.toml");
    std::fs::write(&profile_path, "").unwrap();
    let out = hasp()
        .env("HASP_PROFILES_PATH", profile_path.as_os_str())
        .args(["get", "@undefined/key"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn usage_unsupported_operation() {
    // env:// does not support put → UnsupportedOperation → 1.
    let _env_lock = ENV_LOCK.lock().unwrap();
    let out = hasp().args(["put", "env://ANY", "v"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn not_found_env_missing() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    std::env::remove_var("HASP_EXIT_MISSING_FOR_GET");
    assert_eq!(code(&["get", "env://HASP_EXIT_MISSING_FOR_GET"]), 2);
}

#[test]
fn not_found_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.txt");
    let url = url::Url::from_file_path(&missing).unwrap().to_string();
    assert_eq!(code(&["get", &url]), 2);
}

#[test]
#[cfg(unix)]
fn permission_denied_file_unreadable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unreadable.txt");
    std::fs::write(&path, "secret").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Test runners that execute as root bypass the 0o000 mode and read
    // succeeds. Detect that and skip the assertion rather than fail
    // spuriously in container CI that drops to UID 0.
    let root_can_read = std::fs::read(&path).is_ok();
    let url = url::Url::from_file_path(&path).unwrap().to_string();
    let actual = code(&["get", &url]);
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    if !root_can_read {
        assert_eq!(actual, 3, "expected EXIT_PERMISSION_DENIED");
    }
}

#[test]
fn exists_present_returns_zero() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::set("HASP_EXIT_EXISTS_TRUE", "x");
    assert_eq!(code(&["exists", "env://HASP_EXIT_EXISTS_TRUE"]), 0);
}

#[test]
fn exists_absent_returns_one() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    std::env::remove_var("HASP_EXIT_EXISTS_FALSE");
    assert_eq!(code(&["exists", "env://HASP_EXIT_EXISTS_FALSE"]), 1);
}

#[test]
fn precondition_plain_http_proxy_for_cp() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::set("HTTPS_PROXY", "http://evil.example.com:8080");
    std::env::remove_var("HASP_ALLOW_HTTP_PROXY");
    let out = hasp().args(["cp", "env://A", "env://B"]).output().unwrap();
    assert_eq!(out.status.code(), Some(6));
}

#[test]
fn precondition_cross_environment_cp() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    // Avoid the plain-http proxy refusal kicking in first.
    let _guard_proxy = EnvGuard::set("HTTPS_PROXY", "");
    let _guard_src = EnvGuard::set("HASP_EXIT_CROSS_ENV_SRC", "v");
    let dir = tempfile::tempdir().unwrap();
    let dst_path = dir.path().join("dst.txt");
    let profile_path = dir.path().join("profiles.toml");
    let dst_url = url::Url::from_file_path(&dst_path).unwrap().to_string();
    std::fs::write(
        &profile_path,
        format!(
            r#"
[profiles.stage]
environment = "stage"
db = "env://HASP_EXIT_CROSS_ENV_SRC"

[profiles.prod]
environment = "prod"
db = "{}"
"#,
            dst_url.replace('\\', "\\\\")
        ),
    )
    .unwrap();
    let out = hasp()
        .env("HASP_PROFILES_PATH", profile_path.as_os_str())
        .args(["cp", "@stage/db", "@prod/db"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(6));
}
