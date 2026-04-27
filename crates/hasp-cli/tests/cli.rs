//! Integration tests for `hasp-cli`.
//!
//! Tests invoke the compiled `hasp` binary via `std::process::Command`.
//! They do not depend on external services; secret values come from
//! `env://` and `file://` backends only.

use std::process::{Command, Stdio};

fn hasp() -> Command {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("hasp");
    let mut cmd = Command::new(&path);
    cmd.env_remove("HASP_TEST_INTEGRATION");
    cmd
}

#[test]
fn cli_help_exits_zero() {
    let output = hasp().arg("--help").output().unwrap();
    assert!(
        output.status.success(),
        "hasp --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Unified secrets CLI"), "help missing title");
    assert!(stdout.contains("get"), "help missing get subcommand");
    assert!(stdout.contains("put"), "help missing put subcommand");
}

#[test]
fn cli_get_env_roundtrip() {
    let _guard = EnvGuard::set("HASP_CLI_TEST_SECRET", "my-secret-value");

    let output = hasp()
        .args(["get", "env://HASP_CLI_TEST_SECRET"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "hasp get failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        "my-secret-value"
    );
}

#[test]
fn cli_exists_env() {
    let _guard = EnvGuard::set("HASP_CLI_TEST_EXISTS", "1");

    let output = hasp()
        .args(["exists", "env://HASP_CLI_TEST_EXISTS"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "hasp exists (true) failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_exists_env_missing() {
    std::env::remove_var("HASP_CLI_TEST_EXISTS_MISSING");

    let output = hasp()
        .args(["exists", "env://HASP_CLI_TEST_EXISTS_MISSING"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "hasp exists (false) should return non-zero"
    );
}

#[test]
fn cli_get_file_roundtrip_and_trim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "file-secret\n").unwrap();

    let url = url::Url::from_file_path(&path).unwrap().to_string();

    let output = hasp().args(["get", &url]).output().unwrap();

    assert!(
        output.status.success(),
        "hasp get file failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        "file-secret"
    );
}

#[test]
fn cli_put_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("written.txt");
    let url = url::Url::from_file_path(&path).unwrap().to_string();

    let child = hasp()
        .args(["put", &url, "written-value"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "hasp put failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents, "written-value");
}

#[test]
fn cli_profile_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("profiles.toml");
    std::fs::write(
        &profile_path,
        r#"
[profiles.test]
my_secret = "env://HASP_CLI_PROFILE_SECRET"
"#,
    )
    .unwrap();

    let _guard = EnvGuard::set("HASP_CLI_PROFILE_SECRET", "profile-works");

    let output = hasp()
        .args(["get", "@test/my_secret"])
        .env("HASP_PROFILES_PATH", profile_path.as_os_str())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "hasp get @profile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        "profile-works"
    );
}

#[test]
fn cli_delete_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("to-delete.txt");
    let url = url::Url::from_file_path(&path).unwrap().to_string();

    // put
    let output = hasp()
        .args(["put", &url, "deletable-secret"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "hasp put failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // delete
    let output = hasp().args(["delete", &url]).output().unwrap();
    assert!(
        output.status.success(),
        "hasp delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // exists returns non-zero
    let output = hasp().args(["exists", &url]).output().unwrap();
    assert!(
        !output.status.success(),
        "hasp exists should return non-zero after delete"
    );
}

#[test]
fn cli_list_unsupported() {
    let output = hasp()
        .args(["list", "env://HOME"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "hasp list unsupported should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not support list"),
        "expected unsupported operation in stderr, got: {stderr}"
    );
}

#[test]
fn cli_unknown_scheme() {
    let output = hasp()
        .args(["get", "unknown://thing"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "hasp get unknown:// should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported scheme"),
        "expected 'unsupported scheme' in stderr, got: {stderr}"
    );
}

#[test]
fn cli_complete_bash() {
    let output = hasp().args(["complete", "bash"]).output().unwrap();
    assert!(
        output.status.success(),
        "hasp complete bash failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("_hasp()"),
        "bash completion should define _hasp function, got: {stdout}"
    );
}

#[test]
fn cli_complete_zsh() {
    let output = hasp().args(["complete", "zsh"]).output().unwrap();
    assert!(
        output.status.success(),
        "hasp complete zsh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("#compdef hasp"),
        "zsh completion should contain #compdef, got: {stdout}"
    );
}

#[test]
fn cli_complete_fish() {
    let output = hasp().args(["complete", "fish"]).output().unwrap();
    assert!(
        output.status.success(),
        "hasp complete fish failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("complete -c hasp"),
        "fish completion should register hasp completions, got: {stdout}"
    );
}

#[test]
fn cli_complete_powershell() {
    let output = hasp().args(["complete", "powershell"]).output().unwrap();
    assert!(
        output.status.success(),
        "hasp complete powershell failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Register-ArgumentCompleter"),
        "powershell completion should register an argument completer, got: {stdout}"
    );
}

#[test]
fn cli_complete_dynamic_scheme() {
    let output = hasp()
        .env("COMPLETE", "bash")
        .env("_CLAP_COMPLETE_INDEX", "2")
        .args(["--", "hasp", "get", "env"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dynamic completion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("env://"),
        "expected env:// in completions, got: {stdout}"
    );
}

#[test]
fn cli_complete_dynamic_profile() {
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("profiles.toml");
    std::fs::write(
        &profile_path,
        r#"
[profiles.prod]
db_password = "env://DB_PASSWORD"
api_key = "env://API_KEY"
"#,
    )
    .unwrap();

    let output = hasp()
        .env("COMPLETE", "bash")
        .env("_CLAP_COMPLETE_INDEX", "2")
        .env("HASP_PROFILES_PATH", profile_path.as_os_str())
        .args(["--", "hasp", "get", "@prod/"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dynamic profile completion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("@prod/db_password"),
        "expected @prod/db_password in completions, got: {stdout}"
    );
    assert!(
        stdout.contains("@prod/api_key"),
        "expected @prod/api_key in completions, got: {stdout}"
    );
}

#[test]
fn cli_complete_dynamic_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("testfile.txt");
    std::fs::write(&file_path, "").unwrap();

    let prefix = format!("file://{}/", dir.path().to_string_lossy());
    let output = hasp()
        .env("COMPLETE", "bash")
        .env("_CLAP_COMPLETE_INDEX", "2")
        .args(["--", "hasp", "get", &prefix])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dynamic file completion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("{prefix}testfile.txt");
    assert!(
        stdout.contains(&expected),
        "expected {expected} in completions, got: {stdout}"
    );
}

#[test]
fn cli_complete_dynamic_env_var() {
    let _guard = EnvGuard::set("HASP_COMPLETE_TEST_VAR", "test-value");

    let output = hasp()
        .env("COMPLETE", "bash")
        .env("_CLAP_COMPLETE_INDEX", "2")
        .args(["--", "hasp", "get", "env://HASP_COMPLETE"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dynamic env completion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("env://HASP_COMPLETE_TEST_VAR"),
        "expected env://HASP_COMPLETE_TEST_VAR in completions, got: {stdout}"
    );
}

#[test]
fn cli_man_subcommand() {
    let output = hasp().args(["man"]).output().unwrap();
    assert!(
        output.status.success(),
        "hasp man failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".TH"),
        "man page should contain .TH header, got: {stdout}"
    );
    assert!(
        stdout.contains("hasp"),
        "man page should mention hasp, got: {stdout}"
    );
}

#[test]
fn cli_global_flags_in_help() {
    let output = hasp().arg("--help").output().unwrap();
    assert!(
        output.status.success(),
        "hasp --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--quiet"),
        "help should show --quiet, got: {stdout}"
    );
    assert!(
        stdout.contains("--verbose"),
        "help should show --verbose, got: {stdout}"
    );
}

#[test]
fn cli_verbose_flag() {
    let _guard = EnvGuard::set("HASP_VERBOSE_TEST", "verbose-works");
    let output = hasp()
        .args(["get", "-v", "env://HASP_VERBOSE_TEST"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "hasp get -v failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hasp: get"),
        "verbose should print operation trace to stderr, got: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim_end(), "verbose-works");
}

#[test]
fn cli_quiet_flag_overrides_verbose() {
    let _guard = EnvGuard::set("HASP_QUIET_TEST", "quiet-works");
    let output = hasp()
        .args(["get", "-q", "-v", "env://HASP_QUIET_TEST"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "hasp get -q -v failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // stderr should be empty because -q suppresses -v traces
    assert!(
        output.stderr.is_empty(),
        "quiet should suppress verbose traces, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim_end(), "quiet-works");
}

// Guard that sets an environment variable for the duration of a test
// and restores it afterward.
struct EnvGuard {
    key: String,
    old: Option<String>,
}

impl EnvGuard {
    fn set(key: &str, value: &str) -> Self {
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
