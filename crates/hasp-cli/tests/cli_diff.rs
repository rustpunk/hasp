//! Integration tests for `hasp diff`.
//!
//! Like `cli_cp.rs`, these tests spawn the compiled `hasp` binary and
//! exercise env:// + file:// so no ambient credentials are required.

use hasp_core::test_utils::{EnvGuard, ENV_LOCK};
use std::process::Command;

fn hasp() -> Command {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("hasp");
    let mut cmd = Command::new(&path);
    for var in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        cmd.env_remove(var);
    }
    // Default-on profile-allow enforcement would refuse temp
    // profiles.toml files used in these tests; opt out so the tests
    // exercise their intended diff semantics.
    cmd.env("HASP_REQUIRE_PROFILE_ALLOW", "0");
    cmd
}

fn file_url(p: &std::path::Path) -> String {
    url::Url::from_file_path(p).unwrap().to_string()
}

fn write(p: &std::path::Path, v: &str) {
    std::fs::write(p, v).unwrap();
}

#[test]
fn diff_match_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    write(&a, "same");
    write(&b, "same");

    let output = hasp()
        .args(["diff", &file_url(&a), &file_url(&b)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "match must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"event\":\"diff.start\""),
        "missing diff.start audit event: {stderr}"
    );
    assert!(
        stderr.contains("\"event\":\"diff.done\""),
        "missing diff.done audit event: {stderr}"
    );
    assert!(
        stderr.contains("\"outcome\":\"match\""),
        "missing match outcome: {stderr}"
    );
}

#[test]
fn diff_differ_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    write(&a, "alpha");
    write(&b, "beta");

    let output = hasp()
        .args(["diff", &file_url(&a), &file_url(&b)])
        .output()
        .unwrap();
    // 0 = match, 1 = differ — parallels `hasp exists`.
    assert_eq!(
        output.status.code(),
        Some(1),
        "differ must exit 1, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"outcome\":\"differ\""),
        "missing differ outcome: {stderr}"
    );
}

#[test]
fn diff_unknown_scheme_uses_standard_exit_table() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    write(&a, "x");

    let output = hasp()
        .args(["diff", &file_url(&a), "nope://x"])
        .output()
        .unwrap();
    // UnknownScheme maps to EXIT_USAGE=1 — same as differ. The audit
    // event distinguishes the two paths; users scripting on diff
    // should grep audit, not exit code, when they need to tell apart
    // "values differ" from "URL was invalid."
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported scheme") || stderr.contains("unknown"),
        "expected unsupported scheme message: {stderr}"
    );
}

#[test]
fn diff_self_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.txt");
    write(&f, "x");

    let output = hasp()
        .args(["diff", &file_url(&f), &file_url(&f)])
        .output()
        .unwrap();
    assert!(!output.status.success(), "self-diff must refuse");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("identical"),
        "missing identical-URLs message: {stderr}"
    );
}

#[test]
fn diff_explain_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    write(&a, "alpha");
    // b absent — dry run must not try to fetch

    let output = hasp()
        .args(["--explain", "diff", &file_url(&a), &file_url(&b)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "explain must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dry-run"),
        "missing dry-run banner: {stderr}"
    );
}

#[test]
fn diff_cross_environment_refused_without_yes() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("profiles.toml");
    let prod = dir.path().join("prod.txt");
    let stage = dir.path().join("stage.txt");
    write(&prod, "value");
    write(&stage, "value");

    let prod_url = file_url(&prod);
    let stage_url = file_url(&stage);
    std::fs::write(
        &profile_path,
        format!(
            r#"[profiles.prod]
environment = "prod"
db = "{prod_url}"

[profiles.stage]
environment = "stage"
db = "{stage_url}"
"#
        ),
    )
    .unwrap();

    let _guard = EnvGuard::set("HASP_PROFILES_PATH", profile_path.to_str().unwrap());

    let output = hasp()
        .env("HASP_PROFILES_PATH", profile_path.to_str().unwrap())
        .args(["diff", "@prod/db", "@stage/db"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "cross-env diff without --yes must refuse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cross-environment"),
        "missing cross-environment refusal: {stderr}"
    );
}

#[test]
fn diff_cross_environment_succeeds_with_yes() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("profiles.toml");
    let prod = dir.path().join("prod.txt");
    let stage = dir.path().join("stage.txt");
    write(&prod, "v");
    write(&stage, "v");

    let prod_url = file_url(&prod);
    let stage_url = file_url(&stage);
    std::fs::write(
        &profile_path,
        format!(
            r#"[profiles.prod]
environment = "prod"
db = "{prod_url}"

[profiles.stage]
environment = "stage"
db = "{stage_url}"
"#
        ),
    )
    .unwrap();

    let _guard = EnvGuard::set("HASP_PROFILES_PATH", profile_path.to_str().unwrap());

    let output = hasp()
        .env("HASP_PROFILES_PATH", profile_path.to_str().unwrap())
        .args(["diff", "--yes", "@prod/db", "@stage/db"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cross-env diff with --yes must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn diff_plain_http_proxy_refused() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    write(&a, "v");
    write(&b, "v");

    let output = hasp()
        .env("HTTPS_PROXY", "http://attacker.example:8080")
        .args(["diff", &file_url(&a), &file_url(&b)])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "plain-http proxy must refuse diff"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("plain-http proxy"),
        "missing proxy refusal: {stderr}"
    );
}

#[test]
fn diff_help_lists_in_subcommand_table() {
    let output = hasp().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("diff"),
        "help missing diff subcommand: {stdout}"
    );
}
