//! Integration tests for `hasp cp` and the security-posture flags
//! around it (cross-environment refusal, plain-http proxy refusal,
//! dry-run via `--explain`).
//!
//! Like `cli.rs`, these tests spawn the compiled `hasp` binary and
//! exercise the env:// + file:// backends so no ambient credentials
//! are required.

use hasp_core::test_utils::{EnvGuard, ENV_LOCK};
use std::process::Command;

fn hasp() -> Command {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("hasp");
    let mut cmd = Command::new(&path);
    // Strip injection-style env vars that the hardening module
    // refuses on. The test harness should never inherit these but
    // explicit removal makes the test suite portable to CI runners
    // that wrap with sanitizers.
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
    cmd
}

fn file_url(p: &std::path::Path) -> String {
    url::Url::from_file_path(p).unwrap().to_string()
}

fn write(p: &std::path::Path, v: &str) {
    std::fs::write(p, v).unwrap();
}

fn read(p: &std::path::Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn cp_file_to_file_happy_path() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    write(&src, "value");

    let output = hasp()
        .args(["cp", &file_url(&src), &file_url(&dst)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&dst), "value");
    // Audit events emitted to stderr (one per line, JSON).
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"event\":\"cp.start\""),
        "missing cp.start audit event: {stderr}"
    );
    assert!(
        stderr.contains("\"event\":\"cp.done\""),
        "missing cp.done audit event: {stderr}"
    );
    assert!(
        stderr.contains("\"outcome\":\"copied\""),
        "missing copied outcome: {stderr}"
    );
}

#[test]
fn cp_fail_default_when_dst_exists() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    write(&src, "fresh");
    write(&dst, "stale");

    let output = hasp()
        .args(["cp", &file_url(&src), &file_url(&dst)])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "default Fail must exit non-zero when dst exists"
    );
    assert_eq!(read(&dst), "stale", "dst must be untouched on refusal");
}

#[test]
fn cp_force_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    write(&src, "fresh");
    write(&dst, "stale");

    let output = hasp()
        .args(["cp", "--force", &file_url(&src), &file_url(&dst)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&dst), "fresh");
}

#[test]
fn cp_skip_leaves_dst_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    write(&src, "fresh");
    write(&dst, "stale");

    let output = hasp()
        .args(["cp", "--if-exists=skip", &file_url(&src), &file_url(&dst)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&dst), "stale");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"outcome\":\"skipped\""),
        "audit event should report skipped outcome: {stderr}"
    );
}

#[test]
fn cp_explain_dry_run_does_not_touch_dst() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    write(&src, "value");
    // dst is intentionally absent

    let output = hasp()
        .args(["--explain", "cp", &file_url(&src), &file_url(&dst)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!dst.exists(), "dry-run must not create dst");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dry-run"),
        "missing dry-run banner: {stderr}"
    );
    assert!(
        stderr.contains("\"outcome\":\"dry_run\""),
        "missing dry_run audit outcome: {stderr}"
    );
}

#[test]
fn cp_self_copy_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    write(&src, "v");

    let output = hasp()
        .args(["cp", &file_url(&src), &file_url(&src)])
        .output()
        .unwrap();
    assert!(!output.status.success(), "self-copy must refuse");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("identical"),
        "missing identical-URLs message: {stderr}"
    );
}

#[test]
fn cp_env_to_file_cross_backend() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _g = EnvGuard::set("HASP_CLI_CP_SRC", "from-env");
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("dst.txt");

    let output = hasp()
        .env("HASP_CLI_CP_SRC", "from-env")
        .args(["cp", "env://HASP_CLI_CP_SRC", &file_url(&dst)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&dst), "from-env");
}

#[test]
fn cp_cross_environment_refused_without_yes() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("profiles.toml");
    let prod_secret = dir.path().join("prod.txt");
    let stage_secret = dir.path().join("stage.txt");
    write(&prod_secret, "prod-value");

    let prod_url = file_url(&prod_secret);
    let stage_url = file_url(&stage_secret);
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
        .args(["cp", "@prod/db", "@stage/db"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "cross-env cp without --yes must refuse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cross-environment"),
        "missing cross-environment refusal message: {stderr}"
    );
    assert!(
        !stage_secret.exists(),
        "stage secret must not be written when refused"
    );
}

#[test]
fn cp_cross_environment_succeeds_with_yes() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("profiles.toml");
    let prod_secret = dir.path().join("prod.txt");
    let stage_secret = dir.path().join("stage.txt");
    write(&prod_secret, "prod-value");

    let prod_url = file_url(&prod_secret);
    let stage_url = file_url(&stage_secret);
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
        .args(["cp", "--yes", "@prod/db", "@stage/db"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&stage_secret), "prod-value");
}

#[test]
fn cp_plain_http_proxy_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    write(&src, "v");

    let output = hasp()
        .env("HTTPS_PROXY", "http://attacker.example:8080")
        .args(["cp", &file_url(&src), &file_url(&dst)])
        .output()
        .unwrap();
    assert!(!output.status.success(), "plain-http proxy must refuse cp");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("plain-http proxy"),
        "missing proxy refusal message: {stderr}"
    );
    assert!(
        !dst.exists(),
        "dst must not be created when proxy refusal triggers"
    );
}

#[test]
fn cp_plain_http_proxy_allowed_with_override() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");
    write(&src, "v");

    let output = hasp()
        .env("HTTPS_PROXY", "http://attacker.example:8080")
        .env("HASP_ALLOW_HTTP_PROXY", "1")
        .args(["cp", &file_url(&src), &file_url(&dst)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "override must permit cp: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&dst), "v");
}

#[test]
fn cp_help_lists_in_subcommand_table() {
    let output = hasp().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cp"),
        "help missing cp subcommand: {stdout}"
    );
}

#[test]
fn cp_refuses_on_ld_preload() {
    // The hardening module refuses to start when LD_PRELOAD is set.
    // This tests the full refusal path end-to-end via the binary.
    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        write(&src, "v");

        let output = hasp()
            .env("LD_PRELOAD", "/tmp/nonexistent.so")
            .args([
                "cp",
                &file_url(&src),
                &file_url(&dir.path().join("dst.txt")),
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "LD_PRELOAD must trigger hardening refusal"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("LD_PRELOAD") || stderr.contains("injection"),
            "missing hardening refusal message: {stderr}"
        );
    }
}
