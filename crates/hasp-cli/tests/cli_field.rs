//! CLI tests for `-F` / `--field` field extraction.
//!
//! End-to-end extraction is covered by per-backend unit tests; this
//! suite asserts the CLI surface — flag composition into `?field=`
//! and the refusal when both forms are passed.

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

#[test]
fn explain_threads_field_into_resolved_url() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::set("HASP_FIELD_EXPLAIN", "x");
    let output = hasp()
        .args([
            "--explain",
            "get",
            "-F",
            ".creds.password",
            "env://HASP_FIELD_EXPLAIN",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("field=.creds.password"),
        "explain output should include the threaded field, got: {stderr}"
    );
}

#[test]
fn double_field_refused() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::set("HASP_FIELD_DOUBLE", "x");
    let output = hasp()
        .args([
            "get",
            "-F",
            "password",
            "env://HASP_FIELD_DOUBLE?field=already",
        ])
        .output()
        .unwrap();
    assert_eq!(out_code(&output), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already specifies ?field="),
        "expected refusal message, got: {stderr}"
    );
}

fn out_code(out: &std::process::Output) -> i32 {
    out.status.code().expect("exit code")
}
