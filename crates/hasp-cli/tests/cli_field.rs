//! CLI tests for `-F` / `--field` field extraction.
//!
//! The composition mechanism is unit-tested in `main.rs::tests`. This
//! suite covers the CLI integration surface: refusal when `-F` and
//! `?field=` are both passed, and the `--explain` path's URL validation
//! (now that `Store::resolve` calls `Backend::validate`, a synthesized
//! `?field=` on a backend that doesn't accept query params fails fast).

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
fn explain_rejects_field_on_unsupporting_backend() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::set("HASP_FIELD_EXPLAIN", "x");
    // env:// rejects query params; --explain must surface this rather
    // than silently print a URL that real `get` would refuse.
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
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("env:// does not accept query parameters"),
        "expected env:// query-param refusal, got: {stderr}"
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
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already specifies ?field="),
        "expected refusal message, got: {stderr}"
    );
}
