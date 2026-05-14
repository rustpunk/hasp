//! Integration tests for `hasp run -- <cmd>`.
//!
//! All tests stay inside the safe-by-default backends (`env://`,
//! `file://`) so no ambient cloud credentials are required.
//! Interactive TTY refusal is implicitly bypassed because Rust
//! integration tests run with non-TTY stdout.

use hasp_core::test_utils::{EnvGuard, ENV_LOCK};
use std::process::Command;

fn hasp() -> Command {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("hasp");
    let mut cmd = Command::new(&path);
    cmd.env_remove("HASP_TEST_INTEGRATION");
    cmd.env_remove("HASP_AUDIT");
    cmd
}

#[test]
fn run_injects_env_and_inherits_exit_zero() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_RUN_SRC", "hello-from-hasp");

    let out = hasp()
        .args([
            "run",
            "-e",
            "INJECTED=env://HASP_RUN_SRC",
            "--",
            "/usr/bin/env",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "hasp run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("INJECTED=hello-from-hasp"),
        "expected INJECTED=hello-from-hasp in env output, got: {stdout}"
    );
}

#[test]
fn run_propagates_child_exit_code() {
    let out = hasp()
        .args(["run", "--", "/bin/sh", "-c", "exit 42"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(42),
        "expected child's exit 42 to propagate"
    );
}

#[test]
fn run_short_circuits_on_missing_secret() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    std::env::remove_var("HASP_RUN_MISSING");

    let out = hasp()
        .args([
            "run",
            "-e",
            "X=env://HASP_RUN_MISSING",
            "--",
            // Sentinel file we expect NOT to be created.
            "/usr/bin/touch",
            "/tmp/hasp-run-should-not-exist-39f8c2",
        ])
        .output()
        .unwrap();

    // exit code 2 = NotFound per the new exit-code table.
    assert_eq!(out.status.code(), Some(2));
    assert!(!std::path::Path::new("/tmp/hasp-run-should-not-exist-39f8c2").exists());
}

#[test]
fn run_refuses_duplicate_env_keys() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_RUN_DUP", "v");

    let out = hasp()
        .args([
            "run",
            "-e",
            "DUP=env://HASP_RUN_DUP",
            "-e",
            "DUP=env://HASP_RUN_DUP",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("duplicate key"), "got stderr: {stderr}");
}

#[test]
fn run_refuses_malformed_env_spec() {
    let out = hasp()
        .args(["run", "-e", "NO_EQUALS_SIGN", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("KEY=URL"), "got stderr: {stderr}");
}

#[test]
fn run_requires_command_after_dashes() {
    let out = hasp().args(["run"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires a command"), "got: {stderr}");
}

#[test]
fn run_emits_run_start_and_done_audit_events() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_RUN_AUDIT", "v");

    let out = hasp()
        .args(["run", "-e", "K=env://HASP_RUN_AUDIT", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let names: Vec<&str> = events
        .iter()
        .filter_map(|e| e.get("event").and_then(|v| v.as_str()))
        .collect();
    assert!(names.contains(&"run.start"), "missing run.start: {stderr}");
    assert!(names.contains(&"run.done"), "missing run.done: {stderr}");
    let done = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("run.done"))
        .unwrap();
    assert_eq!(done.get("outcome").and_then(|v| v.as_str()), Some("ok"));
}

#[test]
fn run_done_outcome_child_nonzero_on_nonzero_exit() {
    let out = hasp()
        .args(["run", "--", "/bin/sh", "-c", "exit 3"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let done = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("run.done"))
        .unwrap();
    assert_eq!(
        done.get("outcome").and_then(|v| v.as_str()),
        Some("child_nonzero")
    );
}
