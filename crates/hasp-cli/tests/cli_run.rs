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
        .args(["run", "-e", "INJECTED=env://HASP_RUN_SRC", "--", "env"])
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
        .args(["run", "--", "sh", "-c", "exit 42"])
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

    // Use a fresh tempdir for the sentinel rather than a fixed /tmp
    // path; the assertion that the child was never spawned is then
    // independent of any prior test run that may have left a stale
    // file behind.
    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("child_should_not_run");

    let out = hasp()
        .args([
            "run",
            "-e",
            "X=env://HASP_RUN_MISSING",
            "--",
            "touch",
            sentinel.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // exit code 2 = NotFound per the new exit-code table.
    assert_eq!(out.status.code(), Some(2));
    // The sentinel must not have been created — the child must not
    // have been spawned. (This is the stronger check than just exit
    // code: even if the exit-code mapping changes, we still know the
    // child never ran.)
    assert!(
        !sentinel.exists(),
        "child was spawned despite missing secret"
    );

    // Audit done event must carry outcome=error, error_kind=not_found,
    // not outcome=child_nonzero (which would mean the child *did* run
    // and exit non-zero).
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let run_done = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("run.done"))
        .expect("missing run.done");
    assert_eq!(
        run_done.get("outcome").and_then(|v| v.as_str()),
        Some("error"),
        "expected run.done outcome=error, got: {run_done:?}"
    );
    assert_eq!(
        run_done.get("error_kind").and_then(|v| v.as_str()),
        Some("not_found")
    );
}

#[test]
fn run_umbrella_scheme_is_multi_when_schemes_differ() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g1 = EnvGuard::set("HASP_RUN_MULTI_A", "a");
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("b.txt");
    std::fs::write(&file_path, "b").unwrap();
    let file_url = url::Url::from_file_path(&file_path).unwrap();

    let out = hasp()
        .args([
            "run",
            "-e",
            "A=env://HASP_RUN_MULTI_A",
            "-e",
            &format!("B={}", file_url.as_str()),
            "--",
            "true",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "hasp run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let start = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("run.start"))
        .expect("missing run.start");
    assert_eq!(
        start.get("src_scheme").and_then(|v| v.as_str()),
        Some("multi"),
        "expected umbrella scheme = 'multi' for mixed -e, got: {start:?}"
    );
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
            "true",
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
        .args(["run", "-e", "NO_EQUALS_SIGN", "--", "true"])
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
        .args(["run", "-e", "K=env://HASP_RUN_AUDIT", "--", "true"])
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
        .args(["run", "--", "sh", "-c", "exit 3"])
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
