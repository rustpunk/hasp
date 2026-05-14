//! Verifies that every verb emits structured `*.start` / `*.done`
//! audit events to stderr and that `HASP_AUDIT=off` suppresses them.
//!
//! Stderr is parsed line-by-line because the env-based test fixture
//! is the only one that works without ambient cloud credentials.

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

fn audit_lines(stderr: &str) -> Vec<serde_json::Value> {
    stderr
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect()
}

#[test]
fn get_emits_start_and_done() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_GET", "v");

    let out = hasp()
        .args(["get", "env://HASP_AUDIT_GET"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events = audit_lines(&stderr);
    let names: Vec<&str> = events
        .iter()
        .filter_map(|e| e.get("event").and_then(|v| v.as_str()))
        .collect();
    assert!(
        names.contains(&"get.start"),
        "missing get.start in {stderr}"
    );
    assert!(names.contains(&"get.done"), "missing get.done in {stderr}");
    let done = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("get.done"))
        .unwrap();
    assert_eq!(done.get("outcome").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(done.get("src_scheme").and_then(|v| v.as_str()), Some("env"));
}

#[test]
fn get_emits_done_error_on_missing() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    std::env::remove_var("HASP_AUDIT_MISSING");

    let out = hasp()
        .args(["get", "env://HASP_AUDIT_MISSING"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events = audit_lines(&stderr);
    let done = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("get.done"))
        .expect("missing get.done");
    assert_eq!(done.get("outcome").and_then(|v| v.as_str()), Some("error"));
    assert_eq!(
        done.get("error_kind").and_then(|v| v.as_str()),
        Some("not_found")
    );
}

#[test]
fn exists_emits_present_or_absent_outcome() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_EXISTS", "1");

    let out = hasp()
        .args(["exists", "env://HASP_AUDIT_EXISTS"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events = audit_lines(&stderr);
    let done = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("exists.done"))
        .expect("missing exists.done");
    assert_eq!(
        done.get("outcome").and_then(|v| v.as_str()),
        Some("present")
    );
}

#[test]
fn hasp_audit_off_suppresses_emission() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_OFF_TEST", "1");

    let out = hasp()
        .env("HASP_AUDIT", "off")
        .args(["get", "env://HASP_AUDIT_OFF_TEST"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events = audit_lines(&stderr);
    assert!(events.is_empty(), "audit should be off, got: {stderr}");
}

#[test]
fn hasp_audit_file_writes_to_path() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_FILE_TEST", "1");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");

    let out = hasp()
        .env("HASP_AUDIT", "file")
        .env("HASP_AUDIT_PATH", &path)
        .args(["get", "env://HASP_AUDIT_FILE_TEST"])
        .output()
        .unwrap();
    assert!(out.status.success());

    let body = std::fs::read_to_string(&path).unwrap();
    let events = audit_lines(&body);
    let names: Vec<&str> = events
        .iter()
        .filter_map(|e| e.get("event").and_then(|v| v.as_str()))
        .collect();
    assert!(names.contains(&"get.start"));
    assert!(names.contains(&"get.done"));
}

#[test]
fn audit_toml_routes_to_file_sink() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_TOML_TEST", "1");

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.log");
    let cfg_path = dir.path().join("audit.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[audit]\nsink = \"file\"\npath = \"{}\"\n",
            log_path.display()
        ),
    )
    .unwrap();

    let out = hasp()
        .env("HASP_AUDIT_CONFIG_PATH", &cfg_path)
        .args(["get", "env://HASP_AUDIT_TOML_TEST"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Audit must have gone to the file, not stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr_events = audit_lines(&stderr);
    assert!(
        stderr_events.is_empty(),
        "expected file sink, got stderr events: {stderr}"
    );

    let body = std::fs::read_to_string(&log_path).unwrap();
    let file_events = audit_lines(&body);
    let names: Vec<&str> = file_events
        .iter()
        .filter_map(|e| e.get("event").and_then(|v| v.as_str()))
        .collect();
    assert!(names.contains(&"get.start"));
    assert!(names.contains(&"get.done"));
}

#[test]
fn env_var_overrides_audit_toml() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_OVERRIDE_TEST", "1");

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.log");
    let cfg_path = dir.path().join("audit.toml");
    // TOML says: write to file. Env var says: off. Env wins.
    std::fs::write(
        &cfg_path,
        format!(
            "[audit]\nsink = \"file\"\npath = \"{}\"\n",
            log_path.display()
        ),
    )
    .unwrap();

    let out = hasp()
        .env("HASP_AUDIT_CONFIG_PATH", &cfg_path)
        .env("HASP_AUDIT", "off")
        .args(["get", "env://HASP_AUDIT_OVERRIDE_TEST"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // No emission anywhere.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(audit_lines(&stderr).is_empty(), "stderr leaked: {stderr}");
    assert!(
        !log_path.exists() || std::fs::read_to_string(&log_path).unwrap().is_empty(),
        "file got events despite HASP_AUDIT=off"
    );
}

#[test]
fn hasp_audit_file_open_failure_falls_back_to_noop() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_OPEN_FAIL", "1");

    // Point HASP_AUDIT_PATH at a directory that does not exist —
    // `FileSink::open` returns Err; the CLI must degrade to NoopSink
    // rather than panicking or aborting the verb.
    let out = hasp()
        .env("HASP_AUDIT", "file")
        .env("HASP_AUDIT_PATH", "/nonexistent/dir/audit.log")
        .args(["get", "env://HASP_AUDIT_OPEN_FAIL"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "get should still succeed when audit sink fails to open: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim_end(), "1");
    // No audit events should have been emitted to stderr — the
    // fallback is a true NoopSink, not a silent retry to stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events = audit_lines(&stderr);
    assert!(
        events.is_empty(),
        "expected NoopSink fallback, got audit events: {stderr}"
    );
}

#[test]
fn cp_emits_start_and_done_with_dst_scheme() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let _g = EnvGuard::set("HASP_AUDIT_CP_SRC", "v");
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("dst.txt");
    let dst_url = url::Url::from_file_path(&dst).unwrap();

    let out = hasp()
        .args([
            "cp",
            "env://HASP_AUDIT_CP_SRC",
            dst_url.as_str(),
            "--if-exists=overwrite",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cp failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let events = audit_lines(&stderr);
    let start = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("cp.start"))
        .expect("missing cp.start");
    assert_eq!(
        start.get("src_scheme").and_then(|v| v.as_str()),
        Some("env")
    );
    assert_eq!(
        start.get("dst_scheme").and_then(|v| v.as_str()),
        Some("file")
    );
    let done = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("cp.done"))
        .expect("missing cp.done");
    assert_eq!(done.get("outcome").and_then(|v| v.as_str()), Some("copied"));
}
