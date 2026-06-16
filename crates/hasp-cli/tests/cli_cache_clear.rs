//! CLI tests specific to the persistent-cache surface of
//! `hasp cache clear`. The default behavior is covered by
//! `cli_cache.rs`; this file exercises the `--forget-key` flag and
//! the no-cache-file idempotency path.
//!
//! These tests do not require an OS keyring — the CLI no-ops on the
//! persistent file when the cache is `Disabled`, which is what the
//! default test environment exercises (`HASP_NO_CACHE=1` /
//! `HASP_CACHE_TTL=0`). The point is that `--forget-key` parses, the
//! exit code stays 0, and `--quiet` is honored exactly as in the
//! default `clear` path.

use std::process::Command;

fn hasp() -> Command {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("hasp");
    let mut cmd = Command::new(&path);
    cmd.env_remove("CI");
    cmd.env_remove("HASP_NO_CACHE");
    cmd.env_remove("HASP_CACHE_TTL");
    cmd
}

#[test]
fn cache_clear_forget_key_flag_parses_and_exits_zero() {
    let output = hasp()
        .args(["cache", "clear", "--forget-key"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "hasp cache clear --forget-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cache_clear_is_idempotent_across_invocations() {
    let first = hasp().args(["cache", "clear"]).output().unwrap();
    assert!(first.status.success());
    let second = hasp().args(["cache", "clear"]).output().unwrap();
    assert!(
        second.status.success(),
        "second clear should be idempotent, got stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
}

#[test]
fn cache_clear_forget_key_quiet_suppresses_message() {
    let output = hasp()
        .args(["--quiet", "cache", "clear", "--forget-key"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("cache cleared"),
        "--quiet should suppress the cleared message, got stderr: {stderr}"
    );
}
