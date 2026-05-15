//! Integration tests for the `hasp cache` subcommand and the
//! `HASP_NO_CACHE` / `HASP_CACHE_TTL` env-var integration.
//!
//! All tests invoke the compiled `hasp` binary; they do not depend on
//! external services.

use std::process::Command;

fn hasp() -> Command {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("hasp");
    let mut cmd = Command::new(&path);
    // Strip `CI` so tests that exercise the cache code path can
    // observe it; the auto-disable would mask the behavior otherwise.
    cmd.env_remove("CI");
    cmd.env_remove("HASP_NO_CACHE");
    cmd.env_remove("HASP_CACHE_TTL");
    cmd
}

#[test]
fn cache_clear_exits_zero() {
    let output = hasp().args(["cache", "clear"]).output().unwrap();
    assert!(
        output.status.success(),
        "hasp cache clear failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cache_clear_emits_quiet_message_unless_quiet_flag() {
    let output = hasp().args(["cache", "clear"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cache cleared"),
        "expected user-facing cleared message, got stderr: {stderr}"
    );

    let output = hasp().args(["--quiet", "cache", "clear"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("cache cleared"),
        "--quiet should suppress the cleared message, got stderr: {stderr}"
    );
}

#[test]
fn no_cache_flag_does_not_break_get() {
    use std::env;
    env::set_var("HASP_CLI_NOCACHE_TEST", "v");

    let output = hasp()
        .args(["--no-cache", "get", "env://HASP_CLI_NOCACHE_TEST"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "hasp --no-cache get failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        "v",
        "expected secret value on stdout"
    );

    env::remove_var("HASP_CLI_NOCACHE_TEST");
}

#[test]
fn hasp_cache_ttl_zero_disables_cache_path() {
    use std::env;
    env::set_var("HASP_CLI_TTL0_TEST", "v");

    let output = hasp()
        .env("HASP_CACHE_TTL", "0")
        .args(["get", "env://HASP_CLI_TTL0_TEST"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "HASP_CACHE_TTL=0 get failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    env::remove_var("HASP_CLI_TTL0_TEST");
}

#[test]
fn cache_help_describes_clear() {
    let output = hasp().args(["cache", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clear"),
        "cache --help should list `clear` subcommand: {stdout}"
    );
}
