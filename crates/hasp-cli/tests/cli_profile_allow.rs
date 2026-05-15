//! Integration tests for `hasp profile allow` and `hasp profile show`.
//!
//! Spawns the compiled `hasp` binary with a temp `HASP_PROFILES_PATH`
//! so no real user config is touched.

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
        "HASP_REQUIRE_PROFILE_ALLOW",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

fn write(p: &std::path::Path, v: &str) {
    std::fs::write(p, v).unwrap();
}

fn file_url(p: &std::path::Path) -> String {
    url::Url::from_file_path(p).unwrap().to_string()
}

fn minimal_profiles_toml(secret_url: &str) -> String {
    format!("[profiles.test]\ndb = \"{secret_url}\"\n")
}

#[test]
fn profile_allow_succeeds_on_valid_profiles() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("secret.txt");
    write(&secret, "x");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));

    let output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .args(["profile", "allow"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "profile allow must succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let allowed = dir.path().join("profiles.allowed");
    assert!(allowed.exists(), "profiles.allowed must be created");
}

#[test]
fn profile_show_reports_not_allowed_before_allow() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    write(&profiles, &minimal_profiles_toml("env://DB"));

    let output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .args(["profile", "show"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no"),
        "show should report not allowed: {stdout}"
    );
}

#[test]
fn profile_show_reports_allowed_after_allow() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("secret.txt");
    write(&secret, "x");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));

    let allow_output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .args(["profile", "allow"])
        .output()
        .unwrap();
    assert!(allow_output.status.success());

    let show_output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .args(["profile", "show"])
        .output()
        .unwrap();
    assert!(show_output.status.success());
    let stdout = String::from_utf8_lossy(&show_output.stdout);
    assert!(
        stdout.contains("yes"),
        "show should report allowed: {stdout}"
    );
}

#[test]
fn require_profile_allow_dual_opt_out_is_a_noop() {
    // Setting both `HASP_REQUIRE_PROFILE_ALLOW=0` and `--no-profile-allow`
    // is redundant but not an error — the env-var check shorts the
    // enforcement guard before `--no-profile-allow` is consulted.
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("s.txt");
    write(&secret, "v");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));

    let output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .env("HASP_REQUIRE_PROFILE_ALLOW", "0")
        .args(["--no-profile-allow", "get", &file_url(&secret)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "dual opt-out must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn require_profile_allow_default_on_refuses_unallowed_profiles_toml() {
    // Default-on smoke test. With no `HASP_REQUIRE_PROFILE_ALLOW`
    // override and an unallowed `profiles.toml`, `hasp get @alias` is
    // refused with the precondition exit code (6).
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("s.txt");
    write(&secret, "v");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));

    let output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        // No HASP_REQUIRE_PROFILE_ALLOW set; default is on.
        .args(["get", &file_url(&secret)])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "default-on enforcement must refuse unallowed profiles.toml"
    );
    assert_eq!(
        output.status.code(),
        Some(6),
        "expected exit code 6 (PRECONDITION), got {:?}",
        output.status.code()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("allow") || stderr.contains("trusted"),
        "error message must mention allow: {stderr}"
    );
}

#[test]
fn require_profile_allow_opt_out_with_falsy_value() {
    // `HASP_REQUIRE_PROFILE_ALLOW=0` is the opt-out under default-on.
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("s.txt");
    write(&secret, "v");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));

    let output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .env("HASP_REQUIRE_PROFILE_ALLOW", "0")
        .args(["get", &file_url(&secret)])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "HASP_REQUIRE_PROFILE_ALLOW=0 must opt out: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn require_profile_allow_enforces_on_get_when_not_allowed() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("s.txt");
    write(&secret, "v");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));
    let _g = EnvGuard::set("HASP_PROFILES_PATH", profiles.to_str().unwrap());

    let output = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .env("HASP_REQUIRE_PROFILE_ALLOW", "1")
        .args(["get", &file_url(&secret)])
        .output()
        .unwrap();
    // Not allowed — must fail.
    assert!(
        !output.status.success(),
        "HASP_REQUIRE_PROFILE_ALLOW=1 must refuse when not allowed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("allow") || stderr.contains("trusted"),
        "error message must mention allow: {stderr}"
    );
}

#[test]
fn require_profile_allow_passes_after_allow() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("s.txt");
    write(&secret, "v");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));

    let allow_out = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .args(["profile", "allow"])
        .output()
        .unwrap();
    assert!(allow_out.status.success(), "allow must succeed first");

    let get_out = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .env("HASP_REQUIRE_PROFILE_ALLOW", "1")
        .args(["get", &file_url(&secret)])
        .output()
        .unwrap();
    assert!(
        get_out.status.success(),
        "get should succeed after allow, stderr: {}",
        String::from_utf8_lossy(&get_out.stderr)
    );
}

#[test]
fn no_profile_allow_flag_bypasses_enforcement() {
    let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let profiles = dir.path().join("profiles.toml");
    let secret = dir.path().join("s.txt");
    write(&secret, "v");
    write(&profiles, &minimal_profiles_toml(&file_url(&secret)));
    // No allow, but --no-profile-allow flag should bypass.
    let out = hasp()
        .env("HASP_PROFILES_PATH", profiles.to_str().unwrap())
        .env("HASP_REQUIRE_PROFILE_ALLOW", "1")
        .args(["--no-profile-allow", "get", &file_url(&secret)])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "--no-profile-allow must bypass enforcement, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn profile_help_lists_allow_and_show() {
    let output = hasp().args(["profile", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("allow"), "help missing allow: {stdout}");
    assert!(stdout.contains("show"), "help missing show: {stdout}");
}
