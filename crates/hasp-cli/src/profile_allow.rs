//! direnv-style allow-list for `profiles.toml`.
//!
//! An unaudited `profiles.toml` is an attack surface: a compromised or
//! misconfigured file can silently redirect every `hasp` invocation to
//! an attacker-controlled URL. `hasp profile allow` records the file's
//! current mtime and SHA-256 so that any subsequent modification is
//! detected before the profile is used.
//!
//! Enforcement is on by default. Opt out per environment with
//! `HASP_REQUIRE_PROFILE_ALLOW=0` (also accepts `false` / `no` /
//! `off`); per-invocation bypass via `--no-profile-allow`. Refusal
//! exit code is 6 (precondition).
//!
//! ## Allow-state file format
//!
//! `~/.config/hasp/profiles.allowed` — TOML, `0o600` on Unix:
//!
//! ```toml
//! [allowed]
//! path   = "/home/user/.config/hasp/profiles.toml"
//! mtime  = "2026-05-14T12:34:56Z"          # RFC 3339 UTC
//! sha256 = "abcd...ef"                     # hex, lowercase
//! ```
//!
//! A missing file means "never allowed." A present file with a stale
//! mtime OR a wrong sha256 means "needs re-allow."

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Error variants for the allow-list subsystem. Mapped to CLI exit
/// codes by the caller (EXIT_USAGE for all — profile enforcement is a
/// usage/config-level concern, not a backend error).
#[derive(Debug)]
pub enum ProfileAllowError {
    /// profiles.toml is present but not allowed yet.
    NotAllowed(PathBuf),
    /// A previously-allowed profiles.toml has been modified since `allow`.
    Modified(PathBuf),
    /// Could not compute or verify the allow state (I/O errors, etc.).
    Io(String),
}

impl std::fmt::Display for ProfileAllowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed(p) => write!(
                f,
                "profiles.toml at {} has not been allowed yet.\n\
                 Run `hasp profile allow` to mark it as trusted.",
                p.display()
            ),
            Self::Modified(p) => write!(
                f,
                "profiles.toml at {} has been modified since it was last allowed.\n\
                 Review the changes and run `hasp profile allow` again.",
                p.display()
            ),
            Self::Io(msg) => write!(f, "profile allow-state I/O error: {msg}"),
        }
    }
}

/// TOML shape for the `profiles.allowed` file.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AllowedRecord {
    allowed: AllowedEntry,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AllowedEntry {
    path: String,
    mtime: String,
    sha256: String,
}

/// Resolve the canonical path to `profiles.toml`. Mirrors the logic in
/// `profiles::load_profiles` and `config_init::config_file_path`.
pub fn profiles_toml_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HASP_PROFILES_PATH") {
        return Some(PathBuf::from(p));
    }
    let config = dirs::config_dir()?;
    Some(config.join("hasp").join("profiles.toml"))
}

/// Derive the allow-state path from the profiles.toml directory.
fn allowed_path(profiles_path: &Path) -> PathBuf {
    profiles_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("profiles.allowed")
}

/// Record the current mtime and sha256 of `profiles.toml` as the
/// new trusted state.
///
/// Creates the directory and the `profiles.allowed` file if needed.
/// Sets `0o600` on Unix.
pub fn profile_allow(profiles_path: &Path) -> Result<(), ProfileAllowError> {
    let data = std::fs::read(profiles_path).map_err(|e| {
        ProfileAllowError::Io(format!("could not read {}: {e}", profiles_path.display()))
    })?;

    let meta = std::fs::metadata(profiles_path).map_err(|e| {
        ProfileAllowError::Io(format!("could not stat {}: {e}", profiles_path.display()))
    })?;

    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let mtime_str = system_time_to_rfc3339(mtime);
    let sha256_str = hex_sha256(&data);

    let record = AllowedRecord {
        allowed: AllowedEntry {
            path: profiles_path.display().to_string(),
            mtime: mtime_str,
            sha256: sha256_str,
        },
    };

    let toml_text = toml::to_string_pretty(&record)
        .map_err(|e| ProfileAllowError::Io(format!("could not serialize allow record: {e}")))?;

    let out_path = allowed_path(profiles_path);
    write_0600(&out_path, toml_text.as_bytes())
        .map_err(|e| ProfileAllowError::Io(format!("could not write {}: {e}", out_path.display())))
}

/// Print the resolved path, last-allowed status, and mtime to stdout.
pub fn profile_show(profiles_path: &Path) -> Result<(), ProfileAllowError> {
    let allowed_file = allowed_path(profiles_path);
    let allowed_state = read_allowed_record(&allowed_file);

    if !profiles_path.exists() {
        println!("Path:    {} (not found)", profiles_path.display());
        println!("Allowed: no (file does not exist)");
        return Ok(());
    }

    let meta = std::fs::metadata(profiles_path)
        .map_err(|e| ProfileAllowError::Io(format!("stat failed: {e}")))?;
    let mtime = system_time_to_rfc3339(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));

    println!("Path:    {}", profiles_path.display());
    println!("Mtime:   {mtime}");

    match allowed_state {
        None => {
            println!("Allowed: no (never allowed)");
        }
        Some(record) => {
            if record.allowed.mtime == mtime {
                println!("Allowed: yes (last allowed at {})", record.allowed.mtime);
            } else {
                println!(
                    "Allowed: no (modified since last allow; last allowed at {})",
                    record.allowed.mtime
                );
            }
        }
    }
    Ok(())
}

/// Check whether `profiles.toml` at `profiles_path` is currently
/// allowed (mtime and sha256 match the allow-state file).
///
/// Returns `Ok(())` when:
/// - Enforcement is disabled (env var absent and `no_profile_allow` flag set), or
/// - The allow-state file exists, and both mtime and sha256 match.
///
/// Returns `Err(ProfileAllowError)` otherwise.
pub fn check_profile_allowed(
    profiles_path: &Path,
    no_profile_allow: bool,
) -> Result<(), ProfileAllowError> {
    // If the file doesn't exist at all, there's nothing to check.
    if !profiles_path.exists() {
        return Ok(());
    }

    if no_profile_allow {
        return Ok(());
    }

    let allowed_file = allowed_path(profiles_path);
    let record = match read_allowed_record(&allowed_file) {
        Some(r) => r,
        None => return Err(ProfileAllowError::NotAllowed(profiles_path.to_path_buf())),
    };

    // Verify mtime first (cheap), then sha256 (involves a full read).
    let meta = std::fs::metadata(profiles_path).map_err(|e| {
        ProfileAllowError::Io(format!("could not stat {}: {e}", profiles_path.display()))
    })?;
    let mtime_current = system_time_to_rfc3339(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));

    if mtime_current != record.allowed.mtime {
        return Err(ProfileAllowError::Modified(profiles_path.to_path_buf()));
    }

    // mtime matches — verify sha256 (guards against same-second modifications
    // and platforms where mtime has coarse resolution).
    let data = std::fs::read(profiles_path).map_err(|e| {
        ProfileAllowError::Io(format!("could not read {}: {e}", profiles_path.display()))
    })?;
    if hex_sha256(&data) != record.allowed.sha256 {
        return Err(ProfileAllowError::Modified(profiles_path.to_path_buf()));
    }

    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn read_allowed_record(path: &Path) -> Option<AllowedRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

fn hex_sha256(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in hash.iter() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Format a `SystemTime` as a minimal RFC 3339 UTC string
/// (`YYYY-MM-DDTHH:MM:SSZ`). Doesn't round-trip sub-second precision —
/// that is intentional; mtime is an additional signal, not the only one.
fn system_time_to_rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert days since Unix epoch to (year, month, day). Proleptic
/// Gregorian; good until year 9999 which is well past our use case.
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // Algorithm: compute year by iterating — fast enough for a
    // CLI that calls this once at startup.
    let mut rem = days;
    let mut year: u32 = 1970;
    loop {
        let leap = is_leap(year);
        let dy = if leap { 366 } else { 365 };
        if rem < dy {
            break;
        }
        rem -= dy;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: &[u64] = if leap {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month: u32 = 1;
    for &md in month_days {
        if rem < md {
            break;
        }
        rem -= md;
        month += 1;
    }
    (year, month, rem as u32 + 1)
}

fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Write `data` to `path` with `0o600` permissions on Unix. Creates
/// parent directories as needed.
fn write_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        file.write_all(data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_sha256_produces_64_char_hex() {
        let h = hex_sha256(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn system_time_to_rfc3339_epoch() {
        let t = SystemTime::UNIX_EPOCH;
        assert_eq!(system_time_to_rfc3339(t), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn system_time_to_rfc3339_known_date() {
        // 2026-05-14T00:00:00Z = 1778716800 seconds since epoch
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_778_716_800);
        assert_eq!(system_time_to_rfc3339(t), "2026-05-14T00:00:00Z");
    }

    #[test]
    fn allow_and_check_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles.toml");
        std::fs::write(&profiles, "[profiles.prod]\ndb = \"env://DB\"").unwrap();

        profile_allow(&profiles).expect("allow should succeed");
        check_profile_allowed(&profiles, false).expect("should be allowed after allow");
    }

    #[test]
    fn check_not_allowed_when_no_allow_file() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles.toml");
        std::fs::write(&profiles, "[profiles.prod]\ndb = \"env://DB\"").unwrap();

        let err = check_profile_allowed(&profiles, false).unwrap_err();
        assert!(matches!(err, ProfileAllowError::NotAllowed(_)));
    }

    #[test]
    fn check_modified_when_content_changed() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles.toml");
        std::fs::write(&profiles, "[profiles.prod]\ndb = \"env://DB\"").unwrap();
        profile_allow(&profiles).expect("allow");

        // Modify content. mtime should bump on most platforms; even
        // when it doesn't, sha256 will differ — so the check must
        // refuse via one path or the other.
        std::fs::write(&profiles, "[profiles.prod]\ndb = \"env://DIFFERENT\"").unwrap();

        let err = check_profile_allowed(&profiles, false)
            .expect_err("content changed; check must refuse");
        assert!(
            matches!(err, ProfileAllowError::Modified(_)),
            "expected Modified, got: {err}"
        );
    }

    #[test]
    fn check_modified_via_sha256_fallback_when_mtime_matches() {
        // Forge a `profiles.allowed` whose mtime matches the current
        // file but whose sha256 does not — proves the sha256 path
        // fires when mtime is coarse and an attacker tampers within
        // the same mtime tick.
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles.toml");
        std::fs::write(&profiles, "[profiles.prod]\ndb = \"env://DB\"").unwrap();

        let meta = std::fs::metadata(&profiles).unwrap();
        let mtime = system_time_to_rfc3339(meta.modified().unwrap());

        let forged = format!(
            "[allowed]\npath = \"{}\"\nmtime = \"{mtime}\"\nsha256 = \"{}\"\n",
            profiles.display(),
            // Plausible-looking but wrong digest.
            "0".repeat(64)
        );
        std::fs::write(dir.path().join("profiles.allowed"), forged).unwrap();

        let err = check_profile_allowed(&profiles, false)
            .expect_err("sha256 mismatch must trip even when mtime matches");
        assert!(
            matches!(err, ProfileAllowError::Modified(_)),
            "expected Modified, got: {err}"
        );
    }

    #[test]
    fn no_profile_allow_flag_skips_enforcement() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles.toml");
        std::fs::write(&profiles, "[profiles.prod]\ndb = \"env://DB\"").unwrap();

        // Not allowed, but flag bypasses the check.
        check_profile_allowed(&profiles, true).expect("--no-profile-allow bypasses check");
    }

    #[test]
    fn missing_profiles_file_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("not_there.toml");
        // No profiles.toml at all — nothing to enforce.
        check_profile_allowed(&absent, false).expect("absent profiles file should be ok");
    }
}
