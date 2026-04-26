//! `bw://` backend for hasp.
//!
//! Grammar: `bw://<item>/<field-path>`
//!   - `<item>`       — Bitwarden item name (host component). Must be non-empty.
//!   - `<field-path>` — Dot-separated path into the item JSON (first path
//!     segment). Examples: `login.password`, `notes`, `fields.0.value`.
//!   - No query parameters.
//!
//! Supported operations: `get`, `exists`.
//! `put`, `list`, `delete`: `UnsupportedOperation`.
//!
//! Authentication is ambient only: `BW_SESSION`. If the variable is missing,
//! every operation fails fast with `AuthenticationFailed` before spawning
//! the `bw` binary, preventing biometric unlock prompts in headless contexts.
//!
//! Every `bw` invocation carries a wall-clock timeout (15 s for `get`,
//! 10 s for `exists`) because `bw` may prompt for unlock in interactive
//! mode. The `--nointeraction` flag mitigates but does not eliminate hangs.
//!
//! `bw get item` returns full item JSON. The backend extracts only the
//! requested field and wraps it in `SecretString`. `exists` also fetches
//! full item JSON because `bw` lacks a metadata-only existence probe.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, SecretString};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

/// URL shape for `bw://` addresses.
///
/// `item` and `field_path` are identifiers, not secret values. They may
/// appear in error messages (redacted per URL discipline).
#[derive(Debug)]
pub struct BwUrl {
    pub item: String,
    pub field_path: String,
}

impl TryFrom<&Url> for BwUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "bw" {
            return Err(Error::InvalidUrl("expected bw:// scheme".into()));
        }

        if url.query().is_some() {
            return Err(Error::InvalidUrl(
                "bw:// does not accept query parameters".into(),
            ));
        }

        let item = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("bw:// requires an item name (host)".into()))?
            .to_owned();
        if item.is_empty() {
            return Err(Error::InvalidUrl("bw:// item name must not be empty".into()));
        }

        let mut segments = url.path_segments().into_iter().flatten();
        let field_path = segments
            .next()
            .ok_or_else(|| Error::InvalidUrl("bw:// requires a field path (path segment)".into()))?;
        if field_path.is_empty() {
            return Err(Error::InvalidUrl("bw:// field path must not be empty".into()));
        }

        if segments.next().is_some() {
            return Err(Error::InvalidUrl(
                "bw:// requires exactly one path segment (field path) after the item".into(),
            ));
        }

        Ok(BwUrl {
            item,
            field_path: field_path.to_owned(),
        })
    }
}

/// Subprocess backend for Bitwarden CLI (`bw`).
///
/// Construction runs `bw --version` once. The stored init result is replayed
/// on every operation so errors surface on first use, not at
/// `Store::with_defaults()` time.
#[derive(Debug)]
pub struct BwBackend {
    init: Result<(), Error>,
}

/// Wall-clock timeout for `bw get item` invocations.
///
/// Baseline `bw get item` is ~500 ms–2 s; 15 s absorbs occasional network
/// stalls without blocking CI indefinitely.
const GET_TIMEOUT: Duration = Duration::from_secs(15);

/// Wall-clock timeout for existence probes.
///
/// Should not trigger biometric prompts (auth is pre-checked), but network
/// stalls are still possible.
const EXISTS_TIMEOUT: Duration = Duration::from_secs(10);

/// Wall-clock timeout for the one-time `bw --version` check.
const VERSION_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

impl BwBackend {
    /// Create a new `BwBackend`.
    ///
    /// Verifies `bw` is present by running `--version`. Versions in
    /// `YYYY.MM.N` format are accepted with a floor of 2023.1.0.
    pub fn new() -> Self {
        Self {
            init: Self::check_version(),
        }
    }

    fn ensure_init(&self) -> Result<(), Error> {
        self.init.clone()
    }

    fn check_version() -> Result<(), Error> {
        let output = run_bw_with_timeout(&["--version"], VERSION_CHECK_TIMEOUT)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            return Err(map_bw_stderr(&stderr, exit_code));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = parse_bw_version(&stdout).ok_or_else(|| Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Permanent,
            message: format!("could not parse bw version: {}", stdout.trim()),
        })?;

        // Floor: 2023.1.0 — well past the introduction of `--response`.
        if version.0 < 2023 || (version.0 == 2023 && version.1 < 1) {
            return Err(Error::Backend {
                scheme: "bw",
                kind: BackendFailureKind::Permanent,
                message: format!(
                    "bw CLI version {}.{}.{} is unsupported; hasp requires bw >= 2023.1.0",
                    version.0, version.1, version.2
                ),
            });
        }

        Ok(())
    }
}

impl Default for BwBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for BwBackend {
    fn scheme(&self) -> &'static str {
        "bw"
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let bw_url = BwUrl::try_from(url)?;
        let reference = format!("bw://{}/{}", bw_url.item, bw_url.field_path);
        let envelope = get_item_envelope(&bw_url.item, GET_TIMEOUT, &reference)?;

        let data = envelope
            .get("data")
            .ok_or_else(|| Error::Backend {
                scheme: "bw",
                kind: BackendFailureKind::Permanent,
                message: "bw response missing data field".into(),
            })?;

        let secret = extract_field(data, &bw_url.field_path, &reference)?;
        Ok(SecretString::new(secret.into()))
    }

    fn put(&self, _url: &Url, _value: &SecretString) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "bw",
            operation: "put",
        })
    }

    fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
        Err(Error::UnsupportedOperation {
            scheme: "bw",
            operation: "list",
        })
    }

    fn delete(&self, _url: &Url) -> Result<(), Error> {
        Err(Error::UnsupportedOperation {
            scheme: "bw",
            operation: "delete",
        })
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let bw_url = BwUrl::try_from(url)?;
        let reference = format!("bw://{}/{}", bw_url.item, bw_url.field_path);
        let envelope = get_item_envelope(&bw_url.item, EXISTS_TIMEOUT, &reference)?;

        let success = envelope
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if success {
            return Ok(true);
        }

        let message = envelope
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown bw error");

        if message.eq_ignore_ascii_case("not found.") {
            return Ok(false);
        }

        Err(map_bw_response_error(message, &reference))
    }
}

/// Fetch the JSON response envelope for `bw get item`.
///
/// Parses the `--response` output and checks `success`. On failure, maps
/// the `message` into the hasp error taxonomy.
fn get_item_envelope(
    item: &str,
    timeout: Duration,
    reference: &str,
) -> Result<serde_json::Value, Error> {
    let output = run_bw_with_timeout(
        &["--response", "--nointeraction", "get", "item", item],
        timeout,
    )?;

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| {
        Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Permanent,
            message: format!("bw produced invalid JSON: {e}"),
        }
    })?;

    let success = envelope
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !success {
        let message = envelope
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown bw error");
        return Err(map_bw_response_error(message, reference));
    }

    Ok(envelope)
}

/// Spawn `bw` with the given args and enforce a wall-clock timeout.
///
/// Two reader threads consume stdout and stderr concurrently while the
/// main thread polls `try_wait`. This prevents pipe-buffer deadlock when
/// `bw` emits large JSON or when stderr is verbose.
fn run_bw_with_timeout(
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, Error> {
    let mut child = Command::new("bw")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_spawn_error)?;

    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");

    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stdout_pipe, &mut buf).ok();
        buf
    });

    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stderr_pipe, &mut buf).ok();
        buf
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::Backend {
                        scheme: "bw",
                        kind: BackendFailureKind::Transient,
                        message: "bw invocation timed out".into(),
                    });
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(Error::Backend {
                    scheme: "bw",
                    kind: BackendFailureKind::Transient,
                    message: format!("failed to wait for bw process: {e}"),
                });
            }
        }
    }
}

fn map_spawn_error(err: std::io::Error) -> Error {
    use std::io::ErrorKind;
    if err.kind() == ErrorKind::NotFound {
        Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Permanent,
            message: "bw binary not found in PATH".into(),
        }
    } else {
        Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Transient,
            message: format!("failed to spawn bw: {err}"),
        }
    }
}

/// Map a Bitwarden `--response` error message into the locked
/// `hasp_core::Error` taxonomy.
///
/// Priority is first-anchor-wins, case-insensitive.
fn map_bw_response_error(message: &str, reference: &str) -> Error {
    let lower = message.to_lowercase();

    if lower.contains("not found.") || lower.contains("more than one result was found") {
        return Error::NotFound(reference.to_string());
    }

    if lower.contains("vault is locked")
        || lower.contains("you are not logged in")
        || lower.contains("your authentication request appears to be coming from a bot")
    {
        return Error::AuthenticationFailed(redact_reference(message, reference));
    }

    if lower.contains("fetch failed")
        || lower.contains("timeout")
        || lower.contains("connection")
        || lower.contains("dial")
        || lower.contains("getaddrinfo")
        || lower.contains("no such host")
    {
        return Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Transient,
            message: redact_reference(message, reference),
        };
    }

    if lower.contains("access to this item type is restricted by organizational policy") {
        return Error::PermissionDenied(redact_reference(message, reference));
    }

    Error::Backend {
        scheme: "bw",
        kind: BackendFailureKind::Permanent,
        message: redact_reference(message, reference),
    }
}

/// Map stderr from a non-`--response` `bw` invocation.
///
/// Used only for the `bw --version` path, which does not support
/// `--response` on some older builds.
fn map_bw_stderr(stderr: &str, exit_code: i32) -> Error {
    Error::Backend {
        scheme: "bw",
        kind: BackendFailureKind::Permanent,
        message: format!("bw exited with code {exit_code}: {stderr}"),
    }
}

/// Replace occurrences of the secret-reference URL with a redacted token.
fn redact_reference(message: &str, reference: &str) -> String {
    message.replace(reference, "bw://<redacted>")
}

/// Parse a `YYYY.MM.N` version string from `bw --version` stdout.
///
/// Accepts plain triples (`2026.4.1`) and prefixed releases
/// (`cli-v2026.4.1`).
fn parse_bw_version(output: &str) -> Option<(u32, u32, u32)> {
    let trimmed = output.trim();
    let version_part = trimmed.strip_prefix("cli-v").unwrap_or(trimmed);
    let mut parts = version_part.split('.');
    let year = parts.next()?.parse::<u32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    Some((year, month, patch))
}

/// Fail fast if no ambient Bitwarden session is present.
///
/// `bw` has no universal `--no-prompt` flag. Checking `BW_SESSION`
/// before spawn prevents biometric unlock prompts in headless contexts.
fn check_ambient_credentials() -> Result<(), Error> {
    if std::env::var("BW_SESSION").is_err() {
        return Err(Error::AuthenticationFailed(
            "no ambient Bitwarden session detected; set BW_SESSION".into(),
        ));
    }
    Ok(())
}

/// Extract a string value from a JSON object using a dot-separated path.
///
/// Supports object keys and array indices (e.g. `fields.0.value`).
/// Returns `NotFound` if any segment is missing.
fn extract_field(data: &serde_json::Value, path: &str, reference: &str) -> Result<String, Error> {
    let mut current = data;
    for segment in path.split('.') {
        if segment.is_empty() {
            return Err(Error::InvalidUrl(
                "bw:// field path contains empty segment".into(),
            ));
        }
        if let Ok(index) = segment.parse::<usize>() {
            current = current.get(index).ok_or_else(|| {
                Error::NotFound(format!(
                    "field index {index} out of bounds in {reference}"
                ))
            })?;
        } else {
            current = current.get(segment).ok_or_else(|| {
                Error::NotFound(format!("field '{segment}' not found in {reference}"))
            })?;
        }
    }
    current
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| Error::NotFound(format!("field '{path}' in {reference} is not a string")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: String,
        old: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let old = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.into(),
                old,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    #[test]
    fn parse_valid_url() {
        let url = Url::parse("bw://github.com/login.password").unwrap();
        let bw = BwUrl::try_from(&url).unwrap();
        assert_eq!(bw.item, "github.com");
        assert_eq!(bw.field_path, "login.password");
    }

    #[test]
    fn parse_url_with_encoded_space() {
        let url = Url::parse("bw://My%20Note/notes").unwrap();
        let bw = BwUrl::try_from(&url).unwrap();
        assert_eq!(bw.item, "My%20Note");
        assert_eq!(bw.field_path, "notes");
    }

    #[test]
    fn parse_empty_segment_fails() {
        let url = Url::parse("bw://github.com/").unwrap();
        assert!(BwUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_too_few_segments_fails() {
        let url = Url::parse("bw://github.com").unwrap();
        assert!(BwUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_too_many_segments_fails() {
        let url = Url::parse("bw://github.com/login/password").unwrap();
        assert!(BwUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_query_param_fails() {
        let url = Url::parse("bw://github.com/login.password?raw=true").unwrap();
        assert!(BwUrl::try_from(&url).is_err());
    }

    #[test]
    fn error_map_not_found() {
        let err = map_bw_response_error("Not found.", "bw://github.com/login.password");
        assert!(
            matches!(err, Error::NotFound(ref s) if s == "bw://github.com/login.password")
        );
    }

    #[test]
    fn error_map_multiple_results() {
        let err = map_bw_response_error(
            "More than one result was found. Try getting a specific object by `id` instead.",
            "bw://github.com/login.password",
        );
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn error_map_vault_locked() {
        let err = map_bw_response_error("Vault is locked.", "bw://github.com/login.password");
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn error_map_not_logged_in() {
        let err =
            map_bw_response_error("You are not logged in.", "bw://github.com/login.password");
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn error_map_bot_detection() {
        let err = map_bw_response_error(
            "Your authentication request appears to be coming from a bot.",
            "bw://github.com/login.password",
        );
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn error_map_transient_network() {
        for anchor in [
            "fetch failed",
            "timeout",
            "connection reset",
            "dial tcp",
            "getaddrinfo",
            "no such host",
        ] {
            let err = map_bw_response_error(anchor, "bw://github.com/login.password");
            assert!(
                matches!(
                    err,
                    Error::Backend {
                        kind: BackendFailureKind::Transient,
                        ..
                    }
                ),
                "expected Transient for anchor: {}",
                anchor
            );
        }
    }

    #[test]
    fn error_map_org_policy() {
        let err = map_bw_response_error(
            "Access to this item type is restricted by organizational policy.",
            "bw://github.com/login.password",
        );
        assert!(matches!(err, Error::PermissionDenied(_)));
    }

    #[test]
    fn error_map_unmatched_is_permanent() {
        let err = map_bw_response_error("some unexpected error", "bw://github.com/login.password");
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Permanent,
                ..
            }
        ));
    }

    #[test]
    fn version_parse_valid() {
        assert_eq!(parse_bw_version("2026.4.1"), Some((2026, 4, 1)));
        assert_eq!(parse_bw_version("2023.1.0"), Some((2023, 1, 0)));
        assert_eq!(parse_bw_version("cli-v2024.2.3"), Some((2024, 2, 3)));
        assert_eq!(parse_bw_version("2026.4.1\n"), Some((2026, 4, 1)));
    }

    #[test]
    fn version_parse_malformed() {
        assert_eq!(parse_bw_version("not.a.version"), None);
        assert_eq!(parse_bw_version(""), None);
    }

    #[test]
    fn version_reject_too_old() {
        let version = parse_bw_version("2022.12.0").unwrap();
        assert!(version.0 < 2023 || (version.0 == 2023 && version.1 < 1));
    }

    #[test]
    fn version_accept_exact_floor() {
        let version = parse_bw_version("2023.1.0").unwrap();
        assert!(!(version.0 < 2023 || (version.0 == 2023 && version.1 < 1)));
    }

    #[test]
    fn preflight_auth_no_session_fails_fast() {
        let _lock = ENV_LOCK.lock().unwrap();
        let old_session = std::env::var("BW_SESSION").ok();
        std::env::remove_var("BW_SESSION");

        let result = check_ambient_credentials();

        if let Some(v) = old_session {
            std::env::set_var("BW_SESSION", v);
        }

        assert!(
            matches!(result, Err(Error::AuthenticationFailed(_))),
            "expected AuthenticationFailed when no BW_SESSION is present"
        );
    }

    #[test]
    fn preflight_auth_session_ok() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("BW_SESSION", "test-session-key");
        assert!(check_ambient_credentials().is_ok());
    }

    #[test]
    fn redact_reference_replaces_url() {
        let msg = "could not read secret bw://MyItem/login.password: not found";
        let redacted = redact_reference(msg, "bw://MyItem/login.password");
        assert_eq!(redacted, "could not read secret bw://<redacted>: not found");
    }

    #[test]
    fn extract_field_nested() {
        let data = serde_json::json!({
            "login": {
                "password": "secret123"
            }
        });
        let secret = extract_field(&data, "login.password", "bw://item/login.password").unwrap();
        assert_eq!(secret, "secret123");
    }

    #[test]
    fn extract_field_top_level() {
        let data = serde_json::json!({
            "notes": "my note"
        });
        let secret = extract_field(&data, "notes", "bw://item/notes").unwrap();
        assert_eq!(secret, "my note");
    }

    #[test]
    fn extract_field_array_index() {
        let data = serde_json::json!({
            "fields": [
                { "name": "API Key", "value": "sk-xxx" }
            ]
        });
        let secret = extract_field(&data, "fields.0.value", "bw://item/fields.0.value").unwrap();
        assert_eq!(secret, "sk-xxx");
    }

    #[test]
    fn extract_field_missing() {
        let data = serde_json::json!({
            "login": {
                "password": "secret123"
            }
        });
        let err = extract_field(&data, "login.missing", "bw://item/login.missing").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn extract_field_not_string() {
        let data = serde_json::json!({
            "login": {
                "password": 12345
            }
        });
        let err = extract_field(&data, "login.password", "bw://item/login.password").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }
}
