//! `bw://` backend for hasp.
//!
//! Grammar:
//!   - `bw://<item>/<field-path>` — get / put / delete / exists.
//!   - `bw://<search>` (host only, no path) — list with search filter.
//!     Sentinel host `_` lists every item in the unlocked vault.
//!
//! `<item>` is a Bitwarden item name *or* UUID (write paths resolve
//! names to UUIDs internally before invoking `bw edit|delete`, which
//! reject names). `<field-path>` is the dot-separated identifier into
//! the item JSON; on `put` the inverse mutation splices the value back
//! into a fetched item document (Bitwarden's write API is whole-item
//! replace, with no per-field shorthand).
//!
//! Authentication is ambient only: `BW_SESSION`. If the variable is
//! missing, every operation fails fast with `AuthenticationFailed`
//! before spawning the `bw` binary, preventing biometric unlock prompts
//! in headless contexts.
//!
//! Every `bw` invocation carries a wall-clock timeout (15 s for `get`,
//! 10 s for `exists`, 30 s for `list` and write paths). `--nointeraction`
//! mitigates but does not eliminate hangs.
//!
//! Write payloads (`put` / `create`) are fed via stdin so the
//! base64-encoded item JSON does not live on the subprocess argv. On
//! Linux `/proc/<pid>/cmdline` is same-uid readable; stdin shrinks the
//! exposure window from "full subprocess lifetime" to "pipe consumption
//! interval" and gates `/proc/<pid>/fd/0` behind `PTRACE_MODE_READ_FSCREDS`.
//! `delete` is soft (Trash); `--permanent` is not exposed in 0.1.0 —
//! one misclick stays recoverable for 30 days, mirroring the `op item
//! delete` posture.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hasp_core::{Backend, BackendFailureKind, Entry, Error, ExposeSecret, SecretString};
use std::io::Write;
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
            return Err(Error::InvalidUrl(
                "bw:// item name must not be empty".into(),
            ));
        }

        let mut segments = url.path_segments().into_iter().flatten();
        let field_path = segments.next().ok_or_else(|| {
            Error::InvalidUrl("bw:// requires a field path (path segment)".into())
        })?;
        if field_path.is_empty() {
            return Err(Error::InvalidUrl(
                "bw:// field path must not be empty".into(),
            ));
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

/// URL shape for the `bw list` grammar: `bw://<search>` (host only).
///
/// `search` is forwarded to `bw list items --search`; the sentinel
/// host `_` lists the whole unlocked vault unfiltered.
#[derive(Debug)]
pub struct BwListUrl {
    pub search: Option<String>,
}

impl TryFrom<&Url> for BwListUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "bw" {
            return Err(Error::InvalidUrl("expected bw:// scheme".into()));
        }
        if url.query().is_some() {
            return Err(Error::InvalidUrl(
                "bw:// list does not accept query parameters".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("bw:// list requires a host segment".into()))?;
        if host.is_empty() {
            return Err(Error::InvalidUrl(
                "bw:// list host must not be empty".into(),
            ));
        }
        let extras: Vec<&str> = url
            .path_segments()
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect();
        if !extras.is_empty() {
            return Err(Error::InvalidUrl(
                "bw:// list takes a host only (no path segments)".into(),
            ));
        }
        let search = if host == "_" {
            None
        } else {
            Some(host.to_owned())
        };
        Ok(BwListUrl { search })
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

/// Wall-clock timeout for write paths and `list`.
///
/// `bw list items` decrypts the entire vault client-side; user reports
/// show 2–3 minutes on 700-item vaults. 30 s is the floor that keeps
/// CI viable without hiding pathological cases.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

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

    fn validate(&self, url: &Url) -> Result<(), Error> {
        BwUrl::try_from(url).map(|_| ())
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let bw_url = BwUrl::try_from(url)?;
        let reference = format!("bw://{}/{}", bw_url.item, bw_url.field_path);
        let envelope = get_item_envelope(&bw_url.item, GET_TIMEOUT, &reference)?;

        let data = envelope.get("data").ok_or_else(|| Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Permanent,
            message: "bw response missing data field".into(),
        })?;

        let secret = extract_field(data, &bw_url.field_path, &reference)?;
        Ok(SecretString::new(secret.into()))
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let bw_url = BwUrl::try_from(url)?;
        let reference = format!("bw://{}/{}", bw_url.item, bw_url.field_path);

        // Read-modify-write: fetch the existing item, splice the field,
        // re-encode, and edit via stdin. On NotFound, create a fresh
        // Login item carrying the value.
        match get_item_envelope(&bw_url.item, WRITE_TIMEOUT, &reference) {
            Ok(envelope) => {
                let item_id = envelope
                    .get("data")
                    .and_then(|d| d.get("id"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::Backend {
                        scheme: "bw",
                        kind: BackendFailureKind::Permanent,
                        message: "bw item response missing id".into(),
                    })?
                    .to_owned();
                let mut data = envelope
                    .get("data")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                splice_field(&mut data, &bw_url.field_path, value.expose_secret())?;
                let payload =
                    B64.encode(serde_json::to_vec(&data).map_err(|e| Error::Backend {
                        scheme: "bw",
                        kind: BackendFailureKind::Permanent,
                        message: format!("failed to serialize bw edit payload: {e}"),
                    })?);
                let output = run_bw_with_stdin(
                    &["--response", "--nointeraction", "edit", "item", &item_id],
                    payload.as_bytes(),
                    WRITE_TIMEOUT,
                )?;
                check_response_envelope(&output, &reference)
            }
            Err(Error::NotFound(_)) => {
                let new_item = build_login_item(&bw_url.item, &bw_url.field_path, value)?;
                let payload =
                    B64.encode(serde_json::to_vec(&new_item).map_err(|e| Error::Backend {
                        scheme: "bw",
                        kind: BackendFailureKind::Permanent,
                        message: format!("failed to serialize bw create payload: {e}"),
                    })?);
                let output = run_bw_with_stdin(
                    &["--response", "--nointeraction", "create", "item"],
                    payload.as_bytes(),
                    WRITE_TIMEOUT,
                )?;
                check_response_envelope(&output, &reference)
            }
            Err(e) => Err(e),
        }
    }

    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let list_url = BwListUrl::try_from(url)?;
        let reference = match &list_url.search {
            Some(s) => format!("bw://{s}"),
            None => "bw://_".to_owned(),
        };

        let mut args: Vec<&str> = vec!["--response", "--nointeraction", "list", "items"];
        if let Some(s) = list_url.search.as_deref() {
            args.push("--search");
            args.push(s);
        }
        let output = run_bw_with_timeout(&args, WRITE_TIMEOUT)?;

        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|e| Error::Backend {
                scheme: "bw",
                kind: BackendFailureKind::Permanent,
                message: format!("bw produced invalid JSON: {e}"),
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
            return Err(map_bw_response_error(message, &reference));
        }

        let items = envelope
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(id)
                .to_owned();
            let item_type = item.get("type").and_then(|v| v.as_u64());
            // type 1 = Login, type 2 = SecureNote. Cards / Identities are
            // not directly addressable as single-secret URLs; skip them
            // to keep the list output round-trippable through `hasp get`.
            let default_field = match item_type {
                Some(1) => "login.password",
                Some(2) => "notes",
                _ => continue,
            };
            let entry_url = format!("bw://{id}/{default_field}");
            let parsed = Url::parse(&entry_url).map_err(|e| Error::Backend {
                scheme: "bw",
                kind: BackendFailureKind::Permanent,
                message: format!("bw item list yielded malformed URL: {e}"),
            })?;
            entries.push(Entry { name, url: parsed });
        }
        Ok(entries)
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let bw_url = BwUrl::try_from(url)?;
        let reference = format!("bw://{}/{}", bw_url.item, bw_url.field_path);

        // Resolve name → UUID. `bw delete item` rejects names.
        let envelope = get_item_envelope(&bw_url.item, WRITE_TIMEOUT, &reference)?;
        let item_id = envelope
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Backend {
                scheme: "bw",
                kind: BackendFailureKind::Permanent,
                message: "bw item response missing id".into(),
            })?
            .to_owned();

        // Soft delete (Trash). `--permanent` is deliberately unexposed;
        // mistakes stay recoverable for 30 days, matching the op:// posture.
        let output = run_bw_with_timeout(
            &["--response", "--nointeraction", "delete", "item", &item_id],
            WRITE_TIMEOUT,
        )?;
        check_response_envelope(&output, &reference)
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

        if !success {
            let message = envelope
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown bw error");
            if message.eq_ignore_ascii_case("not found.") {
                return Ok(false);
            }
            return Err(map_bw_response_error(message, &reference));
        }

        let data = envelope.get("data").ok_or_else(|| Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Permanent,
            message: "bw response missing data field".into(),
        })?;

        match extract_field(data, &bw_url.field_path, &reference) {
            Ok(_) => Ok(true),
            Err(Error::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
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

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Permanent,
            message: format!("bw produced invalid JSON: {e}"),
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
fn run_bw_with_timeout(args: &[&str], timeout: Duration) -> Result<std::process::Output, Error> {
    run_bw_inner(args, None, timeout)
}

/// Same as `run_bw_with_timeout` but feeds `stdin_bytes` to the child's
/// stdin (closing the pipe afterward). Used by write paths so the
/// base64-encoded JSON payload never lives on argv.
fn run_bw_with_stdin(
    args: &[&str],
    stdin_bytes: &[u8],
    timeout: Duration,
) -> Result<std::process::Output, Error> {
    run_bw_inner(args, Some(stdin_bytes), timeout)
}

fn run_bw_inner(
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    timeout: Duration,
) -> Result<std::process::Output, Error> {
    let stdin_cfg = if stdin_bytes.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    let mut child = Command::new("bw")
        .args(args)
        .stdin(stdin_cfg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_spawn_error)?;

    if let Some(bytes) = stdin_bytes {
        let mut stdin = child.stdin.take().expect("piped stdin");
        if let Err(e) = stdin.write_all(bytes) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Backend {
                scheme: "bw",
                kind: BackendFailureKind::Transient,
                message: format!("failed to write bw stdin: {e}"),
            });
        }
        // Drop closes the pipe so `bw` sees EOF and proceeds.
        drop(stdin);
    }

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

/// Splice a secret string into the JSON document at `path`. The path
/// uses the same dot-separated grammar as `extract_field` (object keys
/// and integer array indices). Missing intermediate keys are not
/// created — write paths that need to instantiate structure should
/// call `build_login_item` instead.
fn splice_field(data: &mut serde_json::Value, path: &str, value: &str) -> Result<(), Error> {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(Error::InvalidUrl(
            "bw:// field path contains empty segment".into(),
        ));
    }
    let mut current = data;
    for segment in &segments[..segments.len() - 1] {
        current = if let Ok(idx) = segment.parse::<usize>() {
            current.get_mut(idx).ok_or_else(|| {
                Error::NotFound(format!("field index {idx} not found while splicing"))
            })?
        } else {
            current.get_mut(*segment).ok_or_else(|| {
                Error::NotFound(format!("field '{segment}' not found while splicing"))
            })?
        };
    }
    let last = segments.last().expect("non-empty path");
    if let Ok(idx) = last.parse::<usize>() {
        let target = current.get_mut(idx).ok_or_else(|| {
            Error::NotFound(format!("field index {idx} not found while splicing"))
        })?;
        *target = serde_json::Value::String(value.to_owned());
    } else {
        let obj = current.as_object_mut().ok_or_else(|| {
            Error::NotFound(format!("cannot splice '{last}' into non-object node"))
        })?;
        obj.insert(
            (*last).to_owned(),
            serde_json::Value::String(value.to_owned()),
        );
    }
    Ok(())
}

/// Build a minimum-viable Login JSON for `bw create item` from a
/// `bw://<name>/<field-path>` URL. The field-path is honored when it
/// starts with `login.` (the Bitwarden Login type accepts
/// `username|password|totp`); other shapes fall back to a `notes`
/// SecureNote so the round-trip stays addressable.
fn build_login_item(
    name: &str,
    field_path: &str,
    value: &SecretString,
) -> Result<serde_json::Value, Error> {
    let secret = value.expose_secret();
    if let Some(rest) = field_path.strip_prefix("login.") {
        let mut login = serde_json::json!({
            "username": null,
            "password": null,
            "totp": null,
            "uris": [],
        });
        let target = login.as_object_mut().expect("login object");
        match rest {
            "username" | "password" | "totp" => {
                target.insert(
                    rest.to_owned(),
                    serde_json::Value::String(secret.to_owned()),
                );
            }
            _ => {
                return Err(Error::InvalidUrl(format!(
                    "bw:// create cannot synthesize a Login with field '{field_path}'"
                )));
            }
        }
        Ok(serde_json::json!({
            "organizationId": null,
            "collectionIds": null,
            "folderId": null,
            "type": 1,
            "name": name,
            "notes": null,
            "favorite": false,
            "fields": [],
            "login": login,
            "secureNote": null,
            "card": null,
            "identity": null,
            "reprompt": 0,
        }))
    } else if field_path == "notes" {
        Ok(serde_json::json!({
            "organizationId": null,
            "collectionIds": null,
            "folderId": null,
            "type": 2,
            "name": name,
            "notes": secret,
            "favorite": false,
            "fields": [],
            "secureNote": { "type": 0 },
            "login": null,
            "card": null,
            "identity": null,
            "reprompt": 0,
        }))
    } else {
        Err(Error::InvalidUrl(format!(
            "bw:// create only supports login.username|password|totp or notes; got '{field_path}'"
        )))
    }
}

/// Parse a `--response` envelope from a write-path invocation and
/// surface failures through the locked `Error` taxonomy.
fn check_response_envelope(output: &std::process::Output, reference: &str) -> Result<(), Error> {
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| Error::Backend {
            scheme: "bw",
            kind: BackendFailureKind::Permanent,
            message: format!("bw produced invalid JSON: {e}"),
        })?;
    let success = envelope
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if success {
        return Ok(());
    }
    let message = envelope
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown bw error");
    Err(map_bw_response_error(message, reference))
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
                Error::NotFound(format!("field index {index} out of bounds in {reference}"))
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
    use hasp_core::test_utils::{EnvGuard, ENV_LOCK};

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
        assert!(matches!(err, Error::NotFound(ref s) if s == "bw://github.com/login.password"));
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
        let err = map_bw_response_error("You are not logged in.", "bw://github.com/login.password");
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
