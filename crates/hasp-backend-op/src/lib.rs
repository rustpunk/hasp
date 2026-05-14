//! `op://` backend for hasp.
//!
//! Grammar:
//! - 3-segment form `op://vault/item/field` for `get` / `put` /
//!   `delete` / `exists`. All three segments non-empty; no query
//!   parameters.
//! - Vault-only form `op://vault` for `list`. Host only, no path.
//!
//! Supported operations: `get`, `put`, `list`, `delete`, `exists`.
//! `put` issues `op item edit` and falls back to `op item create` on
//! NotFound. `delete` removes the entire item; the URL's `field`
//! segment is ignored on delete. `list` emits `Entry` URLs keyed by
//! the item UUID when `op item list --format=json` carries `id`.
//!
//! `PermissionDenied` is unreachable from `op read` because 1Password's
//! server returns 404 for both missing and no-permission cases (deliberate
//! authorization-aware design preventing existence oracles). These map to
//! `NotFound`.
//!
//! Authentication is ambient only (no auth-bootstrap flows):
//! `OP_SERVICE_ACCOUNT_TOKEN`, `OP_SESSION_*`, or `OP_CONNECT_TOKEN` +
//! `OP_CONNECT_HOST`. If none are present, every operation fails fast with
//! `AuthenticationFailed` before spawning the `op` binary, preventing
//! indefinite hangs in headless contexts.
//!
//! Every `op` subprocess invocation carries a wall-clock timeout (15s for
//! `get`, 10s for `exists`) because `op` has no `--no-prompt` flag — the
//! only mitigation against biometric or desktop-app hangs.
//!
//! Connect HTTP backend mode is deferred. It would recover 401/403/404
//! distinction but requires name-to-UUID resolution and a separate feature
//! gate. Service-account direct HTTP is not technically feasible without
//! reverse-engineering 1Password's SRP handshake.

use hasp_core::{Backend, BackendFailureKind, Entry, Error, SecretString};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

/// URL shape for `op://` addresses.
///
/// Vault, item, and field are identifiers, not secret values. They may
/// appear in error messages (redacted per URL discipline).
#[derive(Debug)]
pub struct OpUrl {
    pub vault: String,
    pub item: String,
    pub field: String,
}

/// URL shape for `op://` listing.
///
/// Listing has different cardinality requirements than `get` / `put` /
/// `delete`: it operates on a vault prefix (or optionally an item to
/// list that item's fields). For v1, only the vault-level case is
/// supported: `op://<vault>` (host only, no path).
#[derive(Debug)]
pub struct OpListUrl {
    pub vault: String,
}

impl TryFrom<&Url> for OpListUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "op" {
            return Err(Error::InvalidUrl("expected op:// scheme".into()));
        }
        if url.query().is_some() {
            return Err(Error::InvalidUrl(
                "op:// does not accept query parameters".into(),
            ));
        }
        let vault = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("op:// requires a vault (host)".into()))?;
        if vault.is_empty() {
            return Err(Error::InvalidUrl("op:// vault must not be empty".into()));
        }

        // Tolerate a single empty trailing path segment (the `op://vault/`
        // form), but reject any non-empty segment for the v1 list grammar.
        let extras: Vec<&str> = url
            .path_segments()
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect();
        if !extras.is_empty() {
            return Err(Error::InvalidUrl(
                "op:// list requires only a vault (no item or field)".into(),
            ));
        }

        Ok(OpListUrl {
            vault: vault.to_owned(),
        })
    }
}

impl TryFrom<&Url> for OpUrl {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if url.scheme() != "op" {
            return Err(Error::InvalidUrl("expected op:// scheme".into()));
        }

        if url.query().is_some() {
            return Err(Error::InvalidUrl(
                "op:// does not accept query parameters".into(),
            ));
        }

        let vault = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("op:// requires a vault (host)".into()))?;
        if vault.is_empty() {
            return Err(Error::InvalidUrl("op:// vault must not be empty".into()));
        }

        let mut segments = url.path_segments().into_iter().flatten();

        let item = segments
            .next()
            .ok_or_else(|| Error::InvalidUrl("op:// requires an item (path segment)".into()))?;
        if item.is_empty() {
            return Err(Error::InvalidUrl("op:// item must not be empty".into()));
        }

        let field = segments
            .next()
            .ok_or_else(|| Error::InvalidUrl("op:// requires a field (path segment)".into()))?;
        if field.is_empty() {
            return Err(Error::InvalidUrl("op:// field must not be empty".into()));
        }

        if segments.next().is_some() {
            return Err(Error::InvalidUrl(
                "op:// requires exactly 2 path segments (item/field) after the vault".into(),
            ));
        }

        Ok(OpUrl {
            vault: vault.to_owned(),
            item: item.to_owned(),
            field: field.to_owned(),
        })
    }
}

/// Subprocess backend for 1Password CLI (`op`).
///
/// Construction runs `op --version` once and rejects versions below
/// 2.30.0. The stored init result is replayed on every operation so
/// errors surface on first use, not at `Store::with_defaults()` time.
///
/// `op://` references (vault/item/field identifiers) may appear on argv;
/// secret values never do. Stdout is always captured via pipe (never a
/// raw file FD) to avoid the documented binary-content corruption when
/// `op read` writes to a non-pipe FD.
#[derive(Debug)]
pub struct OpBackend {
    init: Result<(), Error>,
}

/// Wall-clock timeout for `op read` invocations.
///
/// 1Password community benchmarks show `op read` baseline is ~700ms–2s;
/// 15s absorbs occasional biometric-desktop-app stalls without
/// blocking CI indefinitely.
const GET_TIMEOUT: Duration = Duration::from_secs(15);

/// Wall-clock timeout for `op item list` invocations.
///
/// Slightly shorter than `get` because listing metadata-only should
/// never trigger biometric prompts, but network stalls are still
/// possible.
const EXISTS_TIMEOUT: Duration = Duration::from_secs(10);

/// Wall-clock timeout for the one-time `op --version` check.
const VERSION_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

impl OpBackend {
    /// Create a new `OpBackend`.
    ///
    /// Runs `op --version` once and enforces the minimum supported
    /// version (2.30.0). Versions >= 2.30.0 are accepted without an
    /// upper bound so hasp does not ossify against `op`'s release
    /// cadence.
    pub fn new() -> Self {
        Self {
            init: Self::check_version(),
        }
    }

    fn ensure_init(&self) -> Result<(), Error> {
        self.init.clone()
    }

    fn check_version() -> Result<(), Error> {
        let output = run_op_with_timeout(&["--version"], VERSION_CHECK_TIMEOUT)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            return Err(map_op_error(&stderr, exit_code, "op --version"));
        }

        // Pre-v2.32.1: op could exit 0 on unrecognized server errors.
        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Backend {
                scheme: "op",
                kind: BackendFailureKind::Permanent,
                message: format!(
                    "op exited 0 but emitted stderr: {}",
                    redact_reference(&stderr, "op --version")
                ),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = parse_op_version(&stdout).ok_or_else(|| Error::Backend {
            scheme: "op",
            kind: BackendFailureKind::Permanent,
            message: format!("could not parse op version: {}", stdout.trim()),
        })?;

        if version.0 < 2 || (version.0 == 2 && version.1 < 30) {
            return Err(Error::Backend {
                scheme: "op",
                kind: BackendFailureKind::Permanent,
                message: format!(
                    "op CLI version {}.{}.{} is unsupported; hasp requires op >= 2.30.0",
                    version.0, version.1, version.2
                ),
            });
        }

        Ok(())
    }
}

impl Default for OpBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for OpBackend {
    fn scheme(&self) -> &'static str {
        "op"
    }

    fn validate(&self, url: &Url) -> Result<(), Error> {
        OpUrl::try_from(url).map(|_| ())
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let op_url = OpUrl::try_from(url)?;
        let reference = format!("op://{}/{}/{}", op_url.vault, op_url.item, op_url.field);
        let args: [&str; 3] = ["read", "--no-color", &reference];

        let output = run_op_with_timeout(&args, GET_TIMEOUT)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            return Err(map_op_error(&stderr, exit_code, &reference));
        }

        // Defensive: op < v2.32.1 could exit 0 with non-empty stderr on
        // unrecognized server errors (DG-682 in CLI2 release notes).
        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let redacted = redact_reference(&stderr, &reference);
            return Err(Error::Backend {
                scheme: "op",
                kind: BackendFailureKind::Permanent,
                message: format!("op exited 0 but emitted stderr: {redacted}"),
            });
        }

        // Strip exactly one trailing newline. `op read` appends `\n` by
        // default; stripping client-side preserves a legitimate trailing
        // newline if the secret itself ends in one.
        let mut stdout = output.stdout;
        if stdout.ends_with(b"\n") {
            stdout.pop();
        }

        let secret = String::from_utf8(stdout).map_err(|e| Error::Backend {
            scheme: "op",
            kind: BackendFailureKind::Permanent,
            message: format!("op read produced invalid UTF-8: {e}"),
        })?;

        Ok(SecretString::new(secret.into()))
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        use hasp_core::ExposeSecret;

        self.ensure_init()?;
        check_ambient_credentials()?;

        let op_url = OpUrl::try_from(url)?;
        let reference = format!("op://{}/{}/{}", op_url.vault, op_url.item, op_url.field);

        // `op item edit` requires positional `<field>=<value>` and an
        // existing item. We try edit first; if `op` reports the item
        // doesn't exist, fall back to `op item create`.
        //
        // Argv exposure: the secret value lives on `op`'s argv for the
        // life of the subprocess. On Linux, `/proc/<pid>/cmdline` is
        // same-uid readable. This is the documented cost of the
        // `op item edit|create` API surface (no stdin variant for
        // field values). Document in cli-reference.md; PR description
        // can flag the deferred mitigation as a follow-up.
        let assignment = format!("{}={}", op_url.field, value.expose_secret());

        let edit_args: [&str; 6] = [
            "item",
            "edit",
            &op_url.item,
            "--vault",
            &op_url.vault,
            &assignment,
        ];
        let edit_output = run_op_with_timeout(&edit_args, GET_TIMEOUT)?;

        if edit_output.status.success() {
            return Ok(());
        }

        let edit_err = map_op_error(
            &String::from_utf8_lossy(&edit_output.stderr),
            edit_output.status.code().unwrap_or(-1),
            &reference,
        );

        // Only fall back to create on NotFound. AuthenticationFailed,
        // PermissionDenied, transport — surface as-is.
        if !matches!(edit_err, Error::NotFound(_)) {
            return Err(edit_err);
        }

        let create_args: [&str; 8] = [
            "item",
            "create",
            "--vault",
            &op_url.vault,
            "--title",
            &op_url.item,
            "--category",
            "password",
        ];
        // Append the field assignment as a 9th positional. `op item
        // create` accepts arbitrary `<field>=<value>` after the named
        // flags; the password category default-assigns the value to
        // the `password` field, but explicit `<field>=<value>`
        // overrides for non-default field names.
        let mut create_args = create_args.to_vec();
        create_args.push(&assignment);
        let create_output = run_op_with_timeout(&create_args, GET_TIMEOUT)?;

        if !create_output.status.success() {
            let stderr = String::from_utf8_lossy(&create_output.stderr);
            let exit_code = create_output.status.code().unwrap_or(-1);
            return Err(map_op_error(&stderr, exit_code, &reference));
        }

        Ok(())
    }

    fn list(&self, url: &Url) -> Result<Vec<Entry>, Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let list_url = OpListUrl::try_from(url)?;
        // `--format=json` gives stable parseable output. Field is not
        // exposed at item-list granularity; each Entry's URL synthesizes
        // a placeholder `password` field. Real field-level discovery
        // requires `op item get --format=json` per item (one extra
        // subprocess per entry); that's a follow-up.
        let args = ["item", "list", "--vault", &list_url.vault, "--format=json"];

        let output = run_op_with_timeout(&args, EXISTS_TIMEOUT)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            let reference = format!("op://{}", list_url.vault);
            return Err(map_op_error(&stderr, exit_code, &reference));
        }

        let stdout = String::from_utf8(output.stdout).map_err(|e| Error::Backend {
            scheme: "op",
            kind: BackendFailureKind::Permanent,
            message: format!("op item list produced invalid UTF-8: {e}"),
        })?;

        let items: Vec<serde_json::Value> =
            serde_json::from_str(&stdout).map_err(|e| Error::Backend {
                scheme: "op",
                kind: BackendFailureKind::Permanent,
                message: format!("op item list returned unparseable JSON: {e}"),
            })?;

        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            // Prefer `id` (UUID, rename-stable) for the URL identity;
            // fall back to `title` if `id` is missing (fake-bin tests
            // emit title-only output for simplicity). Document in
            // cli-reference.md that title-keyed URLs are rename-fragile;
            // UUID-keyed cache resolution lands as a follow-up.
            let id = item
                .get("id")
                .and_then(|v| v.as_str())
                .or_else(|| item.get("title").and_then(|v| v.as_str()));
            let title = item
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| id.unwrap_or("?"));
            let Some(id) = id else { continue };

            let entry_url = format!("op://{}/{}/password", list_url.vault, id);
            let parsed = Url::parse(&entry_url).map_err(|e| Error::Backend {
                scheme: "op",
                kind: BackendFailureKind::Permanent,
                message: format!("op item list yielded malformed URL: {e}"),
            })?;
            entries.push(Entry {
                name: title.to_owned(),
                url: parsed,
            });
        }

        Ok(entries)
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let op_url = OpUrl::try_from(url)?;
        let reference = format!("op://{}/{}/{}", op_url.vault, op_url.item, op_url.field);

        // `op item delete` removes the entire item, not just one field.
        // The URL's `field` segment is required by op:// grammar but
        // ignored here. Documented in the per-backend README.
        let args = ["item", "delete", &op_url.item, "--vault", &op_url.vault];
        let output = run_op_with_timeout(&args, EXISTS_TIMEOUT)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);
        Err(map_op_error(&stderr, exit_code, &reference))
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        self.ensure_init()?;
        check_ambient_credentials()?;

        let op_url = OpUrl::try_from(url)?;
        let reference = format!("op://{}/{}/{}", op_url.vault, op_url.item, op_url.field);
        let args: [&str; 3] = ["read", "--no-color", &reference];

        let output = run_op_with_timeout(&args, EXISTS_TIMEOUT)?;

        if output.status.success() {
            return Ok(true);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);
        let err = map_op_error(&stderr, exit_code, &reference);

        match err {
            Error::NotFound(_) => Ok(false),
            _ => Err(err),
        }
    }
}

/// Spawn `op` with the given args and enforce a wall-clock timeout.
///
/// Two reader threads consume stdout and stderr concurrently while the
/// main thread polls `try_wait`. This prevents pipe-buffer deadlock when
/// `op item list` emits large JSON or when stderr is verbose.
///
/// Stdout is always piped; never given a raw File FD. `op read` applies
/// UTF-8 validation that corrupts binary bytes when writing to a
/// non-pipe FD (verified community finding).
fn run_op_with_timeout(args: &[&str], timeout: Duration) -> Result<std::process::Output, Error> {
    let mut child = Command::new("op")
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
                        scheme: "op",
                        kind: BackendFailureKind::Transient,
                        message: "op invocation timed out".into(),
                    });
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(Error::Backend {
                    scheme: "op",
                    kind: BackendFailureKind::Transient,
                    message: format!("failed to wait for op process: {e}"),
                });
            }
        }
    }
}

fn map_spawn_error(err: std::io::Error) -> Error {
    use std::io::ErrorKind;
    if err.kind() == ErrorKind::NotFound {
        Error::Backend {
            scheme: "op",
            kind: BackendFailureKind::Permanent,
            message: "op binary not found in PATH".into(),
        }
    } else {
        Error::Backend {
            scheme: "op",
            kind: BackendFailureKind::Transient,
            message: format!("failed to spawn op: {err}"),
        }
    }
}

/// Map `op` stderr + exit code into the locked `hasp_core::Error` taxonomy.
///
/// Priority is first-anchor-wins, case-insensitive. Unmatched stderr
/// falls through to `Backend { Permanent }` — never to `NotFound`. A
/// future `op` rewording must surface as a backend error, not a silently
/// misclassified missing item.
///
/// `op` echoes the `op://` reference URL inside error messages. The
/// returned error message has the reference redacted.
fn map_op_error(stderr: &str, exit_code: i32, reference: &str) -> Error {
    let lower = stderr.to_lowercase();

    if lower.contains("could not find item")
        || lower.contains("isn't a vault")
        || lower.contains("isn't an item")
        || lower.contains("more than one item matches")
    {
        return Error::NotFound(reference.to_string());
    }

    if lower.contains("not currently signed in")
        || lower.contains("authorization timeout")
        || lower.contains("connecting to desktop app")
        || lower.contains("connection reset")
        || lower.contains("signin credentials are not compatible")
    {
        return Error::AuthenticationFailed(redact_reference(stderr, reference));
    }

    if lower.contains("connection reset")
        || lower.contains("dial")
        || lower.contains("getaddrinfo")
        || lower.contains("i/o timeout")
        || lower.contains("eof")
        || lower.contains("no such host")
    {
        return Error::Backend {
            scheme: "op",
            kind: BackendFailureKind::Transient,
            message: redact_reference(stderr, reference),
        };
    }

    let redacted = redact_reference(stderr, reference);
    Error::Backend {
        scheme: "op",
        kind: BackendFailureKind::Permanent,
        message: format!("op exited with code {exit_code}: {redacted}"),
    }
}

/// Replace occurrences of the secret-reference URL with a redacted token.
///
/// The reference identifies a secret but is not itself a secret value.
/// Redaction preserves URL discipline and prevents accidental log leakage
/// of internal vault/item/field names.
fn redact_reference(stderr: &str, reference: &str) -> String {
    stderr.replace(reference, "op://<redacted>")
}

/// Parse a semver triple from the `op --version` stdout.
///
/// Accepts bare triples (`2.30.0`) and release labels
/// (`2.30.0-beta.1`). Everything after the third numeric component
/// is ignored.
fn parse_op_version(output: &str) -> Option<(u32, u32, u32)> {
    let trimmed = output.trim();
    let version_part = trimmed.split_whitespace().next()?;
    let mut parts = version_part.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// Fail fast if no ambient 1Password credentials are present.
///
/// `op` has no `--no-prompt` flag; spawning without credentials in a
/// headless context causes an indefinite biometric hang. This check
/// happens before every spawn so CI runners and containers never block.
fn check_ambient_credentials() -> Result<(), Error> {
    let has_service = std::env::var("OP_SERVICE_ACCOUNT_TOKEN").is_ok();
    let has_session = std::env::vars().any(|(k, _)| k.starts_with("OP_SESSION_"));
    let has_connect =
        std::env::var("OP_CONNECT_TOKEN").is_ok() && std::env::var("OP_CONNECT_HOST").is_ok();

    if !has_service && !has_session && !has_connect {
        return Err(Error::AuthenticationFailed(
            "no ambient 1Password credentials detected; set OP_SERVICE_ACCOUNT_TOKEN, run `op signin`, or configure Connect".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hasp_core::test_utils::{EnvGuard, ENV_LOCK};

    #[test]
    fn parse_valid_url() {
        let url = Url::parse("op://vault/item/field").unwrap();
        let op = OpUrl::try_from(&url).unwrap();
        assert_eq!(op.vault, "vault");
        assert_eq!(op.item, "item");
        assert_eq!(op.field, "field");
    }

    #[test]
    fn parse_empty_segment_fails() {
        let url = Url::parse("op://vault//field").unwrap();
        assert!(OpUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_too_few_segments_fails() {
        let url = Url::parse("op://vault/item").unwrap();
        assert!(OpUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_too_many_segments_fails() {
        let url = Url::parse("op://vault/item/field/extra").unwrap();
        assert!(OpUrl::try_from(&url).is_err());
    }

    #[test]
    fn parse_query_param_fails() {
        let url = Url::parse("op://vault/item/field?raw=true").unwrap();
        assert!(OpUrl::try_from(&url).is_err());
    }

    #[test]
    fn error_map_not_found_item() {
        let err = map_op_error(
            "[ERROR] 2024/12/29 23:17:25 could not find item MyItem in vault MyVault",
            1,
            "op://MyVault/MyItem/field",
        );
        assert!(matches!(err, Error::NotFound(ref s) if s == "op://MyVault/MyItem/field"));
    }

    #[test]
    fn error_map_not_found_vault() {
        let err = map_op_error(
            r#"[ERROR] 2025/08/08 15:24:36 "Private" isn't a vault in this account."#,
            1,
            "op://Private/Item/field",
        );
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn error_map_not_found_item_isnt() {
        let err = map_op_error(
            r#"[ERROR] 2022/07/06 23:28:40 "-" isn't an item."#,
            1,
            "op://vault/-/field",
        );
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn error_map_not_found_multi_match() {
        let err = map_op_error("more than one item matches", 1, "op://vault/item/field");
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn error_map_auth_not_signed_in() {
        let err = map_op_error(
            "(ERROR) You are not currently signed in.",
            1,
            "op://vault/item/field",
        );
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn error_map_auth_timeout() {
        let err = map_op_error(
            "[ERROR] 2025/07/11 10:16:41 authorization timeout",
            1,
            "op://vault/item/field",
        );
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn error_map_auth_desktop_app() {
        let err = map_op_error(
            "connecting to desktop app: read: connection reset",
            1,
            "op://vault/item/field",
        );
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn error_map_auth_incompatible() {
        let err = map_op_error(
            "Signin credentials are not compatible with the provided user auth from server",
            1,
            "op://vault/item/field",
        );
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn error_map_transient_network() {
        for anchor in [
            "dial tcp",
            "getaddrinfo",
            "i/o timeout",
            "EOF",
            "no such host",
        ] {
            let err = map_op_error(anchor, 1, "op://vault/item/field");
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
    fn error_map_unmatched_is_permanent() {
        let err = map_op_error("some unexpected error from op", 1, "op://vault/item/field");
        assert!(matches!(
            err,
            Error::Backend {
                kind: BackendFailureKind::Permanent,
                ..
            }
        ));
    }

    #[test]
    fn error_map_first_anchor_wins() {
        // "connection reset" appears in both auth and transient rows.
        // Auth row comes first, so this maps to AuthenticationFailed.
        let err = map_op_error(
            "not currently signed in and connection reset",
            1,
            "op://vault/item/field",
        );
        assert!(matches!(err, Error::AuthenticationFailed(_)));
    }

    #[test]
    fn version_parse_valid() {
        assert_eq!(parse_op_version("2.30.0"), Some((2, 30, 0)));
        assert_eq!(parse_op_version("2.30.0-beta.1"), Some((2, 30, 0)));
        assert_eq!(parse_op_version("2.30.0\n"), Some((2, 30, 0)));
    }

    #[test]
    fn version_parse_malformed() {
        assert_eq!(parse_op_version("not.a.version"), None);
        assert_eq!(parse_op_version(""), None);
    }

    #[test]
    fn version_reject_too_old() {
        // We can't easily run op --version in a headless unit test,
        // so we validate the parsing + comparison logic indirectly.
        let version = parse_op_version("2.29.0").unwrap();
        assert!(version.0 < 2 || (version.0 == 2 && version.1 < 30));
    }

    #[test]
    fn version_accept_exact_floor() {
        let version = parse_op_version("2.30.0").unwrap();
        assert!(!(version.0 < 2 || (version.0 == 2 && version.1 < 30)));
    }

    #[test]
    fn preflight_auth_no_creds_fails_fast() {
        let _lock = ENV_LOCK.lock().unwrap();

        let old_service = std::env::var("OP_SERVICE_ACCOUNT_TOKEN").ok();
        let old_connect_token = std::env::var("OP_CONNECT_TOKEN").ok();
        let old_connect_host = std::env::var("OP_CONNECT_HOST").ok();

        std::env::remove_var("OP_SERVICE_ACCOUNT_TOKEN");
        std::env::remove_var("OP_CONNECT_TOKEN");
        std::env::remove_var("OP_CONNECT_HOST");

        // Remove any OP_SESSION_* vars.
        for (k, _) in std::env::vars().filter(|(k, _)| k.starts_with("OP_SESSION_")) {
            std::env::remove_var(&k);
        }

        let result = check_ambient_credentials();

        if let Some(v) = old_service {
            std::env::set_var("OP_SERVICE_ACCOUNT_TOKEN", v);
        }
        if let Some(v) = old_connect_token {
            std::env::set_var("OP_CONNECT_TOKEN", v);
        }
        if let Some(v) = old_connect_host {
            std::env::set_var("OP_CONNECT_HOST", v);
        }

        assert!(
            matches!(result, Err(Error::AuthenticationFailed(_))),
            "expected AuthenticationFailed when no ambient credentials are present"
        );
    }

    #[test]
    fn preflight_auth_service_account_ok() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set("OP_SERVICE_ACCOUNT_TOKEN", "test-token");
        assert!(check_ambient_credentials().is_ok());
    }

    #[test]
    fn redact_reference_replaces_url() {
        let msg = "could not read secret op://MyVault/MyItem/field: not found";
        let redacted = redact_reference(msg, "op://MyVault/MyItem/field");
        assert_eq!(redacted, "could not read secret op://<redacted>: not found");
    }
}
