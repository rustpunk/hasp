//! Structured audit events emitted by every `Store` verb.
//!
//! `AuditEvent` is a closed-shape record: a timestamp, a verb-and-phase
//! label, the URL scheme(s) the verb operated on, a stable outcome
//! label, and (on failure) a stable `error_kind` classifier. No field
//! carries a value, a value-derived length, or any byte of secret
//! material — the redaction posture is enforced by the type system:
//! the struct is `#[non_exhaustive]`, every field is either a
//! timestamp, a `&'static str` chosen from a closed set, or a small
//! owned `String` populated only from a URL scheme.
//!
//! Implementations of `AuditSink` only ever receive an
//! `&AuditEvent` — they cannot construct one with arbitrary content,
//! and they cannot widen the field set.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The verb a `Store` operation belongs to. Closed set so audit event
/// labels are statically known and cannot be widened by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Get,
    Put,
    List,
    Delete,
    Exists,
    Cp,
    Run,
}

impl Verb {
    /// Static label for the `*.start` event.
    pub fn start_label(self) -> &'static str {
        match self {
            Verb::Get => "get.start",
            Verb::Put => "put.start",
            Verb::List => "list.start",
            Verb::Delete => "delete.start",
            Verb::Exists => "exists.start",
            Verb::Cp => "cp.start",
            Verb::Run => "run.start",
        }
    }

    /// Static label for the `*.done` event.
    pub fn done_label(self) -> &'static str {
        match self {
            Verb::Get => "get.done",
            Verb::Put => "put.done",
            Verb::List => "list.done",
            Verb::Delete => "delete.done",
            Verb::Exists => "exists.done",
            Verb::Cp => "cp.done",
            Verb::Run => "run.done",
        }
    }
}

/// A redacted audit event.
///
/// Constructed via [`AuditEvent::start`] or [`AuditEvent::done`]; the
/// struct is `#[non_exhaustive]` so external crates cannot widen the
/// field set by struct-literal initialization. Sink implementations
/// receive `&AuditEvent` and can serialize whichever fields they
/// expose — but every field is, by construction, value-free.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub ts: SystemTime,
    pub event: &'static str,
    pub url_scheme: String,
    pub dst_scheme: Option<String>,
    pub outcome: &'static str,
    pub error_kind: Option<&'static str>,
}

impl AuditEvent {
    /// Build a `*.start` event for `verb` operating on a URL with
    /// `scheme`. Default `outcome` is `"started"`.
    pub fn start(verb: Verb, scheme: impl Into<String>) -> Self {
        Self {
            ts: SystemTime::now(),
            event: verb.start_label(),
            url_scheme: scheme.into(),
            dst_scheme: None,
            outcome: "started",
            error_kind: None,
        }
    }

    /// Build a `*.done` event for `verb` with the given outcome label.
    pub fn done(verb: Verb, scheme: impl Into<String>, outcome: &'static str) -> Self {
        Self {
            ts: SystemTime::now(),
            event: verb.done_label(),
            url_scheme: scheme.into(),
            dst_scheme: None,
            outcome,
            error_kind: None,
        }
    }

    /// Attach a destination scheme (used by `cp`, `diff`, and any future
    /// two-URL verb).
    pub fn with_dst_scheme(mut self, dst_scheme: impl Into<String>) -> Self {
        self.dst_scheme = Some(dst_scheme.into());
        self
    }

    /// Attach a stable error-kind classifier (from `Error::kind()`).
    pub fn with_error_kind(mut self, kind: &'static str) -> Self {
        self.error_kind = Some(kind);
        self
    }

    /// Render to a single-line JSON string with no trailing newline.
    ///
    /// Wire format (fields appear in this order):
    ///
    /// ```json
    /// {"event":"get.done","ts":1234567890,"src_scheme":"vault","outcome":"ok"}
    /// ```
    ///
    /// `dst_scheme` and `error_kind` appear only when populated. The
    /// timestamp is UNIX seconds since the epoch; clock-skew anomalies
    /// fall back to `0` rather than panicking on the secret path.
    pub fn to_json_line(&self) -> String {
        let ts = self
            .ts
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut obj = serde_json::Map::new();
        obj.insert("event".into(), serde_json::Value::String(self.event.into()));
        obj.insert("ts".into(), serde_json::Value::Number(ts.into()));
        obj.insert(
            "src_scheme".into(),
            serde_json::Value::String(self.url_scheme.clone()),
        );
        if let Some(d) = &self.dst_scheme {
            obj.insert("dst_scheme".into(), serde_json::Value::String(d.clone()));
        }
        obj.insert(
            "outcome".into(),
            serde_json::Value::String(self.outcome.into()),
        );
        if let Some(k) = self.error_kind {
            obj.insert("error_kind".into(), serde_json::Value::String(k.into()));
        }
        serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
    }
}

/// A sink that consumes [`AuditEvent`]s.
///
/// Sinks must be `Send + Sync` because `Store` is shared across
/// threads. `emit` is intentionally infallible — the audit path must
/// never poison a verb's result. Sink implementations swallow IO
/// errors and degrade silently.
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &AuditEvent);
}

/// A sink that drops every event. Used to disable audit emission
/// entirely without making the sink itself optional.
pub struct NoopSink;

impl AuditSink for NoopSink {
    fn emit(&self, _event: &AuditEvent) {}
}

/// Writes each event as one JSON line to stderr.
pub struct StderrSink;

impl AuditSink for StderrSink {
    fn emit(&self, event: &AuditEvent) {
        let line = event.to_json_line();
        let _ = writeln!(io::stderr(), "{line}");
    }
}

/// Append-only file sink, one JSON event per line.
///
/// The file is opened in append mode with mode `0o600` on Unix (the
/// audit stream may carry which URLs were accessed and at what time;
/// that's not a secret value but it is process-history a hostile
/// uid-peer should not necessarily read). A `Mutex<File>` serializes
/// writes so concurrent emitters cannot interleave bytes.
pub struct FileSink {
    path: PathBuf,
    file: Mutex<File>,
}

impl FileSink {
    /// Open the audit file in append mode, creating it if missing.
    ///
    /// On Unix, sets the file mode to `0o600` after open. On other
    /// platforms the OS-default ACL applies.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }

        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    /// Path the sink is writing to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileSink {
    fn emit(&self, event: &AuditEvent) {
        let line = event.to_json_line();
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }
}

/// Forwards each event to the local syslog daemon via `libc::syslog`.
///
/// Unix-only (`#[cfg(unix)]`) — Windows has no syslog equivalent
/// (`Event Log` / ETW are a different API surface). Windows callers
/// should use [`FileSink`] and ship the file to whatever ingest the
/// host runs.
///
/// Each call to `emit` invokes `libc::syslog(priority, "%s\0", line)`
/// where `priority` is `LOG_INFO | LOG_USER` (configurable on
/// construction). The libc client takes care of socket-path
/// portability (`/dev/log` on Linux, `/var/run/syslog` on macOS) and
/// RFC3164/5424 framing — we don't reimplement either.
///
/// `openlog` is called once on construction with the passed `ident`
/// (typically `"hasp"`); the syslog connection persists for the
/// lifetime of the sink. `closelog` is called on drop.
#[cfg(unix)]
#[derive(Debug)]
pub struct SyslogSink {
    /// Held for the lifetime of the sink so the C string passed to
    /// `openlog` outlives the syslog connection. `openlog` does NOT
    /// copy its `ident` argument; dropping the storage early would
    /// dangle the pointer the syslog client retains.
    _ident: std::ffi::CString,
    priority: i32,
}

#[cfg(unix)]
impl SyslogSink {
    /// Open a syslog connection with `ident` (program name shown in
    /// log entries) and the default `LOG_INFO | LOG_USER` priority.
    ///
    /// Returns `Err` only if `ident` contains an interior NUL. The
    /// underlying `openlog(3)` is infallible — it does not perform
    /// I/O until the first `syslog(3)` call.
    pub fn open(ident: &str) -> io::Result<Self> {
        let cstr = std::ffi::CString::new(ident).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("syslog ident contains NUL: {e}"),
            )
        })?;
        // SAFETY: `openlog` reads its `ident` argument by pointer for
        // the life of the connection; we keep `cstr` owned in the
        // returned struct so the pointer stays valid until `closelog`.
        // `option = 0` and `facility = LOG_USER` are POSIX-defined
        // constants, safe in any process state.
        unsafe {
            libc::openlog(cstr.as_ptr(), 0, libc::LOG_USER);
        }
        Ok(Self {
            _ident: cstr,
            priority: libc::LOG_INFO | libc::LOG_USER,
        })
    }
}

#[cfg(unix)]
impl AuditSink for SyslogSink {
    fn emit(&self, event: &AuditEvent) {
        let line = event.to_json_line();
        // libc::syslog expects a NUL-terminated C string. Constructing
        // a CString allocates; that's acceptable on the audit path
        // (one allocation per event, off the hot secret-fetch path).
        // If the line contains an interior NUL (it can't, JSON has no
        // NUL bytes by construction) the emit silently drops.
        if let Ok(c) = std::ffi::CString::new(line) {
            // SAFETY: priority is a valid combined facility|level
            // bitmask; format is the literal "%s\0" with one
            // matching `*const c_char` argument; `c.as_ptr()` is
            // valid for the duration of the call. No interior NUL
            // (CString::new enforces).
            unsafe {
                libc::syslog(self.priority, c"%s".as_ptr(), c.as_ptr());
            }
        }
    }
}

#[cfg(unix)]
impl Drop for SyslogSink {
    fn drop(&mut self) {
        // SAFETY: closelog is infallible and idempotent; safe to call
        // even if openlog was never invoked.
        unsafe {
            libc::closelog();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn verb_labels_are_stable_strings() {
        // Soft guard against accidental relabeling — every verb's
        // start/done pair must be discoverable as a `*.start` /
        // `*.done` pattern.
        for v in [
            Verb::Get,
            Verb::Put,
            Verb::List,
            Verb::Delete,
            Verb::Exists,
            Verb::Cp,
            Verb::Run,
        ] {
            assert!(v.start_label().ends_with(".start"));
            assert!(v.done_label().ends_with(".done"));
        }
    }

    #[test]
    fn start_event_serializes_minimal_fields() {
        let ev = AuditEvent::start(Verb::Get, "vault");
        let json = ev.to_json_line();
        assert!(json.contains("\"event\":\"get.start\""));
        assert!(json.contains("\"src_scheme\":\"vault\""));
        assert!(json.contains("\"outcome\":\"started\""));
        assert!(!json.contains("dst_scheme"));
        assert!(!json.contains("error_kind"));
    }

    #[test]
    fn done_event_with_dst_and_error_kind() {
        let ev = AuditEvent::done(Verb::Cp, "vault", "error")
            .with_dst_scheme("aws-sm")
            .with_error_kind("not_found");
        let json = ev.to_json_line();
        assert!(json.contains("\"event\":\"cp.done\""));
        assert!(json.contains("\"src_scheme\":\"vault\""));
        assert!(json.contains("\"dst_scheme\":\"aws-sm\""));
        assert!(json.contains("\"outcome\":\"error\""));
        assert!(json.contains("\"error_kind\":\"not_found\""));
    }

    #[test]
    fn stderr_sink_is_object_safe() {
        let s: Arc<dyn AuditSink> = Arc::new(StderrSink);
        s.emit(&AuditEvent::start(Verb::Get, "env"));
    }

    #[test]
    fn noop_sink_emits_nothing_observable() {
        let s: Arc<dyn AuditSink> = Arc::new(NoopSink);
        s.emit(&AuditEvent::start(Verb::Get, "env"));
    }

    #[test]
    fn file_sink_appends_one_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileSink::open(&path).unwrap();
        sink.emit(&AuditEvent::start(Verb::Get, "env"));
        sink.emit(&AuditEvent::done(Verb::Get, "env", "ok"));
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.lines().next().unwrap().contains("get.start"));
        assert!(body.lines().nth(1).unwrap().contains("get.done"));
    }

    #[cfg(unix)]
    #[test]
    fn file_sink_sets_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let _sink = FileSink::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn syslog_sink_constructs_and_emits_without_panic() {
        // We cannot assert that syslogd actually received the message
        // (no portable way to read the local syslog from a unit test
        // without depending on the daemon being configured). What we
        // can assert: openlog/syslog/closelog do not panic, and the
        // sink is object-safe behind `Arc<dyn AuditSink>`. If syslogd
        // is absent the libc client silently drops — that is the
        // documented degrade behavior.
        let sink: Arc<dyn AuditSink> = Arc::new(SyslogSink::open("hasp-test").expect("openlog"));
        sink.emit(&AuditEvent::start(Verb::Get, "env"));
        sink.emit(&AuditEvent::done(Verb::Get, "env", "ok"));
    }

    #[cfg(unix)]
    #[test]
    fn syslog_sink_rejects_ident_with_interior_nul() {
        let err = SyslogSink::open("hasp\0bad").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
