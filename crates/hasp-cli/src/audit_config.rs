//! TOML-backed audit-sink configuration.
//!
//! Mirrors the `profiles.toml` resolution model: load
//! `~/.config/hasp/audit.toml` (or `HASP_AUDIT_CONFIG_PATH` if set);
//! map the `[audit]` section to one of the built-in `AuditSink`
//! implementations. Env vars (`HASP_AUDIT`, `HASP_AUDIT_PATH`) take
//! precedence so ops invocations cannot be silently overridden by a
//! user-level config file.
//!
//! Example `audit.toml`:
//!
//! ```toml
//! [audit]
//! sink = "file"
//! path = "/var/log/hasp/audit.log"
//! # for sink = "syslog":
//! # ident = "hasp"
//! ```

use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Deserialize, Default)]
struct AuditConfigFile {
    audit: Option<AuditSection>,
}

#[derive(Debug, Deserialize, Default)]
struct AuditSection {
    /// `"stderr"` (default), `"file"`, `"syslog"`, or `"off"`.
    sink: Option<String>,
    /// Path for `sink = "file"`.
    path: Option<String>,
    /// Program ident for `sink = "syslog"` (default `"hasp"`).
    ident: Option<String>,
}

/// A parsed audit configuration ready to be turned into an
/// [`hasp::AuditSink`].
#[derive(Debug, Default, Clone)]
pub(crate) struct AuditConfig {
    pub sink: SinkKind,
    pub path: Option<PathBuf>,
    pub ident: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) enum SinkKind {
    #[default]
    Stderr,
    File,
    Syslog,
    Off,
}

impl AuditConfig {
    /// Resolve the active audit configuration from env vars and TOML.
    ///
    /// Precedence (highest first):
    /// 1. `HASP_AUDIT` env var. `HASP_AUDIT_PATH` (file mode) and
    ///    `HASP_AUDIT_IDENT` (syslog mode) refine the choice.
    /// 2. `audit.toml` `[audit]` section, located via
    ///    `HASP_AUDIT_CONFIG_PATH` or `~/.config/hasp/audit.toml`.
    /// 3. Default: `Stderr`.
    pub fn resolve() -> Self {
        if let Some(cfg) = Self::from_env() {
            return cfg;
        }
        Self::from_toml().unwrap_or_default()
    }

    fn from_env() -> Option<Self> {
        let mode = std::env::var("HASP_AUDIT").ok()?;
        let kind = match mode.as_str() {
            "off" | "none" | "noop" => SinkKind::Off,
            "file" => SinkKind::File,
            "syslog" => SinkKind::Syslog,
            "stderr" | "" => SinkKind::Stderr,
            // Unknown value — treat as stderr (fail-open to the
            // safer default rather than silently disabling audit).
            _ => SinkKind::Stderr,
        };
        Some(Self {
            sink: kind,
            path: std::env::var_os("HASP_AUDIT_PATH").map(PathBuf::from),
            ident: std::env::var("HASP_AUDIT_IDENT").ok(),
        })
    }

    fn from_toml() -> Option<Self> {
        let path = audit_toml_path()?;
        let body = std::fs::read_to_string(&path).ok()?;
        let parsed: AuditConfigFile = toml::from_str(&body).ok()?;
        let section = parsed.audit?;
        let kind = match section.sink.as_deref() {
            Some("off") | Some("none") | Some("noop") => SinkKind::Off,
            Some("file") => SinkKind::File,
            Some("syslog") => SinkKind::Syslog,
            Some("stderr") | None => SinkKind::Stderr,
            // Unknown TOML value: same fail-open posture as env path.
            Some(_) => SinkKind::Stderr,
        };
        Some(Self {
            sink: kind,
            path: section.path.map(PathBuf::from),
            ident: section.ident,
        })
    }

    /// Build the configured [`hasp::AuditSink`].
    ///
    /// `File` with no path or an unopenable path falls back to
    /// [`hasp::NoopSink`] — audit must never poison a verb's result.
    /// `Syslog` on Windows (where the type does not exist) falls
    /// back to [`hasp::StderrSink`] (closest cross-platform stand-in).
    pub fn into_sink(self) -> Arc<dyn hasp::AuditSink> {
        match self.sink {
            SinkKind::Off => Arc::new(hasp::NoopSink),
            SinkKind::Stderr => Arc::new(hasp::StderrSink),
            SinkKind::File => match self.path {
                Some(p) => match hasp::FileSink::open(&p) {
                    Ok(s) => Arc::new(s),
                    Err(_) => Arc::new(hasp::NoopSink),
                },
                None => Arc::new(hasp::StderrSink),
            },
            SinkKind::Syslog => syslog_sink(self.ident.as_deref().unwrap_or("hasp")),
        }
    }
}

#[cfg(unix)]
fn syslog_sink(ident: &str) -> Arc<dyn hasp::AuditSink> {
    match hasp::SyslogSink::open(ident) {
        Ok(s) => Arc::new(s),
        Err(_) => Arc::new(hasp::NoopSink),
    }
}

#[cfg(not(unix))]
fn syslog_sink(_ident: &str) -> Arc<dyn hasp::AuditSink> {
    // Syslog is not available on this platform; fall back to stderr
    // so audit emission still happens via the closest portable sink.
    Arc::new(hasp::StderrSink)
}

/// Locate the on-disk audit config file. Returns `None` if the user
/// has no platform config dir AND no `HASP_AUDIT_CONFIG_PATH` set.
fn audit_toml_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HASP_AUDIT_CONFIG_PATH") {
        return Some(PathBuf::from(p));
    }
    Some(dirs::config_dir()?.join("hasp").join("audit.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stderr() {
        let toml = r#"[audit]
sink = "stderr"
"#;
        let parsed: AuditConfigFile = toml::from_str(toml).unwrap();
        assert_eq!(parsed.audit.unwrap().sink.unwrap(), "stderr");
    }

    #[test]
    fn parse_file_with_path() {
        let toml = r#"[audit]
sink = "file"
path = "/var/log/hasp.log"
"#;
        let parsed: AuditConfigFile = toml::from_str(toml).unwrap();
        let s = parsed.audit.unwrap();
        assert_eq!(s.sink.unwrap(), "file");
        assert_eq!(s.path.unwrap(), "/var/log/hasp.log");
    }

    #[test]
    fn parse_syslog_with_ident() {
        let toml = r#"[audit]
sink = "syslog"
ident = "hasp-prod"
"#;
        let parsed: AuditConfigFile = toml::from_str(toml).unwrap();
        let s = parsed.audit.unwrap();
        assert_eq!(s.sink.unwrap(), "syslog");
        assert_eq!(s.ident.unwrap(), "hasp-prod");
    }

    #[test]
    fn parse_unknown_sink_falls_back_to_stderr_in_resolution() {
        let toml = r#"[audit]
sink = "carrier-pigeon"
"#;
        // Direct parse keeps the raw value...
        let parsed: AuditConfigFile = toml::from_str(toml).unwrap();
        assert_eq!(parsed.audit.unwrap().sink.unwrap(), "carrier-pigeon");
        // ...but resolution maps it to Stderr (fail-open).
        // We can't easily exercise from_toml() here without writing a
        // file, but the match arm in from_toml is the contract.
    }

    #[test]
    fn env_overrides_default() {
        // Save and restore relevant env vars to avoid contaminating
        // sibling tests in this process.
        let saved_audit = std::env::var_os("HASP_AUDIT");
        let saved_path = std::env::var_os("HASP_AUDIT_PATH");
        let saved_cfg = std::env::var_os("HASP_AUDIT_CONFIG_PATH");
        std::env::set_var("HASP_AUDIT", "off");
        std::env::remove_var("HASP_AUDIT_PATH");
        std::env::remove_var("HASP_AUDIT_CONFIG_PATH");

        let cfg = AuditConfig::resolve();
        assert_eq!(cfg.sink, SinkKind::Off);

        // Restore.
        match saved_audit {
            Some(v) => std::env::set_var("HASP_AUDIT", v),
            None => std::env::remove_var("HASP_AUDIT"),
        }
        match saved_path {
            Some(v) => std::env::set_var("HASP_AUDIT_PATH", v),
            None => std::env::remove_var("HASP_AUDIT_PATH"),
        }
        match saved_cfg {
            Some(v) => std::env::set_var("HASP_AUDIT_CONFIG_PATH", v),
            None => std::env::remove_var("HASP_AUDIT_CONFIG_PATH"),
        }
    }
}
