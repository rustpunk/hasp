//! HTTP CONNECT proxy configuration.
//!
//! Corporate networks often force outbound traffic through an HTTP CONNECT
//! proxy (Squid, Blue Coat, Zscaler, etc.). This module provides the
//! configuration type and resolution helpers used by HTTP-based backends.
//!
//! SOCKS5 is out of scope for the current release. If your network requires
//! it, use a local SOCKS5-to-HTTP-CONNECT adapter (e.g. `proxychains-ng`).

use crate::Error;
use secrecy::SecretString;
use std::env;

/// Parsed HTTP CONNECT proxy configuration.
///
/// Credentials are stored in a `SecretString` so they never appear in
/// `Debug` output or error diagnostics. The `url` field is kept for
/// diagnostics but is the raw string supplied by the caller.
#[derive(Clone)]
pub struct ProxyConfig {
    /// The original URL string (for diagnostics only — may contain
    /// credentials that should not be logged).
    pub url: String,
    /// Proxy hostname or IP.
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// Username for Basic auth (optional).
    pub username: Option<String>,
    /// Password for Basic auth (optional).
    pub password: Option<SecretString>,
    /// Original scheme (http or https) — preserved so
    /// `url_without_credentials` reconstructs the correct URL.
    scheme: String,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("url", &self.url_without_credentials())
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl ProxyConfig {
    /// Parse from a URL string like `http://proxy:8080` or
    /// `http://user:pass@proxy:3128`.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidUrl` when the string is not a valid URL,
    /// has no host, or uses a non-HTTP scheme.
    pub fn parse(url: &str) -> Result<Self, Error> {
        let parsed =
            ::url::Url::parse(url).map_err(|e| Error::InvalidUrl(format!("proxy URL: {e}")))?;

        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(Error::InvalidUrl(format!(
                "proxy URL must be http:// or https://, got {}",
                parsed.scheme()
            )));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("proxy URL has no host".to_string()))?
            .to_string();
        let port = parsed.port().unwrap_or(8080);

        let (username, password) = if let Some(pass) = parsed.password() {
            (
                Some(parsed.username().to_string()),
                Some(SecretString::new(pass.to_string().into())),
            )
        } else if !parsed.username().is_empty() {
            (Some(parsed.username().to_string()), None)
        } else {
            (None, None)
        };

        Ok(ProxyConfig {
            url: url.to_string(),
            host,
            port,
            username,
            password,
            scheme: parsed.scheme().to_string(),
        })
    }

    /// Return the proxy URL with credentials removed, suitable for
    /// passing to HTTP client libraries (e.g. `reqwest::Proxy::all`).
    ///
    /// If the original URL contained a password, this returns
    /// `http://proxy:8080` so the library handles auth itself via the
    /// username/password fields.
    pub fn url_without_credentials(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Check whether the target host is covered by the `NO_PROXY`
/// environment variable.
///
/// Supports the same syntax as curl:
///
/// - `*` — disables proxy for every host.
/// - `localhost,127.0.0.1` — exact matches, comma-separated.
/// - `.example.com` — suffix match (`db.example.com` matches,
///   `example.com` does not).
/// - Port numbers in patterns are ignored — hasp matches hostnames only.
pub fn is_no_proxy(target_host: &str) -> bool {
    let no_proxy = match env::var("NO_PROXY").or_else(|_| env::var("no_proxy")) {
        Ok(v) if !v.is_empty() => v,
        _ => return false,
    };

    let target = target_host.to_ascii_lowercase();

    for pattern in no_proxy.split(',') {
        let pattern = pattern.trim().to_ascii_lowercase();
        if pattern.is_empty() {
            continue;
        }

        // Match everything.
        if pattern == "*" {
            return true;
        }

        // Strip port if present (e.g. "host:8080" → "host").
        let pattern_host = pattern.split(':').next().unwrap_or(&pattern);

        // Suffix match: .domain.com matches any.sub.domain.com
        if pattern_host.starts_with('.') {
            if target.ends_with(pattern_host) {
                return true;
            }
        }
        // Exact match, or suffix match without leading dot.
        else if target == pattern_host || target.ends_with(&format!(".{pattern_host}")) {
            return true;
        }
    }

    false
}

/// Resolve proxy configuration from the standard environment
/// variable stack.
///
/// Checks `ALL_PROXY`, then `HTTPS_PROXY` / `HTTP_PROXY`.  Skips
/// `NO_PROXY` hosts at this layer — callers should call
/// `is_no_proxy` separately when they know the target hostname.
///
/// The target hostname is used only for the `NO_PROXY` decision,
/// not for selecting between HTTP vs HTTPS proxy.
pub fn resolve_proxy_from_env(target_host: &str) -> Option<ProxyConfig> {
    if is_no_proxy(target_host) {
        return None;
    }

    let try_env = |name: &str| -> Option<ProxyConfig> {
        env::var(name)
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|url| ProxyConfig::parse(&url).ok())
    };

    try_env("ALL_PROXY")
        .or_else(|| try_env("all_proxy"))
        .or_else(|| try_env("HTTPS_PROXY"))
        .or_else(|| try_env("https_proxy"))
        .or_else(|| try_env("HTTP_PROXY"))
        .or_else(|| try_env("http_proxy"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_simple() {
        let cfg = ProxyConfig::parse("http://proxy:8080").unwrap();
        assert_eq!(cfg.host, "proxy");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.username, None);
        assert!(cfg.password.is_none());
    }

    #[test]
    fn parse_with_auth() {
        let cfg = ProxyConfig::parse("http://user:pass@proxy:3128").unwrap();
        assert_eq!(cfg.host, "proxy");
        assert_eq!(cfg.port, 3128);
        assert_eq!(cfg.username, Some("user".to_string()));
        assert_eq!(cfg.password.as_ref().unwrap().expose_secret(), "pass");
    }

    #[test]
    fn parse_only_username() {
        let cfg = ProxyConfig::parse("http://user@proxy:3128").unwrap();
        assert_eq!(cfg.username, Some("user".to_string()));
        assert!(cfg.password.is_none());
    }

    #[test]
    fn parse_no_port_uses_8080() {
        let cfg = ProxyConfig::parse("http://proxy").unwrap();
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn parse_https_scheme_accepted() {
        let cfg = ProxyConfig::parse("https://proxy:8443").unwrap();
        assert_eq!(cfg.host, "proxy");
        assert_eq!(cfg.port, 8443);
    }

    #[test]
    fn parse_non_http_scheme_rejected() {
        let err = ProxyConfig::parse("socks5://proxy:1080").unwrap_err();
        assert!(
            matches!(err, Error::InvalidUrl(ref s) if s.contains("http:// or https://")),
            "expected InvalidUrl for non-http scheme, got: {err}"
        );
    }

    #[test]
    fn parse_no_host_rejected() {
        let err = ProxyConfig::parse("://missing-scheme").unwrap_err();
        assert!(
            matches!(err, Error::InvalidUrl(ref s) if s.contains("proxy URL")),
            "expected InvalidUrl for missing host, got: {err}"
        );
    }

    #[test]
    fn url_without_credentials_strips_auth() {
        let cfg = ProxyConfig::parse("http://user:pass@proxy:3128").unwrap();
        assert_eq!(cfg.url_without_credentials(), "http://proxy:3128");
    }

    #[test]
    fn url_without_credentials_preserves_https() {
        let cfg = ProxyConfig::parse("https://user:pass@proxy:3128").unwrap();
        assert_eq!(cfg.url_without_credentials(), "https://proxy:3128");
    }

    #[test]
    fn debug_redacts_password() {
        let cfg = ProxyConfig::parse("http://user:s3cr3t@proxy:3128").unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("s3cr3t"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn is_no_proxy_star() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("NO_PROXY", "*");
        assert!(is_no_proxy("anything"));
        env::remove_var("NO_PROXY");
    }

    #[test]
    fn is_no_proxy_exact() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("NO_PROXY", "localhost");
        assert!(is_no_proxy("localhost"));
        assert!(!is_no_proxy("otherhost"));
        env::remove_var("NO_PROXY");
    }

    #[test]
    fn is_no_proxy_suffix() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("NO_PROXY", ".example.com");
        assert!(is_no_proxy("db.example.com"));
        assert!(!is_no_proxy("example.com"));
        env::remove_var("NO_PROXY");
    }

    #[test]
    fn is_no_proxy_case_insensitive() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("NO_PROXY", "LOCALHOST");
        assert!(is_no_proxy("localhost"));
        env::remove_var("NO_PROXY");
    }

    #[test]
    fn is_no_proxy_lower_case_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("no_proxy", "localhost");
        assert!(is_no_proxy("localhost"));
        env::remove_var("no_proxy");
    }

    #[test]
    fn resolve_proxy_from_env_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Should return None when no env vars are set.
        assert!(resolve_proxy_from_env("example.com").is_none());
    }

    #[test]
    fn resolve_proxy_from_env_all_proxy() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("ALL_PROXY", "http://proxy:8080");
        let cfg = resolve_proxy_from_env("example.com").unwrap();
        assert_eq!(cfg.host, "proxy");
        assert_eq!(cfg.port, 8080);
        env::remove_var("ALL_PROXY");
    }

    #[test]
    fn resolve_proxy_from_env_no_proxy_blocks() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("ALL_PROXY", "http://proxy:8080");
        env::set_var("NO_PROXY", "example.com");
        assert!(resolve_proxy_from_env("example.com").is_none());
        env::remove_var("ALL_PROXY");
        env::remove_var("NO_PROXY");
    }

    #[test]
    fn resolve_proxy_from_env_ignores_no_proxy_for_other_host() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("ALL_PROXY", "http://proxy:8080");
        env::set_var("NO_PROXY", "example.com");
        let cfg = resolve_proxy_from_env("other.com").unwrap();
        assert_eq!(cfg.host, "proxy");
        env::remove_var("ALL_PROXY");
        env::remove_var("NO_PROXY");
    }
}
