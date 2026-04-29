//! Profile alias resolution for `hasp-cli`.
//!
//! Profiles are stored in `~/.config/hasp/profiles.toml` (or the
//! platform equivalent) as a flat mapping from alias to URL:
//!
//! ```toml
//! [profiles.prod]
//! db_password = "aws-sm://us-east-1/prod/db-password"
//! api_key     = "op://Production/API/credential"
//!
//! [profiles.local]
//! db_password = "env://DB_PASSWORD"
//! ```
//!
//! Aliases are referenced as `@<profile>/<key>`.  The profile name and
//! key are identifiers, not secrets, and may appear in error messages.
//!
//! If a profile defines a key with the same name as the profile itself
//! (e.g. `[profiles.foo]` with `foo = "file:///etc/foo"`), then the
//! bare alias `@foo` resolves to that URL.  Otherwise `@foo` alone is
//! an error; you must write `@foo/key`.

use std::collections::HashMap;

/// In-memory profile table loaded from disk.
///
/// Outer key is the profile name; inner key is the alias key.
#[derive(Debug, Default)]
pub struct Profiles {
    inner: HashMap<String, HashMap<String, String>>,
}

impl Profiles {
    /// Resolve an alias string to a canonical URL.
    ///
    /// `key` is the text after the leading `@` (e.g. `prod/db_password`).
    /// Returns `Some(url)` when the alias matches a defined profile entry,
    /// or `None` when no match exists.
    pub fn resolve(&self, key: &str) -> Option<String> {
        let (profile_name, rest) = match key.split_once('/') {
            Some((p, r)) => (p, Some(r)),
            None => (key, None),
        };

        let profile = self.inner.get(profile_name)?;

        match rest {
            Some(alias_key) => profile.get(alias_key).cloned(),
            None => profile.get(profile_name).cloned(),
        }
    }

    /// All profile names.
    pub fn list_profiles(&self) -> Vec<String> {
        self.inner.keys().cloned().collect()
    }

    /// All keys defined within a profile.
    pub fn list_keys(&self, profile: &str) -> Vec<String> {
        self.inner
            .get(profile)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Return the `proxy_url` for a named profile, if set.
    pub fn proxy_url(&self, profile_name: &str) -> Option<String> {
        self.inner.get(profile_name)?.get("proxy_url").cloned()
    }
}

/// Load profiles from the config file path.
///
/// The path is taken from the `HASP_PROFILES_PATH` environment variable
/// when present, falling back to the platform config directory
/// (`~/.config/hasp/profiles.toml` on Linux, etc.).
///
/// Fails only if the file exists but is unreadable or unparseable.
/// If the file does not exist, returns an empty `Profiles`.
///
/// URLs are validated at load time so malformed config surfaces
/// immediately, not at first use.
///
/// # Errors
///
/// Returns `std::io::Error` for permission or disk errors.
/// Returns `toml::de::Error` for malformed TOML.
/// Returns `hasp_core::Error::InvalidUrl` for syntactically invalid URLs.
pub fn load_profiles() -> Result<Profiles, Box<dyn std::error::Error>> {
    let path = match std::env::var_os("HASP_PROFILES_PATH") {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let Some(config_dir) = dirs::config_dir() else {
                return Ok(Profiles::default());
            };
            config_dir.join("hasp").join("profiles.toml")
        }
    };

    if !path.is_file() {
        return Ok(Profiles::default());
    }

    let text = std::fs::read_to_string(&path)?;
    let raw: RawProfiles = toml::from_str(&text)?;

    let mut inner: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (profile_name, map) in raw.profiles {
        let mut validated = HashMap::new();
        for (key, url_str) in map {
            if key == "proxy_url" {
                hasp_core::ProxyConfig::parse(&url_str).map_err(|e| {
                    format!("invalid proxy_url in profile '{profile_name}.{key}': {e}")
                })?;
            } else {
                url::Url::parse(&url_str)
                    .map_err(|e| format!("invalid URL in profile '{profile_name}.{key}': {e}"))?;
            }
            validated.insert(key, url_str);
        }
        inner.insert(profile_name, validated);
    }

    Ok(Profiles { inner })
}

/// TOML shape that mirrors the on-disk format.
#[derive(Debug, serde::Deserialize)]
struct RawProfiles {
    #[serde(default)]
    profiles: HashMap<String, HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_exact_key() {
        let mut inner = HashMap::new();
        let mut profile = HashMap::new();
        profile.insert("db_password".into(), "env://DB_PASSWORD".into());
        inner.insert("prod".into(), profile);

        let profiles = Profiles { inner };
        assert_eq!(
            profiles.resolve("prod/db_password"),
            Some("env://DB_PASSWORD".into())
        );
    }

    #[test]
    fn resolve_self_key() {
        let mut inner = HashMap::new();
        let mut profile = HashMap::new();
        profile.insert("foo".into(), "file:///etc/foo".into());
        inner.insert("foo".into(), profile);

        let profiles = Profiles { inner };
        assert_eq!(profiles.resolve("foo"), Some("file:///etc/foo".into()));
    }

    #[test]
    fn resolve_missing_profile() {
        let profiles = Profiles::default();
        assert_eq!(profiles.resolve("prod/db_password"), None);
    }

    #[test]
    fn resolve_missing_key() {
        let mut inner = HashMap::new();
        let profile = HashMap::new();
        inner.insert("prod".into(), profile);

        let profiles = Profiles { inner };
        assert_eq!(profiles.resolve("prod/db_password"), None);
    }

    #[test]
    fn resolve_bare_profile_without_self_key() {
        let mut inner = HashMap::new();
        let mut profile = HashMap::new();
        profile.insert("db_password".into(), "env://DB".into());
        inner.insert("prod".into(), profile);

        let profiles = Profiles { inner };
        assert_eq!(profiles.resolve("prod"), None);
    }

    #[test]
    fn parse_toml_roundtrip() {
        let input = r#"
[profiles.prod]
db_password = "aws-sm://us-east-1/prod/db-password"
api_key = "op://Production/API/credential"

[profiles.local]
db_password = "env://DB_PASSWORD"
"#;

        let raw: RawProfiles = toml::from_str(input).unwrap();
        assert_eq!(raw.profiles.len(), 2);
        let prod = raw.profiles.get("prod").unwrap();
        assert_eq!(
            prod.get("db_password").unwrap(),
            "aws-sm://us-east-1/prod/db-password"
        );
        assert_eq!(
            prod.get("api_key").unwrap(),
            "op://Production/API/credential"
        );
    }

    #[test]
    fn parse_proxy_url() {
        let input = r#"
[profiles.corp]
proxy_url = "http://proxy.corp.example.com:8080"
db_password = "env://DB_PASSWORD"
"#;
        let raw: RawProfiles = toml::from_str(input).unwrap();
        let corp = raw.profiles.get("corp").unwrap();
        assert_eq!(
            corp.get("proxy_url").unwrap(),
            "http://proxy.corp.example.com:8080"
        );
    }

    #[test]
    fn resolve_proxy_url() {
        let mut inner = HashMap::new();
        let mut profile = HashMap::new();
        profile.insert("proxy_url".into(), "http://proxy:8080".into());
        profile.insert("db_password".into(), "env://DB".into());
        inner.insert("prod".into(), profile);

        let profiles = Profiles { inner };
        assert_eq!(
            profiles.proxy_url("prod"),
            Some("http://proxy:8080".to_string())
        );
        assert_eq!(profiles.proxy_url("missing"), None);
    }

    #[test]
    fn load_profiles_rejects_invalid_url() {
        use std::io::Write;

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            r#"[profiles.prod]
db_password = "not-a-valid-url"
"#
        )
        .unwrap();

        let _guard = hasp_core::test_utils::EnvGuard::set(
            "HASP_PROFILES_PATH",
            tmpfile.path().to_str().unwrap(),
        );

        let err = load_profiles().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid URL in profile 'prod.db_password'"),
            "expected URL validation error for malformed TOML entry, got: {msg}"
        );
    }

    #[test]
    fn load_profiles_rejects_invalid_proxy_url() {
        use std::io::Write;

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            r#"[profiles.corp]
proxy_url = "socks5://proxy:1080"
"#
        )
        .unwrap();

        let _guard = hasp_core::test_utils::EnvGuard::set(
            "HASP_PROFILES_PATH",
            tmpfile.path().to_str().unwrap(),
        );

        let err = load_profiles().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid proxy_url"),
            "expected proxy URL validation error, got: {msg}"
        );
    }
}
