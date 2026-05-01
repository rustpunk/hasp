//! Config file initialization wizard for `hasp-cli`.
//!
//! Creates the platform config directory and writes a commented
//! `profiles.toml` template. Respects `HASP_PROFILES_PATH` when set.

use std::io::Write;
use std::path::PathBuf;

const TEMPLATE: &str = r#"# hasp profile aliases
# Reference secrets by short alias instead of full URL:
#
#   hasp get @prod/db_password
#
# Each [profiles.<name>] section defines one profile.
# A profile can optionally set `proxy_url` for HTTP CONNECT / SOCKS5
# proxy configuration scoped to that profile's aliases.

[profiles.example]
# proxy_url = "http://proxy.example.com:8080"
db_password = "env://EXAMPLE_DB_PASSWORD"
api_key = "op://Production/API/credential"
"#;

/// Initialize a default `profiles.toml`.
///
/// If `HASP_PROFILES_PATH` is set, the file is created at that path.
/// Otherwise it is placed in the platform config directory
/// (`~/.config/hasp/profiles.toml` on Linux, etc.).
///
/// Returns an error if the file already exists and `force` is `false`.
pub fn init(force: bool) -> Result<(), String> {
    let file_path = config_file_path()?;

    if !force && file_path.exists() {
        return Err(format!(
            "config file already exists at {}. Use --force to overwrite",
            file_path.display()
        ));
    }

    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create config directory {}: {e}",
                parent.display()
            )
        })?;
    }

    let mut file = std::fs::File::create(&file_path)
        .map_err(|e| format!("failed to create config file {}: {e}", file_path.display()))?;

    file.write_all(TEMPLATE.as_bytes())
        .map_err(|e| format!("failed to write config template: {e}"))?;

    eprintln!("Created {}", file_path.display());
    Ok(())
}

fn config_file_path() -> Result<PathBuf, String> {
    match std::env::var_os("HASP_PROFILES_PATH") {
        Some(p) => Ok(PathBuf::from(p)),
        None => {
            let Some(config_dir) = dirs::config_dir() else {
                return Err("could not determine config directory".to_string());
            };
            Ok(config_dir.join("hasp").join("profiles.toml"))
        }
    }
}
