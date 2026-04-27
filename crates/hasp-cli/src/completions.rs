//! Smart argument completions for `hasp`.
//!
//! Uses `clap_complete::engine` so completions are generated dynamically
//! at tab-press time.  This lets us suggest profile aliases read from the
//! user's `profiles.toml`, URL schemes, and file paths — none of which can
//! be baked into a static AOT completion script.

use std::ffi::OsStr;

use clap_complete::engine::{CompletionCandidate, PathCompleter, ValueCompleter};

/// Smart completer for every `address` positional argument.
///
/// Covers three families of input:
/// - `@` prefixes → profile aliases from `profiles.toml`
/// - `file://`   → native path completion after the prefix
/// - everything else → known URL schemes
pub fn complete_address(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };

    if current.starts_with('@') {
        return complete_profiles(current);
    }

    if current.starts_with("file://") {
        return complete_file_url(current);
    }

    complete_schemes(current)
}

/// Profile-alias completion.
///
/// `current` always begins with `@`.  If a `/` is already present we
/// complete keys inside that profile; otherwise we complete profile
/// names (and, when there is no `/`, expand every key so the user can
/// see the full alias immediately).
fn complete_profiles(current: &str) -> Vec<CompletionCandidate> {
    let profiles = match crate::profiles::load_profiles() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let rest = &current[1..]; // strip leading '@'
    let mut out = Vec::new();

    if rest.is_empty() {
        // No text after '@'  → offer every valid alias.
        for profile in profiles.list_profiles() {
            if profiles.resolve(&profile).is_some() {
                out.push(CompletionCandidate::new(format!("@{profile}")));
            }
            for key in profiles.list_keys(&profile) {
                out.push(CompletionCandidate::new(format!("@{profile}/{key}")));
            }
        }
        return out;
    }

    if let Some((profile_name, key_prefix)) = rest.split_once('/') {
        // Completing the key side of `@profile/<key>`.
        for key in profiles.list_keys(profile_name) {
            if key.starts_with(key_prefix) {
                out.push(CompletionCandidate::new(format!("@{profile_name}/{key}")));
            }
        }
    } else {
        // Completing the profile name side.
        for profile in profiles.list_profiles() {
            if !profile.starts_with(rest) {
                continue;
            }
            if profiles.resolve(&profile).is_some() {
                out.push(CompletionCandidate::new(format!("@{profile}")));
            }
            for key in profiles.list_keys(&profile) {
                out.push(CompletionCandidate::new(format!("@{profile}/{key}")));
            }
        }
    }

    out
}

/// File-path completion inside a `file://` URL.
///
/// Delegates to `PathCompleter` for the path portion and then
/// prepends `file://` back to every candidate.
fn complete_file_url(current: &str) -> Vec<CompletionCandidate> {
    const PREFIX: &str = "file://";
    let path_part = &current[PREFIX.len()..];
    let completer = PathCompleter::any();
    completer
        .complete(OsStr::new(path_part))
        .into_iter()
        .map(|c| {
            let val = c.get_value().to_string_lossy();
            CompletionCandidate::new(format!("{PREFIX}{val}"))
        })
        .collect()
}

const SCHEMES: &[&str] = &[
    "env://",
    "file://",
    "keyring://",
    "aws-sm://",
    "aws-ssm://",
    "vault://",
    "gcp-sm://",
    "azure-kv://",
    "op://",
    "bw://",
];

/// Static URL-scheme completion.
fn complete_schemes(current: &str) -> Vec<CompletionCandidate> {
    SCHEMES
        .iter()
        .filter(|s| s.starts_with(current))
        .map(|s| CompletionCandidate::new(*s))
        .collect()
}
