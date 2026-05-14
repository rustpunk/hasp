//! `?field=` extraction from JSON-encoded secrets.
//!
//! Backends that expose JSON payloads (`vault://`, `aws-sm://`,
//! `gcp-sm://`, `azure-kv://`) use this helper to pull a single value
//! out of the payload before wrapping in `SecretString`. The parent
//! payload never leaves the backend crate as a plaintext `String` —
//! extraction is the security boundary, not the dispatcher.
//!
//! Path grammar:
//! - `password` — top-level key.
//! - `.password` — same, leading `.` is accepted but optional.
//! - `.credentials.api_key` — dotted path into nested objects.
//!
//! Limitations: JSON keys containing `.` cannot be addressed. This
//! mirrors the `vault -field` and `op://vault/item/field` conventions
//! across the surveyed ecosystem.
//!
//! Trailing-newline policy: string leaves are returned verbatim. The
//! `file://` backend trims one trailing `\n` to handle `echo`-style
//! files, but JSON-stored values are typically written by programs
//! that do not add a newline — trimming would break the round-trip
//! for legitimately-newline-bearing values.

use crate::Error;

/// Walk a dotted path through a JSON value and return the leaf as a
/// `String`.
///
/// Returns:
/// - `Error::InvalidUrl` for an empty path or non-scalar leaf.
/// - `Error::NotFound` for a missing key along the path.
///
/// The caller wraps the result in `SecretString`. Errors never carry
/// the parent payload or sibling-key names.
pub fn extract_field(payload: &serde_json::Value, path: &str) -> Result<String, Error> {
    let stripped = path.strip_prefix('.').unwrap_or(path);
    if stripped.is_empty() {
        return Err(Error::InvalidUrl("field path must not be empty".into()));
    }

    let mut current = payload;
    for segment in stripped.split('.') {
        if segment.is_empty() {
            return Err(Error::InvalidUrl(format!(
                "field path '{path}' contains an empty segment"
            )));
        }
        current = current
            .get(segment)
            .ok_or_else(|| Error::NotFound(format!("field '{path}' not found")))?;
    }

    match current {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Err(Error::InvalidUrl(format!("field '{path}' is null"))),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Err(Error::InvalidUrl(format!("field '{path}' is not a scalar")))
        }
    }
}

/// Parse a JSON payload then extract a field. Convenience for backends
/// that hold the raw string from the SDK and have not yet parsed it.
///
/// Non-JSON payloads map to `Error::InvalidUrl` so callers can surface
/// a clear "asked for a field, but the secret isn't JSON" message.
pub fn extract_field_from_str(payload: &str, path: &str) -> Result<String, Error> {
    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|e| Error::InvalidUrl(format!("secret is not JSON; cannot extract field: {e}")))?;
    extract_field(&value, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_string() {
        let v = serde_json::json!({"password": "hunter2"});
        assert_eq!(extract_field(&v, "password").unwrap(), "hunter2");
    }

    #[test]
    fn leading_dot_optional() {
        let v = serde_json::json!({"password": "hunter2"});
        assert_eq!(extract_field(&v, ".password").unwrap(), "hunter2");
    }

    #[test]
    fn nested_dotted_path() {
        let v = serde_json::json!({
            "credentials": {"api_key": "ak-xyz"}
        });
        assert_eq!(extract_field(&v, ".credentials.api_key").unwrap(), "ak-xyz");
    }

    #[test]
    fn missing_top_level_is_not_found() {
        let v = serde_json::json!({"password": "hunter2"});
        let err = extract_field(&v, "username").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn missing_nested_is_not_found() {
        let v = serde_json::json!({"a": {"b": 1}});
        let err = extract_field(&v, "a.c").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn empty_path_is_invalid_url() {
        let v = serde_json::json!({});
        let err = extract_field(&v, "").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn empty_segment_is_invalid_url() {
        let v = serde_json::json!({"a": {"b": 1}});
        let err = extract_field(&v, "a..b").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn numeric_leaf_stringified() {
        let v = serde_json::json!({"port": 5432});
        assert_eq!(extract_field(&v, "port").unwrap(), "5432");
    }

    #[test]
    fn bool_leaf_stringified() {
        let v = serde_json::json!({"enabled": true});
        assert_eq!(extract_field(&v, "enabled").unwrap(), "true");
    }

    #[test]
    fn null_leaf_is_invalid_url() {
        let v = serde_json::json!({"x": null});
        let err = extract_field(&v, "x").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn object_leaf_is_invalid_url() {
        let v = serde_json::json!({"x": {"y": 1}});
        let err = extract_field(&v, "x").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn array_leaf_is_invalid_url() {
        let v = serde_json::json!({"x": [1, 2]});
        let err = extract_field(&v, "x").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn from_str_happy() {
        let r = extract_field_from_str(r#"{"k":"v"}"#, "k").unwrap();
        assert_eq!(r, "v");
    }

    #[test]
    fn from_str_non_json_is_invalid_url() {
        let err = extract_field_from_str("not json", "k").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn newline_preserved_in_string_leaf() {
        // String leaves are NOT trimmed (mirrors vault `extract_secret`).
        let v = serde_json::json!({"k": "v\n"});
        assert_eq!(extract_field(&v, "k").unwrap(), "v\n");
    }
}
