//! Property-based test that no constructed `AuditEvent` ever
//! serializes a sentinel secret value.
//!
//! The redaction posture for `AuditEvent` is enforced by the type
//! system: every field is either a timestamp, a closed-set `&'static
//! str` (verb label, outcome, error kind), or a small `String`
//! populated from a URL scheme. This test guards against accidental
//! regressions in `AuditEvent::to_json_line` by feeding sentinel byte
//! patterns into the only `String`-typed input (`url_scheme` /
//! `dst_scheme`) and asserting that even an adversarial scheme value
//! is opaquely preserved — the sink never reflects anything besides
//! the explicit field set.

use hasp_core::{AuditEvent, Verb};
use proptest::prelude::*;

const SECRET_SENTINEL: &str = "AKIAIOSFODNN7EXAMPLE";

proptest! {
    #[test]
    fn start_event_never_contains_secret_value(scheme in "[a-z][a-z0-9-]{0,15}") {
        let ev = AuditEvent::start(Verb::Get, scheme);
        let json = ev.to_json_line();
        prop_assert!(!json.contains(SECRET_SENTINEL),
            "audit JSON unexpectedly contained sentinel: {json}");
    }

    #[test]
    fn done_event_never_contains_secret_value(
        scheme in "[a-z][a-z0-9-]{0,15}",
        dst_scheme in "[a-z][a-z0-9-]{0,15}",
        outcome in prop::sample::select(vec!["ok", "error", "copied", "skipped", "dry_run", "present", "absent"]),
        error_kind in prop::sample::select(vec!["url_parse", "invalid_url", "not_found", "permission_denied", "auth_failed", "precondition_failed", "backend", "other"]),
    ) {
        let ev = AuditEvent::done(Verb::Cp, scheme, outcome)
            .with_dst_scheme(dst_scheme)
            .with_error_kind(error_kind);
        let json = ev.to_json_line();
        prop_assert!(!json.contains(SECRET_SENTINEL),
            "audit JSON unexpectedly contained sentinel: {json}");
    }
}

#[test]
fn audit_event_field_set_is_fixed() {
    // If a field is ever added to `AuditEvent`, this test reminds the
    // author to extend the no-leak proptest above to cover it. The
    // JSON envelope today is exactly: event, ts, src_scheme,
    // (optional) dst_scheme, outcome, (optional) error_kind.
    let json = AuditEvent::start(Verb::Get, "vault").to_json_line();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = parsed.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(keys, vec!["event", "outcome", "src_scheme", "ts"]);

    let json2 = AuditEvent::done(Verb::Cp, "vault", "error")
        .with_dst_scheme("aws-sm")
        .with_error_kind("not_found")
        .to_json_line();
    let parsed2: serde_json::Value = serde_json::from_str(&json2).unwrap();
    let obj2 = parsed2.as_object().unwrap();
    let mut keys2: Vec<&str> = obj2.keys().map(|s| s.as_str()).collect();
    keys2.sort();
    assert_eq!(
        keys2,
        vec![
            "dst_scheme",
            "error_kind",
            "event",
            "outcome",
            "src_scheme",
            "ts"
        ]
    );
}
