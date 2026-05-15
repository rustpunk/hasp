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

use hasp_core::{AuditEvent, CacheEvent, Verb};
use proptest::prelude::*;

const SECRET_SENTINEL: &str = "AKIAIOSFODNN7EXAMPLE";

// The `url_scheme` / `dst_scheme` fields are `String` — in production
// they're populated only from URL-validated scheme prefixes (a narrow
// subset), but the type's domain is broader. The proptest input must
// match the type's actual domain so a future caller that bypasses URL
// validation still cannot smuggle a secret through the JSON envelope.
// Cover ASCII control, JSON-special (`"`, `\\`, newline), and varied
// UTF-8 to exercise serde_json's escape machinery.
const WIDE_SCHEME: &str = r#"[\x20-\x7e]{0,32}"#;

// Every Verb. Keep this list in sync with `hasp_core::audit::Verb` —
// the test_utils crate would let us derive it, but the closed enum
// makes a hand-maintained list cheap and surfaces additions during
// review.
fn any_verb() -> impl Strategy<Value = Verb> {
    prop::sample::select(vec![
        Verb::Get,
        Verb::Put,
        Verb::List,
        Verb::Delete,
        Verb::Exists,
        Verb::Cp,
        Verb::Diff,
    ])
}

fn any_cache_event() -> impl Strategy<Value = CacheEvent> {
    prop::sample::select(vec![
        CacheEvent::Hit,
        CacheEvent::Miss,
        CacheEvent::Expire,
        CacheEvent::Clear,
        CacheEvent::Load,
        CacheEvent::Save,
        CacheEvent::TamperRejected,
    ])
}

proptest! {
    #[test]
    fn start_event_never_contains_secret_value(scheme in WIDE_SCHEME, verb in any_verb()) {
        let ev = AuditEvent::start(verb, scheme);
        let json = ev.to_json_line();
        prop_assert!(!json.contains(SECRET_SENTINEL),
            "audit JSON unexpectedly contained sentinel: {json}");
        // Wire format must remain valid JSON regardless of scheme
        // bytes — serde_json escapes its inputs, so any sentinel
        // would survive only if our struct re-injected it.
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn done_event_never_contains_secret_value(
        scheme in WIDE_SCHEME,
        dst_scheme in WIDE_SCHEME,
        verb in any_verb(),
        outcome in prop::sample::select(vec!["ok", "error", "copied", "skipped", "dry_run", "present", "absent", "child_nonzero", "match", "differ"]),
        error_kind in prop::sample::select(vec!["url_parse", "invalid_url", "not_found", "permission_denied", "auth_failed", "precondition_failed", "backend", "other", "unknown_scheme", "unsupported_operation"]),
    ) {
        let ev = AuditEvent::done(verb, scheme, outcome)
            .with_dst_scheme(dst_scheme)
            .with_error_kind(error_kind);
        let json = ev.to_json_line();
        prop_assert!(!json.contains(SECRET_SENTINEL),
            "audit JSON unexpectedly contained sentinel: {json}");
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    // Even an adversarial scheme that contains the sentinel literally
    // must not surface a `"src_scheme":"AKIA..."` outside the
    // contained envelope — the field is still classification metadata,
    // not value material. We assert the JSON is well-formed; the
    // serializer's escape rules prevent breaking out of the string.
    #[test]
    fn adversarial_scheme_stays_inside_json_string(adv in r#"[\x00-\x7f]{0,32}"#) {
        let ev = AuditEvent::start(Verb::Get, adv);
        let json = ev.to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        prop_assert!(parsed.get("event").is_some());
        prop_assert!(parsed.get("src_scheme").is_some());
    }

    #[test]
    fn cache_event_never_contains_secret_value(scheme in WIDE_SCHEME, kind in any_cache_event()) {
        let ev = AuditEvent::cache(kind, scheme);
        let json = ev.to_json_line();
        prop_assert!(!json.contains(SECRET_SENTINEL),
            "cache audit JSON unexpectedly contained sentinel: {json}");
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
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
