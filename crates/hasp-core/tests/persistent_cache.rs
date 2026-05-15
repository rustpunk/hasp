//! Integration test for the `cache-persistent` load/save loop.
//!
//! `ProcessCache::new(Persistent, ...)` is exercised end-to-end with
//! a `keyring_core::mock::Store` swapped in for the OS keyring so the
//! test never touches the host's real DBus session bus / Keychain /
//! Credential Manager. The mock store accepts any service+account
//! and persists the symmetric key for the lifetime of the test
//! process — exactly the contract the production code depends on.

#![cfg(feature = "cache-persistent")]

use std::sync::Arc;
use std::time::Duration;

use hasp_core::cache::{CacheKey, CachePolicy, PersistentPolicy, ProcessCache};
use hasp_core::{install as install_hardening, AuditEvent, AuditSink, SecretString};
use secrecy::ExposeSecret;

fn mock_keyring_once() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let store = keyring_core::mock::Store::new().unwrap();
        keyring_core::set_default_store(store);
    });
}

fn policy_in(dir: &std::path::Path, account: &str) -> CachePolicy {
    CachePolicy::Persistent(PersistentPolicy {
        ttl: Duration::from_secs(60),
        path: dir.join("cache.bin"),
        keyring_service: "hasp-test".into(),
        keyring_account: account.into(),
        capacity: 16,
    })
}

#[test]
fn save_then_load_in_fresh_cache_returns_same_value() {
    mock_keyring_once();
    let dir = tempfile::tempdir().unwrap();
    let token = install_hardening().expect("hardening install");

    // First invocation: insert, save.
    {
        let cache = ProcessCache::new(&policy_in(dir.path(), "save-load"), token, None)
            .unwrap()
            .expect("persistent cache constructed");
        cache.insert(
            CacheKey::new("env", "ROUNDTRIP"),
            Arc::new(SecretString::new("hello".to_string().into())),
        );
        cache.save_to_disk().expect("save to disk");
    }

    // Second invocation: load.
    let cache = ProcessCache::new(&policy_in(dir.path(), "save-load"), token, None)
        .unwrap()
        .expect("persistent cache constructed");
    let got = cache
        .get(&CacheKey::new("env", "ROUNDTRIP"))
        .expect("entry hydrated from disk");
    assert_eq!(got.expose_secret(), "hello");
}

#[test]
fn clear_persistent_file_removes_disk_state() {
    mock_keyring_once();
    let dir = tempfile::tempdir().unwrap();
    let token = install_hardening().unwrap();
    let path = dir.path().join("cache.bin");

    let cache = ProcessCache::new(&policy_in(dir.path(), "clear-file"), token, None)
        .unwrap()
        .unwrap();
    cache.insert(
        CacheKey::new("env", "X"),
        Arc::new(SecretString::new("v".to_string().into())),
    );
    cache.save_to_disk().unwrap();
    assert!(path.exists());

    cache.clear_persistent_file(false).unwrap();
    assert!(!path.exists());
}

#[derive(Default)]
struct CaptureSink {
    events: std::sync::Mutex<Vec<&'static str>>,
}

impl AuditSink for CaptureSink {
    fn emit(&self, event: &AuditEvent) {
        if let Ok(mut v) = self.events.lock() {
            v.push(event.event);
        }
    }
}

#[test]
fn load_emits_cache_load_audit_event() {
    mock_keyring_once();
    let dir = tempfile::tempdir().unwrap();
    let token = install_hardening().unwrap();
    let sink: Arc<CaptureSink> = Arc::new(CaptureSink::default());

    let cache = ProcessCache::new(
        &policy_in(dir.path(), "load-event"),
        token,
        Some(sink.clone()),
    )
    .unwrap()
    .unwrap();
    cache.insert(
        CacheKey::new("env", "X"),
        Arc::new(SecretString::new("v".to_string().into())),
    );
    cache.save_to_disk().unwrap();

    // Drop the cache, construct a fresh one — that fires `cache.load`.
    drop(cache);
    sink.events.lock().unwrap().clear();

    let _cache2 = ProcessCache::new(
        &policy_in(dir.path(), "load-event"),
        token,
        Some(sink.clone()),
    )
    .unwrap()
    .unwrap();
    let events = sink.events.lock().unwrap().clone();
    assert!(
        events.contains(&"cache.load"),
        "expected cache.load event, got {events:?}"
    );
}

#[test]
fn aead_tamper_emits_cache_tamper_rejected_audit_event() {
    // Regression guard. A bit-flip inside the ciphertext must surface
    // as `cache.tamper_rejected` so an operator can distinguish a
    // clean cold start from a hostile mutation.
    mock_keyring_once();
    let dir = tempfile::tempdir().unwrap();
    let token = install_hardening().unwrap();

    // First invocation: insert + save.
    {
        let cache = ProcessCache::new(&policy_in(dir.path(), "tamper-event"), token, None)
            .unwrap()
            .unwrap();
        cache.insert(
            hasp_core::CacheKey::new("env", "X"),
            Arc::new(SecretString::new("v".to_string().into())),
        );
        cache.save_to_disk().unwrap();
    }

    // Flip a byte past magic + nonce.
    let path = dir.path().join("cache.bin");
    let mut bytes = std::fs::read(&path).unwrap();
    let flip = 4 /* magic */ + 24 /* nonce */ + 4;
    bytes[flip] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    // Second invocation: load must emit cache.tamper_rejected.
    let sink: Arc<CaptureSink> = Arc::new(CaptureSink::default());
    let _cache = ProcessCache::new(
        &policy_in(dir.path(), "tamper-event"),
        token,
        Some(sink.clone()),
    )
    .unwrap()
    .unwrap();

    let events = sink.events.lock().unwrap().clone();
    assert!(
        events.contains(&"cache.tamper_rejected"),
        "expected cache.tamper_rejected event after AEAD tamper, got {events:?}"
    );
}

#[test]
fn save_emits_cache_save_audit_event() {
    mock_keyring_once();
    let dir = tempfile::tempdir().unwrap();
    let token = install_hardening().unwrap();
    let sink: Arc<CaptureSink> = Arc::new(CaptureSink::default());

    let cache = ProcessCache::new(
        &policy_in(dir.path(), "save-event"),
        token,
        Some(sink.clone()),
    )
    .unwrap()
    .unwrap();
    cache.insert(
        CacheKey::new("env", "X"),
        Arc::new(SecretString::new("v".to_string().into())),
    );
    cache.save_to_disk().unwrap();

    let events = sink.events.lock().unwrap().clone();
    assert!(
        events.contains(&"cache.save"),
        "expected cache.save event, got {events:?}"
    );
}
