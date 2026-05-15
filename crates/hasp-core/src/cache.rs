//! Per-invocation in-process secret cache.
//!
//! `ProcessCache` holds `Arc<SecretString>` values keyed by a
//! `(scheme, identity)` tuple. The Arc is the only handle the cache
//! retains; on eviction, the listener explicitly drops the Arc, and
//! the inner `SecretString`'s `Drop` impl zeroizes the heap buffer
//! once the last holder (the cache, or a borrowed clone) goes away.
//!
//! Cache construction requires a [`crate::hardening::HardeningToken`].
//! Without it the type is unconstructible. The CLI binary obtains the
//! token at startup via [`crate::hardening::install`]; library
//! consumers wanting caching must do the same. This is the
//! architectural lever that makes `PR_SET_DUMPABLE=0`,
//! `RLIMIT_CORE=0`, and env-injection refusal non-bypassable
//! preconditions for any cached secret.
//!
//! ## What this cache is and is not
//!
//! - It is a **per-invocation memoization** layer. Lifetime = process
//!   lifetime. No on-disk persistence, no daemon, no IPC.
//! - It eliminates the duplicate-URL footgun within a single batch
//!   (`hasp get URL URL URL` triggers one backend fetch).
//! - It is not a defense against `/proc/<pid>/mem` inspection by a
//!   same-uid attacker. The hardening token's underlying mitigations
//!   are the only such defense, and they are best-effort.
//!
//! Cross-invocation persistence (Approach A in
//! `RESEARCH-op-caching.md`) lives behind the `cache-persistent`
//! Cargo feature and is opt-in by binary builders only.

use std::sync::Arc;
use std::time::Duration;

use moka::notification::RemovalCause;
use moka::sync::Cache;

use crate::audit::{AuditEvent, AuditSink, CacheEvent};
use crate::hardening::HardeningToken;
use crate::SecretString;

/// Cache key. `scheme` is the URL scheme and is intentionally
/// scheme-namespaced so the same URL string handled by two different
/// backends cannot alias.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CacheKey {
    pub scheme: &'static str,
    pub identity: String,
}

impl CacheKey {
    pub fn new(scheme: &'static str, identity: impl Into<String>) -> Self {
        Self {
            scheme,
            identity: identity.into(),
        }
    }
}

/// Per-invocation in-process cache policy.
///
/// `Disabled` is the safe default and skips every cache code path.
/// `Process` enables in-process memoization with the given TTL and
/// capacity ceiling; capacity-eviction is LRU within moka's segmented
/// design.
///
/// `Persistent` (gated on the `cache-persistent` Cargo feature) is
/// reserved for a future cross-invocation encrypted-file path.
/// Constructing it via [`ProcessCache::new`] currently downgrades to
/// the in-process `Process` policy with the persistent's TTL and
/// capacity — the on-disk encrypted-file implementation is not yet
/// in tree.
#[derive(Debug, Clone, Default)]
pub enum CachePolicy {
    #[default]
    Disabled,
    Process {
        ttl: Duration,
        capacity: u64,
    },
    #[cfg(feature = "cache-persistent")]
    Persistent(PersistentPolicy),
}

/// Persistent cache configuration (scaffold only).
///
/// `ttl` is the per-entry time-to-live, clamped against AWS Secrets
/// Manager Agent's published envelope (300s default, 3600s max, 0
/// disables persistence).
///
/// `path` is the intended encrypted cache file location. Default:
/// `$XDG_CACHE_HOME/hasp/cache.bin`. File mode `0o600` on Unix when
/// the implementation lands.
///
/// `keyring_service` and `keyring_account` identify the OS-keyring
/// entry holding the per-host symmetric key (XChaCha20-Poly1305).
/// Default service is `"hasp"`; default account is
/// `"cache:{user}@{hostname}"`.
///
/// The struct currently pins the design in code; constructing it and
/// passing to [`ProcessCache::new`] is safe but downgrades to the
/// in-process `Process` policy with the persistent's TTL and
/// capacity. The on-disk encrypted-file implementation is not yet
/// in tree.
#[cfg(feature = "cache-persistent")]
#[derive(Debug, Clone)]
pub struct PersistentPolicy {
    pub ttl: Duration,
    pub path: std::path::PathBuf,
    pub keyring_service: String,
    pub keyring_account: String,
    pub capacity: u64,
}

#[cfg(feature = "cache-persistent")]
impl PersistentPolicy {
    /// Maximum permitted TTL. Mirrors AWS Secrets Manager Agent's
    /// 1-hour ceiling. Values above this are clamped to keep the
    /// envelope honest about the worst-case staleness.
    pub const MAX_TTL: Duration = Duration::from_secs(3600);

    /// AWS Secrets Manager Agent's default TTL: 300 seconds.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

    /// Construct with the AWS-Agent default envelope and the default
    /// file path. Returns `None` if `dirs::cache_dir()` fails (e.g.,
    /// `$HOME` is unset and there is no platform default).
    pub fn defaults() -> Option<Self> {
        let dir = dirs::cache_dir()?.join("hasp");
        Some(Self {
            ttl: Self::DEFAULT_TTL,
            path: dir.join("cache.bin"),
            keyring_service: "hasp".into(),
            keyring_account: format!("cache:{}", whoami_or_unknown()),
            capacity: 1024,
        })
    }

    /// Clamp `ttl` to `MAX_TTL`. A `ttl` of zero disables persistence.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = if ttl > Self::MAX_TTL {
            Self::MAX_TTL
        } else {
            ttl
        };
        self
    }
}

#[cfg(feature = "cache-persistent")]
fn whoami_or_unknown() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

impl CachePolicy {
    /// `Process` policy with the canonical AWS-Secrets-Manager-Agent
    /// envelope: 5-minute TTL, 1024-entry capacity ceiling. Capacity
    /// is intentionally generous — moka's overhead per entry is well
    /// under 1 KiB and the per-invocation Store will never approach
    /// the ceiling in practice.
    pub fn process_default() -> Self {
        Self::Process {
            ttl: Duration::from_secs(300),
            capacity: 1024,
        }
    }
}

/// In-process moka-backed cache of `Arc<SecretString>`.
///
/// Constructed via [`ProcessCache::new`], which requires a
/// [`HardeningToken`]. Cache operations are sync (no async runtime
/// involvement); moka's eviction listener fires synchronously on Drop
/// in the `sync` flavor, so the `Arc<SecretString>` zeroize-on-Drop
/// semantics are preserved for evicted entries.
#[derive(Clone)]
pub struct ProcessCache {
    inner: Cache<CacheKey, Arc<SecretString>>,
}

impl ProcessCache {
    /// Construct a cache governed by `policy`. Returns `None` when the
    /// policy is `Disabled`.
    ///
    /// The `_token` parameter is the architectural lever: callers who
    /// have not installed hardening cannot obtain a token and
    /// therefore cannot construct a cache. The token is consumed by
    /// value (it is `Copy`) and is not retained.
    ///
    /// `audit_sink`, when provided, receives `cache.expire` events on
    /// TTL-driven evictions. Explicit `invalidate` / `invalidate_all`
    /// calls do not emit events here — `Store` emits its own
    /// `cache.clear` on the user-facing path.
    pub fn new(
        policy: &CachePolicy,
        _token: HardeningToken,
        audit_sink: Option<Arc<dyn AuditSink>>,
    ) -> Option<Self> {
        match policy {
            #[cfg(feature = "cache-persistent")]
            CachePolicy::Persistent(p) => {
                // Scaffold downgrade: with the on-disk encrypted-file path
                // not yet implemented, `Persistent` runs as an in-process
                // `Process` policy carrying the persistent's TTL and
                // capacity. CLI integration (`HASP_CACHE_TTL`,
                // `hasp cache clear`) operates against the in-memory
                // layer without a behavioral surprise.
                let process = CachePolicy::Process {
                    ttl: p.ttl,
                    capacity: p.capacity,
                };
                Self::new(&process, _token, audit_sink)
            }
            CachePolicy::Disabled => None,
            CachePolicy::Process { ttl, capacity } => {
                let sink = audit_sink.clone();
                let inner = Cache::builder()
                    .max_capacity(*capacity)
                    .time_to_live(*ttl)
                    .eviction_listener(move |k: Arc<CacheKey>, v, cause| {
                        // Drop the Arc<SecretString> first so the inner
                        // zeroize fires promptly. moka 0.12 sync flavor
                        // runs this listener synchronously on the
                        // eviction-causing thread.
                        drop(v);
                        if matches!(cause, RemovalCause::Expired) {
                            if let Some(s) = &sink {
                                s.emit(&AuditEvent::cache(CacheEvent::Expire, k.scheme));
                            }
                        }
                    })
                    .build();
                Some(Self { inner })
            }
        }
    }

    /// Read a cached value. Returns the `Arc<SecretString>` if a
    /// fresh entry exists, or `None` on miss / TTL expiry. Callers
    /// hold the clone — the cache retains its own Arc.
    pub fn get(&self, key: &CacheKey) -> Option<Arc<SecretString>> {
        self.inner.get(key)
    }

    /// Insert or replace a value.
    pub fn insert(&self, key: CacheKey, value: Arc<SecretString>) {
        self.inner.insert(key, value);
    }

    /// Invalidate a single entry. No-op if the key is absent.
    pub fn invalidate(&self, key: &CacheKey) {
        self.inner.invalidate(key);
    }

    /// Drop every entry. Used by `hasp cache clear` and tests.
    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }

    /// Synchronously run pending eviction listeners. Used by tests to
    /// observe deterministic eviction behavior — production callers
    /// do not need to invoke this.
    pub fn run_pending_tasks(&self) {
        self.inner.run_pending_tasks();
    }

    /// Approximate entry count after pending tasks are processed.
    /// Useful for tests and `--explain` diagnostics; not authoritative
    /// under concurrent insertion.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

impl std::fmt::Debug for ProcessCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose contents — only entry count, which is a
        // value-free wall-clock-derived counter.
        f.debug_struct("ProcessCache")
            .field("entry_count", &self.inner.entry_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardening;
    use secrecy::ExposeSecret;

    fn token() -> HardeningToken {
        // Tests run in-process and may interleave; install() is idempotent
        // for the underlying syscalls. If a CI runner sets LD_PRELOAD this
        // returns an error — but that's a real failure we want to surface.
        hardening::install().expect("hardening install should succeed in tests")
    }

    #[test]
    fn disabled_policy_returns_none() {
        let policy = CachePolicy::Disabled;
        assert!(ProcessCache::new(&policy, token(), None).is_none());
    }

    #[test]
    fn process_policy_returns_some() {
        let policy = CachePolicy::process_default();
        assert!(ProcessCache::new(&policy, token(), None).is_some());
    }

    #[test]
    fn insert_then_get_returns_same_secret_bytes() {
        let cache = ProcessCache::new(&CachePolicy::process_default(), token(), None).unwrap();
        let key = CacheKey::new("env", "USER");
        let secret = Arc::new(SecretString::new("alice".to_string().into()));
        cache.insert(key.clone(), secret.clone());

        let got = cache.get(&key).expect("cache hit");
        assert_eq!(got.expose_secret(), "alice");
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = ProcessCache::new(&CachePolicy::process_default(), token(), None).unwrap();
        let key = CacheKey::new("env", "USER");
        cache.insert(
            key.clone(),
            Arc::new(SecretString::new("v".to_string().into())),
        );
        cache.invalidate(&key);
        cache.run_pending_tasks();
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn ttl_expiry_returns_none() {
        let policy = CachePolicy::Process {
            ttl: Duration::from_millis(50),
            capacity: 16,
        };
        let cache = ProcessCache::new(&policy, token(), None).unwrap();
        let key = CacheKey::new("env", "USER");
        cache.insert(
            key.clone(),
            Arc::new(SecretString::new("v".to_string().into())),
        );
        std::thread::sleep(Duration::from_millis(120));
        cache.run_pending_tasks();
        assert!(cache.get(&key).is_none());
    }

    /// Capture-only sink for observing cache events from the eviction
    /// listener under test.
    #[derive(Default)]
    struct TestSink {
        events: std::sync::Mutex<Vec<String>>,
    }

    impl AuditSink for TestSink {
        fn emit(&self, event: &AuditEvent) {
            if let Ok(mut v) = self.events.lock() {
                v.push(event.event.to_string());
            }
        }
    }

    #[test]
    fn ttl_expiry_emits_cache_expire_event() {
        // moka 0.12 sync flavor fires the eviction listener
        // synchronously on the eviction-causing thread; for time-based
        // expiry that means a subsequent op or `run_pending_tasks` is
        // what surfaces the listener invocation. The test sleeps past
        // the TTL, then drives an op + run_pending_tasks.
        let sink: Arc<TestSink> = Arc::new(TestSink::default());
        let policy = CachePolicy::Process {
            ttl: Duration::from_millis(50),
            capacity: 16,
        };
        let cache = ProcessCache::new(&policy, token(), Some(sink.clone())).unwrap();
        let key = CacheKey::new("env", "EXPIRE_TEST");
        cache.insert(
            key.clone(),
            Arc::new(SecretString::new("v".to_string().into())),
        );

        std::thread::sleep(Duration::from_millis(120));
        // Drive the listener: a subsequent get + run_pending_tasks
        // forces moka to process the expired entry.
        let _ = cache.get(&key);
        cache.run_pending_tasks();

        let events = sink.events.lock().unwrap().clone();
        assert!(
            events.iter().any(|e| e == "cache.expire"),
            "expected a cache.expire event, got {events:?}"
        );
    }

    #[test]
    fn capacity_eviction_drops_oldest() {
        let policy = CachePolicy::Process {
            ttl: Duration::from_secs(60),
            capacity: 2,
        };
        let cache = ProcessCache::new(&policy, token(), None).unwrap();
        cache.insert(
            CacheKey::new("env", "A"),
            Arc::new(SecretString::new("a".to_string().into())),
        );
        cache.insert(
            CacheKey::new("env", "B"),
            Arc::new(SecretString::new("b".to_string().into())),
        );
        cache.insert(
            CacheKey::new("env", "C"),
            Arc::new(SecretString::new("c".to_string().into())),
        );
        cache.run_pending_tasks();
        // moka's segmented LRU may not evict deterministically when
        // capacity is tiny; we only assert that the cache stayed at or
        // below its ceiling.
        assert!(cache.entry_count() <= 2);
    }

    #[test]
    fn scheme_namespacing_prevents_cross_backend_alias() {
        let cache = ProcessCache::new(&CachePolicy::process_default(), token(), None).unwrap();
        let k1 = CacheKey::new("env", "DUP");
        let k2 = CacheKey::new("file", "DUP");
        cache.insert(
            k1.clone(),
            Arc::new(SecretString::new("env-value".to_string().into())),
        );
        cache.insert(
            k2.clone(),
            Arc::new(SecretString::new("file-value".to_string().into())),
        );
        assert_eq!(cache.get(&k1).unwrap().expose_secret(), "env-value");
        assert_eq!(cache.get(&k2).unwrap().expose_secret(), "file-value");
    }
}
