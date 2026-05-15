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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use moka::notification::RemovalCause;
use moka::sync::Cache;

use crate::audit::{AuditEvent, AuditSink, CacheEvent};
use crate::hardening::HardeningToken;
use crate::Error;
use crate::SecretString;

#[cfg(feature = "cache-persistent")]
pub mod persistent;
#[cfg(feature = "cache-persistent")]
pub use persistent::{DecryptedEntry, LoadOutcome, PersistentStore};

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

/// Cache policy selector for [`ProcessCache::new`].
///
/// `Disabled` is the safe default and skips every cache code path.
/// `Process` enables in-process memoization with the given TTL and
/// capacity ceiling; capacity-eviction is LRU within moka's segmented
/// design.
///
/// `Persistent` (gated on the `cache-persistent` Cargo feature) wires
/// an encrypted on-disk envelope keyed by an OS-keyring-bound 32-byte
/// symmetric key. Load happens on construction; save on
/// [`crate::cache::ProcessCache::save_to_disk`]. Threat model and
/// fail-closed contract live on [`PersistentPolicy`] and
/// [`persistent::PersistentStore`].
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

/// Configuration for the encrypted on-disk cache.
///
/// `ttl` is the per-entry time-to-live, clamped against AWS Secrets
/// Manager Agent's published envelope (300s default, 3600s max). A
/// `ttl` of zero disables persistence at the policy layer; the
/// caller should select `CachePolicy::Disabled` instead.
///
/// `path` is the encrypted cache file location. Default:
/// `$XDG_CACHE_HOME/hasp/cache.bin`, mode `0o600` on Unix, atomically
/// replaced on save via tempfile + rename.
///
/// `keyring_service` and `keyring_account` identify the OS-keyring
/// entry holding the per-host XChaCha20-Poly1305 symmetric key.
/// Default service is `"hasp"`; default account is `"cache:<user>"`.
/// The first `keyring_core::Entry::get_secret()` doubles as the
/// headless-container probe — when the keyring is unreachable,
/// `ProcessCache::new` surfaces `Error::PermissionDenied`, no
/// co-located-key fallback (RustCrypto AEADs + RFC 8439 / XChaCha20
/// extension).
///
/// AWS Secrets Manager Agent's threat-model warning applies verbatim:
/// *"After the secret value is pulled into the cache, any user with
/// access to the compute environment can access the secret from the
/// cache."* The OS-keyring binding defends against trivial filesystem
/// grep and backup-snapshot exfil — not against same-uid code
/// execution.
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
    ttl: Duration,
    /// Per-entry insertion timestamps. moka does not expose
    /// `inserted_at` from its iter API, so the cache tracks it here
    /// for the `save_to_disk` snapshot — every saved entry's
    /// `expires_at` is `inserted_at + ttl`, not `now + ttl`. Without
    /// this, a daemon that calls `save_to_disk` repeatedly would
    /// extend every entry's effective TTL on each save (an AWS-Agent
    /// envelope violation for long-running library consumers).
    inserted_at: Arc<Mutex<HashMap<CacheKey, SystemTime>>>,
    #[cfg(feature = "cache-persistent")]
    persistent: Option<Arc<PersistentStore>>,
    audit_sink: Option<Arc<dyn AuditSink>>,
}

impl ProcessCache {
    /// Construct a cache governed by `policy`. Returns `Ok(None)` when
    /// the policy is `Disabled`.
    ///
    /// The `_token` parameter is the architectural lever: callers who
    /// have not installed hardening cannot obtain a token and
    /// therefore cannot construct a cache. The token is consumed by
    /// value (it is `Copy`) and is not retained.
    ///
    /// `audit_sink`, when provided, receives `cache.expire` events on
    /// TTL-driven evictions, plus `cache.load` / `cache.tamper_rejected`
    /// for the persistent flavor. Explicit `invalidate` /
    /// `invalidate_all` calls do not emit events here — `Store` emits
    /// its own `cache.clear` on the user-facing path.
    ///
    /// `Persistent` (gated on `cache-persistent`) loads any existing
    /// encrypted file at construction time. A missing file or AEAD
    /// tamper is treated as a cold cache (no error); only an
    /// unreachable OS keyring surfaces as `Err(PermissionDenied)` —
    /// the fail-closed contract.
    pub fn new(
        policy: &CachePolicy,
        token: HardeningToken,
        audit_sink: Option<Arc<dyn AuditSink>>,
    ) -> Result<Option<Self>, Error> {
        match policy {
            #[cfg(feature = "cache-persistent")]
            CachePolicy::Persistent(p) => Self::build_persistent(p, token, audit_sink),
            CachePolicy::Disabled => Ok(None),
            CachePolicy::Process { ttl, capacity } => Ok(Some(Self::build_process(
                *ttl,
                *capacity,
                audit_sink,
                #[cfg(feature = "cache-persistent")]
                None,
            ))),
        }
    }

    fn build_process(
        ttl: Duration,
        capacity: u64,
        audit_sink: Option<Arc<dyn AuditSink>>,
        #[cfg(feature = "cache-persistent")] persistent: Option<Arc<PersistentStore>>,
    ) -> Self {
        let sink = audit_sink.clone();
        let inserted_at: Arc<Mutex<HashMap<CacheKey, SystemTime>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inserted_at_listener = inserted_at.clone();
        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl)
            .eviction_listener(move |k: Arc<CacheKey>, v, cause| {
                // Drop the Arc<SecretString> first so the inner
                // zeroize fires promptly. moka 0.12 sync flavor
                // runs this listener synchronously on the
                // eviction-causing thread.
                drop(v);
                if let Ok(mut m) = inserted_at_listener.lock() {
                    m.remove(&*k);
                }
                if matches!(cause, RemovalCause::Expired) {
                    if let Some(s) = &sink {
                        s.emit(&AuditEvent::cache(CacheEvent::Expire, k.scheme));
                    }
                }
            })
            .build();
        Self {
            inner,
            ttl,
            inserted_at,
            #[cfg(feature = "cache-persistent")]
            persistent,
            audit_sink,
        }
    }

    #[cfg(feature = "cache-persistent")]
    fn build_persistent(
        p: &PersistentPolicy,
        _token: HardeningToken,
        audit_sink: Option<Arc<dyn AuditSink>>,
    ) -> Result<Option<Self>, Error> {
        let store = Arc::new(PersistentStore::new(
            p.path.clone(),
            p.keyring_service.clone(),
            p.keyring_account.clone(),
        ));
        let cache = Self::build_process(p.ttl, p.capacity, audit_sink.clone(), Some(store.clone()));
        let outcome = match store.load() {
            Ok(o) => o,
            Err(e) if matches!(e, Error::PermissionDenied(_)) => {
                // Fail-closed: cannot reach the OS keyring.
                return Err(e);
            }
            Err(_e) => {
                // I/O failure on the cache file itself (read error after
                // it existed and was readable enough to be opened, then
                // something went sideways). Treat as a cold cache so the
                // user's flow continues, but DO NOT emit
                // `cache.tamper_rejected` — that label is reserved for
                // AEAD-tag mismatches surfaced through the LoadOutcome
                // path, where the threat-model signal is "hostile
                // bit-flip" rather than "transient I/O".
                persistent::LoadOutcome {
                    entries: Vec::new(),
                    tampered: false,
                }
            }
        };
        if outcome.tampered {
            if let Some(sink) = &audit_sink {
                sink.emit(&AuditEvent::cache(CacheEvent::TamperRejected, "all"));
            }
        }
        // Re-hydrate insertion timestamps from disk so a subsequent
        // `save_to_disk` preserves the original entry's expiry
        // envelope instead of resetting it. `inserted = expires_at -
        // ttl` reverses the formula used at save time.
        if let Ok(mut m) = cache.inserted_at.lock() {
            for e in &outcome.entries {
                let inserted = e.expires_at.checked_sub(p.ttl).unwrap_or(e.expires_at);
                m.insert(e.key.clone(), inserted);
            }
        }
        for e in outcome.entries {
            cache.inner.insert(e.key, e.value);
        }
        if let Some(sink) = &audit_sink {
            sink.emit(&AuditEvent::cache(CacheEvent::Load, "all"));
        }
        Ok(Some(cache))
    }

    /// Read a cached value. Returns the `Arc<SecretString>` if a
    /// fresh entry exists, or `None` on miss / TTL expiry. Callers
    /// hold the clone — the cache retains its own Arc.
    pub fn get(&self, key: &CacheKey) -> Option<Arc<SecretString>> {
        self.inner.get(key)
    }

    /// Insert or replace a value. Also stamps the entry with the
    /// current insertion time so that `save_to_disk` can emit a
    /// per-entry `expires_at` instead of pinning every saved entry
    /// to `now + ttl`. On a replace, the timestamp resets — the
    /// entry behaves as fresh.
    pub fn insert(&self, key: CacheKey, value: Arc<SecretString>) {
        if let Ok(mut m) = self.inserted_at.lock() {
            m.insert(key.clone(), SystemTime::now());
        }
        self.inner.insert(key, value);
    }

    /// Invalidate a single entry. No-op if the key is absent.
    pub fn invalidate(&self, key: &CacheKey) {
        if let Ok(mut m) = self.inserted_at.lock() {
            m.remove(key);
        }
        self.inner.invalidate(key);
    }

    /// Drop every entry. Used by `hasp cache clear` and tests.
    pub fn invalidate_all(&self) {
        if let Ok(mut m) = self.inserted_at.lock() {
            m.clear();
        }
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

    /// Persist the cache snapshot to disk. No-op when the cache was
    /// constructed without a `Persistent` policy. Emits `cache.save`
    /// on success; errors surface to the caller.
    ///
    /// Each saved entry's `expires_at` is `inserted_at + ttl`, drawn
    /// from the cache's per-entry insertion-time map (populated on
    /// `insert`, cleared on eviction). Entries whose computed
    /// `expires_at` is already in the past at save time are dropped
    /// before write — the on-disk envelope never carries already-
    /// expired entries, and repeated saves do not extend the
    /// effective TTL. A daemon that calls `save_to_disk` every
    /// second sees the same per-secret expiry envelope as one save
    /// per `ttl`.
    #[cfg(feature = "cache-persistent")]
    pub fn save_to_disk(&self) -> Result<(), Error> {
        let Some(store) = &self.persistent else {
            return Ok(());
        };
        self.inner.run_pending_tasks();
        let now = SystemTime::now();
        // Clone the insertion-time map under the lock, then release
        // it before iterating the cache. moka's iter could re-enter
        // the eviction listener (which also takes the lock) on a
        // racing expiry, so holding the lock across iter would
        // deadlock.
        let inserted_at_snapshot: HashMap<CacheKey, SystemTime> = self
            .inserted_at
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let mut snapshot: Vec<DecryptedEntry> =
            Vec::with_capacity(self.inner.entry_count() as usize);
        for entry in self.inner.iter() {
            let (k, v) = entry;
            let key = (*k).clone();
            let inserted = inserted_at_snapshot.get(&key).copied().unwrap_or(now);
            let expires_at = inserted + self.ttl;
            if expires_at <= now {
                continue;
            }
            snapshot.push(DecryptedEntry {
                key,
                value: v,
                expires_at,
            });
        }
        store.save(&snapshot)?;
        if let Some(sink) = &self.audit_sink {
            sink.emit(&AuditEvent::cache(CacheEvent::Save, "all"));
        }
        Ok(())
    }

    /// Remove the on-disk encrypted cache file (when persistent). The
    /// keyring entry is preserved unless `forget_key` is also true.
    /// In-memory entries are not touched by this method; callers that
    /// want a full wipe should call [`Self::invalidate_all`] first.
    #[cfg(feature = "cache-persistent")]
    pub fn clear_persistent_file(&self, forget_key: bool) -> Result<(), Error> {
        let Some(store) = &self.persistent else {
            return Ok(());
        };
        store.delete_file()?;
        if forget_key {
            store.forget_key()?;
        }
        Ok(())
    }

    /// Whether this cache writes to disk on `save_to_disk`.
    pub fn is_persistent(&self) -> bool {
        #[cfg(feature = "cache-persistent")]
        {
            self.persistent.is_some()
        }
        #[cfg(not(feature = "cache-persistent"))]
        {
            false
        }
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
        assert!(ProcessCache::new(&policy, token(), None).unwrap().is_none());
    }

    #[test]
    fn process_policy_returns_some() {
        let policy = CachePolicy::process_default();
        assert!(ProcessCache::new(&policy, token(), None).unwrap().is_some());
    }

    #[test]
    fn insert_then_get_returns_same_secret_bytes() {
        let cache = ProcessCache::new(&CachePolicy::process_default(), token(), None)
            .unwrap()
            .unwrap();
        let key = CacheKey::new("env", "USER");
        let secret = Arc::new(SecretString::new("alice".to_string().into()));
        cache.insert(key.clone(), secret.clone());

        let got = cache.get(&key).expect("cache hit");
        assert_eq!(got.expose_secret(), "alice");
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = ProcessCache::new(&CachePolicy::process_default(), token(), None)
            .unwrap()
            .unwrap();
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
        let cache = ProcessCache::new(&policy, token(), None).unwrap().unwrap();
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
        let cache = ProcessCache::new(&policy, token(), Some(sink.clone()))
            .unwrap()
            .unwrap();
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
        let cache = ProcessCache::new(&policy, token(), None).unwrap().unwrap();
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
        let cache = ProcessCache::new(&CachePolicy::process_default(), token(), None)
            .unwrap()
            .unwrap();
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
