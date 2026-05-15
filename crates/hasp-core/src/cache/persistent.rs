//! Cross-invocation encrypted-file cache for `hasp`.
//!
//! Threat model boundary, reproduced verbatim from AWS Secrets Manager
//! Agent docs: *"After the secret value is pulled into the cache, any
//! user with access to the compute environment can access the secret
//! from the cache."* The on-disk envelope is XChaCha20-Poly1305 AEAD
//! with a per-host 32-byte symmetric key bound to the OS keyring; the
//! same-uid attacker who can read `~/.cache/hasp/cache.bin` can also
//! talk to the OS keyring and obtain the key. The encryption defends
//! against trivial filesystem grep, backup snapshots, and the
//! `~/.aws/cli/cache/`-class exfil pattern — not against
//! same-uid code execution.
//!
//! **Fail-closed.** If the OS keyring is unreachable (headless
//! container without a DBus session bus, locked macOS Keychain, etc.)
//! `PersistentStore::load` returns `Error::PermissionDenied`. There is
//! no co-located-key fallback — a symmetric key alongside the
//! ciphertext is the Doppler anti-pattern: same-uid access already
//! had the key, and now backup-snapshot exfil does too.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::cache::CacheKey;
use crate::{Error, SecretString};

/// Symmetric-key length (XChaCha20-Poly1305).
const KEY_LEN: usize = 32;

/// Nonce length (XChaCha20 extended nonce).
const NONCE_LEN: usize = 24;

/// File magic so future format revisions can be detected without
/// guessing from the first-byte distribution.
const FILE_MAGIC: &[u8; 4] = b"HCV1";

/// One entry inside the JSON envelope. `value_b64` carries the raw
/// secret bytes — base64 keeps the envelope valid JSON even when the
/// secret is binary. The envelope is itself AEAD-encrypted; base64
/// is wire encoding, not protection.
#[derive(Serialize, Deserialize)]
struct DiskEntry {
    scheme: String,
    identity: String,
    value_b64: String,
    expires_at_unix: u64,
}

/// Plaintext envelope serialized inside the AEAD-encrypted blob.
#[derive(Serialize, Deserialize)]
struct Envelope {
    entries: Vec<DiskEntry>,
}

/// One decrypted entry handed back to `ProcessCache` for re-insertion.
pub struct DecryptedEntry {
    pub key: CacheKey,
    pub value: Arc<SecretString>,
    pub expires_at: SystemTime,
}

/// Result of [`PersistentStore::load`]. `tampered` is `true` when the
/// on-disk file existed but failed AEAD verification (or a layer below
/// it: short input, bad magic, plaintext unparseable). The caller is
/// expected to treat the cache as cold AND emit a
/// `cache.tamper_rejected` audit event — distinguishing actual
/// tampering from a clean cold start.
pub struct LoadOutcome {
    pub entries: Vec<DecryptedEntry>,
    pub tampered: bool,
}

/// Driver for the encrypted cache file: load on construction, save on
/// `Store::save_cache()`, tamper-rejection treated as cold cache.
pub struct PersistentStore {
    path: PathBuf,
    service: String,
    account: String,
}

impl PersistentStore {
    pub fn new(path: PathBuf, service: String, account: String) -> Self {
        Self {
            path,
            service,
            account,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load all unexpired entries from the encrypted file.
    ///
    /// `LoadOutcome::tampered` is `true` when the file existed but
    /// failed AEAD verification (or magic / plaintext parse); the
    /// caller emits `cache.tamper_rejected` and proceeds with a cold
    /// cache. Missing file ⇒ `tampered = false`, empty entries.
    /// Returns `Err(Error::PermissionDenied)` when the OS keyring is
    /// unreachable — the fail-closed contract.
    pub fn load(&self) -> Result<LoadOutcome, Error> {
        let key = fetch_or_create_key(&self.service, &self.account)?;
        let raw = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadOutcome {
                    entries: Vec::new(),
                    tampered: false,
                });
            }
            Err(e) => {
                return Err(Error::Backend {
                    scheme: "cache",
                    kind: crate::BackendFailureKind::Transient,
                    message: format!("persistent cache read failed: {e}"),
                });
            }
        };
        Ok(decrypt_envelope(&raw, &key))
    }

    /// Encrypt and atomically write the given entries.
    ///
    /// Atomicity is via tempfile-in-same-dir + rename. The parent
    /// directory is created with mode `0o700` on Unix; the file is
    /// created with mode `0o600`. Concurrent writers race the rename;
    /// the survivor wins, no entry corruption because each save is
    /// a full snapshot.
    pub fn save(&self, entries: &[DecryptedEntry]) -> Result<(), Error> {
        let key = fetch_or_create_key(&self.service, &self.account)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Backend {
                scheme: "cache",
                kind: crate::BackendFailureKind::Transient,
                message: format!("persistent cache mkdir failed: {e}"),
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let ciphertext = encrypt_envelope(entries, &key)?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::Builder::new()
            .prefix(".hasp-cache-")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|e| Error::Backend {
                scheme: "cache",
                kind: crate::BackendFailureKind::Transient,
                message: format!("persistent cache tempfile failed: {e}"),
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600));
        }
        tmp.write_all(&ciphertext).map_err(|e| Error::Backend {
            scheme: "cache",
            kind: crate::BackendFailureKind::Transient,
            message: format!("persistent cache write failed: {e}"),
        })?;
        tmp.as_file().sync_data().ok();
        tmp.persist(&self.path).map_err(|e| Error::Backend {
            scheme: "cache",
            kind: crate::BackendFailureKind::Transient,
            message: format!("persistent cache rename failed: {e}"),
        })?;
        Ok(())
    }

    /// Remove the on-disk cache file. The keyring entry is preserved
    /// so the next save reuses the same symmetric key (and historical
    /// ciphertext on backup tapes remains decryptable for audit).
    /// Pair with [`Self::forget_key`] when full erasure is requested.
    pub fn delete_file(&self) -> Result<(), Error> {
        match fs::remove_file(&self.path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Backend {
                scheme: "cache",
                kind: crate::BackendFailureKind::Transient,
                message: format!("persistent cache delete failed: {e}"),
            }),
        }
    }

    /// Remove the keyring entry holding the symmetric key.
    pub fn forget_key(&self) -> Result<(), Error> {
        ensure_keyring_init()?;
        let entry = keyring_core::Entry::new(&self.service, &self.account)
            .map_err(|e| Error::PermissionDenied(format!("keyring entry creation: {e}")))?;
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::PermissionDenied(format!(
                "keyring delete failed: {e}"
            ))),
        }
    }
}

/// AEAD-decrypt the cache file. Returns `tampered = true` on any path
/// where the file existed but failed validation (short input, bad
/// magic, AEAD tag mismatch, plaintext unparseable). The caller
/// proceeds with a cold cache; the `tampered` flag drives the
/// downstream `cache.tamper_rejected` audit event so an operator can
/// distinguish a clean cold start from a hostile bit-flip.
fn decrypt_envelope(raw: &[u8], key: &[u8; KEY_LEN]) -> LoadOutcome {
    let cold = LoadOutcome {
        entries: Vec::new(),
        tampered: true,
    };
    if raw.len() < FILE_MAGIC.len() + NONCE_LEN + 16 {
        return cold;
    }
    if &raw[..FILE_MAGIC.len()] != FILE_MAGIC {
        return cold;
    }
    let nonce_start = FILE_MAGIC.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = XNonce::from_slice(&raw[nonce_start..nonce_end]);
    let ciphertext = &raw[nonce_end..];
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => return cold,
    };
    let env: Envelope = match serde_json::from_slice(&plaintext) {
        Ok(e) => e,
        Err(_) => return cold,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = Vec::with_capacity(env.entries.len());
    for entry in env.entries {
        if entry.expires_at_unix <= now {
            continue;
        }
        let bytes = match B64.decode(entry.value_b64.as_bytes()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let value = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let scheme_static = static_scheme(&entry.scheme);
        out.push(DecryptedEntry {
            key: CacheKey {
                scheme: scheme_static,
                identity: entry.identity,
            },
            value: Arc::new(SecretString::new(value.into())),
            expires_at: UNIX_EPOCH + Duration::from_secs(entry.expires_at_unix),
        });
    }
    LoadOutcome {
        entries: out,
        tampered: false,
    }
}

fn encrypt_envelope(entries: &[DecryptedEntry], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, Error> {
    use secrecy::ExposeSecret;
    let mut disk = Vec::with_capacity(entries.len());
    for e in entries {
        let exp = e
            .expires_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        disk.push(DiskEntry {
            scheme: e.key.scheme.to_owned(),
            identity: e.key.identity.clone(),
            value_b64: B64.encode(e.value.expose_secret().as_bytes()),
            expires_at_unix: exp,
        });
    }
    let env = Envelope { entries: disk };
    let plaintext = serde_json::to_vec(&env).map_err(|e| Error::Backend {
        scheme: "cache",
        kind: crate::BackendFailureKind::Permanent,
        message: format!("persistent cache serialize failed: {e}"),
    })?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| Error::Backend {
        scheme: "cache",
        kind: crate::BackendFailureKind::Transient,
        message: format!("persistent cache rng failed: {e}"),
    })?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| Error::Backend {
            scheme: "cache",
            kind: crate::BackendFailureKind::Permanent,
            message: format!("persistent cache encrypt failed: {e}"),
        })?;
    let mut out = Vec::with_capacity(FILE_MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Convert a runtime scheme string into the `&'static str` the
/// `CacheKey` shape requires. Persistent cache only retains entries
/// whose backend's scheme matches one of the registered defaults; an
/// unrecognized scheme on disk is treated as a stale entry and
/// dropped. The closed set keeps the leak budget bounded and matches
/// the `AuditEvent` label invariant.
fn static_scheme(scheme: &str) -> &'static str {
    match scheme {
        "env" => "env",
        "file" => "file",
        "keyring" => "keyring",
        "op" => "op",
        "bw" => "bw",
        "vault" => "vault",
        "aws-sm" => "aws-sm",
        "aws-ssm" => "aws-ssm",
        "gcp-sm" => "gcp-sm",
        "azure-kv" => "azure-kv",
        _ => "unknown",
    }
}

/// Lazily initialize the platform keyring store. Mirrors the pattern
/// in `hasp-backend-keyring::ensure_init` so behavior is identical
/// across both keyring code paths and a single keyring-backend swap
/// touches both.
fn ensure_keyring_init() -> Result<(), Error> {
    static INIT: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        if keyring_core::get_default_store().is_some() {
            return Ok(());
        }
        match create_platform_store() {
            Ok(store) => {
                keyring_core::set_default_store(store);
                Ok(())
            }
            Err(e) => Err(format!("keyring store initialization failed: {e}")),
        }
    })
    .clone()
    .map_err(Error::PermissionDenied)
}

#[cfg(target_os = "macos")]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    apple_native_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
}

#[cfg(target_os = "windows")]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    windows_native_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
}

#[cfg(target_os = "linux")]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    dbus_secret_service_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn create_platform_store(
) -> Result<std::sync::Arc<keyring_core::CredentialStore>, keyring_core::Error> {
    Err(keyring_core::Error::NotSupportedByStore(
        "unsupported platform for persistent cache keyring binding".into(),
    ))
}

/// Read the 32-byte symmetric key from the OS keyring, generating it
/// on first use. The first `Entry::get_secret()` is also the headless
/// probe: a same-uid attacker can read the key, but a headless
/// container without a session bus can't reach the keyring at all and
/// surfaces here as `PermissionDenied`.
fn fetch_or_create_key(service: &str, account: &str) -> Result<[u8; KEY_LEN], Error> {
    ensure_keyring_init()?;
    let entry = keyring_core::Entry::new(service, account)
        .map_err(|e| Error::PermissionDenied(format!("keyring entry creation: {e}")))?;
    match entry.get_secret() {
        Ok(secret) => {
            if secret.len() != KEY_LEN {
                return Err(Error::Backend {
                    scheme: "cache",
                    kind: crate::BackendFailureKind::Permanent,
                    message: format!(
                        "keyring-stored cache key is {} bytes, expected {KEY_LEN}",
                        secret.len()
                    ),
                });
            }
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&secret);
            Ok(key)
        }
        Err(keyring_core::Error::NoEntry) => {
            let mut key = [0u8; KEY_LEN];
            getrandom::getrandom(&mut key).map_err(|e| Error::Backend {
                scheme: "cache",
                kind: crate::BackendFailureKind::Transient,
                message: format!("persistent cache rng failed: {e}"),
            })?;
            entry
                .set_secret(&key)
                .map_err(|e| Error::PermissionDenied(format!("keyring set failed: {e}")))?;
            Ok(key)
        }
        Err(e) => Err(Error::PermissionDenied(format!("keyring get failed: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn mock_keyring_once() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let store = keyring_core::mock::Store::new().unwrap();
            keyring_core::set_default_store(store);
        });
    }

    fn entry(scheme: &'static str, id: &str, value: &str, ttl_secs: u64) -> DecryptedEntry {
        DecryptedEntry {
            key: CacheKey::new(scheme, id),
            value: Arc::new(SecretString::new(value.to_owned().into())),
            expires_at: SystemTime::now() + Duration::from_secs(ttl_secs),
        }
    }

    fn store_in(dir: &Path, account: &str) -> PersistentStore {
        PersistentStore::new(
            dir.join("cache.bin"),
            "hasp-test".into(),
            account.to_owned(),
        )
    }

    #[test]
    fn load_after_save_roundtrip() {
        mock_keyring_once();
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "roundtrip");
        let entries = vec![
            entry("env", "USER", "alice", 60),
            entry("file", "/tmp/secret", "filevalue", 60),
        ];
        store.save(&entries).unwrap();
        let loaded = store.load().unwrap();
        assert!(!loaded.tampered);
        assert_eq!(loaded.entries.len(), 2);
        let env_e = loaded
            .entries
            .iter()
            .find(|e| e.key.scheme == "env" && e.key.identity == "USER")
            .unwrap();
        assert_eq!(env_e.value.expose_secret(), "alice");
    }

    #[test]
    fn ttl_expired_entries_dropped_on_load() {
        mock_keyring_once();
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "ttl-expiry");
        // Construct an entry whose expiry is in the past.
        let past = DecryptedEntry {
            key: CacheKey::new("env", "STALE"),
            value: Arc::new(SecretString::new("stale".to_string().into())),
            expires_at: UNIX_EPOCH + Duration::from_secs(1),
        };
        store.save(&[past]).unwrap();
        let loaded = store.load().unwrap();
        assert!(
            loaded.entries.is_empty(),
            "expired entries must not survive load"
        );
        assert!(!loaded.tampered);
    }

    #[test]
    fn aead_tamper_treated_as_cold_cache() {
        mock_keyring_once();
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "tamper");
        store.save(&[entry("env", "X", "v", 60)]).unwrap();

        // Flip a byte deep inside the ciphertext (past magic + nonce).
        let path = dir.path().join("cache.bin");
        let mut bytes = fs::read(&path).unwrap();
        let flip = FILE_MAGIC.len() + NONCE_LEN + 4;
        bytes[flip] ^= 0xff;
        fs::write(&path, &bytes).unwrap();

        let loaded = store.load().unwrap();
        assert!(
            loaded.entries.is_empty(),
            "tampered file must surface as cold cache"
        );
        assert!(
            loaded.tampered,
            "AEAD-tampered file must set tampered=true so the caller can emit cache.tamper_rejected"
        );
    }

    #[test]
    fn missing_file_is_cold_cache() {
        mock_keyring_once();
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "missing");
        let loaded = store.load().unwrap();
        assert!(loaded.entries.is_empty());
        assert!(
            !loaded.tampered,
            "missing file is not the same as tamper-rejected; tampered must be false"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_is_0o600() {
        use std::os::unix::fs::PermissionsExt;
        mock_keyring_once();
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "mode");
        store.save(&[entry("env", "X", "v", 60)]).unwrap();
        let perms = fs::metadata(dir.path().join("cache.bin"))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn delete_file_is_idempotent() {
        mock_keyring_once();
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "delete");
        store.delete_file().unwrap();
        store.save(&[entry("env", "X", "v", 60)]).unwrap();
        store.delete_file().unwrap();
        store.delete_file().unwrap();
    }
}
