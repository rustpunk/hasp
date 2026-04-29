use std::sync::Mutex;

/// Global lock to prevent concurrent env-var mutations across tests.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Guard that sets an environment variable for the duration of a test
/// and restores it afterward.
pub struct EnvGuard {
    key: String,
    old: Option<String>,
}

impl EnvGuard {
    /// Set `key` to `value`, saving the previous value (if any).
    pub fn set(key: &str, value: &str) -> Self {
        let old = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key: key.into(),
            old,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(v) => std::env::set_var(&self.key, v),
            None => std::env::remove_var(&self.key),
        }
    }
}
