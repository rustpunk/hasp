use crate::{Backend, Error, SecretString};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Decorator backend that retries transient failures with exponential backoff.
pub struct RetryBackend {
    inner: Arc<dyn Backend>,
    max_retries: u32,
    base_delay: Duration,
}

impl RetryBackend {
    /// Create a new retry decorator.
    pub fn new(inner: Arc<dyn Backend>) -> Self {
        Self {
            inner,
            max_retries: 3,
            base_delay: Duration::from_millis(100),
        }
    }

    /// Set the maximum number of retry attempts.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Set the base delay between retries (doubles each attempt).
    pub fn base_delay(mut self, d: Duration) -> Self {
        self.base_delay = d;
        self
    }

    fn retry(
        &self,
        mut op: impl FnMut() -> Result<SecretString, Error>,
    ) -> Result<SecretString, Error> {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match op() {
                Ok(val) => return Ok(val),
                Err(e) => {
                    if !e.is_transient() || attempt == self.max_retries {
                        return Err(e);
                    }
                    let delay = self.backoff(attempt);
                    std::thread::sleep(delay);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    fn retry_void(&self, mut op: impl FnMut() -> Result<(), Error>) -> Result<(), Error> {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match op() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !e.is_transient() || attempt == self.max_retries {
                        return Err(e);
                    }
                    let delay = self.backoff(attempt);
                    std::thread::sleep(delay);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    fn retry_bool(&self, mut op: impl FnMut() -> Result<bool, Error>) -> Result<bool, Error> {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match op() {
                Ok(val) => return Ok(val),
                Err(e) => {
                    if !e.is_transient() || attempt == self.max_retries {
                        return Err(e);
                    }
                    let delay = self.backoff(attempt);
                    std::thread::sleep(delay);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    fn retry_vec(
        &self,
        mut op: impl FnMut() -> Result<Vec<crate::Entry>, Error>,
    ) -> Result<Vec<crate::Entry>, Error> {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match op() {
                Ok(val) => return Ok(val),
                Err(e) => {
                    if !e.is_transient() || attempt == self.max_retries {
                        return Err(e);
                    }
                    let delay = self.backoff(attempt);
                    std::thread::sleep(delay);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    /// Exponential backoff with a deterministic per-attempt offset.
    ///
    /// delay = base_delay * 2^attempt plus a small fixed offset that
    /// varies per attempt to spread out retries; the offset is computed
    /// from `attempt`, not randomized, so the schedule is reproducible.
    /// The result saturates at `u64::MAX` milliseconds rather than
    /// overflowing for large `attempt`.
    fn backoff(&self, attempt: u32) -> Duration {
        let base = self.base_delay;
        let multiplier = 1u128.checked_shl(attempt).unwrap_or(u128::MAX);
        let exponential = base.as_millis().saturating_mul(multiplier);
        let offset = (attempt.wrapping_mul(7) % 50) as u128;
        Duration::from_millis(u64::try_from(exponential.saturating_add(offset)).unwrap_or(u64::MAX))
    }
}

impl Backend for RetryBackend {
    fn scheme(&self) -> &'static str {
        self.inner.scheme()
    }

    fn get(&self, url: &Url) -> Result<SecretString, Error> {
        self.retry(|| self.inner.get(url))
    }

    fn put(&self, url: &Url, value: &SecretString) -> Result<(), Error> {
        self.retry_void(|| self.inner.put(url, value))
    }

    fn list(&self, url: &Url) -> Result<Vec<crate::Entry>, Error> {
        self.retry_vec(|| self.inner.list(url))
    }

    fn delete(&self, url: &Url) -> Result<(), Error> {
        self.retry_void(|| self.inner.delete(url))
    }

    fn exists(&self, url: &Url) -> Result<bool, Error> {
        self.retry_bool(|| self.inner.exists(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Backend, Entry, Error, SecretString};
    use std::sync::Arc;
    use std::time::Duration;
    use url::Url;

    // Minimal backend whose methods are never invoked by `backoff`; every
    // verb returns an error so the dummy needs no real secret material.
    struct Dummy;

    impl Backend for Dummy {
        fn scheme(&self) -> &'static str {
            "dummy"
        }
        fn get(&self, _url: &Url) -> Result<SecretString, Error> {
            Err(Error::NotFound("dummy".into()))
        }
        fn put(&self, _url: &Url, _value: &SecretString) -> Result<(), Error> {
            Err(Error::NotFound("dummy".into()))
        }
        fn list(&self, _url: &Url) -> Result<Vec<Entry>, Error> {
            Err(Error::NotFound("dummy".into()))
        }
        fn delete(&self, _url: &Url) -> Result<(), Error> {
            Err(Error::NotFound("dummy".into()))
        }
        fn exists(&self, _url: &Url) -> Result<bool, Error> {
            Err(Error::NotFound("dummy".into()))
        }
    }

    #[test]
    fn backoff_scales_with_base_delay() {
        let r = RetryBackend::new(Arc::new(Dummy)).base_delay(Duration::from_millis(500));
        assert!(r.backoff(0) >= Duration::from_millis(500));
        assert!(r.backoff(1) >= Duration::from_millis(1000));

        let small = RetryBackend::new(Arc::new(Dummy)).base_delay(Duration::from_millis(100));
        assert!(r.backoff(2) > small.backoff(2));
    }

    #[test]
    fn backoff_does_not_panic_on_large_attempt() {
        let r = RetryBackend::new(Arc::new(Dummy));
        let _ = r.backoff(200);
    }
}
