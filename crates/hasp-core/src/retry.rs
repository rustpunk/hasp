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
                    let delay = Self::backoff(attempt);
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
                    let delay = Self::backoff(attempt);
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
                    let delay = Self::backoff(attempt);
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
                    let delay = Self::backoff(attempt);
                    std::thread::sleep(delay);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }

    /// Exponential backoff with deterministic jitter.
    ///
    /// delay = base_delay * 2^attempt + jitter
    /// where jitter = (attempt * 7) % 50 to avoid adding rand.
    fn backoff(attempt: u32) -> Duration {
        let base = Duration::from_millis(100);
        let multiplier = 2_u128.pow(attempt);
        let exponential = base.as_millis().saturating_mul(multiplier);
        let jitter = (attempt.wrapping_mul(7) % 50) as u128;
        Duration::from_millis(u64::try_from(exponential.saturating_add(jitter)).unwrap_or(u64::MAX))
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
