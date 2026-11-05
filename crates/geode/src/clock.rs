use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::GeodeError;

/// Source of wall-clock seconds for lease expiry and audit timestamps.
///
/// Injecting a clock keeps expiry tests deterministic without sleeping.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        unix_now()
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// An injected clock used by [`crate::Store`] and its leases.
pub type SharedClock = Arc<dyn Clock>;

/// A manually advanced clock for tests and deterministic harnesses.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: std::sync::atomic::AtomicU64,
}

impl ManualClock {
    pub fn new(start: u64) -> Self {
        Self {
            now: std::sync::atomic::AtomicU64::new(start),
        }
    }

    pub fn advance(&self, by: Duration) {
        self.now
            .fetch_add(by.as_secs(), std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl fmt::Debug for dyn Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Clock({})", self.now())
    }
}

impl GeodeError {
    pub(crate) fn expired(reference: impl fmt::Display) -> Self {
        Self::Expired(reference.to_string())
    }
}
