//! B4AE Safe Time Utilities
//!
//! Provides panic-free system time access with graceful fallback for
//! misconfigured or pre-epoch system clocks.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns Unix timestamp in seconds. Returns 0 if system time is before Unix epoch.
#[inline]
pub fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Returns Unix timestamp in milliseconds. Returns 0 if system time is before Unix epoch.
#[inline]
pub fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
