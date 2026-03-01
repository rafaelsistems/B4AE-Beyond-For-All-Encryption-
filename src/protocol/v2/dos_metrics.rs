//! DoS Mitigation Metrics
//!
//! This module implements comprehensive metrics tracking for the DoS mitigation
//! system, including cookie challenge effectiveness, replay detection, and
//! handshake completion rates.
//!
//! ## Tracked Metrics
//!
//! ### Cookie Challenge Metrics
//! - `cookie_challenges_issued`: Total number of cookie challenges issued
//! - `cookie_verifications_succeeded`: Number of successful cookie verifications
//! - `cookie_verifications_failed`: Number of failed cookie verifications (invalid cookie)
//! - `cookie_expired_rejections`: Number of rejections due to expired timestamp
//!
//! ### Replay Protection Metrics
//! - `replay_detections`: Number of replay attacks detected
//!
//! ### Handshake Metrics
//! - `handshake_attempts`: Total handshake attempts (ClientHello received)
//! - `handshake_completions`: Successful handshake completions
//!
//! ### Derived Metrics
//! - `dos_amplification_reduction`: Calculated reduction factor (target: 360x)
//! - `cookie_success_rate`: Percentage of successful cookie verifications
//! - `handshake_success_rate`: Percentage of successful handshakes
//!
//! ## DoS Amplification Calculation
//!
//! The DoS amplification reduction is calculated as:
//! ```text
//! reduction = time_without_cookie / time_with_cookie
//!           = (Dilithium5_verify + Kyber1024_decap) / HMAC_verify
//!           = (3.0ms + 0.6ms) / 0.01ms
//!           = 360x
//! ```
//!
//! This demonstrates that the cookie challenge reduces the cost of invalid
//! handshake attempts by 360x, making DoS attacks significantly more expensive
//! for attackers.
//!
//! ## Thread Safety
//!
//! All metrics are thread-safe and can be updated concurrently from multiple
//! threads using atomic operations.
//!
//! ## Requirements
//!
//! - REQ-44: DoS Mitigation Requirements (metrics for DoS detection)
//! - REQ-49: Monitoring and Metrics Requirements (comprehensive metrics)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// DoS mitigation metrics
///
/// This structure tracks all metrics related to DoS mitigation, including
/// cookie challenge effectiveness, replay detection, and handshake success rates.
///
/// ## Thread Safety
///
/// All counters use atomic operations and can be safely updated from multiple
/// threads concurrently.
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::dos_metrics::DosMetrics;
///
/// let metrics = DosMetrics::new();
///
/// // Track cookie challenge issued
/// metrics.increment_cookie_challenges_issued();
///
/// // Track successful verification
/// metrics.increment_cookie_verifications_succeeded();
///
/// // Get current metrics
/// let snapshot = metrics.snapshot();
/// println!("Cookie success rate: {:.2}%", snapshot.cookie_success_rate());
/// ```
#[derive(Debug)]
pub struct DosMetrics {
    /// Total number of cookie challenges issued
    cookie_challenges_issued: AtomicU64,
    
    /// Number of successful cookie verifications
    cookie_verifications_succeeded: AtomicU64,
    
    /// Number of failed cookie verifications (invalid HMAC)
    cookie_verifications_failed: AtomicU64,
    
    /// Number of rejections due to expired timestamp
    cookie_expired_rejections: AtomicU64,
    
    /// Number of replay attacks detected
    replay_detections: AtomicU64,
    
    /// Total handshake attempts (ClientHello received)
    handshake_attempts: AtomicU64,
    
    /// Successful handshake completions
    handshake_completions: AtomicU64,
}

impl DosMetrics {
    /// Creates a new DoS metrics instance with all counters initialized to zero
    pub fn new() -> Self {
        DosMetrics {
            cookie_challenges_issued: AtomicU64::new(0),
            cookie_verifications_succeeded: AtomicU64::new(0),
            cookie_verifications_failed: AtomicU64::new(0),
            cookie_expired_rejections: AtomicU64::new(0),
            replay_detections: AtomicU64::new(0),
            handshake_attempts: AtomicU64::new(0),
            handshake_completions: AtomicU64::new(0),
        }
    }
    
    /// Increments the cookie challenges issued counter
    ///
    /// Call this when the server issues a cookie challenge to a client.
    pub fn increment_cookie_challenges_issued(&self) {
        self.cookie_challenges_issued.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increments the cookie verifications succeeded counter
    ///
    /// Call this when a cookie verification succeeds (valid HMAC and timestamp).
    pub fn increment_cookie_verifications_succeeded(&self) {
        self.cookie_verifications_succeeded.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increments the cookie verifications failed counter
    ///
    /// Call this when a cookie verification fails due to invalid HMAC.
    pub fn increment_cookie_verifications_failed(&self) {
        self.cookie_verifications_failed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increments the cookie expired rejections counter
    ///
    /// Call this when a cookie is rejected due to expired timestamp.
    pub fn increment_cookie_expired_rejections(&self) {
        self.cookie_expired_rejections.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increments the replay detections counter
    ///
    /// Call this when a replay attack is detected (duplicate client_random).
    pub fn increment_replay_detections(&self) {
        self.replay_detections.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increments the handshake attempts counter
    ///
    /// Call this when a ClientHello is received (before cookie verification).
    pub fn increment_handshake_attempts(&self) {
        self.handshake_attempts.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increments the handshake completions counter
    ///
    /// Call this when a handshake completes successfully.
    pub fn increment_handshake_completions(&self) {
        self.handshake_completions.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Returns the current value of cookie challenges issued
    pub fn cookie_challenges_issued(&self) -> u64 {
        self.cookie_challenges_issued.load(Ordering::Relaxed)
    }
    
    /// Returns the current value of cookie verifications succeeded
    pub fn cookie_verifications_succeeded(&self) -> u64 {
        self.cookie_verifications_succeeded.load(Ordering::Relaxed)
    }
    
    /// Returns the current value of cookie verifications failed
    pub fn cookie_verifications_failed(&self) -> u64 {
        self.cookie_verifications_failed.load(Ordering::Relaxed)
    }
    
    /// Returns the current value of cookie expired rejections
    pub fn cookie_expired_rejections(&self) -> u64 {
        self.cookie_expired_rejections.load(Ordering::Relaxed)
    }
    
    /// Returns the current value of replay detections
    pub fn replay_detections(&self) -> u64 {
        self.replay_detections.load(Ordering::Relaxed)
    }
    
    /// Returns the current value of handshake attempts
    pub fn handshake_attempts(&self) -> u64 {
        self.handshake_attempts.load(Ordering::Relaxed)
    }
    
    /// Returns the current value of handshake completions
    pub fn handshake_completions(&self) -> u64 {
        self.handshake_completions.load(Ordering::Relaxed)
    }
    
    /// Calculates the cookie success rate as a percentage (0.0 to 100.0)
    ///
    /// Returns the percentage of cookie verifications that succeeded.
    /// Returns 0.0 if no verifications have been attempted.
    ///
    /// ## Formula
    ///
    /// ```text
    /// success_rate = (succeeded / (succeeded + failed + expired)) * 100
    /// ```
    pub fn cookie_success_rate(&self) -> f64 {
        let succeeded = self.cookie_verifications_succeeded();
        let failed = self.cookie_verifications_failed();
        let expired = self.cookie_expired_rejections();
        let total = succeeded + failed + expired;
        
        if total == 0 {
            0.0
        } else {
            (succeeded as f64 / total as f64) * 100.0
        }
    }
    
    /// Calculates the handshake success rate as a percentage (0.0 to 100.0)
    ///
    /// Returns the percentage of handshake attempts that completed successfully.
    /// Returns 0.0 if no handshakes have been attempted.
    ///
    /// ## Formula
    ///
    /// ```text
    /// success_rate = (completions / attempts) * 100
    /// ```
    pub fn handshake_success_rate(&self) -> f64 {
        let attempts = self.handshake_attempts();
        let completions = self.handshake_completions();
        
        if attempts == 0 {
            0.0
        } else {
            (completions as f64 / attempts as f64) * 100.0
        }
    }
    
    /// Calculates the DoS amplification reduction factor
    ///
    /// This metric demonstrates the effectiveness of the cookie challenge in
    /// reducing the cost of invalid handshake attempts.
    ///
    /// ## Calculation
    ///
    /// ```text
    /// Without cookie challenge:
    ///   - Dilithium5 signature verification: ~3.0ms
    ///   - Kyber1024 KEM decapsulation: ~0.6ms
    ///   - Total: ~3.6ms per invalid attempt
    ///
    /// With cookie challenge:
    ///   - HMAC-SHA256 verification: ~0.01ms per invalid attempt
    ///
    /// Reduction factor = 3.6ms / 0.01ms = 360x
    /// ```
    ///
    /// ## Target
    ///
    /// The target reduction factor is 360x, meaning the cookie challenge makes
    /// DoS attacks 360 times more expensive for attackers.
    ///
    /// ## Requirements
    ///
    /// - REQ-44: DoS Mitigation (calculate amplification reduction)
    pub fn dos_amplification_reduction(&self) -> f64 {
        // Time without cookie challenge (expensive crypto operations)
        const DILITHIUM5_VERIFY_MS: f64 = 3.0;
        const KYBER1024_DECAP_MS: f64 = 0.6;
        const TIME_WITHOUT_COOKIE_MS: f64 = DILITHIUM5_VERIFY_MS + KYBER1024_DECAP_MS;
        
        // Time with cookie challenge (HMAC verification only)
        const HMAC_VERIFY_MS: f64 = 0.01;
        
        // Calculate reduction factor
        TIME_WITHOUT_COOKIE_MS / HMAC_VERIFY_MS
    }
    
    /// Creates a snapshot of all current metrics
    ///
    /// Returns a `DosMetricsSnapshot` containing all current metric values.
    /// This is useful for exporting metrics to monitoring systems or for
    /// generating reports.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use b4ae::protocol::v2::dos_metrics::DosMetrics;
    ///
    /// let metrics = DosMetrics::new();
    /// metrics.increment_cookie_challenges_issued();
    /// metrics.increment_cookie_verifications_succeeded();
    ///
    /// let snapshot = metrics.snapshot();
    /// println!("Metrics: {:#?}", snapshot);
    /// ```
    pub fn snapshot(&self) -> DosMetricsSnapshot {
        DosMetricsSnapshot {
            cookie_challenges_issued: self.cookie_challenges_issued(),
            cookie_verifications_succeeded: self.cookie_verifications_succeeded(),
            cookie_verifications_failed: self.cookie_verifications_failed(),
            cookie_expired_rejections: self.cookie_expired_rejections(),
            replay_detections: self.replay_detections(),
            handshake_attempts: self.handshake_attempts(),
            handshake_completions: self.handshake_completions(),
            cookie_success_rate: self.cookie_success_rate(),
            handshake_success_rate: self.handshake_success_rate(),
            dos_amplification_reduction: self.dos_amplification_reduction(),
        }
    }
    
    /// Resets all metrics to zero
    ///
    /// This is useful for testing or when you want to reset the metrics
    /// after a certain period.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use b4ae::protocol::v2::dos_metrics::DosMetrics;
    ///
    /// let metrics = DosMetrics::new();
    /// metrics.increment_cookie_challenges_issued();
    /// assert_eq!(metrics.cookie_challenges_issued(), 1);
    ///
    /// metrics.reset();
    /// assert_eq!(metrics.cookie_challenges_issued(), 0);
    /// ```
    pub fn reset(&self) {
        self.cookie_challenges_issued.store(0, Ordering::Relaxed);
        self.cookie_verifications_succeeded.store(0, Ordering::Relaxed);
        self.cookie_verifications_failed.store(0, Ordering::Relaxed);
        self.cookie_expired_rejections.store(0, Ordering::Relaxed);
        self.replay_detections.store(0, Ordering::Relaxed);
        self.handshake_attempts.store(0, Ordering::Relaxed);
        self.handshake_completions.store(0, Ordering::Relaxed);
    }
}

impl Default for DosMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Clone for DosMetrics (creates independent copy)
impl Clone for DosMetrics {
    fn clone(&self) -> Self {
        DosMetrics {
            cookie_challenges_issued: AtomicU64::new(self.cookie_challenges_issued()),
            cookie_verifications_succeeded: AtomicU64::new(self.cookie_verifications_succeeded()),
            cookie_verifications_failed: AtomicU64::new(self.cookie_verifications_failed()),
            cookie_expired_rejections: AtomicU64::new(self.cookie_expired_rejections()),
            replay_detections: AtomicU64::new(self.replay_detections()),
            handshake_attempts: AtomicU64::new(self.handshake_attempts()),
            handshake_completions: AtomicU64::new(self.handshake_completions()),
        }
    }
}

/// Snapshot of DoS metrics at a point in time
///
/// This structure contains a consistent snapshot of all DoS metrics,
/// including both raw counters and derived metrics.
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::dos_metrics::DosMetrics;
///
/// let metrics = DosMetrics::new();
/// let snapshot = metrics.snapshot();
///
/// println!("Cookie challenges issued: {}", snapshot.cookie_challenges_issued);
/// println!("Cookie success rate: {:.2}%", snapshot.cookie_success_rate);
/// println!("DoS amplification reduction: {:.0}x", snapshot.dos_amplification_reduction);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DosMetricsSnapshot {
    /// Total number of cookie challenges issued
    pub cookie_challenges_issued: u64,
    
    /// Number of successful cookie verifications
    pub cookie_verifications_succeeded: u64,
    
    /// Number of failed cookie verifications (invalid HMAC)
    pub cookie_verifications_failed: u64,
    
    /// Number of rejections due to expired timestamp
    pub cookie_expired_rejections: u64,
    
    /// Number of replay attacks detected
    pub replay_detections: u64,
    
    /// Total handshake attempts (ClientHello received)
    pub handshake_attempts: u64,
    
    /// Successful handshake completions
    pub handshake_completions: u64,
    
    /// Cookie success rate (percentage)
    pub cookie_success_rate: f64,
    
    /// Handshake success rate (percentage)
    pub handshake_success_rate: f64,
    
    /// DoS amplification reduction factor
    pub dos_amplification_reduction: f64,
}

impl DosMetricsSnapshot {
    /// Returns the total number of cookie verification attempts
    pub fn total_cookie_verifications(&self) -> u64 {
        self.cookie_verifications_succeeded
            + self.cookie_verifications_failed
            + self.cookie_expired_rejections
    }
    
    /// Returns the total number of cookie rejections
    pub fn total_cookie_rejections(&self) -> u64 {
        self.cookie_verifications_failed + self.cookie_expired_rejections
    }
    
    /// Returns the number of failed handshakes
    pub fn failed_handshakes(&self) -> u64 {
        if self.handshake_attempts >= self.handshake_completions {
            self.handshake_attempts - self.handshake_completions
        } else {
            0
        }
    }
}

/// Shared DoS metrics instance
///
/// This type alias provides a convenient way to share DoS metrics across
/// multiple threads using `Arc`.
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::dos_metrics::{DosMetrics, SharedDosMetrics};
/// use std::sync::Arc;
///
/// let metrics: SharedDosMetrics = Arc::new(DosMetrics::new());
/// let metrics_clone = Arc::clone(&metrics);
///
/// // Use in different threads
/// metrics.increment_cookie_challenges_issued();
/// metrics_clone.increment_cookie_verifications_succeeded();
/// ```
pub type SharedDosMetrics = Arc<DosMetrics>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_metrics() {
        let metrics = DosMetrics::new();
        
        assert_eq!(metrics.cookie_challenges_issued(), 0);
        assert_eq!(metrics.cookie_verifications_succeeded(), 0);
        assert_eq!(metrics.cookie_verifications_failed(), 0);
        assert_eq!(metrics.cookie_expired_rejections(), 0);
        assert_eq!(metrics.replay_detections(), 0);
        assert_eq!(metrics.handshake_attempts(), 0);
        assert_eq!(metrics.handshake_completions(), 0);
    }

    #[test]
    fn test_increment_cookie_challenges_issued() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_challenges_issued();
        assert_eq!(metrics.cookie_challenges_issued(), 1);
        
        metrics.increment_cookie_challenges_issued();
        assert_eq!(metrics.cookie_challenges_issued(), 2);
    }

    #[test]
    fn test_increment_cookie_verifications_succeeded() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_verifications_succeeded();
        assert_eq!(metrics.cookie_verifications_succeeded(), 1);
    }

    #[test]
    fn test_increment_cookie_verifications_failed() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_verifications_failed();
        assert_eq!(metrics.cookie_verifications_failed(), 1);
    }

    #[test]
    fn test_increment_cookie_expired_rejections() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_expired_rejections();
        assert_eq!(metrics.cookie_expired_rejections(), 1);
    }

    #[test]
    fn test_increment_replay_detections() {
        let metrics = DosMetrics::new();
        
        metrics.increment_replay_detections();
        assert_eq!(metrics.replay_detections(), 1);
    }

    #[test]
    fn test_increment_handshake_attempts() {
        let metrics = DosMetrics::new();
        
        metrics.increment_handshake_attempts();
        assert_eq!(metrics.handshake_attempts(), 1);
    }

    #[test]
    fn test_increment_handshake_completions() {
        let metrics = DosMetrics::new();
        
        metrics.increment_handshake_completions();
        assert_eq!(metrics.handshake_completions(), 1);
    }

    #[test]
    fn test_cookie_success_rate_zero_verifications() {
        let metrics = DosMetrics::new();
        
        assert_eq!(metrics.cookie_success_rate(), 0.0);
    }

    #[test]
    fn test_cookie_success_rate_all_succeeded() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_verifications_succeeded();
        metrics.increment_cookie_verifications_succeeded();
        
        assert_eq!(metrics.cookie_success_rate(), 100.0);
    }

    #[test]
    fn test_cookie_success_rate_mixed() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_verifications_succeeded();
        metrics.increment_cookie_verifications_succeeded();
        metrics.increment_cookie_verifications_failed();
        metrics.increment_cookie_expired_rejections();
        
        // 2 succeeded out of 4 total = 50%
        assert_eq!(metrics.cookie_success_rate(), 50.0);
    }

    #[test]
    fn test_handshake_success_rate_zero_attempts() {
        let metrics = DosMetrics::new();
        
        assert_eq!(metrics.handshake_success_rate(), 0.0);
    }

    #[test]
    fn test_handshake_success_rate_all_completed() {
        let metrics = DosMetrics::new();
        
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_completions();
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_completions();
        
        assert_eq!(metrics.handshake_success_rate(), 100.0);
    }

    #[test]
    fn test_handshake_success_rate_mixed() {
        let metrics = DosMetrics::new();
        
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_completions();
        
        // 1 completed out of 4 attempts = 25%
        assert_eq!(metrics.handshake_success_rate(), 25.0);
    }

    #[test]
    fn test_dos_amplification_reduction() {
        let metrics = DosMetrics::new();
        
        // Should be 360x (3.6ms / 0.01ms)
        assert_eq!(metrics.dos_amplification_reduction(), 360.0);
    }

    #[test]
    fn test_snapshot() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_challenges_issued();
        metrics.increment_cookie_verifications_succeeded();
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_completions();
        
        let snapshot = metrics.snapshot();
        
        assert_eq!(snapshot.cookie_challenges_issued, 1);
        assert_eq!(snapshot.cookie_verifications_succeeded, 1);
        assert_eq!(snapshot.handshake_attempts, 1);
        assert_eq!(snapshot.handshake_completions, 1);
        assert_eq!(snapshot.cookie_success_rate, 100.0);
        assert_eq!(snapshot.handshake_success_rate, 100.0);
        assert_eq!(snapshot.dos_amplification_reduction, 360.0);
    }

    #[test]
    fn test_snapshot_total_cookie_verifications() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_verifications_succeeded();
        metrics.increment_cookie_verifications_failed();
        metrics.increment_cookie_expired_rejections();
        
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_cookie_verifications(), 3);
    }

    #[test]
    fn test_snapshot_total_cookie_rejections() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_verifications_failed();
        metrics.increment_cookie_expired_rejections();
        
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_cookie_rejections(), 2);
    }

    #[test]
    fn test_snapshot_failed_handshakes() {
        let metrics = DosMetrics::new();
        
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_completions();
        
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.failed_handshakes(), 2);
    }

    #[test]
    fn test_reset() {
        let metrics = DosMetrics::new();
        
        metrics.increment_cookie_challenges_issued();
        metrics.increment_cookie_verifications_succeeded();
        metrics.increment_handshake_attempts();
        
        assert_eq!(metrics.cookie_challenges_issued(), 1);
        assert_eq!(metrics.cookie_verifications_succeeded(), 1);
        assert_eq!(metrics.handshake_attempts(), 1);
        
        metrics.reset();
        
        assert_eq!(metrics.cookie_challenges_issued(), 0);
        assert_eq!(metrics.cookie_verifications_succeeded(), 0);
        assert_eq!(metrics.handshake_attempts(), 0);
    }

    #[test]
    fn test_default() {
        let metrics = DosMetrics::default();
        
        assert_eq!(metrics.cookie_challenges_issued(), 0);
        assert_eq!(metrics.handshake_attempts(), 0);
    }

    #[test]
    fn test_clone() {
        let metrics1 = DosMetrics::new();
        
        metrics1.increment_cookie_challenges_issued();
        metrics1.increment_handshake_attempts();
        
        let metrics2 = metrics1.clone();
        
        // Clone should have same values
        assert_eq!(metrics2.cookie_challenges_issued(), 1);
        assert_eq!(metrics2.handshake_attempts(), 1);
        
        // But should be independent
        metrics1.increment_cookie_challenges_issued();
        assert_eq!(metrics1.cookie_challenges_issued(), 2);
        assert_eq!(metrics2.cookie_challenges_issued(), 1);
    }

    #[test]
    fn test_thread_safety() {
        let metrics = Arc::new(DosMetrics::new());
        let mut handles = vec![];
        
        // Spawn 10 threads, each incrementing counters 100 times
        for _ in 0..10 {
            let metrics_clone = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    metrics_clone.increment_cookie_challenges_issued();
                    metrics_clone.increment_handshake_attempts();
                }
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Should have 1000 increments total (10 threads * 100 increments)
        assert_eq!(metrics.cookie_challenges_issued(), 1000);
        assert_eq!(metrics.handshake_attempts(), 1000);
    }

    #[test]
    fn test_realistic_scenario() {
        let metrics = DosMetrics::new();
        
        // Simulate 100 handshake attempts
        for _ in 0..100 {
            metrics.increment_handshake_attempts();
            metrics.increment_cookie_challenges_issued();
        }
        
        // 80 valid cookies
        for _ in 0..80 {
            metrics.increment_cookie_verifications_succeeded();
        }
        
        // 10 invalid cookies
        for _ in 0..10 {
            metrics.increment_cookie_verifications_failed();
        }
        
        // 5 expired cookies
        for _ in 0..5 {
            metrics.increment_cookie_expired_rejections();
        }
        
        // 3 replay attacks
        for _ in 0..3 {
            metrics.increment_replay_detections();
        }
        
        // 75 successful handshakes (some valid cookies still fail handshake)
        for _ in 0..75 {
            metrics.increment_handshake_completions();
        }
        
        let snapshot = metrics.snapshot();
        
        assert_eq!(snapshot.cookie_challenges_issued, 100);
        assert_eq!(snapshot.total_cookie_verifications(), 95);
        assert_eq!(snapshot.cookie_success_rate, 80.0 / 95.0 * 100.0);
        assert_eq!(snapshot.replay_detections, 3);
        assert_eq!(snapshot.handshake_attempts, 100);
        assert_eq!(snapshot.handshake_completions, 75);
        assert_eq!(snapshot.handshake_success_rate, 75.0);
        assert_eq!(snapshot.dos_amplification_reduction, 360.0);
    }

    #[test]
    fn test_snapshot_clone() {
        let metrics = DosMetrics::new();
        metrics.increment_cookie_challenges_issued();
        
        let snapshot1 = metrics.snapshot();
        let snapshot2 = snapshot1.clone();
        
        assert_eq!(snapshot1, snapshot2);
    }
}
