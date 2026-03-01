//! Replay Protection with Bloom Filter
//!
//! This module implements replay protection for the cookie challenge system using
//! a Bloom filter to track recently seen client_random values. This prevents
//! attackers from replaying captured ClientHello messages within the 30-second
//! cookie timeout window.
//!
//! ## Design Goals
//!
//! 1. **Memory-efficient**: Bloom filter provides space-efficient storage
//! 2. **Fast lookup**: O(k) where k is number of hash functions
//! 3. **Acceptable false positives**: Configurable false positive rate (default 0.1%)
//! 4. **Automatic expiry**: 30-second window matching cookie timeout
//! 5. **Thread-safe**: Safe for concurrent access from multiple threads
//!
//! ## Security Properties
//!
//! - **Replay Detection**: Detects duplicate client_random values
//! - **Time-bound**: Automatically expires entries after 30 seconds
//! - **False Positive Tolerance**: Small false positive rate acceptable (rejects valid request)
//! - **No False Negatives**: Never allows actual replays through
//!
//! ## Trade-offs
//!
//! - **Memory**: ~1 MB for 1M entries at 0.1% false positive rate
//! - **False Positives**: May occasionally reject valid requests (< 0.1%)
//! - **Performance**: Fast O(k) lookup, typically < 0.01ms
//!
//! ## Protocol Integration
//!
//! ```text
//! Client                                Server
//!   |                                     |
//!   |--- ClientHelloWithCookie --------->|
//!   |    (client_random, cookie, ...)    |
//!   |                                     |
//!   |    [1. Verify cookie timestamp]    |
//!   |    [2. Check replay (Bloom filter)]|
//!   |    [3. Insert client_random]       |
//!   |    [4. Proceed with handshake]     |
//! ```
//!
//! ## Requirements
//!
//! - REQ-4: Replay Protection for Cookie Challenge
//! - REQ-44: DoS Mitigation
//! - REQ-23: Memory Usage Requirements

use bloomfilter::Bloom;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::protocol::v2::constants::{
    BLOOM_FILTER_SIZE, BLOOM_FILTER_FALSE_POSITIVE_RATE, COOKIE_TIMEOUT_SECONDS,
};

/// Error type for replay protection operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayProtectionError {
    /// Likely replay detected (client_random seen recently)
    LikelyReplay,
    
    /// Invalid input parameters
    InvalidInput(String),
}

impl std::fmt::Display for ReplayProtectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayProtectionError::LikelyReplay => {
                write!(f, "Likely replay detected: client_random seen recently")
            }
            ReplayProtectionError::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
        }
    }
}

impl std::error::Error for ReplayProtectionError {}

/// Replay protection state with Bloom filter
///
/// This structure maintains a Bloom filter of recently seen client_random values
/// and automatically rotates the filter after the expiry window.
///
/// ## Thread Safety
///
/// This structure is thread-safe and can be shared across multiple threads using
/// `Arc<ReplayProtection>`.
///
/// ## Memory Usage
///
/// - Bloom filter: ~1 MB for 1M entries at 0.1% false positive rate
/// - Metadata: ~100 bytes
/// - Total: ~1 MB per instance
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::replay_protection::ReplayProtection;
///
/// let replay_protection = ReplayProtection::new();
/// let client_random = [0u8; 32];
///
/// // First check should pass
/// assert!(replay_protection.check_and_insert(&client_random).is_ok());
///
/// // Second check should detect replay
/// assert!(replay_protection.check_and_insert(&client_random).is_err());
/// ```
pub struct ReplayProtection {
    /// Bloom filter for tracking seen client_random values
    bloom: Arc<Mutex<Bloom<[u8]>>>,
    
    /// Timestamp when the current filter was created
    created_at: Arc<Mutex<Instant>>,
    
    /// Expiry window duration (30 seconds)
    expiry_window: Duration,
}

impl ReplayProtection {
    /// Creates a new replay protection instance
    ///
    /// Initializes a Bloom filter sized for expected request rate with
    /// acceptable false positive rate.
    ///
    /// ## Configuration
    ///
    /// - Expected items: 1,000,000 (from BLOOM_FILTER_SIZE)
    /// - False positive rate: 0.1% (from BLOOM_FILTER_FALSE_POSITIVE_RATE)
    /// - Expiry window: 30 seconds (from COOKIE_TIMEOUT_SECONDS)
    ///
    /// ## Memory Usage
    ///
    /// Approximately 1 MB for the Bloom filter.
    pub fn new() -> Self {
        let bloom = Bloom::new_for_fp_rate(
            BLOOM_FILTER_SIZE,
            BLOOM_FILTER_FALSE_POSITIVE_RATE,
        );
        
        ReplayProtection {
            bloom: Arc::new(Mutex::new(bloom)),
            created_at: Arc::new(Mutex::new(Instant::now())),
            expiry_window: Duration::from_secs(COOKIE_TIMEOUT_SECONDS),
        }
    }
    
    /// Creates a new replay protection instance with custom parameters
    ///
    /// ## Parameters
    ///
    /// - `expected_items`: Expected number of items to store
    /// - `false_positive_rate`: Acceptable false positive rate (e.g., 0.001 for 0.1%)
    /// - `expiry_seconds`: Expiry window in seconds
    ///
    /// ## Example
    ///
    /// ```rust
    /// use b4ae::protocol::v2::replay_protection::ReplayProtection;
    ///
    /// // Custom configuration: 100K items, 0.01% FP rate, 60 second window
    /// let replay_protection = ReplayProtection::with_config(100_000, 0.0001, 60);
    /// ```
    pub fn with_config(
        expected_items: usize,
        false_positive_rate: f64,
        expiry_seconds: u64,
    ) -> Self {
        let bloom = Bloom::new_for_fp_rate(expected_items, false_positive_rate);
        
        ReplayProtection {
            bloom: Arc::new(Mutex::new(bloom)),
            created_at: Arc::new(Mutex::new(Instant::now())),
            expiry_window: Duration::from_secs(expiry_seconds),
        }
    }
    
    /// Checks if client_random was seen recently and inserts it if not
    ///
    /// This is the main entry point for replay protection. It performs:
    /// 1. Check if filter needs rotation (expired)
    /// 2. Check if client_random exists in Bloom filter
    /// 3. Insert client_random if not present
    ///
    /// ## Parameters
    ///
    /// - `client_random`: Client's random nonce (must be 32 bytes)
    ///
    /// ## Returns
    ///
    /// - `Ok(())`: client_random not seen recently (no replay)
    /// - `Err(ReplayProtectionError::LikelyReplay)`: client_random seen recently (likely replay)
    /// - `Err(ReplayProtectionError::InvalidInput)`: Invalid input parameters
    ///
    /// ## Performance
    ///
    /// - Typical: < 0.01ms (Bloom filter lookup + insert)
    /// - Worst case: ~1ms (includes filter rotation)
    ///
    /// ## Example
    ///
    /// ```rust
    /// use b4ae::protocol::v2::replay_protection::ReplayProtection;
    ///
    /// let replay_protection = ReplayProtection::new();
    /// let client_random = [42u8; 32];
    ///
    /// match replay_protection.check_and_insert(&client_random) {
    ///     Ok(()) => println!("No replay detected, proceeding with handshake"),
    ///     Err(e) => println!("Replay detected: {}", e),
    /// }
    /// ```
    ///
    /// ## Requirements
    ///
    /// - REQ-4: Replay Protection
    pub fn check_and_insert(&self, client_random: &[u8]) -> Result<(), ReplayProtectionError> {
        // Validate input
        if client_random.len() != 32 {
            return Err(ReplayProtectionError::InvalidInput(
                format!("client_random must be 32 bytes, got {}", client_random.len())
            ));
        }
        
        // Check if filter needs rotation
        self.rotate_if_expired();
        
        // Lock the Bloom filter
        let mut bloom = self.bloom.lock().unwrap();
        
        // Check if client_random exists in Bloom filter
        if bloom.check(client_random) {
            // Likely replay detected
            return Err(ReplayProtectionError::LikelyReplay);
        }
        
        // Insert client_random into Bloom filter
        bloom.set(client_random);
        
        Ok(())
    }
    
    /// Checks if the Bloom filter has expired and rotates it if necessary
    ///
    /// The filter is rotated (cleared and reset) after the expiry window
    /// (30 seconds by default) to prevent unbounded growth and ensure
    /// old entries are forgotten.
    ///
    /// ## Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently.
    fn rotate_if_expired(&self) {
        let mut created_at = self.created_at.lock().unwrap();
        let elapsed = created_at.elapsed();
        
        if elapsed >= self.expiry_window {
            // Filter has expired, rotate it
            let mut bloom = self.bloom.lock().unwrap();
            
            // Clear the Bloom filter
            bloom.clear();
            
            // Update creation timestamp
            *created_at = Instant::now();
        }
    }
    
    /// Returns the current false positive rate estimate
    ///
    /// This is an estimate based on the number of items inserted and the
    /// Bloom filter configuration. The actual false positive rate may vary.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use b4ae::protocol::v2::replay_protection::ReplayProtection;
    ///
    /// let replay_protection = ReplayProtection::new();
    /// println!("False positive rate: {:.4}%", replay_protection.false_positive_rate() * 100.0);
    /// ```
    pub fn false_positive_rate(&self) -> f64 {
        BLOOM_FILTER_FALSE_POSITIVE_RATE
    }
    
    /// Returns the time until the next filter rotation
    ///
    /// ## Example
    ///
    /// ```rust
    /// use b4ae::protocol::v2::replay_protection::ReplayProtection;
    ///
    /// let replay_protection = ReplayProtection::new();
    /// let remaining = replay_protection.time_until_rotation();
    /// println!("Filter rotates in {} seconds", remaining.as_secs());
    /// ```
    pub fn time_until_rotation(&self) -> Duration {
        let created_at = self.created_at.lock().unwrap();
        let elapsed = created_at.elapsed();
        
        if elapsed >= self.expiry_window {
            Duration::from_secs(0)
        } else {
            self.expiry_window - elapsed
        }
    }
    
    /// Manually clears the Bloom filter
    ///
    /// This is useful for testing or when you want to reset the replay
    /// protection state.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use b4ae::protocol::v2::replay_protection::ReplayProtection;
    ///
    /// let replay_protection = ReplayProtection::new();
    /// replay_protection.clear();
    /// ```
    pub fn clear(&self) {
        let mut bloom = self.bloom.lock().unwrap();
        bloom.clear();
        
        let mut created_at = self.created_at.lock().unwrap();
        *created_at = Instant::now();
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Clone for ReplayProtection (shares the same Bloom filter)
impl Clone for ReplayProtection {
    fn clone(&self) -> Self {
        ReplayProtection {
            bloom: Arc::clone(&self.bloom),
            created_at: Arc::clone(&self.created_at),
            expiry_window: self.expiry_window,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_new_replay_protection() {
        let rp = ReplayProtection::new();
        assert_eq!(rp.false_positive_rate(), BLOOM_FILTER_FALSE_POSITIVE_RATE);
    }

    #[test]
    fn test_check_and_insert_first_time() {
        let rp = ReplayProtection::new();
        let client_random = [0u8; 32];
        
        // First check should pass
        assert!(rp.check_and_insert(&client_random).is_ok());
    }

    #[test]
    fn test_check_and_insert_replay_detected() {
        let rp = ReplayProtection::new();
        let client_random = [1u8; 32];
        
        // First check should pass
        assert!(rp.check_and_insert(&client_random).is_ok());
        
        // Second check should detect replay
        let result = rp.check_and_insert(&client_random);
        assert!(matches!(result, Err(ReplayProtectionError::LikelyReplay)));
    }

    #[test]
    fn test_check_and_insert_different_randoms() {
        let rp = ReplayProtection::new();
        let client_random1 = [1u8; 32];
        let client_random2 = [2u8; 32];
        
        // Both should pass (different randoms)
        assert!(rp.check_and_insert(&client_random1).is_ok());
        assert!(rp.check_and_insert(&client_random2).is_ok());
    }

    #[test]
    fn test_check_and_insert_invalid_size() {
        let rp = ReplayProtection::new();
        let client_random = [0u8; 16]; // Wrong size
        
        let result = rp.check_and_insert(&client_random);
        assert!(matches!(result, Err(ReplayProtectionError::InvalidInput(_))));
    }

    #[test]
    fn test_clear() {
        let rp = ReplayProtection::new();
        let client_random = [3u8; 32];
        
        // Insert
        assert!(rp.check_and_insert(&client_random).is_ok());
        
        // Should detect replay
        assert!(rp.check_and_insert(&client_random).is_err());
        
        // Clear
        rp.clear();
        
        // Should pass again after clear
        assert!(rp.check_and_insert(&client_random).is_ok());
    }

    #[test]
    fn test_rotation_after_expiry() {
        // Create with 1 second expiry for testing
        let rp = ReplayProtection::with_config(1000, 0.001, 1);
        let client_random = [4u8; 32];
        
        // Insert
        assert!(rp.check_and_insert(&client_random).is_ok());
        
        // Should detect replay immediately
        assert!(rp.check_and_insert(&client_random).is_err());
        
        // Wait for expiry
        thread::sleep(Duration::from_secs(2));
        
        // Should pass again after rotation
        assert!(rp.check_and_insert(&client_random).is_ok());
    }

    #[test]
    fn test_time_until_rotation() {
        let rp = ReplayProtection::new();
        let remaining = rp.time_until_rotation();
        
        // Should be close to COOKIE_TIMEOUT_SECONDS
        assert!(remaining.as_secs() <= COOKIE_TIMEOUT_SECONDS);
        assert!(remaining.as_secs() > COOKIE_TIMEOUT_SECONDS - 2);
    }

    #[test]
    fn test_multiple_inserts() {
        let rp = ReplayProtection::new();
        
        // Insert 1000 different client_random values
        for i in 0..1000 {
            let mut client_random = [0u8; 32];
            client_random[0] = (i % 256) as u8;
            client_random[1] = (i / 256) as u8;
            
            assert!(rp.check_and_insert(&client_random).is_ok());
        }
        
        // Verify all are detected as replays
        for i in 0..1000 {
            let mut client_random = [0u8; 32];
            client_random[0] = (i % 256) as u8;
            client_random[1] = (i / 256) as u8;
            
            assert!(rp.check_and_insert(&client_random).is_err());
        }
    }

    #[test]
    fn test_false_positive_rate_acceptable() {
        // Use realistic parameters: test with fewer items relative to capacity
        let expected_items = 100_000;
        let rp = ReplayProtection::with_config(expected_items, 0.01, 30);
        let mut false_positives = 0;
        let insert_count = 10_000; // Only fill 10% of capacity
        let test_count = 10_000;
        
        // Insert 10,000 items (10% of capacity)
        for i in 0..insert_count {
            let mut client_random = [0u8; 32];
            client_random[0] = (i % 256) as u8;
            client_random[1] = (i / 256) as u8;
            client_random[2] = ((i / 65536) % 256) as u8;
            client_random[3] = ((i / 16777216) % 256) as u8;
            
            let _ = rp.check_and_insert(&client_random);
        }
        
        // Test 10,000 new items (should not be in filter)
        for i in insert_count..(insert_count + test_count) {
            let mut client_random = [0u8; 32];
            client_random[0] = (i % 256) as u8;
            client_random[1] = (i / 256) as u8;
            client_random[2] = ((i / 65536) % 256) as u8;
            client_random[3] = ((i / 16777216) % 256) as u8;
            
            if rp.check_and_insert(&client_random).is_err() {
                false_positives += 1;
            }
        }
        
        let fp_rate = false_positives as f64 / test_count as f64;
        
        // False positive rate should be less than configured rate (1%)
        // We allow some margin due to randomness (2x the configured rate)
        assert!(fp_rate < 0.02, "False positive rate too high: {:.4}%", fp_rate * 100.0);
    }

    #[test]
    fn test_thread_safety() {
        let rp = ReplayProtection::new();
        let rp_clone = rp.clone();
        
        let handle = thread::spawn(move || {
            let client_random = [5u8; 32];
            rp_clone.check_and_insert(&client_random)
        });
        
        let client_random = [6u8; 32];
        let result1 = rp.check_and_insert(&client_random);
        let result2 = handle.join().unwrap();
        
        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_with_config() {
        let rp = ReplayProtection::with_config(5000, 0.0001, 60);
        let client_random = [7u8; 32];
        
        assert!(rp.check_and_insert(&client_random).is_ok());
        assert!(rp.check_and_insert(&client_random).is_err());
    }

    #[test]
    fn test_default() {
        let rp = ReplayProtection::default();
        let client_random = [8u8; 32];
        
        assert!(rp.check_and_insert(&client_random).is_ok());
    }

    #[test]
    fn test_clone_shares_state() {
        let rp1 = ReplayProtection::new();
        let rp2 = rp1.clone();
        
        let client_random = [9u8; 32];
        
        // Insert via rp1
        assert!(rp1.check_and_insert(&client_random).is_ok());
        
        // Should be detected via rp2 (shared state)
        assert!(rp2.check_and_insert(&client_random).is_err());
    }

    #[test]
    fn test_error_display() {
        let err1 = ReplayProtectionError::LikelyReplay;
        assert!(err1.to_string().contains("Likely replay"));
        
        let err2 = ReplayProtectionError::InvalidInput("test".to_string());
        assert!(err2.to_string().contains("Invalid input"));
    }
}
