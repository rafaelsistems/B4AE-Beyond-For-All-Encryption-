//! Cover Traffic Generator
//!
//! Generates dummy messages at a configurable rate to obfuscate real traffic patterns.
//! Dummy messages are indistinguishable from real messages when encrypted and are marked
//! internally to prevent application processing.

use std::time::Instant;
use rand::{Rng, thread_rng};

/// Cover traffic generator that creates dummy messages to hide real traffic patterns.
///
/// The generator uses a probabilistic approach to determine when to send dummy messages,
/// maintaining a target rate relative to real traffic. Dummy messages are sampled from
/// the same size distribution as real messages to ensure indistinguishability.
///
/// # Examples
///
/// ```
/// use b4ae::metadata::cover_traffic::CoverTrafficGenerator;
///
/// let mut generator = CoverTrafficGenerator::new(0.3); // 30% dummy traffic
///
/// // Check if we should send a dummy message
/// if generator.should_send_dummy() {
///     let size_distribution = vec![512, 1024, 2048, 4096];
///     let dummy = generator.generate_dummy_message(&size_distribution);
///     // Send dummy message...
/// }
/// ```
pub struct CoverTrafficGenerator {
    /// Cover traffic rate as a fraction of real traffic (0.0 to 1.0)
    rate: f64,
    /// Last time a dummy message was sent
    last_dummy_time: Instant,
}

impl CoverTrafficGenerator {
    /// Create a new cover traffic generator with the specified rate.
    ///
    /// # Arguments
    ///
    /// * `rate` - Cover traffic rate as a fraction of real traffic (0.0 to 1.0).
    ///            A value of 0.3 means approximately 30% dummy traffic relative to real traffic.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::cover_traffic::CoverTrafficGenerator;
    ///
    /// let generator = CoverTrafficGenerator::new(0.3);
    /// ```
    pub fn new(rate: f64) -> Self {
        Self {
            rate,
            last_dummy_time: Instant::now(),
        }
    }

    /// Determine whether a dummy message should be sent.
    ///
    /// Uses a probabilistic decision based on the configured cover traffic rate
    /// and the time since the last dummy message was sent. The probability increases
    /// with time to maintain the target rate.
    ///
    /// # Returns
    ///
    /// `true` if a dummy message should be sent, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::cover_traffic::CoverTrafficGenerator;
    ///
    /// let mut generator = CoverTrafficGenerator::new(0.3);
    ///
    /// if generator.should_send_dummy() {
    ///     println!("Time to send a dummy message!");
    /// }
    /// ```
    pub fn should_send_dummy(&mut self) -> bool {
        // If rate is 0, never send dummy messages
        if self.rate <= 0.0 {
            return false;
        }

        // Calculate time since last dummy message
        let time_since_last = self.last_dummy_time.elapsed().as_secs_f64();
        
        // Expected interval between dummy messages (in seconds)
        // If rate is 0.3, we want dummy messages at 30% of real traffic rate
        // This is a simplified model - in practice, this would be adjusted based on
        // observed real traffic rate
        let expected_interval = 1.0 / self.rate;
        
        // Probability increases with time since last dummy
        let probability = (time_since_last / expected_interval).min(1.0);
        
        // Generate random value for probabilistic decision
        let mut rng = thread_rng();
        let random_value: f64 = rng.gen();
        
        // Decide whether to send dummy message
        if random_value < probability {
            self.last_dummy_time = Instant::now();
            true
        } else {
            false
        }
    }

    /// Generate a dummy message with a size sampled from the provided distribution.
    ///
    /// The message consists of random bytes and is marked internally as a dummy message
    /// (first byte is 0xFF) to prevent application processing. When encrypted, dummy
    /// messages are indistinguishable from real messages.
    ///
    /// # Arguments
    ///
    /// * `size_distribution` - A slice of message sizes to sample from. The function
    ///                         randomly selects one of these sizes for the dummy message.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing random bytes with the first byte set to 0xFF as a marker.
    ///
    /// # Panics
    ///
    /// Panics if `size_distribution` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::cover_traffic::CoverTrafficGenerator;
    ///
    /// let generator = CoverTrafficGenerator::new(0.3);
    /// let size_distribution = vec![512, 1024, 2048, 4096];
    /// let dummy = generator.generate_dummy_message(&size_distribution);
    ///
    /// assert!(size_distribution.contains(&dummy.len()));
    /// assert_eq!(dummy[0], 0xFF); // Dummy marker
    /// ```
    pub fn generate_dummy_message(&self, size_distribution: &[usize]) -> Vec<u8> {
        assert!(!size_distribution.is_empty(), "size_distribution cannot be empty");
        
        let mut rng = thread_rng();
        
        // Sample size from distribution
        let size_idx = rng.gen_range(0..size_distribution.len());
        let size = size_distribution[size_idx];
        
        // Generate random bytes
        let mut dummy_message = vec![0u8; size];
        rng.fill(&mut dummy_message[..]);
        
        // Mark as dummy message (first byte = 0xFF)
        // This marker is internal and will be encrypted, making it indistinguishable
        // from real messages to external observers
        dummy_message[0] = 0xFF;
        
        dummy_message
    }

    /// Check if a message is a dummy message by examining the internal marker.
    ///
    /// This should be called after decryption to determine if the message should
    /// be processed by the application or discarded as cover traffic.
    ///
    /// # Arguments
    ///
    /// * `message` - The decrypted message to check
    ///
    /// # Returns
    ///
    /// `true` if the message is a dummy message (first byte is 0xFF), `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::cover_traffic::CoverTrafficGenerator;
    ///
    /// let generator = CoverTrafficGenerator::new(0.3);
    /// let size_distribution = vec![512];
    /// let dummy = generator.generate_dummy_message(&size_distribution);
    ///
    /// assert!(CoverTrafficGenerator::is_dummy_message(&dummy));
    ///
    /// let real_message = vec![0x00, 0x01, 0x02];
    /// assert!(!CoverTrafficGenerator::is_dummy_message(&real_message));
    /// ```
    pub fn is_dummy_message(message: &[u8]) -> bool {
        !message.is_empty() && message[0] == 0xFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_new_generator() {
        let generator = CoverTrafficGenerator::new(0.3);
        assert_eq!(generator.rate, 0.3);
    }

    #[test]
    fn test_should_send_dummy_with_zero_rate() {
        let mut generator = CoverTrafficGenerator::new(0.0);
        
        // With rate 0, should never send dummy messages
        for _ in 0..100 {
            assert!(!generator.should_send_dummy());
        }
    }

    #[test]
    fn test_should_send_dummy_probabilistic() {
        let mut generator = CoverTrafficGenerator::new(0.5);
        
        // Over many iterations, should send some dummy messages
        let mut dummy_count = 0;
        for _ in 0..1000 {
            if generator.should_send_dummy() {
                dummy_count += 1;
            }
            // Small delay to allow time to pass
            thread::sleep(Duration::from_micros(10));
        }
        
        // Should have sent at least some dummy messages (not zero)
        assert!(dummy_count > 0, "Should send some dummy messages with rate 0.5");
    }

    #[test]
    fn test_generate_dummy_message_size() {
        let generator = CoverTrafficGenerator::new(0.3);
        let size_distribution = vec![512, 1024, 2048, 4096];
        
        // Generate multiple dummy messages and verify sizes
        for _ in 0..10 {
            let dummy = generator.generate_dummy_message(&size_distribution);
            assert!(size_distribution.contains(&dummy.len()));
        }
    }

    #[test]
    fn test_generate_dummy_message_marker() {
        let generator = CoverTrafficGenerator::new(0.3);
        let size_distribution = vec![512];
        
        let dummy = generator.generate_dummy_message(&size_distribution);
        
        // First byte should be 0xFF (dummy marker)
        assert_eq!(dummy[0], 0xFF);
        assert_eq!(dummy.len(), 512);
    }

    #[test]
    fn test_generate_dummy_message_randomness() {
        let generator = CoverTrafficGenerator::new(0.3);
        let size_distribution = vec![256];
        
        // Generate two dummy messages
        let dummy1 = generator.generate_dummy_message(&size_distribution);
        let dummy2 = generator.generate_dummy_message(&size_distribution);
        
        // They should be different (except for the marker byte)
        // With 256 bytes, probability of collision is negligible
        assert_ne!(dummy1, dummy2);
    }

    #[test]
    #[should_panic(expected = "size_distribution cannot be empty")]
    fn test_generate_dummy_message_empty_distribution() {
        let generator = CoverTrafficGenerator::new(0.3);
        let size_distribution: Vec<usize> = vec![];
        
        // Should panic with empty distribution
        generator.generate_dummy_message(&size_distribution);
    }

    #[test]
    fn test_is_dummy_message_positive() {
        let generator = CoverTrafficGenerator::new(0.3);
        let size_distribution = vec![512];
        let dummy = generator.generate_dummy_message(&size_distribution);
        
        assert!(CoverTrafficGenerator::is_dummy_message(&dummy));
    }

    #[test]
    fn test_is_dummy_message_negative() {
        let real_message = vec![0x00, 0x01, 0x02, 0x03];
        assert!(!CoverTrafficGenerator::is_dummy_message(&real_message));
        
        let another_real = vec![0x42, 0x43, 0x44];
        assert!(!CoverTrafficGenerator::is_dummy_message(&another_real));
    }

    #[test]
    fn test_is_dummy_message_empty() {
        let empty_message: Vec<u8> = vec![];
        assert!(!CoverTrafficGenerator::is_dummy_message(&empty_message));
    }

    #[test]
    fn test_is_dummy_message_only_marker() {
        let marker_only = vec![0xFF];
        assert!(CoverTrafficGenerator::is_dummy_message(&marker_only));
    }

    #[test]
    fn test_multiple_size_distribution() {
        let generator = CoverTrafficGenerator::new(0.3);
        let size_distribution = vec![128, 256, 512, 1024, 2048];
        
        // Generate many messages and verify all sizes are used
        let mut size_counts = std::collections::HashMap::new();
        for _ in 0..100 {
            let dummy = generator.generate_dummy_message(&size_distribution);
            *size_counts.entry(dummy.len()).or_insert(0) += 1;
        }
        
        // Should have generated messages of multiple sizes
        assert!(size_counts.len() > 1, "Should use multiple sizes from distribution");
    }

    #[test]
    fn test_dummy_message_indistinguishability() {
        let generator = CoverTrafficGenerator::new(0.3);
        let size_distribution = vec![512];
        
        let dummy = generator.generate_dummy_message(&size_distribution);
        
        // Dummy message should look random (except for marker)
        // Check that not all bytes are the same
        let first_byte = dummy[1]; // Skip marker
        let all_same = dummy[1..].iter().all(|&b| b == first_byte);
        assert!(!all_same, "Dummy message should be random");
    }

    #[test]
    fn test_rate_affects_probability() {
        // Higher rate should lead to more dummy messages over time
        let mut high_rate_gen = CoverTrafficGenerator::new(0.8);
        let mut low_rate_gen = CoverTrafficGenerator::new(0.1);
        
        // Wait a bit to allow time to accumulate
        thread::sleep(Duration::from_millis(100));
        
        let mut high_rate_count = 0;
        let mut low_rate_count = 0;
        
        for _ in 0..100 {
            if high_rate_gen.should_send_dummy() {
                high_rate_count += 1;
            }
            if low_rate_gen.should_send_dummy() {
                low_rate_count += 1;
            }
            thread::sleep(Duration::from_micros(10));
        }
        
        // High rate should generally produce more dummy messages
        // (This is probabilistic, so we use a loose check)
        assert!(high_rate_count >= low_rate_count, 
                "High rate ({}) should produce at least as many dummies as low rate ({})",
                high_rate_count, low_rate_count);
    }
}
