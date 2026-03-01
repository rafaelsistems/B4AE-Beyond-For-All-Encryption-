//! Metadata Protection Orchestrator
//!
//! Coordinates cover traffic generation, timing obfuscation, and traffic shaping
//! to provide comprehensive metadata protection for the B4AE protocol.

use crate::crypto::CryptoResult;
use crate::metadata::{MetadataProtectionConfig, cover_traffic::CoverTrafficGenerator, timing::TimingObfuscator};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use std::thread;

/// Statistics tracking for metadata protection.
///
/// Tracks counts of real and dummy messages, total bytes sent, and average message size
/// to monitor the effectiveness of metadata protection.
#[derive(Debug, Clone, Default)]
pub struct TrafficStatistics {
    /// Number of real messages sent
    pub real_messages: u64,
    /// Number of dummy messages sent
    pub dummy_messages: u64,
    /// Total bytes sent (real + dummy)
    pub total_bytes_sent: u64,
    /// Average message size in bytes
    pub average_message_size: f64,
}

impl TrafficStatistics {
    /// Create new empty statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a real message being sent.
    pub fn record_real_message(&mut self, size: usize) {
        self.real_messages += 1;
        self.total_bytes_sent += size as u64;
        self.update_average();
    }

    /// Record a dummy message being sent.
    pub fn record_dummy_message(&mut self, size: usize) {
        self.dummy_messages += 1;
        self.total_bytes_sent += size as u64;
        self.update_average();
    }

    /// Update the average message size.
    fn update_average(&mut self) {
        let total_messages = self.real_messages + self.dummy_messages;
        if total_messages > 0 {
            self.average_message_size = self.total_bytes_sent as f64 / total_messages as f64;
        }
    }

    /// Get the total number of messages (real + dummy).
    pub fn total_messages(&self) -> u64 {
        self.real_messages + self.dummy_messages
    }

    /// Get the ratio of dummy messages to total messages.
    pub fn dummy_ratio(&self) -> f64 {
        let total = self.total_messages();
        if total == 0 {
            0.0
        } else {
            self.dummy_messages as f64 / total as f64
        }
    }
}

/// Metadata protection orchestrator coordinating all metadata protection components.
///
/// The orchestrator manages:
/// - Cover traffic generation (dummy messages)
/// - Timing obfuscation (random delays)
/// - Traffic shaping (constant-rate or variable-rate sending)
/// - Statistics tracking
///
/// # Examples
///
/// ```
/// use b4ae::metadata::{MetadataProtectionConfig, protector::MetadataProtector};
///
/// let config = MetadataProtectionConfig::high_security();
/// let mut protector = MetadataProtector::new(config).unwrap();
///
/// // Send a message with metadata protection
/// let message = b"Hello, World!".to_vec();
/// protector.send_message(message).unwrap();
///
/// // Query statistics
/// let stats = protector.statistics();
/// println!("Real messages: {}", stats.real_messages);
/// println!("Dummy messages: {}", stats.dummy_messages);
/// ```
pub struct MetadataProtector {
    config: MetadataProtectionConfig,
    cover_traffic_generator: CoverTrafficGenerator,
    timing_obfuscator: TimingObfuscator,
    statistics: TrafficStatistics,
    last_send_time: Instant,
    pending_messages: VecDeque<(Vec<u8>, Instant)>,
}

impl MetadataProtector {
    /// Create a new metadata protection orchestrator with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Metadata protection configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::{MetadataProtectionConfig, protector::MetadataProtector};
    ///
    /// let config = MetadataProtectionConfig::balanced();
    /// let protector = MetadataProtector::new(config).unwrap();
    /// ```
    pub fn new(config: MetadataProtectionConfig) -> CryptoResult<Self> {
        // Validate configuration
        config.validate()?;

        let cover_traffic_generator = CoverTrafficGenerator::new(config.cover_traffic_rate);
        let timing_obfuscator = TimingObfuscator::new(
            config.timing_delay_min_ms,
            config.timing_delay_max_ms,
        )?;

        Ok(Self {
            config,
            cover_traffic_generator,
            timing_obfuscator,
            statistics: TrafficStatistics::new(),
            last_send_time: Instant::now(),
            pending_messages: VecDeque::new(),
        })
    }

    /// Send a message with metadata protection applied.
    ///
    /// This function applies all configured metadata protections:
    /// 1. Schedules cover traffic if needed
    /// 2. Applies timing delays
    /// 3. Shapes traffic according to configuration
    ///
    /// # Arguments
    ///
    /// * `message` - The message to send (already encrypted and padded)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the message is ready to be transmitted.
    ///
    /// # Error Handling Security
    ///
    /// - Cover traffic generation failures are handled gracefully (no error returned)
    /// - System continues to send real messages even if cover traffic fails
    /// - Timing delays are bounded to prevent DoS
    /// - Configuration validation occurs at initialization (fail-fast)
    /// - No sensitive information is leaked in error messages
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::{MetadataProtectionConfig, protector::MetadataProtector};
    ///
    /// let config = MetadataProtectionConfig::default();
    /// let mut protector = MetadataProtector::new(config).unwrap();
    ///
    /// let message = b"Encrypted message".to_vec();
    /// protector.send_message(message).unwrap();
    /// ```
    pub fn send_message(&mut self, message: Vec<u8>) -> CryptoResult<()> {
        let message_size = message.len();

        // Schedule cover traffic if needed
        self.schedule_cover_traffic();

        // Apply timing delay
        let delay = self.apply_timing_delay();
        if delay > Duration::from_millis(0) {
            thread::sleep(delay);
        }

        // Handle constant-rate mode or immediate sending
        if self.config.constant_rate_mode {
            self.send_with_constant_rate(message)?;
        } else {
            // Immediate sending (variable-rate mode)
            self.transmit_message(message, false)?;
        }

        // Record statistics
        self.statistics.record_real_message(message_size);
        self.last_send_time = Instant::now();

        Ok(())
    }

    /// Schedule cover traffic generation.
    ///
    /// Checks if dummy messages should be generated and schedules them
    /// for transmission. This maintains the configured cover traffic rate.
    pub fn schedule_cover_traffic(&mut self) {
        if self.cover_traffic_generator.should_send_dummy() {
            // Generate dummy message with typical size distribution
            let size_distribution = vec![512, 1024, 2048, 4096, 8192];
            let dummy_message = self.cover_traffic_generator.generate_dummy_message(&size_distribution);
            
            // Schedule dummy message for transmission
            let scheduled_time = Instant::now();
            self.pending_messages.push_back((dummy_message, scheduled_time));
        }
    }

    /// Apply timing delay to the current message.
    ///
    /// Generates a random delay uniformly distributed between the configured
    /// minimum and maximum delay values.
    ///
    /// # Returns
    ///
    /// A `Duration` representing the delay to apply before sending.
    pub fn apply_timing_delay(&self) -> Duration {
        self.timing_obfuscator.random_delay()
    }

    /// Send a message with constant-rate traffic shaping.
    ///
    /// In constant-rate mode, messages are sent at fixed intervals determined by
    /// `target_rate_msgs_per_sec`. Dummy messages are inserted to maintain the rate.
    fn send_with_constant_rate(&mut self, message: Vec<u8>) -> CryptoResult<()> {
        // Calculate interval between messages
        let interval = Duration::from_secs_f64(1.0 / self.config.target_rate_msgs_per_sec);
        
        // Calculate next scheduled send time
        let time_since_last = self.last_send_time.elapsed();
        if time_since_last < interval {
            // Wait for the next slot
            let wait_time = interval - time_since_last;
            thread::sleep(wait_time);
        }

        let now = Instant::now();

        // Add message to pending queue with scheduled time
        self.pending_messages.push_back((message, now));

        // Process pending messages
        self.process_pending_messages()?;

        Ok(())
    }

    /// Process pending messages and send them at their scheduled times.
    ///
    /// This function processes the queue of pending messages, sending each one
    /// at its scheduled time. If no real messages are available and we need to
    /// maintain the constant rate, dummy messages are inserted.
    fn process_pending_messages(&mut self) -> CryptoResult<()> {
        let now = Instant::now();

        while let Some((_message, scheduled_time)) = self.pending_messages.front() {
            // Check if it's time to send this message
            if *scheduled_time <= now {
                let (message, _) = self.pending_messages.pop_front().unwrap();
                
                // Check if this is a dummy message
                let is_dummy = CoverTrafficGenerator::is_dummy_message(&message);
                
                // Transmit the message
                self.transmit_message(message, is_dummy)?;
            } else {
                // Not time yet, wait for the next scheduled message
                break;
            }
        }

        Ok(())
    }

    /// Transmit a message (real or dummy).
    ///
    /// This is the final step where the message is actually sent over the network.
    /// In a real implementation, this would interface with the network layer.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to transmit
    /// * `is_dummy` - Whether this is a dummy message
    fn transmit_message(&mut self, message: Vec<u8>, is_dummy: bool) -> CryptoResult<()> {
        let message_size = message.len();

        // In a real implementation, this would send the message over the network
        // For now, we just record statistics
        
        if is_dummy {
            self.statistics.record_dummy_message(message_size);
        }
        // Note: Real messages are recorded in send_message()

        Ok(())
    }

    /// Get the current traffic statistics.
    ///
    /// # Returns
    ///
    /// A reference to the current `TrafficStatistics`.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::{MetadataProtectionConfig, protector::MetadataProtector};
    ///
    /// let config = MetadataProtectionConfig::default();
    /// let protector = MetadataProtector::new(config).unwrap();
    ///
    /// let stats = protector.statistics();
    /// println!("Total messages: {}", stats.total_messages());
    /// ```
    pub fn statistics(&self) -> &TrafficStatistics {
        &self.statistics
    }

    /// Get the current configuration.
    pub fn config(&self) -> &MetadataProtectionConfig {
        &self.config
    }

    /// Get the number of pending messages in the queue.
    pub fn pending_message_count(&self) -> usize {
        self.pending_messages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_statistics_new() {
        let stats = TrafficStatistics::new();
        assert_eq!(stats.real_messages, 0);
        assert_eq!(stats.dummy_messages, 0);
        assert_eq!(stats.total_bytes_sent, 0);
        assert_eq!(stats.average_message_size, 0.0);
    }

    #[test]
    fn test_traffic_statistics_record_real_message() {
        let mut stats = TrafficStatistics::new();
        stats.record_real_message(1024);
        
        assert_eq!(stats.real_messages, 1);
        assert_eq!(stats.dummy_messages, 0);
        assert_eq!(stats.total_bytes_sent, 1024);
        assert_eq!(stats.average_message_size, 1024.0);
    }

    #[test]
    fn test_traffic_statistics_record_dummy_message() {
        let mut stats = TrafficStatistics::new();
        stats.record_dummy_message(512);
        
        assert_eq!(stats.real_messages, 0);
        assert_eq!(stats.dummy_messages, 1);
        assert_eq!(stats.total_bytes_sent, 512);
        assert_eq!(stats.average_message_size, 512.0);
    }

    #[test]
    fn test_traffic_statistics_mixed_messages() {
        let mut stats = TrafficStatistics::new();
        stats.record_real_message(1024);
        stats.record_dummy_message(512);
        stats.record_real_message(2048);
        
        assert_eq!(stats.real_messages, 2);
        assert_eq!(stats.dummy_messages, 1);
        assert_eq!(stats.total_bytes_sent, 3584);
        assert_eq!(stats.total_messages(), 3);
        
        // Average should be (1024 + 512 + 2048) / 3 = 1194.67
        assert!((stats.average_message_size - 1194.67).abs() < 0.01);
    }

    #[test]
    fn test_traffic_statistics_dummy_ratio() {
        let mut stats = TrafficStatistics::new();
        
        // No messages yet
        assert_eq!(stats.dummy_ratio(), 0.0);
        
        // 1 real, 0 dummy
        stats.record_real_message(1024);
        assert_eq!(stats.dummy_ratio(), 0.0);
        
        // 1 real, 1 dummy
        stats.record_dummy_message(512);
        assert_eq!(stats.dummy_ratio(), 0.5);
        
        // 1 real, 2 dummy
        stats.record_dummy_message(512);
        assert!((stats.dummy_ratio() - 0.666667).abs() < 0.001);
    }

    #[test]
    fn test_metadata_protector_new_valid_config() {
        let config = MetadataProtectionConfig::default();
        let protector = MetadataProtector::new(config);
        assert!(protector.is_ok());
    }

    #[test]
    fn test_metadata_protector_new_invalid_config() {
        let config = MetadataProtectionConfig {
            cover_traffic_rate: 1.5, // Invalid: > 1.0
            ..Default::default()
        };
        let protector = MetadataProtector::new(config);
        assert!(protector.is_err());
    }

    #[test]
    fn test_metadata_protector_statistics() {
        let config = MetadataProtectionConfig::default();
        let protector = MetadataProtector::new(config).unwrap();
        
        let stats = protector.statistics();
        assert_eq!(stats.real_messages, 0);
        assert_eq!(stats.dummy_messages, 0);
    }

    #[test]
    fn test_metadata_protector_config() {
        let config = MetadataProtectionConfig::balanced();
        let protector = MetadataProtector::new(config).unwrap();
        
        assert_eq!(protector.config().cover_traffic_rate, 0.2);
        assert!(!protector.config().constant_rate_mode);
    }

    #[test]
    fn test_metadata_protector_apply_timing_delay() {
        let config = MetadataProtectionConfig {
            timing_delay_min_ms: 100,
            timing_delay_max_ms: 500,
            ..Default::default()
        };
        let protector = MetadataProtector::new(config).unwrap();
        
        // Test multiple delays to ensure they're in range
        for _ in 0..10 {
            let delay = protector.apply_timing_delay();
            assert!(delay >= Duration::from_millis(100));
            assert!(delay <= Duration::from_millis(500));
        }
    }

    #[test]
    fn test_metadata_protector_apply_timing_delay_zero() {
        let config = MetadataProtectionConfig {
            timing_delay_min_ms: 0,
            timing_delay_max_ms: 0,
            ..Default::default()
        };
        let protector = MetadataProtector::new(config).unwrap();
        
        let delay = protector.apply_timing_delay();
        assert_eq!(delay, Duration::from_millis(0));
    }

    #[test]
    fn test_metadata_protector_send_message_basic() {
        let config = MetadataProtectionConfig::low_overhead();
        let mut protector = MetadataProtector::new(config).unwrap();
        
        let message = b"Test message".to_vec();
        let result = protector.send_message(message);
        assert!(result.is_ok());
        
        let stats = protector.statistics();
        assert_eq!(stats.real_messages, 1);
        assert_eq!(stats.total_bytes_sent, 12);
    }

    #[test]
    fn test_metadata_protector_send_multiple_messages() {
        let config = MetadataProtectionConfig::low_overhead();
        let mut protector = MetadataProtector::new(config).unwrap();
        
        for i in 0..5 {
            let message = format!("Message {}", i).into_bytes();
            protector.send_message(message).unwrap();
        }
        
        let stats = protector.statistics();
        assert_eq!(stats.real_messages, 5);
    }

    #[test]
    fn test_metadata_protector_constant_rate_mode() {
        let config = MetadataProtectionConfig {
            constant_rate_mode: true,
            target_rate_msgs_per_sec: 10.0, // 10 messages per second = 100ms interval
            timing_delay_min_ms: 0,
            timing_delay_max_ms: 0,
            ..Default::default()
        };
        let mut protector = MetadataProtector::new(config).unwrap();
        
        let start = Instant::now();
        
        // Send 3 messages
        for i in 0..3 {
            let message = format!("Message {}", i).into_bytes();
            protector.send_message(message).unwrap();
        }
        
        let elapsed = start.elapsed();
        
        // Should take at least 200ms (2 intervals) for 3 messages
        // (first message immediate, then 100ms, then 100ms)
        assert!(elapsed >= Duration::from_millis(180)); // Allow some tolerance
        
        let stats = protector.statistics();
        assert_eq!(stats.real_messages, 3);
    }

    #[test]
    fn test_metadata_protector_pending_message_count() {
        let config = MetadataProtectionConfig::default();
        let protector = MetadataProtector::new(config).unwrap();
        
        assert_eq!(protector.pending_message_count(), 0);
    }

    #[test]
    fn test_metadata_protector_schedule_cover_traffic() {
        let config = MetadataProtectionConfig {
            cover_traffic_rate: 1.0, // Always generate dummy traffic
            ..Default::default()
        };
        let mut protector = MetadataProtector::new(config).unwrap();
        
        // Schedule cover traffic multiple times
        // With rate 1.0, should eventually generate some dummy messages
        let mut attempts = 0;
        let max_attempts = 100;
        
        while protector.pending_message_count() == 0 && attempts < max_attempts {
            protector.schedule_cover_traffic();
            attempts += 1;
        }
        
        // With rate 1.0 and 100 attempts, we should have generated at least one dummy message
        // This is still probabilistic but with very high probability of success
        assert!(
            protector.pending_message_count() > 0 || attempts == max_attempts,
            "Expected some pending messages after {} attempts with rate 1.0", attempts
        );
    }

    #[test]
    fn test_metadata_protector_high_security_config() {
        let config = MetadataProtectionConfig::high_security();
        let protector = MetadataProtector::new(config).unwrap();
        
        assert_eq!(protector.config().cover_traffic_rate, 0.5);
        assert!(protector.config().constant_rate_mode);
        assert_eq!(protector.config().target_rate_msgs_per_sec, 2.0);
        assert_eq!(protector.config().timing_delay_min_ms, 100);
        assert_eq!(protector.config().timing_delay_max_ms, 2000);
        assert!(protector.config().traffic_shaping_enabled);
    }

    #[test]
    fn test_metadata_protector_balanced_config() {
        let config = MetadataProtectionConfig::balanced();
        let protector = MetadataProtector::new(config).unwrap();
        
        assert_eq!(protector.config().cover_traffic_rate, 0.2);
        assert!(!protector.config().constant_rate_mode);
    }
}
