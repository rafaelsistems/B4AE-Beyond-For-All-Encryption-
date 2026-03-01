//! B4AE Metadata Protection Module
//!
//! Padding, timing obfuscation, dummy traffic for traffic analysis resistance.

/// PKCS#7 and random padding.
pub mod padding;
/// Timing delay strategies.
pub mod timing;
/// Dummy traffic and pattern obfuscation.
pub mod obfuscation;
/// Cover traffic generator for metadata protection.
pub mod cover_traffic;
/// Metadata protection orchestrator coordinating all components.
pub mod protector;

use crate::error::{B4aeError, B4aeResult};
use crate::crypto::{CryptoError, CryptoResult};
use crate::protocol::ProtocolConfig;
use sha3::{Sha3_256, Digest};
use subtle::ConstantTimeEq;

/// Metadata protection level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    /// No metadata protection
    None,
    /// Basic protection (padding only)
    Basic,
    /// Standard protection (padding + timing)
    Standard,
    /// High protection (padding + timing + dummy traffic)
    High,
    /// Maximum protection (all techniques)
    Maximum,
}

impl ProtectionLevel {
    /// Whether padding is enabled.
    pub fn padding_enabled(&self) -> bool {
        !matches!(self, ProtectionLevel::None)
    }

    /// Whether timing obfuscation is enabled.
    pub fn timing_enabled(&self) -> bool {
        matches!(self, ProtectionLevel::Standard | ProtectionLevel::High | ProtectionLevel::Maximum)
    }

    /// Whether dummy traffic generation is enabled.
    pub fn dummy_traffic_enabled(&self) -> bool {
        matches!(self, ProtectionLevel::High | ProtectionLevel::Maximum)
    }

    /// Whether onion routing is enabled.
    pub fn onion_routing_enabled(&self) -> bool {
        matches!(self, ProtectionLevel::Maximum)
    }
}

/// Metadata protection manager
pub struct MetadataProtection {
    config: ProtocolConfig,
    level: ProtectionLevel,
    /// Optional metadata key from session (for padding authentication)
    metadata_key: Option<Vec<u8>>,
}

impl MetadataProtection {
    /// Create new metadata protection manager
    pub fn new(config: ProtocolConfig, level: ProtectionLevel) -> Self {
        MetadataProtection { config, level, metadata_key: None }
    }

    /// Create with session metadata key (for authenticated padding)
    pub fn with_metadata_key(mut self, key: &[u8]) -> Self {
        self.metadata_key = Some(key.to_vec());
        self
    }

    /// Apply metadata protection to message
    pub fn protect_message(&self, message: &[u8]) -> B4aeResult<Vec<u8>> {
        let mut protected = message.to_vec();

        // Apply padding
        if self.level.padding_enabled() {
            protected = padding::apply_padding(&protected, self.config.padding_block_size)?;
        }

        // Append MAC when metadata_key available (authenticates padding)
        if let Some(ref key) = self.metadata_key {
            let tag = compute_padding_tag(key, &protected);
            protected.extend_from_slice(&tag);
        }

        Ok(protected)
    }

    /// Remove metadata protection from message
    pub fn unprotect_message(&self, protected: &[u8]) -> B4aeResult<Vec<u8>> {
        let mut message = protected.to_vec();

        // Verify and strip MAC when metadata_key available
        if let Some(ref key) = self.metadata_key {
            if message.len() < 32 {
                return Err(B4aeError::CryptoError("Message too short for metadata tag".to_string()));
            }
            let tag_len = 32;
            let (payload, tag) = message.split_at(message.len() - tag_len);
            let expected = compute_padding_tag(key, payload);
            let tag_arr: [u8; 32] = tag.try_into().map_err(|_| B4aeError::CryptoError("Tag size mismatch".to_string()))?;
            if bool::from(tag_arr.ct_eq(&expected)) == false {
                return Err(B4aeError::CryptoError("Metadata protection tag verification failed".to_string()));
            }
            message = payload.to_vec();
        }

        // Remove padding
        if self.level.padding_enabled() {
            message = padding::remove_padding(&message)?;
        }

        Ok(message)
    }

    /// Get timing delay for obfuscation
    pub fn get_timing_delay_ms(&self) -> u64 {
        if self.level.timing_enabled() {
            timing::calculate_delay(0, self.config.max_timing_delay_ms)
        } else {
            0
        }
    }

    /// Check if dummy traffic should be generated
    pub fn should_generate_dummy(&self) -> bool {
        if !self.level.dummy_traffic_enabled() {
            return false;
        }

        use crate::crypto::random::random_range;
        random_range(100) < self.config.dummy_traffic_percent as u64
    }
}

/// Compute 32-byte MAC for padded message (padding authentication)
fn compute_padding_tag(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Metadata protection configuration for cover traffic, timing obfuscation, and traffic shaping.
///
/// This configuration controls all aspects of metadata protection including:
/// - Cover traffic generation rate (dummy messages)
/// - Constant-rate sending mode
/// - Timing delays (random delays between min and max)
/// - Traffic shaping to hide burst patterns
///
/// # Examples
///
/// ```
/// use b4ae::metadata::MetadataProtectionConfig;
///
/// // High security configuration
/// let config = MetadataProtectionConfig {
///     cover_traffic_rate: 0.5,
///     constant_rate_mode: true,
///     target_rate_msgs_per_sec: 2.0,
///     timing_delay_min_ms: 100,
///     timing_delay_max_ms: 2000,
///     traffic_shaping_enabled: true,
/// };
///
/// // Validate configuration
/// config.validate().expect("Invalid configuration");
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetadataProtectionConfig {
    /// Cover traffic rate as a fraction of real traffic (0.0 to 1.0).
    ///
    /// A value of 0.3 means approximately 30% dummy traffic relative to real traffic.
    /// Set to 0.0 to disable cover traffic generation.
    pub cover_traffic_rate: f64,

    /// Enable constant-rate sending mode for maximum metadata protection.
    ///
    /// When enabled, messages are sent at constant intervals determined by
    /// `target_rate_msgs_per_sec`. Dummy messages are inserted to maintain the rate.
    pub constant_rate_mode: bool,

    /// Target message rate in messages per second for constant-rate mode.
    ///
    /// Only used when `constant_rate_mode` is true. Must be greater than 0.0.
    pub target_rate_msgs_per_sec: f64,

    /// Minimum random delay in milliseconds to apply to messages.
    ///
    /// Set both min and max to 0 to disable timing delays.
    pub timing_delay_min_ms: u64,

    /// Maximum random delay in milliseconds to apply to messages.
    ///
    /// Must be greater than or equal to `timing_delay_min_ms`.
    pub timing_delay_max_ms: u64,

    /// Enable traffic shaping to hide burst patterns.
    ///
    /// When enabled, messages are shaped to avoid detectable burst patterns.
    pub traffic_shaping_enabled: bool,
}

impl MetadataProtectionConfig {
    /// Validate the configuration parameters.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidInput` if:
    /// - `cover_traffic_rate` is not in the range [0.0, 1.0]
    /// - `timing_delay_min_ms` > `timing_delay_max_ms`
    /// - `target_rate_msgs_per_sec` ≤ 0.0 when `constant_rate_mode` is enabled
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::MetadataProtectionConfig;
    ///
    /// let config = MetadataProtectionConfig::default();
    /// assert!(config.validate().is_ok());
    ///
    /// let invalid_config = MetadataProtectionConfig {
    ///     cover_traffic_rate: 1.5, // Invalid: > 1.0
    ///     ..Default::default()
    /// };
    /// assert!(invalid_config.validate().is_err());
    /// ```
    pub fn validate(&self) -> CryptoResult<()> {
        // Validate cover_traffic_rate is in [0.0, 1.0]
        if self.cover_traffic_rate < 0.0 || self.cover_traffic_rate > 1.0 {
            return Err(CryptoError::InvalidInput(
                format!(
                    "cover_traffic_rate must be in range [0.0, 1.0], got {}",
                    self.cover_traffic_rate
                )
            ));
        }

        // Validate timing delays
        if self.timing_delay_min_ms > self.timing_delay_max_ms {
            return Err(CryptoError::InvalidInput(
                format!(
                    "timing_delay_min_ms ({}) must be <= timing_delay_max_ms ({})",
                    self.timing_delay_min_ms, self.timing_delay_max_ms
                )
            ));
        }

        // Validate target rate when constant-rate mode is enabled
        if self.constant_rate_mode && self.target_rate_msgs_per_sec <= 0.0 {
            return Err(CryptoError::InvalidInput(
                format!(
                    "target_rate_msgs_per_sec must be > 0.0 when constant_rate_mode is enabled, got {}",
                    self.target_rate_msgs_per_sec
                )
            ));
        }

        Ok(())
    }

    /// Create a high security configuration with maximum metadata protection.
    ///
    /// - Cover traffic rate: 50%
    /// - Constant-rate mode: enabled (2 msgs/sec)
    /// - Timing delays: 100-2000ms
    /// - Traffic shaping: enabled
    pub fn high_security() -> Self {
        Self {
            cover_traffic_rate: 0.5,
            constant_rate_mode: true,
            target_rate_msgs_per_sec: 2.0,
            timing_delay_min_ms: 100,
            timing_delay_max_ms: 2000,
            traffic_shaping_enabled: true,
        }
    }

    /// Create a balanced configuration with moderate metadata protection.
    ///
    /// - Cover traffic rate: 20%
    /// - Constant-rate mode: disabled
    /// - Timing delays: 50-500ms
    /// - Traffic shaping: enabled
    pub fn balanced() -> Self {
        Self {
            cover_traffic_rate: 0.2,
            constant_rate_mode: false,
            target_rate_msgs_per_sec: 1.0,
            timing_delay_min_ms: 50,
            timing_delay_max_ms: 500,
            traffic_shaping_enabled: true,
        }
    }

    /// Create a low overhead configuration with minimal metadata protection.
    ///
    /// - Cover traffic rate: 0% (disabled)
    /// - Constant-rate mode: disabled
    /// - Timing delays: none
    /// - Traffic shaping: disabled
    pub fn low_overhead() -> Self {
        Self {
            cover_traffic_rate: 0.0,
            constant_rate_mode: false,
            target_rate_msgs_per_sec: 1.0,
            timing_delay_min_ms: 0,
            timing_delay_max_ms: 0,
            traffic_shaping_enabled: false,
        }
    }
}

impl Default for MetadataProtectionConfig {
    /// Create a default configuration with metadata protection disabled.
    ///
    /// This is equivalent to `MetadataProtectionConfig::low_overhead()`.
    fn default() -> Self {
        Self::low_overhead()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_levels() {
        assert!(!ProtectionLevel::None.padding_enabled());
        assert!(ProtectionLevel::Basic.padding_enabled());
        assert!(ProtectionLevel::Standard.timing_enabled());
        assert!(ProtectionLevel::High.dummy_traffic_enabled());
        assert!(ProtectionLevel::Maximum.onion_routing_enabled());
    }

    #[test]
    fn test_metadata_protection() {
        let config = ProtocolConfig::default();
        let protection = MetadataProtection::new(config, ProtectionLevel::Standard);

        let message = b"Hello, B4AE!";
        let protected = protection.protect_message(message).unwrap();
        
        // Protected message should be larger due to padding
        assert!(protected.len() >= message.len());
        
        let unprotected = protection.unprotect_message(&protected).unwrap();
        assert_eq!(message, unprotected.as_slice());
    }

    #[test]
    fn test_metadata_protection_with_key() {
        let config = ProtocolConfig::default();
        let key = [0x42u8; 32];
        let protection = MetadataProtection::new(config, ProtectionLevel::Standard)
            .with_metadata_key(&key);

        let message = b"Hello, B4AE with MAC!";
        let protected = protection.protect_message(message).unwrap();
        assert!(protected.len() >= message.len() + 32);

        let unprotected = protection.unprotect_message(&protected).unwrap();
        assert_eq!(message, unprotected.as_slice());

        // Tampered message should fail
        let mut tampered = protected.clone();
        tampered[protected.len() - 1] ^= 0xff;
        assert!(protection.unprotect_message(&tampered).is_err());
    }

    // Tests for MetadataProtectionConfig

    #[test]
    fn test_config_default_validation() {
        let config = MetadataProtectionConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_high_security_validation() {
        let config = MetadataProtectionConfig::high_security();
        assert!(config.validate().is_ok());
        assert_eq!(config.cover_traffic_rate, 0.5);
        assert!(config.constant_rate_mode);
        assert_eq!(config.target_rate_msgs_per_sec, 2.0);
        assert_eq!(config.timing_delay_min_ms, 100);
        assert_eq!(config.timing_delay_max_ms, 2000);
        assert!(config.traffic_shaping_enabled);
    }

    #[test]
    fn test_config_balanced_validation() {
        let config = MetadataProtectionConfig::balanced();
        assert!(config.validate().is_ok());
        assert_eq!(config.cover_traffic_rate, 0.2);
        assert!(!config.constant_rate_mode);
        assert_eq!(config.timing_delay_min_ms, 50);
        assert_eq!(config.timing_delay_max_ms, 500);
        assert!(config.traffic_shaping_enabled);
    }

    #[test]
    fn test_config_low_overhead_validation() {
        let config = MetadataProtectionConfig::low_overhead();
        assert!(config.validate().is_ok());
        assert_eq!(config.cover_traffic_rate, 0.0);
        assert!(!config.constant_rate_mode);
        assert_eq!(config.timing_delay_min_ms, 0);
        assert_eq!(config.timing_delay_max_ms, 0);
        assert!(!config.traffic_shaping_enabled);
    }

    #[test]
    fn test_config_invalid_cover_traffic_rate_too_low() {
        let config = MetadataProtectionConfig {
            cover_traffic_rate: -0.1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_cover_traffic_rate_too_high() {
        let config = MetadataProtectionConfig {
            cover_traffic_rate: 1.5,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_valid_cover_traffic_rate_boundaries() {
        let config_zero = MetadataProtectionConfig {
            cover_traffic_rate: 0.0,
            ..Default::default()
        };
        assert!(config_zero.validate().is_ok());

        let config_one = MetadataProtectionConfig {
            cover_traffic_rate: 1.0,
            ..Default::default()
        };
        assert!(config_one.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_timing_delay_min_greater_than_max() {
        let config = MetadataProtectionConfig {
            timing_delay_min_ms: 1000,
            timing_delay_max_ms: 500,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_valid_timing_delay_equal() {
        let config = MetadataProtectionConfig {
            timing_delay_min_ms: 500,
            timing_delay_max_ms: 500,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_target_rate_zero_with_constant_rate_mode() {
        let config = MetadataProtectionConfig {
            constant_rate_mode: true,
            target_rate_msgs_per_sec: 0.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_target_rate_negative_with_constant_rate_mode() {
        let config = MetadataProtectionConfig {
            constant_rate_mode: true,
            target_rate_msgs_per_sec: -1.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_valid_target_rate_zero_without_constant_rate_mode() {
        let config = MetadataProtectionConfig {
            constant_rate_mode: false,
            target_rate_msgs_per_sec: 0.0,
            ..Default::default()
        };
        // Should be valid because constant_rate_mode is disabled
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_valid_all_parameters() {
        let config = MetadataProtectionConfig {
            cover_traffic_rate: 0.3,
            constant_rate_mode: true,
            target_rate_msgs_per_sec: 5.0,
            timing_delay_min_ms: 200,
            timing_delay_max_ms: 1000,
            traffic_shaping_enabled: true,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_edge_case_max_cover_traffic() {
        let config = MetadataProtectionConfig {
            cover_traffic_rate: 1.0,
            constant_rate_mode: true,
            target_rate_msgs_per_sec: 10.0,
            timing_delay_min_ms: 0,
            timing_delay_max_ms: 5000,
            traffic_shaping_enabled: true,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_edge_case_no_delays() {
        let config = MetadataProtectionConfig {
            cover_traffic_rate: 0.5,
            constant_rate_mode: false,
            target_rate_msgs_per_sec: 1.0,
            timing_delay_min_ms: 0,
            timing_delay_max_ms: 0,
            traffic_shaping_enabled: false,
        };
        assert!(config.validate().is_ok());
    }
}
