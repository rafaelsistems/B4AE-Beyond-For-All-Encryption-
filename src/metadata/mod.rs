// B4AE Metadata Protection Module

pub mod padding;
pub mod timing;
pub mod obfuscation;

use crate::error::B4aeResult;
use crate::protocol::ProtocolConfig;

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
    pub fn padding_enabled(&self) -> bool {
        !matches!(self, ProtectionLevel::None)
    }

    pub fn timing_enabled(&self) -> bool {
        matches!(self, ProtectionLevel::Standard | ProtectionLevel::High | ProtectionLevel::Maximum)
    }

    pub fn dummy_traffic_enabled(&self) -> bool {
        matches!(self, ProtectionLevel::High | ProtectionLevel::Maximum)
    }

    pub fn onion_routing_enabled(&self) -> bool {
        matches!(self, ProtectionLevel::Maximum)
    }
}

/// Metadata protection manager
pub struct MetadataProtection {
    config: ProtocolConfig,
    level: ProtectionLevel,
}

impl MetadataProtection {
    /// Create new metadata protection manager
    pub fn new(config: ProtocolConfig, level: ProtectionLevel) -> Self {
        MetadataProtection { config, level }
    }

    /// Apply metadata protection to message
    pub fn protect_message(&self, message: &[u8]) -> B4aeResult<Vec<u8>> {
        let mut protected = message.to_vec();

        // Apply padding
        if self.level.padding_enabled() {
            protected = padding::apply_padding(&protected, self.config.padding_block_size)?;
        }

        Ok(protected)
    }

    /// Remove metadata protection from message
    pub fn unprotect_message(&self, protected: &[u8]) -> B4aeResult<Vec<u8>> {
        let mut message = protected.to_vec();

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
}
