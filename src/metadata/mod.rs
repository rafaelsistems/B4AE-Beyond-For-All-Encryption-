//! B4AE Metadata Protection Module
//!
//! Padding, timing obfuscation, dummy traffic for traffic analysis resistance.

/// PKCS#7 and random padding.
pub mod padding;
/// Timing delay strategies.
pub mod timing;
/// Dummy traffic and pattern obfuscation.
pub mod obfuscation;

use crate::error::{B4aeError, B4aeResult};
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
}
