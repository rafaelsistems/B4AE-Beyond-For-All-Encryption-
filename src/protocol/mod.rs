//! B4AE Protocol Implementation
//!
//! Implements [B4AE Protocol Specification v1.0](../../specs/B4AE_Protocol_Specification_v1.0.md):
//! handshake, message format, session keys, key derivation.

/// Three-way handshake and key derivation.
pub mod handshake;
/// Message format, serialization, flags.
pub mod message;
/// Session state, key rotation, message crypto.
pub mod session;

use crate::error::{B4aeError, B4aeResult};
use serde::{Deserialize, Serialize};

/// Wire protocol version (Protocol Specification v1.0). Re-exported from crate root.
pub const PROTOCOL_VERSION: u16 = 1;

/// Protocol message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake initiation
    HandshakeInit = 0x01,
    /// Handshake response
    HandshakeResponse = 0x02,
    /// Handshake completion
    HandshakeComplete = 0x03,
    /// Encrypted data message
    DataMessage = 0x10,
    /// Key rotation request
    KeyRotation = 0x20,
    /// Acknowledgment
    Ack = 0x30,
    /// Error message
    Error = 0xFF,
}

impl MessageType {
    /// Parse message type from wire byte.
    pub fn from_u8(value: u8) -> B4aeResult<Self> {
        match value {
            0x01 => Ok(MessageType::HandshakeInit),
            0x02 => Ok(MessageType::HandshakeResponse),
            0x03 => Ok(MessageType::HandshakeComplete),
            0x10 => Ok(MessageType::DataMessage),
            0x20 => Ok(MessageType::KeyRotation),
            0x30 => Ok(MessageType::Ack),
            0xFF => Ok(MessageType::Error),
            _ => Err(B4aeError::ProtocolError(format!("Unknown message type: {}", value))),
        }
    }

    /// Serialize to wire byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// IP anonymization settings (proxy/Tor).
#[derive(Debug, Clone, Default)]
pub struct AnonymizationConfig {
    /// Optional SOCKS5 proxy URL (e.g. "socks5://127.0.0.1:9050" for Tor).
    pub proxy_url: Option<String>,
    /// Use Tor for IP anonymization when proxy_url points to Tor.
    pub use_tor: bool,
}

/// Protocol configuration
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Enable metadata protection
    pub metadata_protection: bool,
    /// Traffic padding block size (bytes)
    pub padding_block_size: usize,
    /// Enable timing obfuscation
    pub timing_obfuscation: bool,
    /// Maximum timing delay (milliseconds)
    pub max_timing_delay_ms: u64,
    /// Enable dummy traffic
    pub dummy_traffic: bool,
    /// Dummy traffic percentage (0-100)
    pub dummy_traffic_percent: u8,
    /// IP anonymization (proxy, Tor)
    pub anonymization: AnonymizationConfig,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig {
            metadata_protection: true,
            padding_block_size: 4096,
            timing_obfuscation: true,
            max_timing_delay_ms: 2000,
            dummy_traffic: false,
            dummy_traffic_percent: 10,
            anonymization: AnonymizationConfig::default(),
        }
    }
}

/// Security profile presets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Standard security (balanced)
    Standard,
    /// High security (more protection, higher overhead)
    High,
    /// Maximum security (maximum protection, highest overhead)
    Maximum,
}

impl SecurityProfile {
    /// Convert to ProtocolConfig with profile-specific defaults.
    pub fn to_config(self) -> ProtocolConfig {
        match self {
            SecurityProfile::Standard => ProtocolConfig {
                metadata_protection: true,
                padding_block_size: 4096,
                timing_obfuscation: true,
                max_timing_delay_ms: 2000,
                dummy_traffic: false,
                dummy_traffic_percent: 10,
                anonymization: AnonymizationConfig::default(),
            },
            SecurityProfile::High => ProtocolConfig {
                metadata_protection: true,
                padding_block_size: 16384,
                timing_obfuscation: true,
                max_timing_delay_ms: 5000,
                dummy_traffic: true,
                dummy_traffic_percent: 20,
                anonymization: AnonymizationConfig::default(),
            },
            SecurityProfile::Maximum => ProtocolConfig {
                metadata_protection: true,
                padding_block_size: 65536,
                timing_obfuscation: true,
                max_timing_delay_ms: 10000,
                dummy_traffic: true,
                dummy_traffic_percent: 30,
                anonymization: AnonymizationConfig::default(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::HandshakeInit.to_u8(), 0x01);
        assert_eq!(MessageType::from_u8(0x01).unwrap(), MessageType::HandshakeInit);
    }

    #[test]
    fn test_security_profiles() {
        let standard = SecurityProfile::Standard.to_config();
        let high = SecurityProfile::High.to_config();
        let maximum = SecurityProfile::Maximum.to_config();

        assert!(standard.padding_block_size < high.padding_block_size);
        assert!(high.padding_block_size < maximum.padding_block_size);
    }
}
