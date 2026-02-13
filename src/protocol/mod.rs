// B4AE Protocol Implementation

pub mod handshake;
pub mod message;
pub mod session;

use crate::error::{B4aeError, B4aeResult};
use serde::{Deserialize, Serialize};

/// B4AE Protocol Version
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

    pub fn to_u8(self) -> u8 {
        self as u8
    }
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
    pub fn to_config(self) -> ProtocolConfig {
        match self {
            SecurityProfile::Standard => ProtocolConfig {
                metadata_protection: true,
                padding_block_size: 4096,
                timing_obfuscation: true,
                max_timing_delay_ms: 2000,
                dummy_traffic: false,
                dummy_traffic_percent: 10,
            },
            SecurityProfile::High => ProtocolConfig {
                metadata_protection: true,
                padding_block_size: 16384,
                timing_obfuscation: true,
                max_timing_delay_ms: 5000,
                dummy_traffic: true,
                dummy_traffic_percent: 20,
            },
            SecurityProfile::Maximum => ProtocolConfig {
                metadata_protection: true,
                padding_block_size: 65536,
                timing_obfuscation: true,
                max_timing_delay_ms: 10000,
                dummy_traffic: true,
                dummy_traffic_percent: 30,
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
