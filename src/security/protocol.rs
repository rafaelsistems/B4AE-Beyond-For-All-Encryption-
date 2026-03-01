//! Security-hardened protocol implementation with panic-free parsing
//!
//! This module provides zero-trust parsing and deterministic state machines
//! for the B4AE protocol handshake and message handling.

use crate::security::hardened_core::{
    SecurityBuffer, SecurityResult, SecurityError, SecurityStateMachine,
    constant_time_eq_security, checked_add_security, checked_sub_security
};
use std::convert::TryFrom;

/// Protocol version with explicit validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1_0 = 0x0100,
}

impl ProtocolVersion {
    pub const SIZE: usize = 2;
    
    pub fn from_bytes(bytes: [u8; 2]) -> SecurityResult<Self> {
        match u16::from_be_bytes(bytes) {
            0x0100 => Ok(ProtocolVersion::V1_0),
            actual => Err(SecurityError::InvalidProtocolVersion { 
                expected: 0x0100, 
                actual 
            }),
        }
    }
    
    pub fn to_bytes(&self) -> [u8; 2] {
        match self {
            ProtocolVersion::V1_0 => [0x01, 0x00],
        }
    }
}

/// Message type with explicit validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    HandshakeComplete = 0x03,
    Data = 0x04,
    KeepAlive = 0x05,
    Close = 0x06,
}

impl MessageType {
    pub fn from_u8(byte: u8) -> SecurityResult<Self> {
        match byte {
            0x01 => Ok(MessageType::HandshakeInit),
            0x02 => Ok(MessageType::HandshakeResponse),
            0x03 => Ok(MessageType::HandshakeComplete),
            0x04 => Ok(MessageType::Data),
            0x05 => Ok(MessageType::KeepAlive),
            0x06 => Ok(MessageType::Close),
            actual => Err(SecurityError::InvalidMessageType(actual)),
        }
    }
    
    pub fn to_u8(&self) -> u8 {
        match self {
            MessageType::HandshakeInit => 0x01,
            MessageType::HandshakeResponse => 0x02,
            MessageType::HandshakeComplete => 0x03,
            MessageType::Data => 0x04,
            MessageType::KeepAlive => 0x05,
            MessageType::Close => 0x06,
        }
    }
}

/// Cipher suite with explicit validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    HybridKyber1024X25519 = 0x0101,
    HybridDilithium5Ed25519 = 0x0202,
    Aes256Gcm = 0x0303,
}

impl CipherSuite {
    pub fn from_u8(byte: u8) -> SecurityResult<Self> {
        match byte {
            0x01 => Ok(CipherSuite::HybridKyber1024X25519),
            0x02 => Ok(CipherSuite::HybridDilithium5Ed25519),
            0x03 => Ok(CipherSuite::Aes256Gcm),
            actual => Err(SecurityError::InvalidCipherSuite(actual)),
        }
    }
    
    pub fn to_u8(&self) -> u8 {
        match self {
            CipherSuite::HybridKyber1024X25519 => 0x01,
            CipherSuite::HybridDilithium5Ed25519 => 0x02,
            CipherSuite::Aes256Gcm => 0x03,
        }
    }
}

/// Security-hardened message header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityMessageHeader {
    pub version: ProtocolVersion,
    pub message_type: MessageType,
    pub cipher_suite: CipherSuite,
    pub message_id: u64,
    pub payload_length: u32,
    pub timestamp: u64,
}

impl SecurityMessageHeader {
    pub const SIZE: usize = 2 + 1 + 1 + 8 + 4 + 8; // 24 bytes total
    
    pub fn parse_security(buffer: &mut SecurityBuffer) -> SecurityResult<Self> {
        // Parse version (2 bytes)
        let version_bytes = buffer.read_exact(2)?;
        let version = ProtocolVersion::from_bytes([
            version_bytes[0], version_bytes[1]
        ])?;
        
        // Parse message type (1 byte)
        let message_type_byte = buffer.read_u8()?;
        let message_type = MessageType::from_u8(message_type_byte)?;
        
        // Parse cipher suite (1 byte)
        let cipher_suite_byte = buffer.read_u8()?;
        let cipher_suite = CipherSuite::from_u8(cipher_suite_byte)?;
        
        // Parse message ID (8 bytes)
        let message_id = buffer.read_i64_be()?;
        
        // Parse payload length (4 bytes)
        let payload_length = buffer.read_u32_be()?;
        
        // Parse timestamp (8 bytes)
        let timestamp = buffer.read_i64_be()?;
        
        Ok(SecurityMessageHeader {
            version,
            message_type,
            cipher_suite,
            message_id: message_id.try_into().unwrap_or(0),
            payload_length,
            timestamp: timestamp.try_into().unwrap_or(0),
        })
    }
    
    pub fn serialize_security(&self, buffer: &mut SecurityBuffer) -> SecurityResult<()> {
        // Serialize version (2 bytes)
        let version_bytes = self.version.to_bytes();
        buffer.write_slice(&version_bytes)?;
        
        // Serialize message type (1 byte)
        buffer.write_u8(self.message_type.to_u8())?;
        
        // Serialize cipher suite (1 byte)
        buffer.write_u8(self.cipher_suite.to_u8())?;
        
        // Serialize message ID (8 bytes)
        buffer.write_u64_be(self.message_id)?;
        
        // Serialize payload length (4 bytes)
        buffer.write_u32_be(self.payload_length)?;
        
        // Serialize timestamp (8 bytes)
        buffer.write_u64_be(self.timestamp)?;
        
        Ok(())
    }
    
    pub fn validate_security(&self) -> SecurityResult<()> {
        // Validate version
        if self.version != ProtocolVersion::V1_0 {
            return Err(SecurityError::InvalidProtocolVersion {
                expected: 0x0100,
                actual: u16::from_be_bytes(self.version.to_bytes()),
            });
        }
        
        // Validate payload length limits
        const MAX_PAYLOAD_SIZE: u32 = 1024 * 1024; // 1 MiB
        if self.payload_length > MAX_PAYLOAD_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "payload_length".to_string(),
                limit: MAX_PAYLOAD_SIZE as usize,
                requested: self.payload_length as usize,
            });
        }
        
        // Validate timestamp (must be within reasonable range)
        const MAX_TIMESTAMP_DRIFT: u64 = 3600; // 1 hour in seconds
        let current_timestamp = crate::time::current_time_secs();
        let timestamp_diff = if self.timestamp > current_timestamp {
            self.timestamp - current_timestamp
        } else {
            current_timestamp - self.timestamp
        };
        
        if timestamp_diff > MAX_TIMESTAMP_DRIFT {
            return Err(SecurityError::InvalidTimestamp(timestamp_diff as i64));
        }
        
        Ok(())
    }
}

/// Handshake state machine with explicit transitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Init,
    WaitingResponse,
    WaitingComplete,
    Completed,
    Failed,
}

impl HandshakeState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, HandshakeState::Completed | HandshakeState::Failed)
    }
    
    pub fn can_transition_to(&self, next: HandshakeState) -> SecurityResult<()> {
        match (*self, next) {
            (HandshakeState::Init, HandshakeState::WaitingResponse) => Ok(()),
            (HandshakeState::WaitingResponse, HandshakeState::WaitingComplete) => Ok(()),
            (HandshakeState::WaitingResponse, HandshakeState::Failed) => Ok(()),
            (HandshakeState::WaitingComplete, HandshakeState::Completed) => Ok(()),
            (HandshakeState::WaitingComplete, HandshakeState::Failed) => Ok(()),
            (HandshakeState::Failed, HandshakeState::Init) => Ok(()), // Allow restart
            _ => Err(SecurityError::InvalidStateTransition {
                from: format!("{:?}", self),
                to: format!("{:?}", next),
            }),
        }
    }
}

/// Security-hardened handshake parser
pub struct SecurityHandshakeParser {
    state: HandshakeState,
    buffer: SecurityBuffer,
}

impl SecurityHandshakeParser {
    pub fn new(max_size: usize) -> SecurityResult<Self> {
        Ok(SecurityHandshakeParser {
            state: HandshakeState::Init,
            buffer: SecurityBuffer::new(max_size)?,
        })
    }
    
    pub fn parse_message(&mut self, data: &[u8]) -> SecurityResult<SecurityMessageHeader> {
        // Validate input size
        if data.len() > self.buffer.capacity() {
            return Err(SecurityError::BufferTooSmall {
                required: data.len(),
                available: self.buffer.capacity(),
            });
        }
        
        // Reset buffer and write data
        self.buffer.clear()?;
        self.buffer.write_slice(data)?;
        self.buffer.set_position(0)?;
        
        // Parse header
        let header = SecurityMessageHeader::parse_security(&mut self.buffer)?;
        
        // Validate header
        header.validate_security()?;
        
        Ok(header)
    }
    
    pub fn transition_state(&mut self, new_state: HandshakeState) -> SecurityResult<()> {
        self.state.can_transition_to(new_state)?;
        self.state = new_state;
        Ok(())
    }
    
    pub fn current_state(&self) -> HandshakeState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_version_validation() {
        // Valid version
        let valid = ProtocolVersion::from_bytes([0x01, 0x00]);
        assert!(valid.is_ok());
        assert_eq!(valid.unwrap(), ProtocolVersion::V1_0);
        
        // Invalid version
        let invalid = ProtocolVersion::from_bytes([0x02, 0x00]);
        assert!(invalid.is_err());
    }
    
    #[test]
    fn test_message_type_validation() {
        // Valid types
        assert!(MessageType::from_u8(0x01).is_ok());
        assert!(MessageType::from_u8(0x02).is_ok());
        assert!(MessageType::from_u8(0x03).is_ok());
        assert!(MessageType::from_u8(0x04).is_ok());
        assert!(MessageType::from_u8(0x05).is_ok());
        assert!(MessageType::from_u8(0x06).is_ok());
        
        // Invalid type
        assert!(MessageType::from_u8(0x07).is_err());
    }
    
    #[test]
    fn test_handshake_state_transitions() {
        let mut state = HandshakeState::Init;
        
        // Valid transition
        assert!(state.can_transition_to(HandshakeState::WaitingResponse).is_ok());
        state = HandshakeState::WaitingResponse;
        
        // Invalid transition
        assert!(state.can_transition_to(HandshakeState::Init).is_err());
        
        // Valid failure transition
        assert!(state.can_transition_to(HandshakeState::Failed).is_ok());
    }
}