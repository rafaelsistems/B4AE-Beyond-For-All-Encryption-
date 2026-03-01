//! Security-hardened network input parsing with zero-trust validation
//!
//! This module provides comprehensive bounds checking and input validation
//! for all network protocol parsing operations.

use crate::security::{
    SecurityResult, SecurityError, SecurityBuffer, SecurityStateMachine,
    ProtocolVersion, MessageType, CipherSuite, SecurityMessageHeader
};
use std::convert::TryFrom;

/// Maximum sizes for network protocol elements
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MiB
pub const MAX_HEADER_SIZE: usize = 64; // 64 bytes
pub const MAX_EXTENSION_SIZE: usize = 4096; // 4 KiB
pub const MAX_HANDSHAKE_SIZE: usize = 16 * 1024; // 16 KiB

/// Network protocol parser with comprehensive validation
pub struct SecurityNetworkParser {
    max_message_size: usize,
    max_header_size: usize,
    max_extension_size: usize,
    strict_validation: bool,
}

impl SecurityNetworkParser {
    pub fn new() -> Self {
        SecurityNetworkParser {
            max_message_size: MAX_MESSAGE_SIZE,
            max_header_size: MAX_HEADER_SIZE,
            max_extension_size: MAX_EXTENSION_SIZE,
            strict_validation: true,
        }
    }
    
    pub fn with_limits(
        max_message_size: usize,
        max_header_size: usize,
        max_extension_size: usize,
    ) -> SecurityResult<Self> {
        // Validate limits
        if max_message_size == 0 || max_message_size > 16 * 1024 * 1024 {
            return Err(SecurityError::InvalidLength {
                expected: 1,
                actual: max_message_size,
            });
        }
        
        if max_header_size == 0 || max_header_size > 256 {
            return Err(SecurityError::InvalidLength {
                expected: 1,
                actual: max_header_size,
            });
        }
        
        if max_extension_size == 0 || max_extension_size > 64 * 1024 {
            return Err(SecurityError::InvalidLength {
                expected: 1,
                actual: max_extension_size,
            });
        }
        
        Ok(SecurityNetworkParser {
            max_message_size,
            max_header_size,
            max_extension_size,
            strict_validation: true,
        })
    }
    
    /// Parse complete network message with header and payload
    pub fn parse_message(&self, data: &[u8]) -> SecurityResult<SecurityNetworkMessage> {
        // Validate total message size
        if data.len() > self.max_message_size {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "message_size".to_string(),
                limit: self.max_message_size,
                requested: data.len(),
            });
        }
        
        if data.len() < SecurityMessageHeader::SIZE {
            return Err(SecurityError::BufferTooSmall {
                required: SecurityMessageHeader::SIZE,
                available: data.len(),
            });
        }
        
        // Create buffer and parse header
        let mut buffer = SecurityBuffer::new(data.len())?;
        buffer.write_slice(data)?;
        buffer.set_position(0)?;
        
        let header = SecurityMessageHeader::parse_security(&mut buffer)?;
        
        // Validate header
        header.validate_security()?;
        
        // Validate payload size matches header
        let payload_size = data.len() - SecurityMessageHeader::SIZE;
        if payload_size != header.payload_length as usize {
            return Err(SecurityError::InvalidLength {
                expected: header.payload_length as usize,
                actual: payload_size,
            });
        }
        
        // Extract payload
        let payload = buffer.read_exact(payload_size)?.to_vec();
        
        Ok(SecurityNetworkMessage {
            header,
            payload,
        })
    }
    
    /// Parse only the message header
    pub fn parse_header(&self, data: &[u8]) -> SecurityResult<SecurityMessageHeader> {
        // Validate header size
        if data.len() != SecurityMessageHeader::SIZE {
            return Err(SecurityError::InvalidLength {
                expected: SecurityMessageHeader::SIZE,
                actual: data.len(),
            });
        }
        
        // Create buffer and parse header
        let mut buffer = SecurityBuffer::new(data.len())?;
        buffer.write_slice(data)?;
        buffer.set_position(0)?;
        
        let header = SecurityMessageHeader::parse_security(&mut buffer)?;
        header.validate_security()?;
        
        Ok(header)
    }
    
    /// Parse handshake message with specific validation
    pub fn parse_handshake_message(&self, data: &[u8], expected_type: MessageType) -> SecurityResult<SecurityHandshakeMessage> {
        // Validate handshake message size
        if data.len() > MAX_HANDSHAKE_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "handshake_message".to_string(),
                limit: MAX_HANDSHAKE_SIZE,
                requested: data.len(),
            });
        }
        
        // Parse message
        let message = self.parse_message(data)?;
        
        // Validate message type
        if message.header.message_type != expected_type {
            return Err(SecurityError::InvalidMessageType(
                message.header.message_type.to_u8()
            ));
        }
        
        // Validate cipher suite for handshake
        match message.header.cipher_suite {
            CipherSuite::HybridKyber1024X25519 => {},
            _ => return Err(SecurityError::InvalidCipherSuite(message.header.cipher_suite.to_u8())),
        }
        
        Ok(SecurityHandshakeMessage {
            message,
        })
    }
    
    /// Parse data message
    pub fn parse_data_message(&self, data: &[u8]) -> SecurityResult<SecurityDataMessage> {
        let message = self.parse_message(data)?;
        
        // Validate message type
        if message.header.message_type != MessageType::Data {
            return Err(SecurityError::InvalidMessageType(message.header.message_type.to_u8()));
        }
        
        // Additional data message validation
        if message.payload.is_empty() {
            return Err(SecurityError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        }
        
        Ok(SecurityDataMessage {
            message,
        })
    }
    
    /// Validate message structure without full parsing
    pub fn validate_message_structure(&self, data: &[u8]) -> SecurityResult<()> {
        // Quick validation without full parsing
        if data.len() < SecurityMessageHeader::SIZE {
            return Err(SecurityError::BufferTooSmall {
                required: SecurityMessageHeader::SIZE,
                available: data.len(),
            });
        }
        
        if data.len() > self.max_message_size {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "message_size".to_string(),
                limit: self.max_message_size,
                requested: data.len(),
            });
        }
        
        // Basic header validation
        let mut buffer = SecurityBuffer::new(SecurityMessageHeader::SIZE)?;
        buffer.write_slice(&data[..SecurityMessageHeader::SIZE])?;
        buffer.set_position(0)?;
        
        let header = SecurityMessageHeader::parse_security(&mut buffer)?;
        header.validate_security()?;
        
        // Validate payload size consistency
        let payload_size = data.len() - SecurityMessageHeader::SIZE;
        if payload_size != header.payload_length as usize {
            return Err(SecurityError::InvalidLength {
                expected: header.payload_length as usize,
                actual: payload_size,
            });
        }
        
        Ok(())
    }
    
    /// Check if more data is needed for complete message
    pub fn needs_more_data(&self, data: &[u8]) -> SecurityResult<bool> {
        if data.len() < SecurityMessageHeader::SIZE {
            return Ok(true);
        }
        
        // Parse header to get total message size
        let mut buffer = SecurityBuffer::new(SecurityMessageHeader::SIZE)?;
        buffer.write_slice(&data[..SecurityMessageHeader::SIZE])?;
        buffer.set_position(0)?;
        
        let header = SecurityMessageHeader::parse_security(&mut buffer)?;
        let total_size = SecurityMessageHeader::SIZE + header.payload_length as usize;
        
        Ok(data.len() < total_size)
    }
    
    /// Enable or disable strict validation mode
    pub fn set_strict_validation(&mut self, strict: bool) {
        self.strict_validation = strict;
    }
    
    /// Get current validation settings
    pub fn validation_settings(&self) -> SecurityValidationSettings {
        SecurityValidationSettings {
            max_message_size: self.max_message_size,
            max_header_size: self.max_header_size,
            max_extension_size: self.max_extension_size,
            strict_validation: self.strict_validation,
        }
    }
}

/// Complete network message with header and payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityNetworkMessage {
    pub header: SecurityMessageHeader,
    pub payload: Vec<u8>,
}

/// Handshake message wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHandshakeMessage {
    pub message: SecurityNetworkMessage,
}

/// Data message wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDataMessage {
    pub message: SecurityNetworkMessage,
}

/// Validation settings for network parser
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityValidationSettings {
    pub max_message_size: usize,
    pub max_header_size: usize,
    pub max_extension_size: usize,
    pub strict_validation: bool,
}

/// Network message validator for streaming protocols
pub struct SecurityStreamingValidator {
    parser: SecurityNetworkParser,
    buffer: SecurityBuffer,
}

impl SecurityStreamingValidator {
    pub fn new(max_buffer_size: usize) -> SecurityResult<Self> {
        Ok(SecurityStreamingValidator {
            parser: SecurityNetworkParser::new(),
            buffer: SecurityBuffer::new(max_buffer_size)?,
        })
    }
    
    /// Add data to buffer and validate
    pub fn add_data(&mut self, data: &[u8]) -> SecurityResult<()> {
        // Check if we have space
        let remaining = self.buffer.capacity() - self.buffer.len();
        if data.len() > remaining {
            return Err(SecurityError::BufferTooSmall {
                required: data.len(),
                available: remaining,
            });
        }
        
        self.buffer.write_slice(data)?;
        Ok(())
    }
    
    /// Check if we have a complete message
    pub fn has_complete_message(&self) -> SecurityResult<bool> {
        if self.buffer.len() < SecurityMessageHeader::SIZE {
            return Ok(false);
        }
        
        // Parse header to check if we have complete message
        let mut temp_buffer = SecurityBuffer::new(SecurityMessageHeader::SIZE)?;
        temp_buffer.write_slice(&self.buffer.as_slice()[..SecurityMessageHeader::SIZE])?;
        temp_buffer.set_position(0)?;
        
        let header = SecurityMessageHeader::parse_security(&mut temp_buffer)?;
        let total_size = SecurityMessageHeader::SIZE + header.payload_length as usize;
        
        Ok(self.buffer.len() >= total_size)
    }
    
    /// Extract complete message if available
    pub fn extract_message(&mut self) -> SecurityResult<Option<SecurityNetworkMessage>> {
        if !self.has_complete_message()? {
            return Ok(None);
        }
        
        // Get total message size
        let mut temp_buffer = SecurityBuffer::new(SecurityMessageHeader::SIZE)?;
        temp_buffer.write_slice(&self.buffer.as_slice()[..SecurityMessageHeader::SIZE])?;
        temp_buffer.set_position(0)?;
        
        let header = SecurityMessageHeader::parse_security(&mut temp_buffer)?;
        let total_size = SecurityMessageHeader::SIZE + header.payload_length as usize;
        
        // Extract message
        let message_data = self.buffer.read_exact(total_size)?.to_vec();
        
        // Parse message
        let message = self.parser.parse_message(&message_data)?;
        
        Ok(Some(message))
    }
    
    /// Reset buffer
    pub fn reset(&mut self) -> SecurityResult<()> {
        self.buffer.clear()?;
        Ok(())
    }
    
    /// Get current buffer usage
    pub fn buffer_usage(&self) -> (usize, usize) {
        (self.buffer.len(), self.buffer.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_parser_limits() {
        // Valid limits
        let parser = SecurityNetworkParser::with_limits(1024, 64, 512);
        assert!(parser.is_ok());
        
        // Invalid limits
        let parser = SecurityNetworkParser::with_limits(0, 64, 512);
        assert!(parser.is_err());
        
        let parser = SecurityNetworkParser::with_limits(1024, 0, 512);
        assert!(parser.is_err());
        
        let parser = SecurityNetworkParser::with_limits(1024, 64, 0);
        assert!(parser.is_err());
    }
    
    #[test]
    fn test_message_parsing() {
        let parser = SecurityNetworkParser::new();
        
        // Create valid message
        let mut buffer = SecurityBuffer::new(1000).expect("Buffer creation should succeed");
        
        // Write header
        buffer.write_slice(&[0x01, 0x00]).expect("Write should succeed"); // Version
        buffer.write_u8(0x04).expect("Write should succeed"); // Message type (Data)
        buffer.write_u8(0x03).expect("Write should succeed"); // Cipher suite (AES-GCM)
        buffer.write_u64_be(12345).expect("Write should succeed"); // Message ID
        buffer.write_u32_be(64).expect("Write should succeed"); // Payload length
        buffer.write_u64_be(0).expect("Write should succeed"); // Timestamp
        
        // Write payload
        let payload = vec![0x42u8; 64];
        buffer.write_slice(&payload).expect("Write should succeed");
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        // Parse message
        let result = parser.parse_message(buffer.as_slice());
        assert!(result.is_ok());
        
        let message = result.unwrap();
        assert_eq!(message.header.message_type, MessageType::Data);
        assert_eq!(message.payload.len(), 64);
    }
    
    #[test]
    fn test_oversized_message_protection() {
        let parser = SecurityNetworkParser::with_limits(1024, 64, 512).expect("Parser creation should succeed");
        
        // Create oversized message
        let mut buffer = SecurityBuffer::new(2000).expect("Buffer creation should succeed");
        
        // Write header
        buffer.write_slice(&[0x01, 0x00]).expect("Write should succeed"); // Version
        buffer.write_u8(0x04).expect("Write should succeed"); // Message type
        buffer.write_u8(0x03).expect("Write should succeed"); // Cipher suite
        buffer.write_u64_be(12345).expect("Write should succeed"); // Message ID
        buffer.write_u32_be(1500).expect("Write should succeed"); // Payload length (too large)
        buffer.write_u64_be(0).expect("Write should succeed"); // Timestamp
        
        // Write payload
        let payload = vec![0x42u8; 1500];
        buffer.write_slice(&payload).expect("Write should succeed");
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        // Parse message - should fail due to size limit
        let result = parser.parse_message(buffer.as_slice());
        assert!(result.is_err());
    }
    
    #[test]
    fn test_streaming_validator() {
        let mut validator = SecurityStreamingValidator::new(4096).expect("Validator creation should succeed");
        
        // Create message in parts
        let mut buffer = SecurityBuffer::new(1000).expect("Buffer creation should succeed");
        
        // Write header
        buffer.write_slice(&[0x01, 0x00]).expect("Write should succeed"); // Version
        buffer.write_u8(0x04).expect("Write should succeed"); // Message type
        buffer.write_u8(0x03).expect("Write should succeed"); // Cipher suite
        buffer.write_u64_be(12345).expect("Write should succeed"); // Message ID
        buffer.write_u32_be(64).expect("Write should succeed"); // Payload length
        buffer.write_u64_be(0).expect("Write should succeed"); // Timestamp
        
        // Write payload
        let payload = vec![0x42u8; 64];
        buffer.write_slice(&payload).expect("Write should succeed");
        
        let full_message = buffer.data().to_vec();
        
        // Add data in chunks
        let chunk1 = &full_message[..30];
        let chunk2 = &full_message[30..];
        
        assert!(!validator.has_complete_message().expect("Check should succeed"));
        
        validator.add_data(chunk1).expect("Add data should succeed");
        assert!(!validator.has_complete_message().expect("Check should succeed"));
        
        validator.add_data(chunk2).expect("Add data should succeed");
        assert!(validator.has_complete_message().expect("Check should succeed"));
        
        let extracted = validator.extract_message().expect("Extract should succeed");
        assert!(extracted.is_some());
        
        let message = extracted.unwrap();
        assert_eq!(message.header.message_type, MessageType::Data);
        assert_eq!(message.payload.len(), 64);
    }
    
    #[test]
    fn test_header_only_parsing() {
        let parser = SecurityNetworkParser::new();
        
        // Create header-only data
        let mut buffer = SecurityBuffer::new(SecurityMessageHeader::SIZE).expect("Buffer creation should succeed");
        
        buffer.write_slice(&[0x01, 0x00]).expect("Write should succeed"); // Version
        buffer.write_u8(0x04).expect("Write should succeed"); // Message type
        buffer.write_u8(0x03).expect("Write should succeed"); // Cipher suite
        buffer.write_i64_be(12345).expect("Write should succeed"); // Message ID
        buffer.write_u32_be(100).expect("Write should succeed"); // Payload length
        buffer.write_i64_be(0).expect("Write should succeed"); // Timestamp
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        // Parse header only
        let result = parser.parse_header(buffer.data());
        assert!(result.is_ok());
        
        let header = result.unwrap();
        assert_eq!(header.message_type, MessageType::Data);
        assert_eq!(header.payload_length, 100);
    }
}