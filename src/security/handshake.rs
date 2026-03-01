//! Security-hardened protocol handshake implementation
//!
//! This module provides panic-free parsing of handshake messages with
//! comprehensive bounds checking and zero-trust input validation.

use crate::security::{
    SecurityResult, SecurityError, SecurityBuffer,
    ProtocolVersion, MessageType, CipherSuite, SecurityMessageHeader,
    HandshakeState, SecurityHandshakeParser
};
use std::convert::TryFrom;

/// Maximum sizes for security validation
const MAX_ECDH_SIZE: usize = 256;
const KYBER_CIPHERTEXT_SIZE: usize = 1568;
const MAX_ECDSA_SIZE: usize = 128;
const DILITHIUM_SIGNATURE_SIZE: usize = 4595;
const MAX_EXTENSIONS_SIZE: usize = 4096;

/// Security-hardened hybrid ciphertext parsing
pub struct SecurityHybridParser;

impl SecurityHybridParser {
    /// Parse hybrid ciphertext with comprehensive bounds checking
    pub fn parse_ciphertext(buffer: &mut SecurityBuffer) -> SecurityResult<SecurityHybridCiphertext> {
        // Read ECDH ephemeral public key length (4 bytes)
        let ecdh_len = buffer.read_u32_be()? as usize;
        
        // Validate ECDH length
        const MAX_ECDH_SIZE: usize = 256;
        if ecdh_len > MAX_ECDH_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "ecdh_length".to_string(),
                limit: MAX_ECDH_SIZE,
                requested: ecdh_len,
            });
        }
        
        // Read ECDH ephemeral public key
        let ecdh_ephemeral_public = buffer.read_exact(ecdh_len)?.to_vec();
        
        // Read Kyber ciphertext (fixed size)
        const KYBER_CIPHERTEXT_SIZE: usize = 1568; // Kyber-1024 ciphertext size
        let kyber_ciphertext = buffer.read_exact(KYBER_CIPHERTEXT_SIZE)?.to_vec();
        
        Ok(SecurityHybridCiphertext {
            ecdh_ephemeral_public,
            kyber_ciphertext,
        })
    }
    
    /// Parse hybrid signature with comprehensive bounds checking
    pub fn parse_signature(buffer: &mut SecurityBuffer) -> SecurityResult<SecurityHybridSignature> {
        // Read ECDSA signature length (4 bytes)
        let ecdsa_len = buffer.read_u32_be()? as usize;
        
        // Validate ECDSA length
        const MAX_ECDSA_SIZE: usize = 128;
        if ecdsa_len > MAX_ECDSA_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "ecdsa_length".to_string(),
                limit: MAX_ECDSA_SIZE,
                requested: ecdsa_len,
            });
        }
        
        // Read ECDSA signature
        let ecdsa_signature = buffer.read_exact(ecdsa_len)?.to_vec();
        
        // Read Dilithium signature (fixed size)
        const DILITHIUM_SIGNATURE_SIZE: usize = 4595; // Dilithium5 signature size
        let dilithium_signature = buffer.read_exact(DILITHIUM_SIGNATURE_SIZE)?.to_vec();
        
        Ok(SecurityHybridSignature {
            ecdsa_signature,
            dilithium_signature,
        })
    }
    
    /// Serialize hybrid ciphertext with bounds checking
    pub fn serialize_ciphertext(ciphertext: &SecurityHybridCiphertext, buffer: &mut SecurityBuffer) -> SecurityResult<()> {
        // Validate sizes
        if ciphertext.ecdh_ephemeral_public.len() > MAX_ECDH_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "ecdh_public_key_size".to_string(),
                limit: MAX_ECDH_SIZE,
                requested: ciphertext.ecdh_ephemeral_public.len(),
            });
        }
        
        if ciphertext.kyber_ciphertext.len() != KYBER_CIPHERTEXT_SIZE {
            return Err(SecurityError::InvalidLength {
                expected: KYBER_CIPHERTEXT_SIZE,
                actual: ciphertext.kyber_ciphertext.len(),
            });
        }
        
        // Write ECDH length and data
        buffer.write_u32_be(ciphertext.ecdh_ephemeral_public.len() as u32)?;
        buffer.write_slice(&ciphertext.ecdh_ephemeral_public)?;
        
        // Write Kyber ciphertext
        buffer.write_slice(&ciphertext.kyber_ciphertext)?;
        
        Ok(())
    }
    
    /// Serialize hybrid signature with bounds checking
    pub fn serialize_signature(signature: &SecurityHybridSignature, buffer: &mut SecurityBuffer) -> SecurityResult<()> {
        // Validate sizes
        if signature.ecdsa_signature.len() > MAX_ECDSA_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "ecdsa_signature_size".to_string(),
                limit: MAX_ECDSA_SIZE,
                requested: signature.ecdsa_signature.len(),
            });
        }
        
        if signature.dilithium_signature.len() != DILITHIUM_SIGNATURE_SIZE {
            return Err(SecurityError::InvalidLength {
                expected: DILITHIUM_SIGNATURE_SIZE,
                actual: signature.dilithium_signature.len(),
            });
        }
        
        // Write ECDSA length and data
        buffer.write_u32_be(signature.ecdsa_signature.len() as u32)?;
        buffer.write_slice(&signature.ecdsa_signature)?;
        
        // Write Dilithium signature
        buffer.write_slice(&signature.dilithium_signature)?;
        
        Ok(())
    }
}

/// Security-hardened hybrid ciphertext structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHybridCiphertext {
    pub ecdh_ephemeral_public: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
}

/// Security-hardened hybrid signature structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHybridSignature {
    pub ecdsa_signature: Vec<u8>,
    pub dilithium_signature: Vec<u8>,
}

/// Security-hardened handshake message parser
pub struct SecurityHandshakeMessageParser;

impl SecurityHandshakeMessageParser {
    /// Parse handshake init message
    pub fn parse_init(buffer: &mut SecurityBuffer) -> SecurityResult<SecurityHandshakeInit> {
        // Parse protocol version
        let version_bytes = buffer.read_exact(2)?;
        let version = ProtocolVersion::from_bytes([version_bytes[0], version_bytes[1]])?;
        
        // Parse cipher suite
        let cipher_suite_byte = buffer.read_u8()?;
        let cipher_suite = CipherSuite::from_u8(cipher_suite_byte)?;
        
        // Parse ephemeral public keys
        let ephemeral_keys = SecurityHybridParser::parse_ciphertext(buffer)?;
        
        // Parse timestamp
        let timestamp = buffer.read_i64_be()?;
        
        // Parse extensions length
        let extensions_len = buffer.read_u16_be()? as usize;
        
        // Validate extensions length
        const MAX_EXTENSIONS_SIZE: usize = 4096;
        if extensions_len > MAX_EXTENSIONS_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "extensions_length".to_string(),
                limit: MAX_EXTENSIONS_SIZE,
                requested: extensions_len,
            });
        }
        
        // Parse extensions
        let extensions = if extensions_len > 0 {
            buffer.read_exact(extensions_len)?.to_vec()
        } else {
            Vec::new()
        };
        
        Ok(SecurityHandshakeInit {
            version,
            cipher_suite,
            ephemeral_keys,
            timestamp: timestamp.try_into().unwrap_or(0),
            extensions,
        })
    }
    
    /// Parse handshake response message
    pub fn parse_response(buffer: &mut SecurityBuffer) -> SecurityResult<SecurityHandshakeResponse> {
        // Parse protocol version
        let version_bytes = buffer.read_exact(2)?;
        let version = ProtocolVersion::from_bytes([version_bytes[0], version_bytes[1]])?;
        
        // Parse cipher suite
        let cipher_suite_byte = buffer.read_u8()?;
        let cipher_suite = CipherSuite::from_u8(cipher_suite_byte)?;
        
        // Parse ephemeral public keys
        let ephemeral_keys = SecurityHybridParser::parse_ciphertext(buffer)?;
        
        // Parse signature
        let signature = SecurityHybridParser::parse_signature(buffer)?;
        
        // Parse timestamp
        let timestamp = buffer.read_i64_be()?;
        
        // Parse extensions length
        let extensions_len = buffer.read_u16_be()? as usize;
        
        // Validate extensions length
        if extensions_len > MAX_EXTENSIONS_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "extensions_length".to_string(),
                limit: MAX_EXTENSIONS_SIZE,
                requested: extensions_len,
            });
        }
        
        // Parse extensions
        let extensions = if extensions_len > 0 {
            buffer.read_exact(extensions_len)?.to_vec()
        } else {
            Vec::new()
        };
        
        Ok(SecurityHandshakeResponse {
            version,
            cipher_suite,
            ephemeral_keys,
            signature,
            timestamp: timestamp.try_into().unwrap_or(0),
            extensions,
        })
    }
    
    /// Parse handshake complete message
    pub fn parse_complete(buffer: &mut SecurityBuffer) -> SecurityResult<SecurityHandshakeComplete> {
        // Parse protocol version
        let version_bytes = buffer.read_exact(2)?;
        let version = ProtocolVersion::from_bytes([version_bytes[0], version_bytes[1]])?;
        
        // Parse signature
        let signature = SecurityHybridParser::parse_signature(buffer)?;
        
        // Parse timestamp
        let timestamp = buffer.read_i64_be()?;
        
        // Parse extensions length
        let extensions_len = buffer.read_u16_be()? as usize;
        
        // Validate extensions length
        if extensions_len > MAX_EXTENSIONS_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "extensions_length".to_string(),
                limit: MAX_EXTENSIONS_SIZE,
                requested: extensions_len,
            });
        }
        
        // Parse extensions
        let extensions = if extensions_len > 0 {
            buffer.read_exact(extensions_len)?.to_vec()
        } else {
            Vec::new()
        };
        
        Ok(SecurityHandshakeComplete {
            version,
            signature,
            timestamp: timestamp.try_into().unwrap_or(0),
            extensions,
        })
    }
}

/// Security-hardened handshake init message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHandshakeInit {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub ephemeral_keys: SecurityHybridCiphertext,
    pub timestamp: u64,
    pub extensions: Vec<u8>,
}

/// Security-hardened handshake response message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHandshakeResponse {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub ephemeral_keys: SecurityHybridCiphertext,
    pub signature: SecurityHybridSignature,
    pub timestamp: u64,
    pub extensions: Vec<u8>,
}

/// Security-hardened handshake complete message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHandshakeComplete {
    pub version: ProtocolVersion,
    pub signature: SecurityHybridSignature,
    pub timestamp: u64,
    pub extensions: Vec<u8>,
}

/// Handshake state machine implementation
pub struct SecurityHandshakeStateMachine {
    state: HandshakeState,
    max_message_size: usize,
}

impl SecurityHandshakeStateMachine {
    pub fn new(max_message_size: usize) -> SecurityResult<Self> {
        // Validate max message size
        const MIN_MESSAGE_SIZE: usize = 1024; // 1 KB minimum
        const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64 KB maximum
        
        if max_message_size < MIN_MESSAGE_SIZE || max_message_size > MAX_MESSAGE_SIZE {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "max_message_size".to_string(),
                limit: MAX_MESSAGE_SIZE,
                requested: max_message_size,
            });
        }
        
        Ok(SecurityHandshakeStateMachine {
            state: HandshakeState::Init,
            max_message_size,
        })
    }
    
    pub fn process_init(&mut self, data: &[u8]) -> SecurityResult<SecurityHandshakeInit> {
        // Validate state transition
        self.state.can_transition_to(HandshakeState::WaitingResponse)?;
        
        // Validate message size
        if data.len() > self.max_message_size {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "message_size".to_string(),
                limit: self.max_message_size,
                requested: data.len(),
            });
        }
        
        // Parse message
        let mut buffer = SecurityBuffer::new(data.len())?;
        buffer.write_slice(data)?;
        buffer.set_position(0)?;
        
        let init = SecurityHandshakeMessageParser::parse_init(&mut buffer)?;
        
        // Update state
        self.state = HandshakeState::WaitingResponse;
        
        Ok(init)
    }
    
    pub fn process_response(&mut self, data: &[u8]) -> SecurityResult<SecurityHandshakeResponse> {
        // Validate state transition
        self.state.can_transition_to(HandshakeState::WaitingComplete)?;
        
        // Validate message size
        if data.len() > self.max_message_size {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "message_size".to_string(),
                limit: self.max_message_size,
                requested: data.len(),
            });
        }
        
        // Parse message
        let mut buffer = SecurityBuffer::new(data.len())?;
        buffer.write_slice(data)?;
        buffer.set_position(0)?;
        
        let response = SecurityHandshakeMessageParser::parse_response(&mut buffer)?;
        
        // Update state
        self.state = HandshakeState::WaitingComplete;
        
        Ok(response)
    }
    
    pub fn process_complete(&mut self, data: &[u8]) -> SecurityResult<SecurityHandshakeComplete> {
        // Validate state transition
        self.state.can_transition_to(HandshakeState::Completed)?;
        
        // Validate message size
        if data.len() > self.max_message_size {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: "message_size".to_string(),
                limit: self.max_message_size,
                requested: data.len(),
            });
        }
        
        // Parse message
        let mut buffer = SecurityBuffer::new(data.len())?;
        buffer.write_slice(data)?;
        buffer.set_position(0)?;
        
        let complete = SecurityHandshakeMessageParser::parse_complete(&mut buffer)?;
        
        // Update state
        self.state = HandshakeState::Completed;
        
        Ok(complete)
    }
    
    pub fn current_state(&self) -> HandshakeState {
        self.state
    }
    
    pub fn transition_state(&mut self, new_state: HandshakeState) -> SecurityResult<()> {
        self.state.can_transition_to(new_state)?;
        self.state = new_state;
        Ok(())
    }
    
    pub fn reset(&mut self) -> SecurityResult<()> {
        self.state.can_transition_to(HandshakeState::Init)?;
        self.state = HandshakeState::Init;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hybrid_ciphertext_parsing() {
        let mut buffer = SecurityBuffer::new(2000).expect("Buffer creation should succeed");
        
        // Create test ciphertext
        let ecdh_public = vec![0u8; 32];
        let kyber_ciphertext = vec![0u8; 1568];
        
        // Write to buffer
        buffer.write_u32_be(ecdh_public.len() as u32).expect("Write should succeed");
        buffer.write_slice(&ecdh_public).expect("Write should succeed");
        buffer.write_slice(&kyber_ciphertext).expect("Write should succeed");
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        // Parse
        let parsed = SecurityHybridParser::parse_ciphertext(&mut buffer);
        assert!(parsed.is_ok());
        
        let ciphertext = parsed.unwrap();
        assert_eq!(ciphertext.ecdh_ephemeral_public.len(), 32);
        assert_eq!(ciphertext.kyber_ciphertext.len(), 1568);
    }
    
    #[test]
    fn test_hybrid_signature_parsing() {
        let mut buffer = SecurityBuffer::new(5000).expect("Buffer creation should succeed");
        
        // Create test signature
        let ecdsa_signature = vec![0u8; 64];
        let dilithium_signature = vec![0u8; 4595];
        
        // Write to buffer
        buffer.write_u32_be(ecdsa_signature.len() as u32).expect("Write should succeed");
        buffer.write_slice(&ecdsa_signature).expect("Write should succeed");
        buffer.write_slice(&dilithium_signature).expect("Write should succeed");
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        // Parse
        let parsed = SecurityHybridParser::parse_signature(&mut buffer);
        assert!(parsed.is_ok());
        
        let signature = parsed.unwrap();
        assert_eq!(signature.ecdsa_signature.len(), 64);
        assert_eq!(signature.dilithium_signature.len(), 4595);
    }
    
    #[test]
    fn test_handshake_state_machine_transitions() {
        let mut sm = SecurityHandshakeStateMachine::new(16384).expect("State machine creation should succeed");
        
        assert_eq!(sm.current_state(), HandshakeState::Init);
        
        // Create valid init message
        let mut buffer = SecurityBuffer::new(2000).expect("Buffer creation should succeed");
        buffer.write_slice(&[0x01, 0x00]).expect("Write should succeed"); // Version
        buffer.write_u8(0x01).expect("Write should succeed"); // Cipher suite
        
        // Add ephemeral keys (simplified)
        buffer.write_u32_be(32).expect("Write should succeed");
        buffer.write_slice(&vec![0u8; 32]).expect("Write should succeed");
        buffer.write_slice(&vec![0u8; 1568]).expect("Write should succeed");
        
        // Add timestamp and extensions
        buffer.write_u64_be(1234567890).expect("Write should succeed");
        buffer.write_u16_be(0).expect("Write should succeed"); // No extensions
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        let data = buffer.as_slice();
        let result = sm.process_init(data);
        assert!(result.is_ok());
        assert_eq!(sm.current_state(), HandshakeState::WaitingResponse);
    }
    
    #[test]
    fn test_bounds_checking() {
        let mut buffer = SecurityBuffer::new(100).expect("Buffer creation should succeed");
        
        // Write insufficient data for ECDH length
        buffer.write_u8(0x42).expect("Write should succeed");
        buffer.set_position(0).expect("Set position should succeed");
        
        // Try to parse - should fail due to insufficient data
        let result = SecurityHybridParser::parse_ciphertext(&mut buffer);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_oversized_message_protection() {
        let mut sm = SecurityHandshakeStateMachine::new(16384).expect("State machine creation should succeed");
        
        // Create oversized message
        let oversized_data = vec![0u8; 20000];
        
        // Should fail due to size limit
        let result = sm.process_init(&oversized_data);
        assert!(result.is_err());
    }
}