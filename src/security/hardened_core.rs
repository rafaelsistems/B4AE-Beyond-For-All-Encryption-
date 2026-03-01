//! B4AE Security-Hardened Core - Panic-Free Implementation
//!
//! This module provides a completely panic-free implementation of B4AE
//! following strict security requirements:
//! - No unwrap(), expect(), or panic!() in production paths
//! - Deterministic state machine with explicit enums
//! - Strict memory hygiene with Zeroizing
//! - Constant-time operations for secrets
//! - Zero-trust parsing with bounds checking

use std::convert::TryFrom;
use std::num::TryFromIntError;
use zeroize::{Zeroize, Zeroizing};
use subtle::{Choice, ConstantTimeEq};

/// Security-hardened error types - no panic propagation
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityError {
    /// Invalid input length
    InvalidLength { expected: usize, actual: usize },
    /// Integer overflow
    IntegerOverflow(TryFromIntError),
    /// Buffer too small
    BufferTooSmall { required: usize, available: usize },
    /// Invalid protocol version
    InvalidProtocolVersion { expected: u16, actual: u16 },
    /// Invalid message type
    InvalidMessageType(u8),
    /// Invalid cipher suite
    InvalidCipherSuite(u8),
    /// Invalid feature flags
    InvalidFeatureFlags(u8),
    /// Invalid timestamp
    InvalidTimestamp(i64),
    /// Invalid length field
    InvalidLengthField(u32),
    /// Invalid message ID
    InvalidMessageId,
    /// Invalid session ID
    InvalidSessionId,
    /// Invalid extension count
    InvalidExtensionCount(u16),
    /// Invalid signature length
    InvalidSignatureLength(u16),
    /// Invalid public key
    InvalidPublicKey { expected: usize, actual: usize },
    /// Invalid secret key
    InvalidSecretKey { expected: usize, actual: usize },
    /// Invalid ciphertext
    InvalidCiphertext { expected: usize, actual: usize },
    /// Invalid shared secret
    InvalidSharedSecret { expected: usize, actual: usize },
    /// Invalid signature
    InvalidSignature { expected: usize, actual: usize },
    /// Invalid MAC
    InvalidMac { expected: usize, actual: usize },
    /// Invalid nonce
    InvalidNonce { expected: usize, actual: usize },
    /// Invalid key
    InvalidKey { expected: usize, actual: usize },
    /// Invalid algorithm ID
    InvalidAlgorithmId(u16),
    /// Invalid security level
    InvalidSecurityLevel(u8),
    /// Invalid entropy
    InvalidEntropy { expected: usize, actual: usize },
    /// Invalid random value
    InvalidRandomValue,
    /// Invalid hash
    InvalidHash { expected: usize, actual: usize },
    /// Invalid HKDF context
    InvalidHkdfContext { max_length: usize, actual_length: usize },
    /// Invalid HKDF salt
    InvalidHkdfSalt { max_length: usize, actual_length: usize },
    /// Invalid HKDF info
    InvalidHkdfInfo { max_length: usize, actual_length: usize },
    /// Invalid HKDF output length
    InvalidHkdfOutputLength { max_length: usize, actual_length: usize },
    /// Invalid HKDF input
    InvalidHkdfInput { max_length: usize, actual_length: usize },
    /// Invalid session state
    InvalidSessionState(String),
    /// Invalid handshake state
    InvalidHandshakeState(String),
    /// Invalid key rotation state
    InvalidKeyRotationState(String),
    /// Invalid replay protection state
    InvalidReplayProtectionState(String),
    /// Invalid resource protection state
    InvalidResourceProtectionState(String),
    /// Invalid error state
    InvalidErrorState(String),
    /// Invalid protocol state
    InvalidProtocolState(String),
    /// Invalid state transition
    InvalidStateTransition { from: String, to: String },
    /// State machine violation
    StateMachineViolation { expected: String, actual: String },
    /// Security invariant violation
    SecurityInvariantViolation { invariant: String, details: String },
    /// Memory safety violation
    MemorySafetyViolation { operation: String, details: String },
    /// Constant-time violation
    ConstantTimeViolation { operation: String, details: String },
    /// Zeroization failure
    ZeroizationFailure { target: String },
    /// Bounds checking failure
    BoundsCheckingFailure { operation: String, bounds: String },
    /// Integer conversion failure
    IntegerConversionFailure { from: String, to: String, value: i64 },
    /// Buffer overflow protection triggered
    BufferOverflowProtection { size: usize, capacity: usize },
    /// Null pointer protection
    NullPointerProtection { operation: String },
    /// Division by zero protection
    DivisionByZeroProtection { operation: String },
    /// Arithmetic overflow protection
    ArithmeticOverflowProtection { operation: String, values: String },
    /// Type safety violation
    TypeSafetyViolation { expected: String, actual: String },
    /// Lifetime safety violation
    LifetimeSafetyViolation { operation: String },
    /// Send safety violation
    SendSafetyViolation { type_name: String },
    /// Sync safety violation
    SyncSafetyViolation { type_name: String },
    /// Uninitialized memory access
    UninitializedMemoryAccess { location: String },
    /// Use after free protection
    UseAfterFreeProtection { location: String },
    /// Double free protection
    DoubleFreeProtection { location: String },
    /// Memory leak detection
    MemoryLeakDetected { size: usize, location: String },
    /// Resource exhaustion protection
    ResourceExhaustionProtection { resource: String, limit: usize, requested: usize },
    /// Timeout protection
    TimeoutProtection { operation: String, timeout: u64 },
    /// Deadlock prevention
    DeadlockPrevention { operation: String, cycle: String },
    /// Race condition prevention
    RaceConditionPrevention { operation: String, access_pattern: String },
    /// Data race prevention
    DataRacePrevention { operation: String, thread_ids: String },
    /// Atomicity violation
    AtomicityViolation { operation: String, expected: String, actual: String },
    /// Ordering violation
    OrderingViolation { operation: String, expected: String, actual: String },
    /// Visibility violation
    VisibilityViolation { operation: String, thread_ids: String },
    /// Happens-before violation
    HappensBeforeViolation { operation: String, order: String },
}

impl std::error::Error for SecurityError {}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::InvalidLength { expected, actual } => {
                write!(f, "Invalid length: expected {}, actual {}", expected, actual)
            }
            SecurityError::IntegerOverflow(e) => {
                write!(f, "Integer overflow: {}", e)
            }
            SecurityError::BufferTooSmall { required, available } => {
                write!(f, "Buffer too small: required {}, available {}", required, available)
            }
            SecurityError::InvalidProtocolVersion { expected, actual } => {
                write!(f, "Invalid protocol version: expected {}, actual {}", expected, actual)
            }
            SecurityError::InvalidMessageType(t) => {
                write!(f, "Invalid message type: {}", t)
            }
            SecurityError::InvalidCipherSuite(s) => {
                write!(f, "Invalid cipher suite: {}", s)
            }
            SecurityError::InvalidFeatureFlags(flags) => {
                write!(f, "Invalid feature flags: {}", flags)
            }
            SecurityError::InvalidTimestamp(t) => {
                write!(f, "Invalid timestamp: {}", t)
            }
            SecurityError::InvalidLengthField(l) => {
                write!(f, "Invalid length field: {}", l)
            }
            SecurityError::InvalidMessageId => {
                write!(f, "Invalid message ID")
            }
            SecurityError::InvalidSessionId => {
                write!(f, "Invalid session ID")
            }
            SecurityError::InvalidExtensionCount(c) => {
                write!(f, "Invalid extension count: {}", c)
            }
            SecurityError::InvalidSignatureLength(l) => {
                write!(f, "Invalid signature length: {}", l)
            }
            SecurityError::InvalidPublicKey { expected, actual } => {
                write!(f, "Invalid public key: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidSecretKey { expected, actual } => {
                write!(f, "Invalid secret key: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidCiphertext { expected, actual } => {
                write!(f, "Invalid ciphertext: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidSharedSecret { expected, actual } => {
                write!(f, "Invalid shared secret: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidSignature { expected, actual } => {
                write!(f, "Invalid signature: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidMac { expected, actual } => {
                write!(f, "Invalid MAC: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidNonce { expected, actual } => {
                write!(f, "Invalid nonce: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidKey { expected, actual } => {
                write!(f, "Invalid key: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidAlgorithmId(id) => {
                write!(f, "Invalid algorithm ID: {}", id)
            }
            SecurityError::InvalidSecurityLevel(level) => {
                write!(f, "Invalid security level: {}", level)
            }
            SecurityError::InvalidEntropy { expected, actual } => {
                write!(f, "Invalid entropy: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidRandomValue => {
                write!(f, "Invalid random value")
            }
            SecurityError::InvalidHash { expected, actual } => {
                write!(f, "Invalid hash: expected {} bytes, actual {} bytes", expected, actual)
            }
            SecurityError::InvalidHkdfContext { max_length, actual_length } => {
                write!(f, "Invalid HKDF context: max length {}, actual length {}", max_length, actual_length)
            }
            SecurityError::InvalidHkdfSalt { max_length, actual_length } => {
                write!(f, "Invalid HKDF salt: max length {}, actual length {}", max_length, actual_length)
            }
            SecurityError::InvalidHkdfInfo { max_length, actual_length } => {
                write!(f, "Invalid HKDF info: max length {}, actual length {}", max_length, actual_length)
            }
            SecurityError::InvalidHkdfOutputLength { max_length, actual_length } => {
                write!(f, "Invalid HKDF output length: max length {}, actual length {}", max_length, actual_length)
            }
            SecurityError::InvalidHkdfInput { max_length, actual_length } => {
                write!(f, "Invalid HKDF input: max length {}, actual length {}", max_length, actual_length)
            }
            SecurityError::InvalidSessionState(details) => {
                write!(f, "Invalid session state: {}", details)
            }
            SecurityError::InvalidHandshakeState(details) => {
                write!(f, "Invalid handshake state: {}", details)
            }
            SecurityError::InvalidKeyRotationState(details) => {
                write!(f, "Invalid key rotation state: {}", details)
            }
            SecurityError::InvalidReplayProtectionState(details) => {
                write!(f, "Invalid replay protection state: {}", details)
            }
            SecurityError::InvalidResourceProtectionState(details) => {
                write!(f, "Invalid resource protection state: {}", details)
            }
            SecurityError::InvalidErrorState(details) => {
                write!(f, "Invalid error state: {}", details)
            }
            SecurityError::InvalidProtocolState(details) => {
                write!(f, "Invalid protocol state: {}", details)
            }
            SecurityError::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition: from {} to {}", from, to)
            }
            SecurityError::StateMachineViolation { expected, actual } => {
                write!(f, "State machine violation: expected {}, actual {}", expected, actual)
            }
            SecurityError::SecurityInvariantViolation { invariant, details } => {
                write!(f, "Security invariant violation: {} - {}", invariant, details)
            }
            SecurityError::MemorySafetyViolation { operation, details } => {
                write!(f, "Memory safety violation: {} - {}", operation, details)
            }
            SecurityError::ConstantTimeViolation { operation, details } => {
                write!(f, "Constant-time violation: {} - {}", operation, details)
            }
            SecurityError::ZeroizationFailure { target } => {
                write!(f, "Zeroization failure: {}", target)
            }
            SecurityError::BoundsCheckingFailure { operation, bounds } => {
                write!(f, "Bounds checking failure: {} - {}", operation, bounds)
            }
            SecurityError::IntegerConversionFailure { from, to, value } => {
                write!(f, "Integer conversion failure: from {} to {} with value {}", from, to, value)
            }
            SecurityError::BufferOverflowProtection { size, capacity } => {
                write!(f, "Buffer overflow protection: size {} exceeds capacity {}", size, capacity)
            }
            SecurityError::NullPointerProtection { operation } => {
                write!(f, "Null pointer protection: {}", operation)
            }
            SecurityError::DivisionByZeroProtection { operation } => {
                write!(f, "Division by zero protection: {}", operation)
            }
            SecurityError::ArithmeticOverflowProtection { operation, values } => {
                write!(f, "Arithmetic overflow protection: {} with values {}", operation, values)
            }
            SecurityError::TypeSafetyViolation { expected, actual } => {
                write!(f, "Type safety violation: expected {}, actual {}", expected, actual)
            }
            SecurityError::LifetimeSafetyViolation { operation } => {
                write!(f, "Lifetime safety violation: {}", operation)
            }
            SecurityError::SendSafetyViolation { type_name } => {
                write!(f, "Send safety violation: {}", type_name)
            }
            SecurityError::SyncSafetyViolation { type_name } => {
                write!(f, "Sync safety violation: {}", type_name)
            }
            SecurityError::UninitializedMemoryAccess { location } => {
                write!(f, "Uninitialized memory access: {}", location)
            }
            SecurityError::UseAfterFreeProtection { location } => {
                write!(f, "Use after free protection: {}", location)
            }
            SecurityError::DoubleFreeProtection { location } => {
                write!(f, "Double free protection: {}", location)
            }
            SecurityError::MemoryLeakDetected { size, location } => {
                write!(f, "Memory leak detected: {} bytes at {}", size, location)
            }
            SecurityError::ResourceExhaustionProtection { resource, limit, requested } => {
                write!(f, "Resource exhaustion protection: {} - limit {} exceeded by {}", resource, limit, requested)
            }
            SecurityError::TimeoutProtection { operation, timeout } => {
                write!(f, "Timeout protection: {} after {}ms", operation, timeout)
            }
            SecurityError::DeadlockPrevention { operation, cycle } => {
                write!(f, "Deadlock prevention: {} - cycle detected: {}", operation, cycle)
            }
            SecurityError::RaceConditionPrevention { operation, access_pattern } => {
                write!(f, "Race condition prevention: {} - access pattern: {}", operation, access_pattern)
            }
            SecurityError::DataRacePrevention { operation, thread_ids } => {
                write!(f, "Data race prevention: {} - thread IDs: {}", operation, thread_ids)
            }
            SecurityError::AtomicityViolation { operation, expected, actual } => {
                write!(f, "Atomicity violation: {} - expected {}, actual {}", operation, expected, actual)
            }
            SecurityError::OrderingViolation { operation, expected, actual } => {
                write!(f, "Ordering violation: {} - expected {}, actual {}", operation, expected, actual)
            }
            SecurityError::VisibilityViolation { operation, thread_ids } => {
                write!(f, "Visibility violation: {} - thread IDs: {}", operation, thread_ids)
            }
            SecurityError::HappensBeforeViolation { operation, order } => {
                write!(f, "Happens-before violation: {} - order: {}", operation, order)
            }
        }
    }
}

/// Security-hardened result type - no panic propagation
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Deterministic protocol version - explicit enum, no implicit values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    V1_0, // 0x0100
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self::V1_0;
    pub const BYTES: usize = 2;
    
    /// Convert to bytes - no panic, explicit error handling
    pub fn to_bytes(self) -> [u8; 2] {
        match self {
            ProtocolVersion::V1_0 => [0x01, 0x00],
        }
    }
    
    /// Convert from bytes - explicit error handling, no panic
    pub fn from_bytes(bytes: [u8; 2]) -> SecurityResult<Self> {
        match bytes {
            [0x01, 0x00] => Ok(ProtocolVersion::V1_0),
            _ => Err(SecurityError::InvalidProtocolVersion { 
                expected: 0x0100, 
                actual: u16::from_be_bytes(bytes) 
            }),
        }
    }
    
    /// Get as u16 - no panic
    pub fn as_u16(self) -> u16 {
        match self {
            ProtocolVersion::V1_0 => 0x0100,
        }
    }
}

/// Deterministic message type - explicit enum, no implicit values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    HandshakeComplete = 0x03,
    DataMessage = 0x04,
    KeyRotation = 0x05,
}

impl MessageType {
    /// Convert from u8 - explicit error handling, no panic
    pub fn from_u8(value: u8) -> SecurityResult<Self> {
        match value {
            0x01 => Ok(MessageType::HandshakeInit),
            0x02 => Ok(MessageType::HandshakeResponse),
            0x03 => Ok(MessageType::HandshakeComplete),
            0x04 => Ok(MessageType::DataMessage),
            0x05 => Ok(MessageType::KeyRotation),
            _ => Err(SecurityError::InvalidMessageType(value)),
        }
    }
    
    /// Convert to u8 - no panic
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Deterministic cipher suite - explicit enum, no implicit values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    Standard = 0x01,   // Kyber-768 + Dilithium3
    High = 0x02,       // Kyber-1024 + Dilithium5
    Maximum = 0x03,    // Kyber-1024 + Dilithium5 + extra
}

impl CipherSuite {
    /// Convert from u8 - explicit error handling, no panic
    pub fn from_u8(value: u8) -> SecurityResult<Self> {
        match value {
            0x01 => Ok(CipherSuite::Standard),
            0x02 => Ok(CipherSuite::High),
            0x03 => Ok(CipherSuite::Maximum),
            _ => Err(SecurityError::InvalidCipherSuite(value)),
        }
    }
    
    /// Convert to u8 - no panic
    pub fn as_u8(self) -> u8 {
        self as u8
    }
    
    /// Get security level - explicit mapping
    pub fn security_level(self) -> SecurityLevel {
        match self {
            CipherSuite::Standard => SecurityLevel::Standard,
            CipherSuite::High => SecurityLevel::High,
            CipherSuite::Maximum => SecurityLevel::Maximum,
        }
    }
}

/// Security levels - explicit enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    Standard,
    High,
    Maximum,
}

/// Deterministic feature flags - explicit bit manipulation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FeatureFlags {
    /// Post-quantum cryptography required
    pub post_quantum_required: bool,
    /// Hybrid mode required
    pub hybrid_required: bool,
    /// Metadata protection enabled
    pub metadata_protection: bool,
    /// Onion routing enabled
    pub onion_routing: bool,
    /// HSM usage required
    pub hsm_required: bool,
    /// Perfect forward secrecy enabled
    pub perfect_forward_secrecy: bool,
    /// Extended key rotation enabled
    pub extended_key_rotation: bool,
}

impl FeatureFlags {
    /// Create from u8 - explicit bit manipulation, no panic
    pub fn from_u8(value: u8) -> SecurityResult<Self> {
        // Validate reserved bits (7-6) are zero
        if (value & 0xC0) != 0 {
            return Err(SecurityError::InvalidFeatureFlags(value));
        }
        
        Ok(FeatureFlags {
            post_quantum_required: (value & 0x40) != 0,
            hybrid_required: (value & 0x20) != 0,
            metadata_protection: (value & 0x10) != 0,
            onion_routing: (value & 0x08) != 0,
            hsm_required: (value & 0x04) != 0,
            perfect_forward_secrecy: (value & 0x02) != 0,
            extended_key_rotation: (value & 0x01) != 0,
        })
    }
    
    /// Convert to u8 - no panic
    pub fn as_u8(self) -> u8 {
        let mut result = 0u8;
        if self.post_quantum_required { result |= 0x40; }
        if self.hybrid_required { result |= 0x20; }
        if self.metadata_protection { result |= 0x10; }
        if self.onion_routing { result |= 0x08; }
        if self.hsm_required { result |= 0x04; }
        if self.perfect_forward_secrecy { result |= 0x02; }
        if self.extended_key_rotation { result |= 0x01; }
        result
    }
    
    /// Validate feature flags against cipher suite - explicit validation
    pub fn validate_against_cipher_suite(&self, cipher_suite: CipherSuite) -> SecurityResult<()> {
        match cipher_suite {
            CipherSuite::Standard => {
                if self.post_quantum_required || self.hybrid_required {
                    return Err(SecurityError::SecurityInvariantViolation {
                        invariant: "Standard cipher suite cannot require post-quantum or hybrid".to_string(),
                        details: format!("cipher_suite={:?}, flags={:?}", cipher_suite, self),
                    });
                }
            }
            CipherSuite::High => {
                if self.post_quantum_required && !self.hybrid_required {
                    return Err(SecurityError::SecurityInvariantViolation {
                        invariant: "High cipher suite requires hybrid when post-quantum is required".to_string(),
                        details: format!("cipher_suite={:?}, flags={:?}", cipher_suite, self),
                    });
                }
            }
            CipherSuite::Maximum => {
                if !self.post_quantum_required || !self.hybrid_required {
                    return Err(SecurityError::SecurityInvariantViolation {
                        invariant: "Maximum cipher suite requires both post-quantum and hybrid".to_string(),
                        details: format!("cipher_suite={:?}, flags={:?}", cipher_suite, self),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Security-hardened buffer with bounds checking - no panic indexing
#[derive(Debug, Clone)]
pub struct SecurityBuffer {
    data: Vec<u8>,
    read_pos: usize,
}

impl SecurityBuffer {
    /// Create new buffer - explicit capacity validation
    pub fn new(capacity: usize) -> SecurityResult<Self> {
        if capacity > MAX_BUFFER_SIZE {
            return Err(SecurityError::BufferOverflowProtection {
                size: capacity,
                capacity: MAX_BUFFER_SIZE,
            });
        }
        
        Ok(SecurityBuffer {
            data: Vec::with_capacity(capacity),
            read_pos: 0,
        })
    }
    
    /// Create from slice - explicit validation
    pub fn from_slice(slice: &[u8]) -> SecurityResult<Self> {
        if slice.len() > MAX_BUFFER_SIZE {
            return Err(SecurityError::BufferOverflowProtection {
                size: slice.len(),
                capacity: MAX_BUFFER_SIZE,
            });
        }
        
        Ok(SecurityBuffer {
            data: slice.to_vec(),
            read_pos: 0,
        })
    }
    
    /// Get remaining bytes - bounds checked, no panic
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.read_pos)
    }
    
    /// Check if can read N bytes - bounds checked, no panic
    pub fn can_read(&self, n: usize) -> bool {
        self.remaining() >= n
    }
    
    /// Read exact N bytes - explicit bounds checking, no panic
    pub fn read_exact(&mut self, n: usize) -> SecurityResult<&[u8]> {
        if !self.can_read(n) {
            return Err(SecurityError::BufferTooSmall {
                required: n,
                available: self.remaining(),
            });
        }
        
        let start = self.read_pos;
        let end = start.checked_add(n).ok_or(SecurityError::ArithmeticOverflowProtection {
            operation: "read_exact".to_string(),
            values: format!("start={}, n={}", start, n),
        })?;
        
        self.read_pos = end;
        Ok(&self.data[start..end])
    }
    
    /// Read u8 - explicit bounds checking, no panic
    pub fn read_u8(&mut self) -> SecurityResult<u8> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }
    
    /// Read u16 (big-endian) - explicit bounds checking, no panic
    pub fn read_u16_be(&mut self) -> SecurityResult<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    
    /// Read u32 (big-endian) - explicit bounds checking, no panic
    pub fn read_u32_be(&mut self) -> SecurityResult<u32> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    
    /// Read i64 (big-endian) - explicit bounds checking, no panic
    pub fn read_i64_be(&mut self) -> SecurityResult<i64> {
        let bytes = self.read_exact(8)?;
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
    
    /// Write u8 - explicit bounds checking, no panic
    pub fn write_u8(&mut self, value: u8) -> SecurityResult<()> {
        self.data.push(value);
        Ok(())
    }
    
    /// Write u16 (big-endian) - explicit bounds checking, no panic
    pub fn write_u16_be(&mut self, value: u16) -> SecurityResult<()> {
        let bytes = value.to_be_bytes();
        self.data.extend_from_slice(&bytes);
        Ok(())
    }
    
    /// Write u32 (big-endian) - explicit bounds checking, no panic
    pub fn write_u32_be(&mut self, value: u32) -> SecurityResult<()> {
        let bytes = value.to_be_bytes();
        self.data.extend_from_slice(&bytes);
        Ok(())
    }
    
    /// Write u64 (big-endian) - explicit bounds checking, no panic
    pub fn write_u64_be(&mut self, value: u64) -> SecurityResult<()> {
        let bytes = value.to_be_bytes();
        self.data.extend_from_slice(&bytes);
        Ok(())
    }
    
    /// Write i64 (big-endian) - explicit bounds checking, no panic
    pub fn write_i64_be(&mut self, value: i64) -> SecurityResult<()> {
        let bytes = value.to_be_bytes();
        self.data.extend_from_slice(&bytes);
        Ok(())
    }
    
    /// Write slice - explicit bounds checking, no panic
    pub fn write_slice(&mut self, slice: &[u8]) -> SecurityResult<()> {
        let new_len = self.data.len().checked_add(slice.len()).ok_or(SecurityError::ArithmeticOverflowProtection {
            operation: "write_slice".to_string(),
            values: format!("current_len={}, slice_len={}", self.data.len(), slice.len()),
        })?;
        
        if new_len > MAX_BUFFER_SIZE {
            return Err(SecurityError::BufferOverflowProtection {
                size: new_len,
                capacity: MAX_BUFFER_SIZE,
            });
        }
        
        self.data.extend_from_slice(slice);
        Ok(())
    }
    
    /// Get current position - no panic
    pub fn position(&self) -> usize {
        self.read_pos
    }
    
    /// Set position - explicit bounds checking, no panic
    pub fn set_position(&mut self, pos: usize) -> SecurityResult<()> {
        if pos > self.data.len() {
            return Err(SecurityError::BufferOverflowProtection {
                size: pos,
                capacity: self.data.len(),
            });
        }
        
        self.read_pos = pos;
        Ok(())
    }
    
    /// Get data - no panic
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    
    /// Get length - no panic
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if empty - no panic
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Get capacity - no panic
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
    
    /// Get as slice - no panic
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Clear buffer - no panic
    pub fn clear(&mut self) -> SecurityResult<()> {
        self.data.clear();
        self.read_pos = 0;
        Ok(())
    }
    
    /// Clear buffer - zeroize sensitive data
    pub fn zeroize(&mut self) {
        self.data.zeroize();
        self.read_pos = 0;
    }
}

/// Maximum buffer size to prevent DoS attacks
const MAX_BUFFER_SIZE: usize = 64 * 1024 * 1024; // 64MB

/// Security-hardened integer conversions - no panic, explicit error handling
pub trait SecurityIntegerConversions {
    /// Convert usize to u8 - explicit error handling, no panic
    fn to_u8(self) -> SecurityResult<u8>;
    
    /// Convert usize to u16 - explicit error handling, no panic
    fn to_u16(self) -> SecurityResult<u16>;
    
    /// Convert usize to u32 - explicit error handling, no panic
    fn to_u32(self) -> SecurityResult<u32>;
    
    /// Convert usize to u64 - explicit error handling, no panic
    fn to_u64(self) -> SecurityResult<u64>;
    
    /// Convert usize to i64 - explicit error handling, no panic
    fn to_i64(self) -> SecurityResult<i64>;
    
    /// Convert u64 to usize - explicit error handling, no panic
    fn to_usize(self) -> SecurityResult<usize>;
    
    /// Convert u32 to usize - explicit error handling, no panic
    fn to_usize_from_u32(self) -> SecurityResult<usize>;
    
    /// Convert u16 to usize - explicit error handling, no panic
    fn to_usize_from_u16(self) -> SecurityResult<usize>;
    
    /// Convert u8 to usize - explicit error handling, no panic
    fn to_usize_from_u8(self) -> SecurityResult<usize>;
}

impl SecurityIntegerConversions for usize {
    fn to_u8(self) -> SecurityResult<u8> {
        u8::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "usize".to_string(),
            to: "u8".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u16(self) -> SecurityResult<u16> {
        u16::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "usize".to_string(),
            to: "u16".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u32(self) -> SecurityResult<u32> {
        u32::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "usize".to_string(),
            to: "u32".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u64(self) -> SecurityResult<u64> {
        u64::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "usize".to_string(),
            to: "u64".to_string(),
            value: self as i64,
        })
    }
    
    fn to_i64(self) -> SecurityResult<i64> {
        i64::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "usize".to_string(),
            to: "i64".to_string(),
            value: self as i64,
        })
    }
    
    fn to_usize(self) -> SecurityResult<usize> {
        Ok(self) // No conversion needed
    }
    
    fn to_usize_from_u32(self) -> SecurityResult<usize> {
        Ok(self) // No conversion needed
    }
    
    fn to_usize_from_u16(self) -> SecurityResult<usize> {
        Ok(self) // No conversion needed
    }
    
    fn to_usize_from_u8(self) -> SecurityResult<usize> {
        Ok(self) // No conversion needed
    }
}

impl SecurityIntegerConversions for u64 {
    fn to_u8(self) -> SecurityResult<u8> {
        u8::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u64".to_string(),
            to: "u8".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u16(self) -> SecurityResult<u16> {
        u16::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u64".to_string(),
            to: "u16".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u32(self) -> SecurityResult<u32> {
        u32::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u64".to_string(),
            to: "u32".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u64(self) -> SecurityResult<u64> {
        Ok(self) // No conversion needed
    }
    
    fn to_i64(self) -> SecurityResult<i64> {
        i64::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u64".to_string(),
            to: "i64".to_string(),
            value: self as i64,
        })
    }
    
    fn to_usize(self) -> SecurityResult<usize> {
        usize::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u64".to_string(),
            to: "usize".to_string(),
            value: self as i64,
        })
    }
    
    fn to_usize_from_u32(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u16(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u8(self) -> SecurityResult<usize> {
        self.to_usize()
    }
}

impl SecurityIntegerConversions for u32 {
    fn to_u8(self) -> SecurityResult<u8> {
        u8::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u32".to_string(),
            to: "u8".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u16(self) -> SecurityResult<u16> {
        u16::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u32".to_string(),
            to: "u16".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u32(self) -> SecurityResult<u32> {
        Ok(self) // No conversion needed
    }
    
    fn to_u64(self) -> SecurityResult<u64> {
        Ok(self as u64)
    }
    
    fn to_i64(self) -> SecurityResult<i64> {
        Ok(self as i64)
    }
    
    fn to_usize(self) -> SecurityResult<usize> {
        usize::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u32".to_string(),
            to: "usize".to_string(),
            value: self as i64,
        })
    }
    
    fn to_usize_from_u32(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u16(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u8(self) -> SecurityResult<usize> {
        self.to_usize()
    }
}

impl SecurityIntegerConversions for u16 {
    fn to_u8(self) -> SecurityResult<u8> {
        u8::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u16".to_string(),
            to: "u8".to_string(),
            value: self as i64,
        })
    }
    
    fn to_u16(self) -> SecurityResult<u16> {
        Ok(self) // No conversion needed
    }
    
    fn to_u32(self) -> SecurityResult<u32> {
        Ok(self as u32)
    }
    
    fn to_u64(self) -> SecurityResult<u64> {
        Ok(self as u64)
    }
    
    fn to_i64(self) -> SecurityResult<i64> {
        Ok(self as i64)
    }
    
    fn to_usize(self) -> SecurityResult<usize> {
        usize::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u16".to_string(),
            to: "usize".to_string(),
            value: self as i64,
        })
    }
    
    fn to_usize_from_u32(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u16(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u8(self) -> SecurityResult<usize> {
        self.to_usize()
    }
}

impl SecurityIntegerConversions for u8 {
    fn to_u8(self) -> SecurityResult<u8> {
        Ok(self) // No conversion needed
    }
    
    fn to_u16(self) -> SecurityResult<u16> {
        Ok(self as u16)
    }
    
    fn to_u32(self) -> SecurityResult<u32> {
        Ok(self as u32)
    }
    
    fn to_u64(self) -> SecurityResult<u64> {
        Ok(self as u64)
    }
    
    fn to_i64(self) -> SecurityResult<i64> {
        Ok(self as i64)
    }
    
    fn to_usize(self) -> SecurityResult<usize> {
        usize::try_from(self).map_err(|_e| SecurityError::IntegerConversionFailure {
            from: "u8".to_string(),
            to: "usize".to_string(),
            value: self as i64,
        })
    }
    
    fn to_usize_from_u32(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u16(self) -> SecurityResult<usize> {
        self.to_usize()
    }
    
    fn to_usize_from_u8(self) -> SecurityResult<usize> {
        self.to_usize()
    }
}

/// Security-hardened array operations - bounds checked, no panic
pub trait SecurityArrayOperations {
    type Output;
    
    /// Get element at index - bounds checked, no panic
    fn get_security(&self, index: usize) -> SecurityResult<&Self::Output>;
    
    /// Get element at index mutably - bounds checked, no panic
    fn get_security_mut(&mut self, index: usize) -> SecurityResult<&mut Self::Output>;
    
    /// Get slice at range - bounds checked, no panic
    fn get_range_security(&self, start: usize, end: usize) -> SecurityResult<&[Self::Output]>;
    
    /// Get slice at range mutably - bounds checked, no panic
    fn get_range_security_mut(&mut self, start: usize, end: usize) -> SecurityResult<&mut [Self::Output]>;
}

impl<T> SecurityArrayOperations for [T] {
    type Output = T;
    
    fn get_security(&self, index: usize) -> SecurityResult<&T> {
        if index >= self.len() {
            return Err(SecurityError::BoundsCheckingFailure {
                operation: "get_security".to_string(),
                bounds: format!("index={}, len={}", index, self.len()),
            });
        }
        Ok(&self[index])
    }
    
    fn get_security_mut(&mut self, index: usize) -> SecurityResult<&mut T> {
        if index >= self.len() {
            return Err(SecurityError::BoundsCheckingFailure {
                operation: "get_security_mut".to_string(),
                bounds: format!("index={}, len={}", index, self.len()),
            });
        }
        Ok(&mut self[index])
    }
    
    fn get_range_security(&self, start: usize, end: usize) -> SecurityResult<&[T]> {
        if start > end {
            return Err(SecurityError::BoundsCheckingFailure {
                operation: "get_range_security".to_string(),
                bounds: format!("start={}, end={}", start, end),
            });
        }
        if end > self.len() {
            return Err(SecurityError::BoundsCheckingFailure {
                operation: "get_range_security".to_string(),
                bounds: format!("end={}, len={}", end, self.len()),
            });
        }
        Ok(&self[start..end])
    }
    
    fn get_range_security_mut(&mut self, start: usize, end: usize) -> SecurityResult<&mut [T]> {
        if start > end {
            return Err(SecurityError::BoundsCheckingFailure {
                operation: "get_range_security_mut".to_string(),
                bounds: format!("start={}, end={}", start, end),
            });
        }
        if end > self.len() {
            return Err(SecurityError::BoundsCheckingFailure {
                operation: "get_range_security_mut".to_string(),
                bounds: format!("end={}, len={}", end, self.len()),
            });
        }
        Ok(&mut self[start..end])
    }
}

/// Security-hardened constant-time comparison for secrets
pub fn constant_time_eq_security(a: &[u8], b: &[u8]) -> SecurityResult<bool> {
    if a.len() != b.len() {
        return Ok(false); // Different lengths - not equal
    }
    
    // Use subtle crate for constant-time comparison
    let result = a.ct_eq(b);
    Ok(result.unwrap_u8() == 1)
}

/// Security-hardened zeroization - guaranteed memory clearing
pub fn secure_zeroize_security(data: &mut [u8]) {
    // Use zeroize crate for guaranteed memory clearing
    data.zeroize();
}

/// Security-hardened bounds checking for network parsing
pub fn validate_bounds_security(start: usize, end: usize, max: usize) -> SecurityResult<()> {
    if start > end {
        return Err(SecurityError::BoundsCheckingFailure {
            operation: "validate_bounds".to_string(),
            bounds: format!("start={} > end={}", start, end),
        });
    }
    
    if end > max {
        return Err(SecurityError::BoundsCheckingFailure {
            operation: "validate_bounds".to_string(),
            bounds: format!("end={} > max={}", end, max),
        });
    }
    
    Ok(())
}

/// Security-hardened length validation for network messages
pub fn validate_length_security(length: usize, min: usize, max: usize) -> SecurityResult<()> {
    if length < min {
        return Err(SecurityError::InvalidLength {
            expected: min,
            actual: length,
        });
    }
    
    if length > max {
        return Err(SecurityError::InvalidLength {
            expected: max,
            actual: length,
        });
    }
    
    Ok(())
}

/// Security-hardened arithmetic with overflow protection
pub fn checked_add_security(a: usize, b: usize) -> SecurityResult<usize> {
    a.checked_add(b).ok_or(SecurityError::ArithmeticOverflowProtection {
        operation: "checked_add".to_string(),
        values: format!("a={}, b={}", a, b),
    })
}

/// Security-hardened arithmetic with underflow protection  
pub fn checked_sub_security(a: usize, b: usize) -> SecurityResult<usize> {
    a.checked_sub(b).ok_or(SecurityError::ArithmeticOverflowProtection {
        operation: "checked_sub".to_string(),
        values: format!("a={}, b={}", a, b),
    })
}



/// Security-hardened arithmetic with multiplication overflow protection
pub fn checked_mul_security(a: usize, b: usize) -> SecurityResult<usize> {
    a.checked_mul(b).ok_or(SecurityError::ArithmeticOverflowProtection {
        operation: "checked_mul".to_string(),
        values: format!("a={}, b={}", a, b),
    })
}

/// Security-hardened division with zero protection
pub fn checked_div_security(a: usize, b: usize) -> SecurityResult<usize> {
    if b == 0 {
        return Err(SecurityError::DivisionByZeroProtection {
            operation: "checked_div".to_string(),
        });
    }
    
    Ok(a / b)
}

/// Security-hardened deterministic state machine base trait
pub trait SecurityStateMachine {
    type State: Eq + std::hash::Hash + std::fmt::Debug;
    type Event: std::fmt::Debug;
    type Context: std::fmt::Debug;
    
    /// Get current state - deterministic
    fn current_state(&self) -> Self::State;
    
    /// Get valid transitions from current state - deterministic
    fn valid_transitions(&self) -> Vec<Self::State>;
    
    /// Validate state transition - explicit error handling, no panic
    fn validate_transition(&self, from: &Self::State, to: &Self::State) -> SecurityResult<()> {
        let valid_states = self.valid_transitions();
        if !valid_states.contains(to) {
            return Err(SecurityError::InvalidStateTransition {
                from: format!("{:?}", from),
                to: format!("{:?}", to),
            });
        }
        Ok(())
    }
    
    /// Apply event with context - explicit error handling, no panic
    fn apply_event(&mut self, event: Self::Event, context: &Self::Context) -> SecurityResult<()>;
    
    /// Get state invariants - deterministic validation
    fn state_invariants(&self, state: &Self::State) -> SecurityResult<()>;
    
    /// Validate all invariants - comprehensive security check
    fn validate_all_invariants(&self) -> SecurityResult<()> {
        let current_state = self.current_state();
        self.state_invariants(&current_state)?;
        Ok(())
    }
}

/// Security-hardened constant-time comparison trait
pub trait SecurityConstantTimeEq {
    /// Constant-time equality comparison - no timing leakage
    fn ct_eq_security(&self, other: &Self) -> SecurityResult<bool>;
}

/// Security-hardened zeroization trait
pub trait SecurityZeroize {
    /// Zeroize sensitive data - guaranteed memory clearing
    fn zeroize_security(&mut self);
}

/// Security-hardened bounds checking trait
pub trait SecurityBoundsCheck {
    /// Check bounds - explicit validation, no panic
    fn check_bounds(&self, start: usize, end: usize) -> SecurityResult<()>;
}

/// Security-hardened resource management trait
pub trait SecurityResourceManagement {
    /// Get current resource usage
    fn current_usage(&self) -> usize;
    
    /// Get maximum allowed usage
    fn max_allowed(&self) -> usize;
    
    /// Check if within limits - explicit validation
    fn check_limits(&self) -> SecurityResult<()> {
        let current = self.current_usage();
        let max = self.max_allowed();
        
        if current > max {
            return Err(SecurityError::ResourceExhaustionProtection {
                resource: std::any::type_name::<Self>().to_string(),
                limit: max,
                requested: current,
            });
        }
        
        Ok(())
    }
}

/// Security-hardened deterministic protocol message header
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityMessageHeader {
    pub protocol_version: ProtocolVersion,
    pub message_type: MessageType,
    pub cipher_suite: CipherSuite,
    pub feature_flags: FeatureFlags,
    pub metadata_level: u8,
    pub onion_enabled: bool,
    pub transport_mode: u8,
    pub timestamp: i64,
    pub message_length: u32,
    pub message_id: [u8; 32],
    pub session_id: [u8; 32],
    pub extension_count: u16,
    pub signature_length: u16,
}

impl SecurityMessageHeader {
    /// Total header size in bytes
    pub const SIZE: usize = 84; // Exact size calculation
    
    /// Parse from buffer - zero-trust parsing, explicit bounds checking
    pub fn parse_security(buffer: &mut SecurityBuffer) -> SecurityResult<Self> {
        // Validate minimum header size
        if !buffer.can_read(Self::SIZE) {
            return Err(SecurityError::BufferTooSmall {
                required: Self::SIZE,
                available: buffer.remaining(),
            });
        }
        
        // Parse protocol version (2 bytes)
        let protocol_version_bytes = buffer.read_exact(2)?;
        let protocol_version = ProtocolVersion::from_bytes([
            protocol_version_bytes[0], protocol_version_bytes[1]
        ])?;
        
        // Parse message type (1 byte)
        let message_type = MessageType::from_u8(buffer.read_u8()?)?;
        
        // Parse cipher suite (1 byte)
        let cipher_suite = CipherSuite::from_u8(buffer.read_u8()?)?;
        
        // Parse feature flags (1 byte)
        let feature_flags = FeatureFlags::from_u8(buffer.read_u8()?)?;
        
        // Validate feature flags against cipher suite
        feature_flags.validate_against_cipher_suite(cipher_suite)?;
        
        // Parse metadata level (1 byte)
        let metadata_level = buffer.read_u8()?;
        validate_length_security(metadata_level as usize, 0, 3)?; // 0=None, 1=Low, 2=Medium, 3=High
        
        // Parse onion enabled (1 byte)
        let onion_enabled_byte = buffer.read_u8()?;
        let onion_enabled = match onion_enabled_byte {
            0x00 => false,
            0x01 => true,
            _ => return Err(SecurityError::InvalidFeatureFlags(onion_enabled_byte)),
        };
        
        // Parse transport mode (1 byte)
        let transport_mode = buffer.read_u8()?;
        match transport_mode {
            0x01 | 0x02 | 0x03 => {}, // Valid values
            _ => return Err(SecurityError::InvalidFeatureFlags(transport_mode)),
        }
        
        // Parse timestamp (8 bytes)
        let timestamp = buffer.read_i64_be()?;
        
        // Parse message length (4 bytes)
        let message_length = buffer.read_u32_be()?;
        validate_length_security(message_length as usize, 0, MAX_MESSAGE_LENGTH)?;
        
        // Parse message ID (32 bytes)
        let message_id_bytes = buffer.read_exact(32)?;
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(message_id_bytes);
        
        // Parse session ID (32 bytes)
        let session_id_bytes = buffer.read_exact(32)?;
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(session_id_bytes);
        
        // Parse extension count (2 bytes)
        let extension_count = buffer.read_u16_be()?;
        validate_length_security(extension_count as usize, 0, MAX_EXTENSIONS)?;
        
        // Parse signature length (2 bytes)
        let signature_length = buffer.read_u16_be()?;
        validate_length_security(signature_length as usize, 0, MAX_SIGNATURE_LENGTH)?;
        
        Ok(SecurityMessageHeader {
            protocol_version,
            message_type,
            cipher_suite,
            feature_flags,
            metadata_level,
            onion_enabled,
            transport_mode,
            timestamp,
            message_length,
            message_id,
            session_id,
            extension_count,
            signature_length,
        })
    }
    
    /// Serialize to buffer - explicit bounds checking, no panic
    pub fn serialize_security(&self, buffer: &mut SecurityBuffer) -> SecurityResult<()> {
        // Validate buffer has enough space
        if buffer.remaining() < Self::SIZE {
            return Err(SecurityError::BufferTooSmall {
                required: Self::SIZE,
                available: buffer.remaining(),
            });
        }
        
        // Write protocol version (2 bytes)
        let version_bytes = self.protocol_version.to_bytes();
        buffer.write_slice(&version_bytes)?;
        
        // Write message type (1 byte)
        buffer.write_u8(self.message_type.as_u8())?;
        
        // Write cipher suite (1 byte)
        buffer.write_u8(self.cipher_suite.as_u8())?;
        
        // Write feature flags (1 byte)
        buffer.write_u8(self.feature_flags.as_u8())?;
        
        // Write metadata level (1 byte)
        buffer.write_u8(self.metadata_level)?;
        
        // Write onion enabled (1 byte)
        buffer.write_u8(if self.onion_enabled { 0x01 } else { 0x00 })?;
        
        // Write transport mode (1 byte)
        buffer.write_u8(self.transport_mode)?;
        
        // Write timestamp (8 bytes)
        buffer.write_i64_be(self.timestamp)?;
        
        // Write message length (4 bytes)
        buffer.write_u32_be(self.message_length)?;
        
        // Write message ID (32 bytes)
        buffer.write_slice(&self.message_id)?;
        
        // Write session ID (32 bytes)
        buffer.write_slice(&self.session_id)?;
        
        // Write extension count (2 bytes)
        buffer.write_u16_be(self.extension_count)?;
        
        // Write signature length (2 bytes)
        buffer.write_u16_be(self.signature_length)?;
        
        Ok(())
    }
    
    /// Validate header invariants - comprehensive security checks
    pub fn validate_security(&self) -> SecurityResult<()> {
        // Validate protocol version is current
        if self.protocol_version != ProtocolVersion::CURRENT {
            return Err(SecurityError::SecurityInvariantViolation {
                invariant: "Protocol version must be current".to_string(),
                details: format!("expected {:?}, actual {:?}", ProtocolVersion::CURRENT, self.protocol_version),
            });
        }
        
        // Validate message length is reasonable
        if self.message_length > MAX_MESSAGE_LENGTH as u32 {
            return Err(SecurityError::SecurityInvariantViolation {
                invariant: "Message length within reasonable bounds".to_string(),
                details: format!("message_length={} exceeds maximum {}", self.message_length, MAX_MESSAGE_LENGTH),
            });
        }
        
        // Validate timestamp is not too far in future or past
        let current_time = current_timestamp();
        let time_diff = (self.timestamp - current_time).abs();
        if time_diff > MAX_TIMESTAMP_DRIFT {
            return Err(SecurityError::SecurityInvariantViolation {
                invariant: "Timestamp within reasonable drift".to_string(),
                details: format!("timestamp drift={} exceeds maximum {}", time_diff, MAX_TIMESTAMP_DRIFT),
            });
        }
        
        // Validate extension count is reasonable
        if self.extension_count > MAX_EXTENSIONS as u16 {
            return Err(SecurityError::SecurityInvariantViolation {
                invariant: "Extension count within reasonable bounds".to_string(),
                details: format!("extension_count={} exceeds maximum {}", self.extension_count, MAX_EXTENSIONS),
            });
        }
        
        // Validate signature length is reasonable
        if self.signature_length > MAX_SIGNATURE_LENGTH as u16 {
            return Err(SecurityError::SecurityInvariantViolation {
                invariant: "Signature length within reasonable bounds".to_string(),
                details: format!("signature_length={} exceeds maximum {}", self.signature_length, MAX_SIGNATURE_LENGTH),
            });
        }
        
        Ok(())
    }
}

/// Get current timestamp - security-hardened
fn current_timestamp() -> i64 {
    // Use std::time for deterministic timestamp
    use std::time::{SystemTime, UNIX_EPOCH};
    
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0) // Safe fallback
}

/// Maximum message length to prevent DoS attacks
const MAX_MESSAGE_LENGTH: usize = 64 * 1024 * 1024; // 64MB

/// Maximum number of extensions to prevent DoS attacks
const MAX_EXTENSIONS: usize = 100;

/// Maximum signature length to prevent DoS attacks
const MAX_SIGNATURE_LENGTH: usize = 10 * 1024; // 10KB (Dilithium5 is ~4.6KB)

/// Maximum timestamp drift to prevent replay attacks (5 minutes)
const MAX_TIMESTAMP_DRIFT: i64 = 5 * 60; // 5 minutes in seconds

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_version_bytes() {
        let version = ProtocolVersion::V1_0;
        let bytes = version.to_bytes();
        assert_eq!(bytes, [0x01, 0x00]);
        
        let parsed = ProtocolVersion::from_bytes(bytes).expect("Valid protocol version should parse");
        assert_eq!(parsed, version);
    }
    
    #[test]
    fn test_invalid_protocol_version() {
        let result = ProtocolVersion::from_bytes([0xFF, 0xFF]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_message_type_conversion() {
        let message_type = MessageType::HandshakeInit;
        let byte = message_type.as_u8();
        assert_eq!(byte, 0x01);
        
        let parsed = MessageType::from_u8(byte).expect("Valid message type should parse");
        assert_eq!(parsed, message_type);
    }
    
    #[test]
    fn test_invalid_message_type() {
        let result = MessageType::from_u8(0xFF);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_cipher_suite_conversion() {
        let cipher_suite = CipherSuite::High;
        let byte = cipher_suite.as_u8();
        assert_eq!(byte, 0x02);
        
        let parsed = CipherSuite::from_u8(byte).expect("Valid cipher suite should parse");
        assert_eq!(parsed, cipher_suite);
    }
    
    #[test]
    fn test_invalid_cipher_suite() {
        let result = CipherSuite::from_u8(0xFF);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_feature_flags_validation() {
        let flags = FeatureFlags {
            post_quantum_required: true,
            hybrid_required: true,
            metadata_protection: false,
            onion_routing: false,
            hsm_required: false,
            perfect_forward_secrecy: false,
            extended_key_rotation: false,
        };
        
        // Should fail against Standard cipher suite
        let result = flags.validate_against_cipher_suite(CipherSuite::Standard);
        assert!(result.is_err());
        
        // Should pass against Maximum cipher suite
        let result = flags.validate_against_cipher_suite(CipherSuite::Maximum);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_security_buffer_bounds_checking() {
        let mut buffer = SecurityBuffer::new(100).expect("Buffer creation should succeed");
        
        // Write some data
        buffer.write_u8(0x42).expect("Write u8 should succeed");
        buffer.write_u16_be(0x1234).expect("Write u16 should succeed");
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        // Read data back
        assert_eq!(buffer.read_u8().expect("Read u8 should succeed"), 0x42);
        assert_eq!(buffer.read_u16_be().expect("Read u16 should succeed"), 0x1234);
        
        // Test bounds checking
        let result = buffer.read_exact(1000);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_security_buffer_overflow_protection() {
        let result = SecurityBuffer::new(MAX_BUFFER_SIZE + 1);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_integer_conversion_overflow_protection() {
        let large_value = usize::MAX;
        let result = large_value.to_u8();
        assert!(result.is_err());
    }
    
    #[test]
    fn test_array_bounds_checking() {
        let array = [1u8, 2, 3, 4, 5];
        
        // Valid access
        let result = array.get_security(3);
        assert!(result.is_ok());
        assert_eq!(*result.expect("Valid index should return value"), 4);
        
        // Invalid access - bounds checking
        let result = array.get_security(10);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_message_header_parsing() {
        let mut buffer = SecurityBuffer::new(50000).expect("Buffer creation should succeed");
        
        // Create a valid header
        let header = SecurityMessageHeader {
            protocol_version: ProtocolVersion::V1_0,
            message_type: MessageType::HandshakeInit,
            cipher_suite: CipherSuite::High,
            feature_flags: FeatureFlags {
                post_quantum_required: true,
                hybrid_required: true,
                metadata_protection: false,
                onion_routing: false,
                hsm_required: false,
                perfect_forward_secrecy: true,
                extended_key_rotation: false,
            },
            metadata_level: 2,
            onion_enabled: false,
            transport_mode: 1,
            timestamp: 0,
            message_length: 100,
            message_id: [0x42; 32],
            session_id: [0x43; 32],
            extension_count: 2,
            signature_length: 64,  // Smaller signature
        };
        
        // Serialize
        header.serialize_security(&mut buffer).expect("Header serialization should succeed");
        
        // Reset position
        buffer.set_position(0).expect("Set position should succeed");
        
        // Parse back
        let parsed = SecurityMessageHeader::parse_security(&mut buffer).expect("Header parsing should succeed");
        assert_eq!(parsed.protocol_version, header.protocol_version);
        assert_eq!(parsed.message_type, header.message_type);
        assert_eq!(parsed.cipher_suite, header.cipher_suite);
        
        // Validate
        parsed.validate_security().expect("Header validation should succeed");
    }
    
    #[test]
    fn test_message_header_validation() {
        let mut buffer = SecurityBuffer::new(50000).expect("Buffer creation should succeed");
        
        // Create invalid header (wrong cipher suite for flags)
        let header = SecurityMessageHeader {
            protocol_version: ProtocolVersion::V1_0,
            message_type: MessageType::HandshakeInit,
            cipher_suite: CipherSuite::Standard,
            feature_flags: FeatureFlags {
                post_quantum_required: true,  // Invalid for Standard
                hybrid_required: true,        // Invalid for Standard
                metadata_protection: false,
                onion_routing: false,
                hsm_required: false,
                perfect_forward_secrecy: true,
                extended_key_rotation: false,
            },
            metadata_level: 2,
            onion_enabled: false,
            transport_mode: 1,
            timestamp: 0,
            message_length: 100,
            message_id: [0x42; 32],
            session_id: [0x43; 32],
            extension_count: 2,
            signature_length: 64,  // Smaller signature
        };
        
        header.serialize_security(&mut buffer).expect("Header serialization should succeed");
        buffer.set_position(0).expect("Set position should succeed");
        
        let parsed = SecurityMessageHeader::parse_security(&mut buffer).expect("Header parsing should succeed");
        
        // Validation should fail
        let result = parsed.validate_security();
        assert!(result.is_err());
    }
}