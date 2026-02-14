//! B4AE Cryptographic Core Module
//!
//! Implements NIST-standardized post-quantum cryptography and classical primitives.

/// Kyber KEM (NIST ML-KEM).
pub mod kyber;
/// Dilithium signatures (NIST ML-DSA).
pub mod dilithium;
/// Hybrid cryptography (PQC + classical).
pub mod hybrid;
/// AES-256-GCM encryption.
pub mod aes_gcm;
/// HKDF key derivation.
pub mod hkdf;
/// Onion routing primitives.
pub mod onion;
/// Hardware acceleration helpers.
pub mod perf;
/// CSPRNG and random utilities.
pub mod random;
/// Perfect Forward Secrecy Plus.
pub mod pfs_plus;
/// Zero-knowledge authentication.
pub mod zkauth;

use std::error::Error;
use std::fmt;

/// B4AE Cryptographic Error Types
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Key generation failed.
    KeyGenerationFailed(String),
    /// Encryption failed.
    EncryptionFailed(String),
    /// Decryption failed.
    DecryptionFailed(String),
    /// Signature generation failed.
    SignatureFailed(String),
    /// Signature verification failed.
    VerificationFailed(String),
    /// Invalid key size.
    InvalidKeySize(String),
    /// Invalid input.
    InvalidInput(String),
    /// Hardware acceleration not available.
    HardwareAccelerationUnavailable,
    /// Authentication failed.
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyGenerationFailed(msg) => write!(f, "Key generation failed: {}", msg),
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            CryptoError::SignatureFailed(msg) => write!(f, "Signature generation failed: {}", msg),
            CryptoError::VerificationFailed(msg) => write!(f, "Signature verification failed: {}", msg),
            CryptoError::InvalidKeySize(msg) => write!(f, "Invalid key size: {}", msg),
            CryptoError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            CryptoError::HardwareAccelerationUnavailable => write!(f, "Hardware acceleration unavailable"),
            CryptoError::AuthenticationFailed => write!(f, "Authentication failed"),
        }
    }
}

impl Error for CryptoError {}

/// Result type for crypto operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Security levels for B4AE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Standard security (256-bit quantum resistance)
    Standard,
    /// High security (384-bit quantum resistance)
    High,
    /// Maximum security (512-bit quantum resistance)
    Maximum,
}

impl SecurityLevel {
    /// Returns key size in bytes for this security level.
    pub fn key_size(&self) -> usize {
        match self {
            SecurityLevel::Standard => 32,  // 256 bits
            SecurityLevel::High => 48,      // 384 bits
            SecurityLevel::Maximum => 64,   // 512 bits
        }
    }
}

/// B4AE Cryptographic Configuration
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Security level (Standard/High/Maximum).
    pub security_level: SecurityLevel,
    /// Enable AES-NI, AVX2 when available.
    pub enable_hardware_acceleration: bool,
    /// Use hybrid PQC + classical.
    pub enable_hybrid_mode: bool,
    /// Require quantum-resistant algorithms.
    pub quantum_resistant: bool,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        CryptoConfig {
            security_level: SecurityLevel::Standard,
            enable_hardware_acceleration: true,
            enable_hybrid_mode: true,
            quantum_resistant: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        assert_eq!(SecurityLevel::Standard.key_size(), 32);
        assert_eq!(SecurityLevel::High.key_size(), 48);
        assert_eq!(SecurityLevel::Maximum.key_size(), 64);
    }

    #[test]
    fn test_default_config() {
        let config = CryptoConfig::default();
        assert_eq!(config.security_level, SecurityLevel::Standard);
        assert!(config.enable_hardware_acceleration);
        assert!(config.enable_hybrid_mode);
        assert!(config.quantum_resistant);
    }
}
