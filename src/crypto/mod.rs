// B4AE Cryptographic Core Module
// Phase 2: Core Development - Cryptographic Implementation

pub mod kyber;
pub mod dilithium;
pub mod hybrid;
pub mod aes_gcm;
pub mod hkdf;
pub mod perf;
pub mod random;
pub mod pfs_plus;
pub mod zkauth;

use std::error::Error;
use std::fmt;

/// B4AE Cryptographic Error Types
#[derive(Debug, Clone)]
pub enum CryptoError {
    KeyGenerationFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    SignatureFailed(String),
    VerificationFailed(String),
    InvalidKeySize(String),
    InvalidInput(String),
    HardwareAccelerationUnavailable,
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
    pub security_level: SecurityLevel,
    pub enable_hardware_acceleration: bool,
    pub enable_hybrid_mode: bool,
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
