// B4AE Error Types

use std::fmt;
use std::error::Error;

/// B4AE Error Type
#[derive(Debug, Clone)]
pub enum B4aeError {
    /// Cryptographic operation failed
    CryptoError(String),
    
    /// Protocol error
    ProtocolError(String),
    
    /// Network error
    NetworkError(String),
    
    /// Invalid input
    InvalidInput(String),
    
    /// Authentication failed
    AuthenticationFailed,
    
    /// Key exchange failed
    KeyExchangeFailed(String),
    
    /// Message encryption/decryption failed
    MessageError(String),
    
    /// Metadata protection error
    MetadataError(String),
    
    /// Configuration error
    ConfigError(String),
    
    /// Internal error
    InternalError(String),
}

impl fmt::Display for B4aeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            B4aeError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            B4aeError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            B4aeError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            B4aeError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            B4aeError::AuthenticationFailed => write!(f, "Authentication failed"),
            B4aeError::KeyExchangeFailed(msg) => write!(f, "Key exchange failed: {}", msg),
            B4aeError::MessageError(msg) => write!(f, "Message error: {}", msg),
            B4aeError::MetadataError(msg) => write!(f, "Metadata error: {}", msg),
            B4aeError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            B4aeError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl Error for B4aeError {}

/// Convert CryptoError to B4aeError
impl From<crate::crypto::CryptoError> for B4aeError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        B4aeError::CryptoError(err.to_string())
    }
}

/// B4AE Result Type
pub type B4aeResult<T> = Result<T, B4aeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = B4aeError::CryptoError("test error".to_string());
        assert_eq!(err.to_string(), "Cryptographic error: test error");
    }

    #[test]
    fn test_error_conversion() {
        let crypto_err = crate::crypto::CryptoError::EncryptionFailed("test".to_string());
        let b4ae_err: B4aeError = crypto_err.into();
        
        match b4ae_err {
            B4aeError::CryptoError(_) => (),
            _ => panic!("Wrong error type"),
        }
    }
}
