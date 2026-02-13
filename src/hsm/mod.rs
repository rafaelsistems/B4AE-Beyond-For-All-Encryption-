//! Hardware Security Module (HSM) integration
//!
//! Trait dan stub untuk integrasi HSM di masa depan.
//! Digunakan untuk key storage, signing, dan key derivation di hardware.

use crate::error::{B4aeError, B4aeResult};

/// HSM backend abstraction.
///
/// Implementasi konkret dapat menggunakan PKCS#11, Windows CNG, atau vendor-specific API.
#[allow(clippy::module_name_repetitions)]
pub trait HsmBackend: Send + Sync {
    /// Generate keypair dalam HSM
    fn generate_keypair(&self, _key_id: &str) -> B4aeResult<Vec<u8>> {
        Err(B4aeError::ProtocolError(
            "HSM not configured".to_string(),
        ))
    }

    /// Sign data dengan key di HSM
    fn sign(&self, _key_id: &str, _data: &[u8]) -> B4aeResult<Vec<u8>> {
        Err(B4aeError::ProtocolError(
            "HSM not configured".to_string(),
        ))
    }

    /// Verify signature
    fn verify(&self, _key_id: &str, _data: &[u8], _signature: &[u8]) -> B4aeResult<bool> {
        Err(B4aeError::ProtocolError(
            "HSM not configured".to_string(),
        ))
    }

    /// Cek apakah HSM tersedia
    fn is_available(&self) -> bool {
        false
    }
}

/// No-op HSM: fallback ketika HSM tidak tersedia.
///
/// Semua operasi mengembalikan error; untuk development/testing.
#[derive(Debug, Clone)]
pub struct NoOpHsm;

impl NoOpHsm {
    /// Create new NoOp HSM instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoOpHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmBackend for NoOpHsm {
    fn is_available(&self) -> bool {
        false
    }
}

#[cfg(feature = "hsm-pkcs11")]
pub mod pkcs11;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_hsm_unavailable() {
        let hsm = NoOpHsm::new();
        assert!(!hsm.is_available());
    }

    #[test]
    fn test_noop_hsm_generate_errors() {
        let hsm = NoOpHsm::new();
        let r = hsm.generate_keypair("test");
        assert!(r.is_err());
    }
}
