// B4AE HKDF Implementation
// HMAC-based Key Derivation Function using SHA3-256

use crate::crypto::{CryptoError, CryptoResult};
use hkdf::Hkdf;
use sha3::Sha3_256;

/// Derive key using HKDF-SHA3-256
/// 
/// # Arguments
/// * `input_key_material` - Input key material (IKM) - can be multiple sources
/// * `info` - Application-specific context information
/// * `output_length` - Desired output key length in bytes
pub fn derive_key(
    input_key_material: &[&[u8]],
    info: &[u8],
    output_length: usize,
) -> CryptoResult<Vec<u8>> {
    // Concatenate all input key material
    let mut ikm = Vec::new();
    for material in input_key_material {
        ikm.extend_from_slice(material);
    }

    // Use empty salt (as per RFC 5869, this is acceptable)
    let hkdf = Hkdf::<Sha3_256>::new(None, &ikm);

    let mut output = vec![0u8; output_length];
    hkdf.expand(info, &mut output)
        .map_err(|e| CryptoError::InvalidInput(format!("HKDF expand failed: {}", e)))?;

    Ok(output)
}

/// Derive key with explicit salt
pub fn derive_key_with_salt(
    salt: &[u8],
    input_key_material: &[&[u8]],
    info: &[u8],
    output_length: usize,
) -> CryptoResult<Vec<u8>> {
    // Concatenate all input key material
    let mut ikm = Vec::new();
    for material in input_key_material {
        ikm.extend_from_slice(material);
    }

    let hkdf = Hkdf::<Sha3_256>::new(Some(salt), &ikm);

    let mut output = vec![0u8; output_length];
    hkdf.expand(info, &mut output)
        .map_err(|e| CryptoError::InvalidInput(format!("HKDF expand failed: {}", e)))?;

    Ok(output)
}

/// Derive multiple keys from single input
pub fn derive_multiple_keys(
    input_key_material: &[&[u8]],
    info_prefix: &[u8],
    key_count: usize,
    key_length: usize,
) -> CryptoResult<Vec<Vec<u8>>> {
    let mut keys = Vec::with_capacity(key_count);

    for i in 0..key_count {
        let mut info = info_prefix.to_vec();
        info.extend_from_slice(&(i as u32).to_be_bytes());

        let key = derive_key(input_key_material, &info, key_length)?;
        keys.push(key);
    }

    Ok(keys)
}

/// B4AE-specific key derivation for protocol
pub struct B4aeKeyDerivation {
    master_secret: Vec<u8>,
}

impl B4aeKeyDerivation {
    /// Create new key derivation context from master secret
    pub fn new(master_secret: Vec<u8>) -> Self {
        B4aeKeyDerivation { master_secret }
    }

    /// Derive encryption key
    pub fn derive_encryption_key(&self) -> CryptoResult<Vec<u8>> {
        derive_key(
            &[&self.master_secret],
            b"B4AE-v1-encryption-key",
            32, // 256 bits
        )
    }

    /// Derive authentication key
    pub fn derive_authentication_key(&self) -> CryptoResult<Vec<u8>> {
        derive_key(
            &[&self.master_secret],
            b"B4AE-v1-authentication-key",
            32, // 256 bits
        )
    }

    /// Derive metadata protection key
    pub fn derive_metadata_key(&self) -> CryptoResult<Vec<u8>> {
        derive_key(
            &[&self.master_secret],
            b"B4AE-v1-metadata-key",
            32, // 256 bits
        )
    }

    /// Derive all protocol keys at once
    pub fn derive_all_keys(&self) -> CryptoResult<ProtocolKeys> {
        Ok(ProtocolKeys {
            encryption_key: self.derive_encryption_key()?,
            authentication_key: self.derive_authentication_key()?,
            metadata_key: self.derive_metadata_key()?,
        })
    }

    /// Derive session-specific keys
    pub fn derive_session_keys(&self, session_id: &[u8]) -> CryptoResult<ProtocolKeys> {
        let mut info_prefix = b"B4AE-v1-session-".to_vec();
        info_prefix.extend_from_slice(session_id);

        let keys = derive_multiple_keys(
            &[&self.master_secret],
            &info_prefix,
            3,
            32,
        )?;

        Ok(ProtocolKeys {
            encryption_key: keys[0].clone(),
            authentication_key: keys[1].clone(),
            metadata_key: keys[2].clone(),
        })
    }
}

/// Protocol keys derived from master secret
#[derive(Clone)]
pub struct ProtocolKeys {
    pub encryption_key: Vec<u8>,
    pub authentication_key: Vec<u8>,
    pub metadata_key: Vec<u8>,
}

impl ProtocolKeys {
    /// Zero out all keys
    pub fn zeroize(&mut self) {
        for byte in &mut self.encryption_key {
            *byte = 0;
        }
        for byte in &mut self.authentication_key {
            *byte = 0;
        }
        for byte in &mut self.metadata_key {
            *byte = 0;
        }
    }
}

impl Drop for ProtocolKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Drop for B4aeKeyDerivation {
    fn drop(&mut self) {
        // Zero out master secret
        for byte in &mut self.master_secret {
            *byte = 0;
        }
    }
}

impl std::fmt::Debug for ProtocolKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtocolKeys([REDACTED])")
    }
}

impl std::fmt::Debug for B4aeKeyDerivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B4aeKeyDerivation([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let ikm = b"input key material";
        let info = b"application context";
        
        let key1 = derive_key(&[ikm], info, 32).unwrap();
        let key2 = derive_key(&[ikm], info, 32).unwrap();
        
        // Same input should produce same output
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_different_info_different_keys() {
        let ikm = b"input key material";
        
        let key1 = derive_key(&[ikm], b"context1", 32).unwrap();
        let key2 = derive_key(&[ikm], b"context2", 32).unwrap();
        
        // Different context should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_multiple_keys() {
        let ikm = b"input key material";
        let keys = derive_multiple_keys(&[ikm], b"prefix", 3, 32).unwrap();
        
        assert_eq!(keys.len(), 3);
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_b4ae_key_derivation() {
        let master_secret = vec![0x42; 32];
        let kdf = B4aeKeyDerivation::new(master_secret);
        
        let keys = kdf.derive_all_keys().unwrap();
        
        assert_eq!(keys.encryption_key.len(), 32);
        assert_eq!(keys.authentication_key.len(), 32);
        assert_eq!(keys.metadata_key.len(), 32);
        
        // All keys should be different
        assert_ne!(keys.encryption_key, keys.authentication_key);
        assert_ne!(keys.authentication_key, keys.metadata_key);
        assert_ne!(keys.encryption_key, keys.metadata_key);
    }

    #[test]
    fn test_session_keys() {
        let master_secret = vec![0x42; 32];
        let kdf = B4aeKeyDerivation::new(master_secret);
        
        let session1 = kdf.derive_session_keys(b"session1").unwrap();
        let session2 = kdf.derive_session_keys(b"session2").unwrap();
        
        // Different sessions should have different keys
        assert_ne!(session1.encryption_key, session2.encryption_key);
    }

    #[test]
    fn test_derive_with_salt() {
        let salt = b"random salt";
        let ikm = b"input key material";
        let info = b"context";
        
        let key1 = derive_key_with_salt(salt, &[ikm], info, 32).unwrap();
        let key2 = derive_key_with_salt(salt, &[ikm], info, 32).unwrap();
        
        assert_eq!(key1, key2);
        
        // Different salt should produce different key
        let key3 = derive_key_with_salt(b"different salt", &[ikm], info, 32).unwrap();
        assert_ne!(key1, key3);
    }
}
